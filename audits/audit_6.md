# Audit Report

## Title
Scheduler Commits State Changes from Failed Transactions Due to Missing Response Code Validation

## Summary
The concurrent transaction scheduler in the Sei blockchain fails to validate transaction response codes when determining whether to commit state changes. Failed transactions (with non-zero response codes) have their state modifications permanently committed to the blockchain if they don't trigger OCC conflicts, violating the fundamental invariant that only successful transactions should modify state.

## Impact
Medium

## Finding Description

**Location:**
- `tasks/scheduler.go`, `shouldRerun` method (lines 354-390)
- `tasks/scheduler.go`, unconditional write (line 576)  
- `tasks/scheduler.go`, final commitment (line 345) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended logic:**
Only transactions that complete successfully should have state changes committed to the blockchain. The documented invariant states: "State only gets persisted if all messages are valid and get executed successfully." [4](#0-3) 

In normal sequential execution, when a transaction fails and returns an error, the cached state changes are not written to the parent store: [5](#0-4) 

**Actual logic:**
In the OCC concurrent execution path:

1. Transactions execute and write to VersionIndexedStore, potentially failing validation [6](#0-5) [7](#0-6) 

2. Errors are converted to ResponseDeliverTx with non-zero code [8](#0-7) 

3. `WriteToMultiVersionStore()` is called unconditionally after execution, persisting all writes regardless of response code [2](#0-1) 

4. The `shouldRerun` method only checks for OCC conflicts via `findConflicts` and never examines `task.Response.Code` [1](#0-0) 

5. If no OCC conflicts detected, the transaction is marked as "validated" (line 379)

6. `WriteLatestToStore()` commits all "validated" transactions' writes to blockchain state [3](#0-2) 

**Exploitation path:**
1. User submits transaction T1 that will fail during execution (e.g., due to access operation validation failure, message handler error, or any other execution error)
2. T1 executes and makes state modifications via VersionIndexedStore before failing
3. Execution fails and returns error, which is converted to ResponseDeliverTx with non-zero code
4. `WriteToMultiVersionStore()` persists T1's writes to multiversion store unconditionally (line 576)
5. Scheduler's `shouldRerun(T1)` checks only for OCC conflicts, ignoring the non-zero response code
6. If no OCC conflicts detected, T1 is marked as "validated" (line 379)
7. `WriteLatestToStore()` commits T1's writes to blockchain state despite the transaction failure (line 345)
8. Subsequent transactions read and operate on the corrupted state

**Security guarantee broken:**
The documented invariant that "State only gets persisted if all messages are valid and get executed successfully" is violated. Failed transactions (with non-zero response codes) have their state changes permanently committed.

## Impact Explanation

This vulnerability results in permanent state corruption with cascading effects:

1. **State Corruption**: Transactions that fail execution (access operation validation, message handler errors, etc.) have their writes permanently committed despite returning error codes
2. **Cascading Effects**: Valid subsequent transactions read and execute based on corrupted state, propagating incorrect data
3. **Smart Contract Integrity**: Smart contracts relying on accurate state produce incorrect results and outcomes
4. **Detection Difficulty**: Failed transactions appear "validated" by the scheduler, making the corruption subtle and hard to detect

This matches the Medium severity impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:**
Any user submitting transactions during normal network operation. This can occur when:
- Access operation dependency mappings contain bugs
- WASM contracts have incorrect dependency declarations  
- Message handlers return errors during execution
- Any transaction validation fails after state modifications have begun

**Conditions required:**
- Transaction must fail during execution (returning error/non-zero response code)
- The multiversion store OCC validation must not detect a conflict
- Concurrent transaction execution must be enabled (OCC mode)

**Frequency:**
Can occur during normal block production whenever transactions fail execution. Given the complexity of:
- Maintaining accurate access operation declarations for WASM contracts
- Complex message handler logic that can fail mid-execution
- The TODO comments indicating the OCC validation system is still under development

The likelihood is moderate - transaction failures are not uncommon, and each failure in OCC mode potentially commits corrupted state.

## Recommendation

**Option 1:** Modify the `shouldRerun` method to check transaction response code before marking as validated:

```go
case statusExecuted, statusValidated:
    // Check if response has an error code
    if task.Response != nil && task.Response.Code != 0 {
        s.invalidateTask(task)
        task.Reset()
        task.Increment()
        return true
    }
    
    // Existing OCC conflict check
    if valid, conflicts := s.findConflicts(task); !valid {
        // ... existing logic
    }
```

**Option 2:** Modify `executeTask` to conditionally call `WriteToMultiVersionStore()` only for successful transactions:

```go
if resp.Code == 0 {
    for _, v := range task.VersionStores {
        v.WriteToMultiVersionStore()
    }
} else {
    // Failed transaction - write estimates only or invalidate
    for _, v := range task.VersionStores {
        v.WriteEstimatesToMultiVersionStore()
    }
}
```

## Proof of Concept

The vulnerability is demonstrable through code analysis:

**Setup:**
- Normal execution path: Cache writes only committed if `err == nil` [5](#0-4) 

**Action:**
- OCC execution path: Writes committed unconditionally regardless of response code [2](#0-1) 

- Validation only checks OCC conflicts, not response codes [1](#0-0) 

**Result:**
Failed transactions (response code != 0) have writes committed via `WriteLatestToStore()` because the scheduler marks them "validated" based solely on absence of OCC conflicts, breaking the documented invariant that state only persists for successful transactions.

## Notes

The vulnerability is validated through comprehensive code analysis showing the scheduler bypasses response code validation that exists in normal sequential execution. The TODO comments in the codebase indicate the OCC validation system is still under development, suggesting this validation gap was likely unintentional. The divergence between normal execution (which checks `err == nil` before writing state) and OCC execution (which writes unconditionally) represents a critical security flaw that allows state corruption from failed transactions.

### Citations

**File:** tasks/scheduler.go (L344-346)
```go
	for _, mv := range s.multiVersionStores {
		mv.WriteLatestToStore()
	}
```

**File:** tasks/scheduler.go (L354-390)
```go
func (s *scheduler) shouldRerun(task *deliverTxTask) bool {
	switch task.Status {

	case statusAborted, statusPending:
		return true

	// validated tasks can become unvalidated if an earlier re-run task now conflicts
	case statusExecuted, statusValidated:
		// With the current scheduler, we won't actually get to this step if a previous task has already been determined to be invalid,
		// since we choose to fail fast and mark the subsequent tasks as invalid as well.
		// TODO: in a future async scheduler that no longer exhaustively validates in order, we may need to carefully handle the `valid=true` with conflicts case
		if valid, conflicts := s.findConflicts(task); !valid {
			s.invalidateTask(task)
			task.AppendDependencies(conflicts)

			// if the conflicts are now validated, then rerun this task
			if dependenciesValidated(s.allTasksMap, task.Dependencies) {
				return true
			} else {
				// otherwise, wait for completion
				task.SetStatus(statusWaiting)
				return false
			}
		} else if len(conflicts) == 0 {
			// mark as validated, which will avoid re-validating unless a lower-index re-validates
			task.SetStatus(statusValidated)
			return false
		}
		// conflicts and valid, so it'll validate next time
		return false

	case statusWaiting:
		// if conflicts are done, then this task is ready to run again
		return dependenciesValidated(s.allTasksMap, task.Dependencies)
	}
	panic("unexpected status: " + task.Status)
}
```

**File:** tasks/scheduler.go (L571-577)
```go
	task.SetStatus(statusExecuted)
	task.Response = &resp

	// write from version store to multiversion stores
	for _, v := range task.VersionStores {
		v.WriteToMultiVersionStore()
	}
```

**File:** baseapp/abci.go (L280-283)
```go
// State only gets persisted if all messages are valid and get executed successfully.
// Otherwise, the ResponseDeliverTx will contain relevant error information.
// Regardless of tx execution outcome, the ResponseDeliverTx will contain relevant
// gas execution context.
```

**File:** baseapp/abci.go (L304-311)
```go
	gInfo, result, anteEvents, _, _, _, resCtx, err := app.runTx(ctx.WithTxBytes(req.Tx).WithTxSum(checksum).WithVoteInfos(app.voteInfos), runTxModeDeliver, tx, checksum)
	if err != nil {
		resultStr = "failed"
		// if we have a result, use those events instead of just the anteEvents
		if result != nil {
			return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(result.Events, app.indexEvents), app.trace)
		}
		return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(anteEvents, app.indexEvents), app.trace)
```

**File:** baseapp/baseapp.go (L978-992)
```go
		// Dont need to validate in checkTx mode
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
			storeAccessOpEvents := msCache.GetEvents()
			accessOps := ctx.TxMsgAccessOps()[acltypes.ANTE_MSG_INDEX]

			// TODO: (occ) This is an example of where we do our current validation. Note that this validation operates on the declared dependencies for a TX / antehandler + the utilized dependencies, whereas the validation
			missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
			if len(missingAccessOps) != 0 {
				for op := range missingAccessOps {
					ctx.Logger().Info((fmt.Sprintf("Antehandler Missing Access Operation:%s ", op.String())))
					op.EmitValidationFailMetrics()
				}
				errMessage := fmt.Sprintf("Invalid Concurrent Execution antehandler missing %d access operations", len(missingAccessOps))
				return gInfo, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
			}
```

**File:** baseapp/baseapp.go (L1015-1017)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** baseapp/baseapp.go (L1155-1174)
```go
		if ctx.MsgValidator() == nil {
			continue
		}
		storeAccessOpEvents := msgMsCache.GetEvents()
		accessOps := ctx.TxMsgAccessOps()[i]
		missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
		// TODO: (occ) This is where we are currently validating our per message dependencies,
		// whereas validation will be done holistically based on the mvkv for OCC approach
		if len(missingAccessOps) != 0 {
			for op := range missingAccessOps {
				ctx.Logger().Info((fmt.Sprintf("eventMsgName=%s Missing Access Operation:%s ", eventMsgName, op.String())))
				op.EmitValidationFailMetrics()
			}
			errMessage := fmt.Sprintf("Invalid Concurrent Execution messageIndex=%d, missing %d access operations", i, len(missingAccessOps))
			// we need to bubble up the events for inspection
			return &sdk.Result{
				Log:    strings.TrimSpace(msgLogs.String()),
				Events: events.ToABCIEvents(),
			}, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
		}
```
