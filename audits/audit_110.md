# Audit Report

## Title
Access Operation Validation Failures Not Checked During Scheduler Validation Leading to State Corruption

## Summary
The concurrent transaction scheduler in `tasks/scheduler.go` validates transactions only for OCC (Optimistic Concurrency Control) conflicts but fails to check transaction response codes. This allows transactions that fail access operation validation (or any validation that returns an error) to have their state changes permanently committed to the blockchain, violating the fundamental invariant that failed transactions should not modify state.

## Impact
Medium

## Finding Description

**Location:**
- Primary vulnerability: `tasks/scheduler.go`, `shouldRerun` method (lines 354-390)
- Unconditional write persistence: `tasks/scheduler.go`, line 576 (`WriteToMultiVersionStore`)
- Final state commitment: `tasks/scheduler.go`, line 345 (`WriteLatestToStore`) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended logic:**
Only transactions that complete successfully should have their state changes committed to the blockchain. In normal sequential execution, when a transaction fails validation and returns an error, the cached state changes are not written to the parent store. [4](#0-3) 

**Actual logic:**
In the OCC concurrent execution path:
1. Transactions execute and can fail access operation validation, returning an error with non-zero response code
2. `WriteToMultiVersionStore()` is called unconditionally after execution (line 576), persisting all writes regardless of the response code
3. The `shouldRerun` method (lines 354-390) only checks for OCC conflicts via `findConflicts` and never examines `task.Response.Code`
4. If no OCC conflicts are detected, the transaction is marked as "validated" (line 379)
5. `WriteLatestToStore()` (line 345) commits all "validated" transactions' writes to the blockchain state, including those from failed transactions [5](#0-4) 

**Exploitation path:**
1. A transaction T1 is submitted with incorrect access operation declarations (due to bugs in mappings or malicious WASM contracts)
2. T1 executes and makes state modifications via the VersionIndexedStore
3. Access operation validation fails during execution, returning an error response with non-zero code
4. `WriteToMultiVersionStore()` persists T1's writes to the multiversion store (line 576)
5. The scheduler's `shouldRerun(T1)` checks only for OCC conflicts via `findConflicts` (lines 365)
6. If no OCC conflicts are detected, T1 is marked as "validated" (line 379)
7. `WriteLatestToStore()` commits T1's writes to the blockchain state despite the validation failure (line 345)
8. Subsequent transactions reading this state execute with corrupted data

**Security guarantee broken:**
The fundamental blockchain invariant that failed transactions do not modify state is violated. The scheduler bypasses response code validation, allowing invalid transactions to corrupt blockchain state.

## Impact Explanation

This vulnerability results in permanent state corruption with cascading effects:

1. **State Corruption**: Transactions that fail access operation validation have their writes permanently committed to blockchain state despite returning error codes
2. **Cascading Effects**: Valid transactions reading corrupted state will execute with incorrect data, propagating corruption throughout the blockchain
3. **Smart Contract Integrity**: Smart contracts relying on accurate state will produce incorrect results
4. **Difficult Detection**: Failed transactions appear "validated" by the scheduler, making corruption subtle and hard to detect

This matches the Medium severity impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:**
Any user submitting transactions can trigger this when:
- Access operation dependency mappings contain bugs
- WASM contracts have incorrect dependency declarations  
- The dynamic dependency generator has bugs

**Conditions required:**
- Transaction must have incomplete/incorrect access operation declarations
- Transaction must fail `ValidateAccessOperations` during execution
- The multiversion store OCC validation (`findConflicts`) must not detect a conflict
- Concurrent transaction execution must be enabled (OCC mode)

**Frequency:**
- Can occur during normal block production if access operation mappings have bugs
- More likely with complex WASM contracts where dependency tracking is difficult
- Given the complexity of maintaining accurate access operation declarations for all message types, bugs in declarations are reasonably probable [6](#0-5) 

## Recommendation

Modify the `shouldRerun` method in `tasks/scheduler.go` to check the transaction's response code before marking it as validated:

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

Alternatively, modify `executeTask` to conditionally call `WriteToMultiVersionStore()` only for successful transactions:

```go
if resp.Code == 0 {
    for _, v := range task.VersionStores {
        v.WriteToMultiVersionStore()
    }
} else {
    for _, v := range task.VersionStores {
        v.WriteEstimatesToMultiVersionStore()
    }
}
```

## Proof of Concept

**Conceptual PoC flow** (implementable in `tasks/scheduler_test.go`):

**Setup:**
1. Initialize test context with KV store and MsgValidator
2. Create a deliverTx function that fails validation and returns a response with Code=1
3. Create two transactions where T1 writes to the store but returns error code, T2 reads correctly

**Action:**
1. Execute both transactions via the scheduler
2. T1 executes, modifies state, and returns error response (Code != 0)
3. `WriteToMultiVersionStore()` persists T1's writes unconditionally
4. Scheduler validates both transactions using only OCC conflict detection
5. No OCC conflicts detected, so both marked as "validated"
6. `WriteLatestToStore()` commits both transactions' writes

**Result:**
- T1's response has error code (validation failed)
- Despite the error, T1's write to the store is persisted in the blockchain state
- This demonstrates that the scheduler's validation logic only checks OCC conflicts and does not verify response codes

The vulnerability is confirmed through code analysis showing that `shouldRerun` never checks `task.Response.Code`, allowing failed transactions to have their writes committed via `WriteLatestToStore()`.

## Notes

The vulnerability is validated through comprehensive code analysis:

1. In normal sequential execution at [4](#0-3) , failed transactions do not commit state changes
2. In OCC concurrent execution, this invariant is broken because the scheduler never validates response codes
3. Access operation validation failures return errors at [5](#0-4) , which are converted to non-zero response codes
4. However, the scheduler unconditionally persists writes and only checks OCC conflicts, not response codes

This breaks the access control system's security model, which relies on accurate resource access declarations to enable safe concurrent execution.

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

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-55)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
	}
	for _, accessOp := range accessOps {
		err := ValidateAccessOp(accessOp)
		if err != nil {
			return err
		}
	}

	return nil
}

func ValidateAccessOp(accessOp acltypes.AccessOperation) error {
	if accessOp.IdentifierTemplate == "" {
		return ErrEmptyIdentifierString
	}
	if accessOp.ResourceType.HasChildren() && accessOp.IdentifierTemplate != "*" {
		return ErrNonLeafResourceTypeWithIdentifier
	}
	return nil
}
```
