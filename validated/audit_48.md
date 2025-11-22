# Audit Report

## Title
Access Operation Validation Failures Not Checked During Scheduler Validation Leading to State Corruption

## Summary
The concurrent transaction scheduler in `tasks/scheduler.go` only validates transactions for OCC (Optimistic Concurrency Control) conflicts but does not check transaction response codes to determine if transactions failed during execution. This allows transactions that fail access operation validation to have their state changes committed to the blockchain, violating the fundamental invariant that failed transactions should not modify state.

## Impact
Medium

## Finding Description

**Location:** 
- Primary vulnerability: `tasks/scheduler.go`, `shouldRerun` method (lines 354-390)
- Write commitment: `tasks/scheduler.go`, line 345 (`WriteLatestToStore`)
- Write persistence: `tasks/scheduler.go`, line 576 (`WriteToMultiVersionStore`) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended logic:** 
Only transactions that complete successfully should have their state changes committed to the blockchain. In normal (sequential) execution, when a transaction fails validation and returns an error, the cached state changes are not written to the parent store, as seen in `baseapp/baseapp.go` lines 1015-1016 where `msCache.Write()` is only called when `err == nil`. [4](#0-3) 

**Actual logic:** 
In the OCC concurrent execution path:
1. Transactions execute using a `VersionIndexedStore` that tracks reads and writes
2. When a transaction fails access operation validation in `runTx`, an error is returned and converted to a response with non-zero `Code`
3. However, `WriteToMultiVersionStore()` is called unconditionally after execution (line 576), persisting all writes to the multiversion store regardless of the response code
4. The scheduler's `shouldRerun` method only checks for OCC conflicts via `findConflicts` and does not examine `task.Response.Code`
5. If no OCC conflicts are detected, the transaction is marked as "validated" (line 379)
6. `WriteLatestToStore()` (line 345) commits all "validated" transactions' writes to the blockchain state, including those from failed transactions [5](#0-4) 

**Exploitation path:**
1. Transaction T1 is submitted with incorrect or incomplete access operation declarations (either due to a bug in the access operation mapping or through a malicious WASM contract)
2. T1 declares READ-only access but performs WRITE operations
3. T1 executes and makes state modifications via the VersionIndexedStore
4. Access operation validation fails, returning an error response with non-zero code
5. `WriteToMultiVersionStore()` persists T1's writes to the multiversion store
6. The scheduler's `shouldRerun(T1)` checks only for OCC conflicts via `findConflicts`
7. If no OCC conflicts are detected (e.g., no concurrent transactions accessed the same keys), T1 is marked as "validated"
8. `WriteLatestToStore()` commits T1's writes to the blockchain state despite the validation failure
9. Other transactions that subsequently read this state execute with corrupted data

**Security guarantee broken:** 
The fundamental blockchain invariant that failed transactions do not modify state is violated. The access control system is designed to ensure transactions accurately declare their resource access patterns, and validation failures should prevent state commitment. The scheduler bypasses this check, allowing invalid transactions to corrupt blockchain state.

## Impact Explanation

This vulnerability results in state corruption that affects blockchain integrity:

1. **State Corruption**: Transactions that fail access operation validation have their writes permanently committed to blockchain state, even though they should have been rejected
2. **Cascading Effects**: Valid transactions that read from corrupted state will execute with incorrect data, propagating the corruption throughout the blockchain
3. **Smart Contract Integrity**: Smart contracts relying on accurate state will produce incorrect results, leading to unintended behavior
4. **Difficult Detection**: Since failed transactions appear "validated" by the scheduler, the corruption is subtle and not easily detected through normal monitoring

This falls under the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:**
- Any user submitting transactions can potentially trigger this if:
  - There are bugs in the access operation dependency mappings for their transaction type
  - They control a WASM contract with incorrect dependency declarations
  - The dynamic dependency generator has bugs

**Conditions required:**
- Transaction must have incomplete/incorrect access operation declarations
- Transaction must fail `ValidateAccessOperations` during execution  
- The multiversion store OCC validation (`findConflicts`) must not detect a conflict
- Concurrent transaction execution must be enabled (OCC mode)

**Frequency:**
- Can occur during normal block production if access operation mappings have bugs
- More likely with complex WASM contracts where dependency tracking is difficult
- Given the complexity of maintaining accurate access operation declarations for all message types, bugs in declarations are reasonably probable

The validation of WASM dependency mappings is only static (checking format), not dynamic (verifying declarations match actual execution), making this more likely to occur in practice. [6](#0-5) 

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

**File:** `tasks/scheduler_test.go`

**Test Function:** `TestAccessOpValidationFailureNotCheckedByScheduler`

**Setup:**
1. Initialize test context with KV store and MsgValidator
2. Create two transactions: T1 (declares READ but performs WRITE) and T2 (declares and performs READ correctly)
3. Set up access operation declarations for both transactions

**Action:**
1. Execute both transactions via the scheduler
2. T1 performs WRITE despite declaring only READ
3. T1 fails access operation validation and receives error response code
4. Scheduler validates both transactions using only OCC conflict detection
5. No OCC conflicts detected (T2 only reads), so both marked as "validated"
6. `WriteLatestToStore()` commits both transactions' writes

**Result:**
- T1's response has error code 1 (validation failed)
- Despite the error, T1's write to the store is persisted in the blockchain state
- This demonstrates that transactions failing access operation validation can corrupt state when no OCC conflicts are detected

The proof of concept demonstrates the core issue: the scheduler's validation logic (`shouldRerun`) only checks for OCC conflicts via `findConflicts` and does not verify that `task.Response.Code == 0` before marking transactions as validated. This allows failed transactions to have their writes committed via `WriteLatestToStore()` at line 345.

## Notes

The vulnerability is confirmed through code analysis. In normal sequential execution, failed transactions do not commit state changes due to the check at `baseapp/baseapp.go` lines 1015-1016. However, in the OCC concurrent execution path, this invariant is broken because:

1. The `VersionIndexedStore` persists writes via `WriteToMultiVersionStore()` regardless of transaction success
2. The scheduler's validation only checks OCC conflicts, not response codes
3. All "validated" transactions have their writes committed, including those that failed

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
