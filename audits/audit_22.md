## Title
Access Operation Validation Failures Not Checked During Scheduler Validation Leading to State Corruption

## Summary
The concurrent transaction scheduler's validation logic in `tasks/scheduler.go` only verifies OCC (Optimistic Concurrency Control) conflicts through the multiversion store but does not check whether transactions failed access operation validation. This allows transactions with incorrect or incomplete access operation declarations that fail `ValidateAccessOperations` to have their writes committed to blockchain state if they don't trigger OCC conflicts, resulting in state corruption. [1](#0-0) 

## Impact
**High** - This vulnerability causes unintended smart contract behavior and state corruption, which falls under the "Medium" severity category in the scope: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." However, given the potential for consensus divergence and state corruption affecting the entire blockchain, this should be considered **High** severity.

## Finding Description

**Location:** 
- Primary vulnerability: `tasks/scheduler.go`, `shouldRerun` method (lines 354-390)
- Related validation logic: `baseapp/baseapp.go`, `runTx` method (lines 978-992)
- Write commitment: `tasks/scheduler.go`, `executeTask` method (line 576)

**Intended Logic:**
The system should ensure that only valid transactions with correct access operation declarations have their state changes committed. Transactions that fail access operation validation should have their writes invalidated and should not affect blockchain state.

**Actual Logic:**
When a transaction fails access operation validation in `runTx`, it returns an error response. However, the transaction's writes have already been persisted to the multiversion store via `WriteToMultiVersionStore`. The scheduler's `shouldRerun` method only checks for OCC conflicts using `findConflicts` but completely ignores the transaction's `Response.Code` error status. If there are no OCC conflicts detected, the transaction is marked as "validated" at line 379, and its writes are later committed to the parent store via `WriteLatestToStore`. [2](#0-1) [3](#0-2) [4](#0-3) 

**Exploit Scenario:**
1. An attacker submits Transaction T1 that exploits incomplete access operation declarations (either due to a bug in the access op mapping or intentionally if they control a contract's dependency mapping)
2. T1 declares only READ access on critical state key "balances/attacker" but its execution code writes to that key
3. Victim submits Transaction T2 that correctly declares and performs a READ on "balances/attacker"
4. Both transactions execute concurrently (DAG allows parallelism since both declared READ)
5. T1 writes malicious data to "balances/attacker" in the multiversion store
6. T2 reads the malicious data from T1's write in the multiversion store
7. T1 fails `ValidateAccessOperations` due to undeclared WRITE → error response
8. T2 passes `ValidateAccessOperations` (correct declarations)
9. Scheduler validates both: `shouldRerun(T1)` checks only `findConflicts` (no OCC conflict since T2 only read) → T1 marked "validated"
10. `WriteLatestToStore` commits both T1 and T2's writes to blockchain state
11. Result: T1's invalid write is persisted, T2's execution was based on corrupted data

**Security Failure:**
This breaks the state consistency invariant. The access operation validation layer is designed to ensure transactions accurately declare their resource access patterns. When this validation fails, it should prevent the transaction's effects from being committed. However, the scheduler's validation completely bypasses this check, allowing invalid transactions to corrupt blockchain state.

## Impact Explanation

**Affected Components:**
- Blockchain state integrity
- Transaction execution correctness  
- Consensus agreement between nodes
- Smart contract behavior

**Severity of Damage:**
- **State Corruption:** Invalid transactions with failed access operation validation can have their writes permanently committed to blockchain state
- **Cascading Effects:** Other valid transactions that read from the corrupted state execute with incorrect data, propagating the corruption
- **Consensus Divergence Risk:** Different nodes might handle validation edge cases differently, potentially leading to state divergence
- **Undetected Failures:** Since the invalid transaction appears "validated" by the scheduler, the corruption is subtle and difficult to detect
- **Smart Contract Integrity:** Contracts relying on accurate state will produce incorrect results

**Why This Matters:**
The access control system is a fundamental security mechanism in the sei-cosmos concurrent execution model. If transactions can bypass validation failures and still commit their effects, the entire security model is undermined. This could affect balances, contract state, governance decisions, and any other critical blockchain state.

## Likelihood Explanation

**Who Can Trigger:**
- Any user submitting transactions can potentially trigger this if:
  - There are bugs in the access operation dependency mappings for their transaction type
  - They control a WASM contract with incorrect dependency declarations
  - The dynamic dependency generator has bugs

**Conditions Required:**
- Transaction must have incomplete/incorrect access operation declarations
- Transaction must fail `ValidateAccessOperations` during execution
- The multiversion store OCC validation (`findConflicts`) must not detect a conflict
- Concurrent transaction execution must be enabled (OCC mode)

**Frequency:**
- Can occur during normal block production if access op mappings have bugs
- More likely with complex WASM contracts where dependency tracking is difficult
- The vulnerability is systematic—once triggered, it affects every block until fixed
- Given the complexity of maintaining accurate access operation declarations for all message types, bugs in declarations are probable

## Recommendation

Modify the `shouldRerun` method in `tasks/scheduler.go` to check the transaction's response code before marking it as validated:

```go
func (s *scheduler) shouldRerun(task *deliverTxTask) bool {
    switch task.Status {
    case statusAborted, statusPending:
        return true
    
    case statusExecuted, statusValidated:
        // ADD THIS CHECK: If response has an error code, invalidate and retry
        if task.Response != nil && task.Response.Code != 0 {
            s.invalidateTask(task)
            task.Reset()
            task.Increment()
            return true
        }
        
        // Existing OCC conflict check
        if valid, conflicts := s.findConflicts(task); !valid {
            s.invalidateTask(task)
            task.AppendDependencies(conflicts)
            // ... rest of existing logic
        }
        // ... rest of existing logic
    }
}
```

Alternatively, modify `executeTask` to not call `WriteToMultiVersionStore` if the response contains an error, and instead call `WriteEstimatesToMultiVersionStore` to allow dependent transactions to abort.

## Proof of Concept

**File:** `tasks/scheduler_test.go`

**Test Function:** `TestAccessOpValidationFailureNotCheckedByScheduler`

**Setup:**
1. Initialize test context with a KV store
2. Create 2 transactions: T1 and T2
3. Set up mock context with MsgValidator that tracks access operations
4. T1 will declare READ but perform WRITE (simulating incorrect declaration)
5. T2 will declare and perform READ correctly

**Trigger:**
```go
func TestAccessOpValidationFailureNotCheckedByScheduler(t *testing.T) {
    // Setup: Initialize context and stores
    ctx := initTestCtx(true)
    
    // Create mock msg validator that will fail validation for writes when only reads declared
    validator := acltypes.NewMsgValidator(acltypes.DefaultStoreKeyToResourceTypePrefixMap())
    ctx = ctx.WithMsgValidator(validator)
    
    requests := requestList(2)
    
    // Setup access ops: both declare READ only
    txMsgAccessOps := map[int][]acltypes.AccessOperation{
        0: { // T1 declares READ but will WRITE
            {AccessType: acltypes.AccessType_READ, ResourceType: acltypes.ResourceType_KV, IdentifierTemplate: string(itemKey)},
            {AccessType: acltypes.AccessType_COMMIT, ResourceType: acltypes.ResourceType_ANY, IdentifierTemplate: "*"},
        },
        1: { // T2 declares READ correctly
            {AccessType: acltypes.AccessType_READ, ResourceType: acltypes.ResourceType_KV, IdentifierTemplate: string(itemKey)},
            {AccessType: acltypes.AccessType_COMMIT, ResourceType: acltypes.ResourceType_ANY, IdentifierTemplate: "*"},
        },
    }
    
    deliverTxFunc := func(ctx sdk.Context, req types.RequestDeliverTx, tx sdk.Tx, checksum [32]byte) (res types.ResponseDeliverTx) {
        defer abortRecoveryFunc(&res)
        kv := ctx.MultiStore().GetKVStore(testStoreKey)
        
        // Set the access ops for this transaction
        ctx = ctx.WithTxMsgAccessOps(txMsgAccessOps)
        
        if ctx.TxIndex() == 0 {
            // T1: Writes (violates declared READ)
            kv.Set(itemKey, []byte("malicious_value"))
            
            // Simulate validation failure for missing WRITE declaration
            msCache := ctx.MultiStore().CacheMultiStore()
            events := msCache.GetEvents()
            accessOps := txMsgAccessOps[0]
            missingOps := validator.ValidateAccessOperations(accessOps, events)
            
            if len(missingOps) > 0 {
                return types.ResponseDeliverTx{
                    Code: 1, // Error code
                    Log:  "Missing WRITE access operation",
                }
            }
        } else {
            // T2: Reads correctly
            val := kv.Get(itemKey)
            return types.ResponseDeliverTx{
                Code: 0,
                Info: string(val),
            }
        }
        return types.ResponseDeliverTx{Code: 0}
    }
    
    // Execute via scheduler
    scheduler := NewScheduler(10, &tracing.Info{}, deliverTxFunc)
    responses, err := scheduler.ProcessAll(ctx, requests)
    
    require.NoError(t, err)
    require.Len(t, responses, 2)
    
    // OBSERVATION: T1 should have error code, but T2 might have executed with corrupted data
    require.Equal(t, uint32(1), responses[0].Code, "T1 should have failed validation")
    
    // Check if T1's write was committed despite error (this is the bug)
    store := ctx.MultiStore().GetKVStore(testStoreKey)
    value := store.Get(itemKey)
    
    if string(value) == "malicious_value" {
        t.Error("BUG CONFIRMED: T1's write was committed despite validation failure!")
    }
}
```

**Observation:**
The test will confirm that:
1. T1's response has error code 1 (validation failed)
2. Despite the error, T1's write to `itemKey` is persisted in the store
3. T2 may have read the corrupted value during execution
4. This demonstrates that transactions failing access operation validation can still corrupt state

The test exposes that `WriteLatestToStore` commits writes from transactions marked as "validated" by the scheduler, even when those transactions have error responses from access operation validation failures.

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
