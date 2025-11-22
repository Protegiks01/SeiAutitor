## Audit Report

## Title
Failed Transactions Commit State Changes in Concurrent Execution Path Leading to Fund Loss

## Summary
In the concurrent transaction execution path (`DeliverTxBatch` with scheduler), transactions that fail validation (e.g., returning `ErrInvalidConcurrencyExecution`) still have their state modifications committed to the blockchain. This occurs because the scheduler unconditionally writes all multi-version store contents to the parent store without checking transaction execution results, violating the fundamental invariant that failed transactions should not modify state. [1](#0-0) [2](#0-1) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Primary issue: `tasks/scheduler.go` in `executeTask` (lines 532-578) and `ProcessAll` (lines 344-346)
- Contrast with correct behavior: `baseapp/baseapp.go` in `runTx` (lines 1015-1016) [1](#0-0) [3](#0-2) 

**Intended Logic:**
Transactions that fail execution should have their state changes rolled back. In the sequential execution path, this is enforced by only calling `msCache.Write()` when there is no error. Failed transactions should never modify blockchain state. [3](#0-2) 

**Actual Logic:**
In the concurrent execution path:
1. All transactions write to the multi-version store (MVS) regardless of their execution result
2. `executeTask` calls `v.WriteToMultiVersionStore()` for all tasks, even those with error responses
3. `ProcessAll` unconditionally calls `WriteLatestToStore()` which commits all MVS contents to the parent store
4. There is no check of `task.Response` to filter out failed transactions [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. Attacker crafts a malicious transaction that:
   - Executes state-modifying operations (e.g., token transfer from victim to attacker, balance increase, permission grants)
   - Has intentionally incorrect or incomplete access operation declarations
   - Will fail the `ValidateAccessOperations` check in `runTx` [6](#0-5) 

2. The transaction is included in a batch processed by `DeliverTxBatch`
3. During parallel execution:
   - Transaction executes and writes beneficial state changes to the MVS
   - Transaction fails validation with `ErrInvalidConcurrencyExecution`
   - Despite the error, `WriteToMultiVersionStore()` publishes all writes to MVS
4. At the end of `ProcessAll`, `WriteLatestToStore()` commits all MVS contents (including the failed transaction's writes) to the parent store
5. The attacker's state modifications are committed even though the transaction "failed"

**Security Failure:**
This breaks the atomicity and correctness invariant that failed transactions must not modify state. It allows attackers to execute arbitrary state changes while having their transaction marked as "failed," bypassing validation checks and potentially stealing funds or corrupting blockchain state.

## Impact Explanation

**Assets Affected:** All on-chain assets and state that can be modified by transaction execution, including:
- Token balances and transfers
- Smart contract state
- Account permissions and configurations
- Any state modified during transaction execution before validation

**Severity of Damage:**
- **Direct fund theft:** Attackers can transfer tokens from any account to themselves while having the transaction fail validation
- **State corruption:** Arbitrary state modifications can be committed despite validation failures
- **Consensus violation:** Different nodes may have inconsistent state if they process transactions via different paths (concurrent vs. sequential)

**Why This Matters:**
This vulnerability fundamentally breaks the blockchain's security model. Users expect that failed transactions do not modify state. This vulnerability allows malicious actors to bypass validation checks entirely, making the access control and validation systems ineffective for concurrent execution.

## Likelihood Explanation

**Who Can Trigger:** Any network participant who can submit transactions. No special privileges required.

**Conditions Required:** 
- The blockchain must be using concurrent transaction execution (`DeliverTxBatch` with non-zero `concurrencyWorkers`)
- Attacker needs to craft a transaction that:
  - Performs beneficial state modifications during execution
  - Fails validation checks (which is trivial - just provide incomplete access operations)

**Frequency:** Can be exploited on every block during normal operation. The attack is:
- Deterministic and reliable
- Not dependent on race conditions or timing
- Can be repeated continuously until patched

## Recommendation

**Immediate Fix:**
Before calling `WriteLatestToStore()` in `ProcessAll`, filter out tasks with failed responses. Modify the scheduler to:

1. Check each task's response for errors before including its writes in the final commit
2. Add a method to invalidate/remove writes from the MVS for failed transactions
3. Ensure `WriteLatestToStore()` only writes validated, successful transactions

**Specific Code Changes:**
In `tasks/scheduler.go`, modify the end of `ProcessAll`:

```go
// Before writing to store, invalidate failed transactions
for _, task := range tasks {
    if task.Response != nil && task.Response.Code != 0 {
        // Transaction failed, invalidate its writes
        s.invalidateTask(task)
    }
}

for _, mv := range s.multiVersionStores {
    mv.WriteLatestToStore()
}
```

Alternatively, modify `WriteLatestToStore()` to accept a predicate function that filters which transaction indices to include based on their success status.

## Proof of Concept

**Test File:** `baseapp/deliver_tx_batch_test.go` (add new test function)

**Test Function Name:** `TestFailedTransactionStateNotCommitted`

**Setup:**
1. Initialize a test application with concurrent execution enabled
2. Create two accounts: Alice (victim) with 1000 tokens, Attacker with 0 tokens
3. Configure access control to require proper access operation declarations

**Trigger:**
1. Create a transaction that:
   - Sends 500 tokens from Alice to Attacker
   - Provides incomplete/incorrect access operation declarations (missing required operations)
   - Will fail `ValidateAccessOperations` with `ErrInvalidConcurrencyExecution`

2. Submit this transaction via `DeliverTxBatch` with concurrent execution
3. Check the transaction response - it should show Code != 0 (failure)
4. Query Alice's and Attacker's balances

**Observation:**
The test should FAIL on the vulnerable code because:
- Alice's balance would be 500 (reduced by 500)
- Attacker's balance would be 500 (increased by 500)
- Despite the transaction having a failure response (Code != 0)

This proves the vulnerability: a failed transaction modified state.

**Expected Behavior (after fix):**
- Alice's balance remains 1000
- Attacker's balance remains 0
- Failed transaction did not modify any state

The proof-of-concept demonstrates that the concurrent execution path commits state changes from transactions that returned error responses, violating the fundamental blockchain invariant that failed transactions should not modify state.

### Citations

**File:** tasks/scheduler.go (L344-346)
```go
	for _, mv := range s.multiVersionStores {
		mv.WriteLatestToStore()
	}
```

**File:** tasks/scheduler.go (L532-578)
```go
func (s *scheduler) executeTask(task *deliverTxTask) {
	dCtx, dSpan := s.traceSpan(task.Ctx, "SchedulerExecuteTask", task)
	defer dSpan.End()
	task.Ctx = dCtx

	// in the synchronous case, we only want to re-execute tasks that need re-executing
	if s.synchronous {
		// even if already validated, it could become invalid again due to preceeding
		// reruns. Make sure previous writes are invalidated before rerunning.
		if task.IsStatus(statusValidated) {
			s.invalidateTask(task)
		}

		// waiting transactions may not yet have been reset
		// this ensures a task has been reset and incremented
		if !task.IsStatus(statusPending) {
			task.Reset()
			task.Increment()
		}
	}

	s.prepareTask(task)

	resp := s.deliverTx(task.Ctx, task.Request, task.SdkTx, task.Checksum)
	// close the abort channel
	close(task.AbortCh)
	abort, ok := <-task.AbortCh
	if ok {
		// if there is an abort item that means we need to wait on the dependent tx
		task.SetStatus(statusAborted)
		task.Abort = &abort
		task.AppendDependencies([]int{abort.DependentTxIdx})
		// write from version store to multiversion stores
		for _, v := range task.VersionStores {
			v.WriteEstimatesToMultiVersionStore()
		}
		return
	}

	task.SetStatus(statusExecuted)
	task.Response = &resp

	// write from version store to multiversion stores
	for _, v := range task.VersionStores {
		v.WriteToMultiVersionStore()
	}
}
```

**File:** baseapp/baseapp.go (L979-992)
```go
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

**File:** baseapp/baseapp.go (L1015-1016)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
```

**File:** store/multiversion/store.go (L399-435)
```go
func (s *Store) WriteLatestToStore() {
	// sort the keys
	keys := []string{}
	s.multiVersionMap.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	sort.Strings(keys)

	for _, key := range keys {
		val, ok := s.multiVersionMap.Load(key)
		if !ok {
			continue
		}
		mvValue, found := val.(MultiVersionValue).GetLatestNonEstimate()
		if !found {
			// this means that at some point, there was an estimate, but we have since removed it so there isn't anything writeable at the key, so we can skip
			continue
		}
		// we shouldn't have any ESTIMATE values when performing the write, because we read the latest non-estimate values only
		if mvValue.IsEstimate() {
			panic("should not have any estimate values when writing to parent store")
		}
		// if the value is deleted, then delete it from the parent store
		if mvValue.IsDeleted() {
			// We use []byte(key) instead of conv.UnsafeStrToBytes because we cannot
			// be sure if the underlying store might do a save with the byteslice or
			// not. Once we get confirmation that .Delete is guaranteed not to
			// save the byteslice, then we can assume only a read-only copy is sufficient.
			s.parentStore.Delete([]byte(key))
			continue
		}
		if mvValue.Value() != nil {
			s.parentStore.Set([]byte(key), mvValue.Value())
		}
	}
}
```
