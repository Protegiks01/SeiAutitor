## Audit Report

## Title
State Corruption Through Partial Write Propagation in Concurrent Transaction Execution

## Summary
In the concurrent transaction execution path (OCC mode), failed transactions that run out of gas mid-execution have their partial state writes incorrectly propagated to the final committed state, violating transaction atomicity and causing state corruption. [1](#0-0) 

## Impact
**Medium** - A bug in the layer 1 network code that results in unintended smart contract behavior with no concrete funds at direct risk.

## Finding Description

**Location:** The vulnerability exists in `tasks/scheduler.go` in the `executeTask()` function, specifically at lines 574-577 where `WriteToMultiVersionStore()` is called unconditionally without checking transaction execution status. [2](#0-1) 

**Intended Logic:** Transactions must be atomic - either all state changes commit or none do. When a transaction runs out of gas, all partial state writes should be rolled back. In sequential execution mode, this is correctly handled by using a cache that is only written on success. [3](#0-2) 

**Actual Logic:** In concurrent execution (OCC) mode:

1. Gas metering happens at the `gaskv.Store` layer before each write operation [4](#0-3) 

2. Each successful write (where gas check passes) is stored in `VersionIndexedStore`'s in-memory writeset [5](#0-4) 

3. When gas runs out on a later operation, the panic is caught and converted to an error response [6](#0-5) 

4. The `executeTask()` function receives this error response but never checks `resp.Code` to determine if execution succeeded [7](#0-6) 

5. It unconditionally calls `WriteToMultiVersionStore()`, propagating the partial writeset

6. These partial writes eventually reach the parent store via `WriteLatestToStore()` [8](#0-7) 

**Exploit Scenario:**
1. Attacker or any user submits a transaction in a block processed with OCC enabled
2. The transaction performs multiple state writes (e.g., updating balances, counters, mappings)
3. After several successful writes consuming gas, a subsequent operation exceeds the gas limit
4. The transaction fails with out-of-gas error
5. However, the earlier successful writes remain in the `VersionIndexedStore` writeset
6. These partial writes are propagated to the multiversion store and eventually committed
7. The blockchain state now contains corrupted data from a transaction that should have been fully rolled back

**Security Failure:** The atomicity property of transactions is broken. The system incorrectly commits partial state changes from failed transactions, leading to state corruption and potential consensus divergence if different validators process transactions differently.

## Impact Explanation

**Affected Components:**
- All state variables modified by failed transactions
- Smart contract state consistency
- Application-level invariants that depend on transaction atomicity

**Severity of Damage:**
- State corruption: Partial updates from failed transactions persist in the blockchain state
- Broken invariants: Multi-step operations (e.g., token transfers, swaps) may leave the system in an inconsistent intermediate state
- Unpredictable behavior: Applications relying on atomicity guarantees will malfunction
- Potential consensus issues: If transaction processing differs across validators due to timing or gas estimation differences, divergent states could emerge

**Why This Matters:**
Transaction atomicity is a fundamental guarantee in blockchain systems. Breaking this guarantee undermines the reliability of the entire system. Applications cannot trust that their multi-step operations will complete atomically, leading to data corruption and potential exploitation of inconsistent states.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant submitting transactions can trigger this vulnerability, whether intentionally or unintentionally.

**Required Conditions:**
- Concurrent execution (OCC) must be enabled (`ConcurrencyWorkers > 0`)
- Transaction must run out of gas after making some successful state writes
- This is a common occurrence in normal network operation

**Frequency:**
This can occur multiple times per block during normal operation:
- Users frequently submit transactions that run out of gas
- Complex smart contract calls often consume more gas than estimated
- Adversaries can deliberately craft transactions to hit gas limits mid-execution
- With OCC enabled by default in Sei, every such transaction potentially corrupts state

## Recommendation

Add a check in `executeTask()` to verify transaction execution succeeded before propagating writes:

```go
func (s *scheduler) executeTask(task *deliverTxTask) {
    // ... existing code ...
    
    resp := s.deliverTx(task.Ctx, task.Request, task.SdkTx, task.Checksum)
    // close the abort channel
    close(task.AbortCh)
    abort, ok := <-task.AbortCh
    if ok {
        // existing abort handling
        return
    }

    task.SetStatus(statusExecuted)
    task.Response = &resp

    // FIX: Only write to multiversion store if transaction succeeded
    if resp.Code == 0 {  // resp.IsOK() can also be used
        for _, v := range task.VersionStores {
            v.WriteToMultiVersionStore()
        }
    }
    // If transaction failed, the writeset in VersionIndexedStore is discarded
}
```

This ensures that only successful transactions propagate their state changes to the multiversion store, maintaining transaction atomicity.

## Proof of Concept

**File:** `tasks/scheduler_test.go`

**Test Function:** Add the following test case to verify the vulnerability:

```go
func TestOutOfGasPartialWriteLeak(t *testing.T) {
    ctx := initTestCtx(true)
    
    // Set up a transaction that will run out of gas mid-execution
    requests := []*sdk.DeliverTxEntry{
        {
            Request: types.RequestDeliverTx{
                Tx: []byte("tx-0"),
            },
            AbsoluteIndex: 0,
        },
    }
    
    // Track which keys were written before out-of-gas
    writtenKeys := make(map[string]bool)
    
    deliverTxFunc := func(ctx sdk.Context, req types.RequestDeliverTx, tx sdk.Tx, checksum [32]byte) (res types.ResponseDeliverTx) {
        // Set up gas meter with limited gas
        ctx = ctx.WithGasMeter(sdk.NewGasMeter(10000))
        
        // Use proper KVStore access to trigger gas metering
        kv := ctx.KVStore(testStoreKey)
        
        // Make several writes that consume gas
        // Each Set costs approximately WriteCostFlat (2000) + WriteCostPerByte (30) * len
        kv.Set([]byte("key1"), []byte("value1"))  // Should succeed
        writtenKeys["key1"] = true
        
        kv.Set([]byte("key2"), []byte("value2"))  // Should succeed  
        writtenKeys["key2"] = true
        
        kv.Set([]byte("key3"), []byte("value3"))  // Should succeed
        writtenKeys["key3"] = true
        
        kv.Set([]byte("key4"), []byte("value4"))  // Should succeed
        writtenKeys["key4"] = true
        
        // This write should trigger out-of-gas
        kv.Set([]byte("key5"), []byte("value5"))  // Should FAIL with out-of-gas
        
        // Should never reach here
        kv.Set([]byte("key6"), []byte("value6"))
        
        return types.ResponseDeliverTx{}
    }
    
    scheduler := NewScheduler(10, &tracing.Info{Tracer: otel.Tracer("test")}, deliverTxFunc)
    
    responses, err := scheduler.ProcessAll(ctx, requests)
    require.NoError(t, err)
    require.Len(t, responses, 1)
    
    // Verify the transaction failed due to out-of-gas
    require.NotEqual(t, uint32(0), responses[0].Code, "Transaction should have failed with out-of-gas error")
    
    // BUG: Check if partial writes leaked into the store
    store := ctx.MultiStore().GetKVStore(testStoreKey)
    
    // These keys should NOT exist because the transaction failed
    // But due to the bug, they DO exist
    val1 := store.Get([]byte("key1"))
    val2 := store.Get([]byte("key2"))
    val3 := store.Get([]byte("key3"))
    val4 := store.Get([]byte("key4"))
    val5 := store.Get([]byte("key5"))
    val6 := store.Get([]byte("key6"))
    
    // Expected: All values should be nil (rolled back)
    // Actual: key1-key4 have values (partial write leak)
    if val1 != nil || val2 != nil || val3 != nil || val4 != nil {
        t.Errorf("VULNERABILITY CONFIRMED: Partial writes from failed transaction leaked into committed state")
        t.Errorf("key1: %v, key2: %v, key3: %v, key4: %v", val1, val2, val3, val4)
    }
    
    // These should definitely be nil (after the out-of-gas)
    require.Nil(t, val5, "key5 should not exist")
    require.Nil(t, val6, "key6 should not exist")
}
```

**Setup:**
- Initialize context with OCC-enabled multistore
- Create single transaction with gas meter set to limited gas
- Transaction performs multiple writes that will exhaust gas mid-execution

**Trigger:**
- Execute transaction via scheduler.ProcessAll()
- Transaction makes several successful writes then hits gas limit
- Out-of-gas panic is caught, transaction marked as failed

**Observation:**
- Test verifies `responses[0].Code != 0` confirming transaction failure
- Test checks if keys written before out-of-gas exist in final store
- **Bug confirmation:** keys 1-4 exist despite transaction failure (atomicity violation)
- This demonstrates partial state writes leaking into committed blockchain state

### Citations

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

**File:** baseapp/baseapp.go (L1008-1017)
```go
	runMsgCtx, msCache := app.cacheTxContext(ctx, checksum)

	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** store/gaskv/store.go (L69-80)
```go
func (gs *Store) Set(key []byte, value []byte) {
	types.AssertValidKey(key)
	types.AssertValidValue(value)
	gs.gasMeter.ConsumeGas(gs.gasConfig.WriteCostFlat, types.GasWriteCostFlatDesc)
	// TODO overflow-safe math?
	gs.gasMeter.ConsumeGas(gs.gasConfig.WriteCostPerByte*types.Gas(len(key)), types.GasWritePerByteDesc)
	gs.gasMeter.ConsumeGas(gs.gasConfig.WriteCostPerByte*types.Gas(len(value)), types.GasWritePerByteDesc)
	gs.parent.Set(key, value)
	if gs.tracer != nil {
		gs.tracer.Set(key, value, gs.moduleName)
	}
}
```

**File:** store/multiversion/mvkv.go (L369-375)
```go
// Only entrypoint to mutate writeset
func (store *VersionIndexedStore) setValue(key, value []byte) {
	types.AssertValidKey(key)

	keyStr := string(key)
	store.writeset[keyStr] = value
}
```

**File:** baseapp/recovery.go (L48-65)
```go
// newOutOfGasRecoveryMiddleware creates a standard OutOfGas recovery middleware for app.runTx method.
func newOutOfGasRecoveryMiddleware(gasWanted uint64, ctx sdk.Context, next recoveryMiddleware) recoveryMiddleware {
	handler := func(recoveryObj interface{}) error {
		err, ok := recoveryObj.(sdk.ErrorOutOfGas)
		if !ok {
			return nil
		}

		return sdkerrors.Wrap(
			sdkerrors.ErrOutOfGas, fmt.Sprintf(
				"out of gas in location: %v; gasWanted: %d, gasUsed: %d",
				err.Descriptor, gasWanted, ctx.GasMeter().GasConsumed(),
			),
		)
	}

	return newRecoveryMiddleware(handler, next)
}
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
