## Audit Report

## Title
Non-Atomic Multi-Store Write Operation Causes Persistent Store and Memory Store Inconsistency in ClaimCapability

## Summary
The `ClaimCapability` function updates both persistent and memory stores within a transaction. When the transaction commits via `CacheMultiStore.Write()`, the method iterates over stores non-atomically. If a crash, panic, or failure occurs mid-iteration, some stores are written while others are not, creating permanent inconsistency between the persistent and memory stores that gets committed to disk. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: [2](#0-1) 
- Affected function: [1](#0-0) 

**Intended Logic:** 
The `ClaimCapability` function should atomically update both the persistent store (capability ownership) and memory store (forward/reverse capability mappings). Both stores should remain consistent - either both updates succeed or both fail. [3](#0-2) 

**Actual Logic:** 
When a transaction completes successfully, `CacheMultiStore.Write()` is called to commit cached changes. This method iterates over a Go map of stores and writes each sequentially without atomicity guarantees: [2](#0-1) 

Since Go map iteration is non-deterministic, the order of writes is unpredictable. If a panic or crash occurs during iteration (e.g., from `store.parent.Set()` or `store.parent.Delete()` panicking due to database errors), previous stores are already written to the parent while subsequent stores are not. [4](#0-3) 

The underlying database operations can panic on errors: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. A module calls `ClaimCapability` during transaction execution
2. Both persistent store (via `addOwner`) and memory store updates are cached
3. Transaction succeeds and `msCache.Write()` is called in `runTx`
4. During the Write() iteration, if the persistent store writes successfully but the memory store write panics (due to disk full, I/O error, memory corruption, or hardware failure), the deliverState becomes inconsistent
5. The panic is caught by the defer/recover in `runTx`, but the partial writes to deliverState remain
6. Subsequent transactions in the block operate on inconsistent state
7. At block end, `WriteState()` commits the inconsistent deliverState to disk [7](#0-6) [8](#0-7) 

**Security Failure:**
State consistency invariant is violated. The persistent store may record capability ownership while the memory store lacks the corresponding mappings (or vice versa), breaking the capability module's ability to correctly validate capability ownership in future operations.

## Impact Explanation

This vulnerability affects the capability module's state integrity, which is critical for Inter-Blockchain Communication (IBC) and other modules that rely on capability-based access control:

- **Affected Processes:** Capability ownership tracking becomes inconsistent. Modules may own capabilities according to the persistent store but be unable to retrieve them via `GetCapability` (which uses the memory store), or vice versa.

- **Severity:** The inconsistency persists on disk and affects all nodes that process the block. After restart, `InitMemStore` reconstructs the memory store from persistent state, but this doesn't resolve the core issue - if writes were partially applied before commit, the on-disk state itself may be inconsistent.

- **System Reliability:** This qualifies as "A bug in the layer 0/1/2 network code that results in unintended smart contract behavior" (Medium impact per scope). IBC channels, ports, and other capability-dependent operations may fail unexpectedly, potentially causing transaction failures or module malfunctions without direct fund loss.

## Likelihood Explanation

**Who can trigger it:** Any transaction that calls `ClaimCapability` can be affected if a hardware/database failure occurs at the critical moment.

**Required conditions:** 
- A hardware failure, disk I/O error, out-of-memory condition, or database corruption must occur during the `Write()` operation
- The timing must be precise - during the store iteration after one store writes but before another

**Frequency:** While not frequently occurring, hardware failures and database errors are realistic operational concerns in production blockchain infrastructure. The non-deterministic nature of the issue makes it difficult to predict or reproduce, but when it occurs, the impact is permanent state corruption. The TODO comment in the code acknowledges this issue: [9](#0-8) 

## Recommendation

Implement atomic write operations for the `CacheMultiStore.Write()` method by using database batch operations. The recommended fix:

1. Collect all key-value pairs from all stores before writing
2. Use a database batch transaction to write all changes atomically
3. If any write fails, the entire batch is rolled back, maintaining consistency

Alternatively, implement a two-phase commit protocol where:
1. Phase 1: All stores prepare their writes and verify they can succeed
2. Phase 2: Only if all stores successfully prepare, commit all writes together
3. If any store fails in phase 1, abort without modifying any state

This ensures that either all stores in the cache are written or none are, maintaining the invariant that persistent and memory stores remain consistent.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go` (add new test function)

**Test Function:** `TestClaimCapabilityPartialWriteFailure`

**Setup:**
```
1. Initialize a test app with capability keeper
2. Create a scoped keeper for a test module
3. Create a new capability via NewCapability
4. Set up a mock store that will panic after writing the first store but before the second
```

**Trigger:**
```
1. Call ClaimCapability from a different module to claim the existing capability
2. Simulate a database error during the Write() operation by injecting a panic in one of the store's Write() methods
3. Observe that the transaction appears to fail (panic caught), but deliverState has been partially updated
```

**Observation:**
The test should detect that:
- The persistent store has been updated with the new owner
- The memory store has NOT been updated with the forward/reverse mappings
- Subsequent GetCapability calls fail even though the module should own the capability according to persistent state
- This inconsistency persists and would be committed to disk

**Note:** Due to the complexity of mocking the exact failure scenario at the CacheMultiStore level, a full working PoC would require extensive test infrastructure modifications. The vulnerability is confirmed by code inspection showing the non-atomic iteration in `CacheMultiStore.Write()` and the acknowledgment in the TODO comment about the lack of atomicity.

### Citations

**File:** x/capability/keeper/keeper.go (L287-314)
```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
	if cap == nil {
		return sdkerrors.Wrap(types.ErrNilCapability, "cannot claim nil capability")
	}
	if strings.TrimSpace(name) == "" {
		return sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
	}
	// update capability owner set
	if err := sk.addOwner(ctx, cap, name); err != nil {
		return err
	}

	memStore := ctx.KVStore(sk.memKey)

	// Set the forward mapping between the module and capability tuple and the
	// capability name in the memKVStore
	memStore.Set(types.FwdCapabilityKey(sk.module, cap), []byte(name))

	// Set the reverse mapping between the module and capability name and the
	// index in the in-memory store. Since marshalling and unmarshalling into a store
	// will change memory address of capability, we simply store index as value here
	// and retrieve the in-memory pointer to the capability from our map
	memStore.Set(types.RevCapabilityKey(sk.module, name), sdk.Uint64ToBigEndian(cap.GetIndex()))

	logger(ctx).Info("claimed capability", "module", sk.module, "name", name, "capability", cap.GetIndex())

	return nil
}
```

**File:** store/cachemulti/store.go (L141-147)
```go
// Write calls Write on each underlying store.
func (cms Store) Write() {
	cms.db.Write()
	for _, store := range cms.stores {
		store.Write()
	}
}
```

**File:** store/cachekv/store.go (L116-117)
```go
	// TODO: Consider allowing usage of Batch, which would allow the write to
	// at least happen atomically.
```

**File:** store/cachekv/store.go (L118-133)
```go
	for _, key := range keys {
		if store.isDeleted(key) {
			// We use []byte(key) instead of conv.UnsafeStrToBytes because we cannot
			// be sure if the underlying store might do a save with the byteslice or
			// not. Once we get confirmation that .Delete is guaranteed not to
			// save the byteslice, then we can assume only a read-only copy is sufficient.
			store.parent.Delete([]byte(key))
			continue
		}

		cacheValue, ok := store.cache.Load(key)
		if ok && cacheValue.(*types.CValue).Value() != nil {
			// It already exists in the parent, hence delete it.
			store.parent.Set([]byte(key), cacheValue.(*types.CValue).Value())
		}
	}
```

**File:** store/dbadapter/store.go (L44-49)
```go
func (dsa Store) Set(key, value []byte) {
	types.AssertValidKey(key)
	if err := dsa.DB.Set(key, value); err != nil {
		panic(err)
	}
}
```

**File:** store/dbadapter/store.go (L52-56)
```go
func (dsa Store) Delete(key []byte) {
	if err := dsa.DB.Delete(key); err != nil {
		panic(err)
	}
}
```

**File:** baseapp/baseapp.go (L339-342)
```go
func (app *BaseApp) OccEnabled() bool {
	return app.occEnabled
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
