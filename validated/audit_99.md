# Audit Report

## Title
Transaction Rollback Inconsistency in Capability Module Causes Node Panic

## Summary
The capability module's `ReleaseCapability` function creates a state inconsistency when called within a failing transaction. The function deletes entries from both the transactional memStore and the non-transactional `capMap` Go map. When the transaction fails and rolls back, memStore deletions are reverted but `capMap` deletions persist, causing `GetCapability` to panic when it finds an index in memStore but nil in capMap. [1](#0-0) 

## Impact
Medium

## Finding Description

- **location**: `x/capability/keeper/keeper.go` lines 319-356 (`ReleaseCapability`) and lines 361-388 (`GetCapability`)

- **intended logic**: When a transaction fails, all state changes should be rolled back atomically. The capability module should maintain consistency between persistent store, memory store, and the in-memory `capMap`. Transaction rollback should restore all three storage layers to their pre-transaction state.

- **actual logic**: The `capMap` is a shared Go map that is NOT part of the transactional store system. [2](#0-1)  When `ReleaseCapability` executes, it deletes from memStore [3](#0-2)  and from capMap. [4](#0-3)  If the transaction fails, memStore deletions are rolled back (part of cached context), but capMap deletion persists (just a Go map operation).

- **exploitation path**:
  1. A capability exists in both memStore and capMap
  2. A transaction creates a cached context [5](#0-4) 
  3. `ReleaseCapability` is called within the cached context, deleting from both memStore and capMap
  4. Transaction fails due to gas exhaustion, validation error, or any runtime error
  5. The transaction execution framework does not write the cache [6](#0-5) 
  6. MemStore deletions are reverted, but capMap deletion persists
  7. Later `GetCapability` retrieves the index from memStore successfully [7](#0-6)  but finds `capMap[index]` returns nil [8](#0-7) , triggering panic

- **security guarantee broken**: This violates transaction atomicity guarantees and node availability. The code acknowledges this class of issue with a TODO comment [9](#0-8)  but only handles the `NewCapability` case (extra entries in map), not the `ReleaseCapability` case (missing entries in map).

## Impact Explanation

This vulnerability causes node panics leading to crashes. When a corrupted capability is accessed via `GetCapability`, the node immediately panics and terminates. Each failed transaction containing `ReleaseCapability` permanently corrupts one capability in the capMap until node restart.

The impact includes:
- **Node crashes**: The panic at line 384 immediately terminates the node process
- **Validator impact**: If ≥30% of validators encounter this during normal operations (e.g., IBC channel management), consensus is degraded
- **Persistent corruption**: The corrupted state persists until node restart, and can recur if the same transaction patterns repeat
- **Non-deterministic failures**: Different nodes may have different capMap states based on their transaction execution history

This matches the Medium severity impact: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network"

## Likelihood Explanation

**High likelihood** - This can be triggered during normal network operations:

- **Trigger conditions**: Any transaction that calls `ReleaseCapability` and subsequently fails (e.g., IBC channel close with gas exhaustion, port unbinding with validation errors)
- **Who can trigger**: Any user submitting transactions; no special privileges required
- **Frequency**: Transaction failures are routine in blockchain operations due to gas limits, state conflicts, or validation errors
- **Cumulative effect**: Each failure corrupts one capability; over time, more capabilities become corrupted, increasing the probability of panics during normal operations

## Recommendation

Implement transactional semantics for capMap operations:

1. **Deferred capMap Updates** (Recommended): Store pending capMap operations in the cached context and apply them only on successful commit:
   - Extend the cached context to track pending capMap additions/deletions
   - Implement a post-commit hook that applies these operations when `msCache.Write()` is called
   - Discard pending operations if the cache is not written

2. **Alternative - Defensive GetCapability**: Modify `GetCapability` to detect and recover from inconsistencies:
   - If `capMap[index]` is nil but index exists in memStore, check if capability exists in persistent store
   - If found in persistent store, recreate the capMap entry
   - Only panic if the inconsistency cannot be resolved

## Proof of Concept

**File**: `x/capability/keeper/keeper_test.go`

**Setup**: Create a capability in the original context, verify it exists in both memStore and capMap.

**Action**: 
1. Create a cached context via `CacheMultiStore()` [10](#0-9) 
2. Call `ReleaseCapability` in the cached context (deletes from both stores)
3. Do NOT call `msCache.Write()` (simulate transaction failure/rollback)
4. Attempt to call `GetCapability` from the original context

**Result**: The test should panic with message "capability found in memstore is missing from map" because:
- The index exists in memStore (deletion was rolled back)
- But `capMap[index]` returns nil (deletion was NOT rolled back)
- This triggers the panic at line 384

Test code structure (following existing test pattern from `TestRevertCapability`):
```go
func (suite *KeeperTestSuite) TestReleaseCapabilityPanicOnTransactionRollback() {
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    
    // Setup: Create capability in original context
    cap, err := sk.NewCapability(suite.ctx, "transfer")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    // Verify capability exists
    got, ok := sk.GetCapability(suite.ctx, "transfer")
    suite.Require().True(ok)
    suite.Require().Equal(cap, got)
    
    // Action: Release in cached context without writing
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    // NOT calling msCache.Write() - simulating transaction failure
    
    // Result: Should panic when accessing from original context
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "transfer")
    })
}
```

## Notes

The existing `TestRevertCapability` test validates the opposite scenario (creating a capability in a cached context without committing), demonstrating that the test infrastructure exists to reproduce this vulnerability. The TODO comment in the code explicitly acknowledges awareness of transaction rollback issues with the capMap but only addresses one direction of the problem.

### Citations

**File:** x/capability/keeper/keeper.go (L33-33)
```go
		capMap        map[uint64]*types.Capability
```

**File:** x/capability/keeper/keeper.go (L48-48)
```go
		capMap   map[uint64]*types.Capability
```

**File:** x/capability/keeper/keeper.go (L332-336)
```go
	memStore.Delete(types.FwdCapabilityKey(sk.module, cap))

	// Delete the reverse mapping between the module and capability name and the
	// index in the in-memory store.
	memStore.Delete(types.RevCapabilityKey(sk.module, name))
```

**File:** x/capability/keeper/keeper.go (L349-349)
```go
		delete(sk.capMap, cap.GetIndex())
```

**File:** x/capability/keeper/keeper.go (L368-369)
```go
	indexBytes := memStore.Get(key)
	index := sdk.BigEndianToUint64(indexBytes)
```

**File:** x/capability/keeper/keeper.go (L372-377)
```go
		// If a tx failed and NewCapability got reverted, it is possible
		// to still have the capability in the go map since changes to
		// go map do not automatically get reverted on tx failure,
		// so we delete here to remove unnecessary values in map
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805
```

**File:** x/capability/keeper/keeper.go (L382-384)
```go
	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
```

**File:** types/context.go (L589-592)
```go
func (c Context) CacheContext() (cc Context, writeCache func()) {
	cms := c.MultiStore().CacheMultiStore()
	cc = c.WithMultiStore(cms).WithEventManager(NewEventManager())
	return cc, cms.Write
```

**File:** baseapp/baseapp.go (L1015-1017)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** x/capability/keeper/keeper_test.go (L282-283)
```go
	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)
```
