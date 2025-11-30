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

- **actual logic**: The `capMap` is a shared Go map that is NOT part of the transactional store system. [1](#0-0)  When `ReleaseCapability` executes, it deletes from memStore [2](#0-1)  and from capMap. [3](#0-2)  If the transaction fails, memStore deletions are rolled back (part of cached context), but capMap deletion persists (just a Go map operation).

- **exploitation path**:
  1. A capability exists in both memStore and capMap with a single owner
  2. A transaction creates a cached context [4](#0-3) 
  3. `ReleaseCapability` is called within the cached context, deleting from both memStore and capMap
  4. Transaction fails due to gas exhaustion, validation error, or any runtime error
  5. The transaction execution framework does not write the cache [5](#0-4) 
  6. MemStore deletions are reverted, but capMap deletion persists
  7. Later `GetCapability` retrieves the index from memStore successfully [6](#0-5)  but finds `capMap[index]` returns nil, triggering panic [7](#0-6) 

- **security guarantee broken**: This violates transaction atomicity guarantees and node availability. The code acknowledges this class of issue with a TODO comment [8](#0-7)  but only handles the `NewCapability` case (extra entries in map), not the `ReleaseCapability` case (missing entries in map).

## Impact Explanation

This vulnerability causes node panics leading to crashes. When a corrupted capability is accessed via `GetCapability`, the node immediately panics and terminates. Each failed transaction containing `ReleaseCapability` permanently corrupts one capability in the capMap until node restart.

The impact includes:
- **Node crashes**: The panic immediately terminates the node process
- **Validator impact**: All validators executing the same block would experience identical corruption due to deterministic transaction execution, potentially causing widespread outages
- **Persistent corruption**: The corrupted state persists until node restart
- **IBC operations**: Since capabilities are used for IBC port and channel management, [9](#0-8)  corrupted capabilities could cause cascading failures in cross-chain operations

This matches the Medium severity impact: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network"

## Likelihood Explanation

This vulnerability has realistic exploitability during normal network operations:

- **Trigger conditions**: Any transaction that calls `ReleaseCapability` and subsequently fails (e.g., IBC channel close with gas exhaustion, port unbinding with validation errors). The capability module is designed to be used by other modules for resource management, particularly IBC.
- **Who can trigger**: Any user submitting transactions; no special privileges required
- **Frequency**: Transaction failures are routine in blockchain operations due to gas limits, state conflicts, or validation errors
- **Deterministic corruption**: All nodes executing the same failed transaction in DeliverTx mode would experience identical corruption, potentially affecting all validators simultaneously
- **Cumulative effect**: Each failure corrupts one capability; the corrupted capability causes a panic only when accessed again via `GetCapability`

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

**Setup**: Create a capability in the original context with a single owner, verify it exists in both memStore and capMap.

**Action**: 
1. Create a cached context via `CacheMultiStore()` [10](#0-9) 
2. Call `ReleaseCapability` in the cached context (deletes from both memStore and capMap)
3. Do NOT call `msCache.Write()` (simulate transaction failure/rollback)
4. Attempt to call `GetCapability` from the original context

**Result**: The test should panic with message "capability found in memstore is missing from map" because:
- The index exists in memStore (deletion was rolled back)
- But `capMap[index]` returns nil (deletion was NOT rolled back)
- This triggers the panic at line 384

## Notes

The existing `TestRevertCapability` test validates the opposite scenario (creating a capability in a cached context without committing), demonstrating that the test infrastructure exists to reproduce this vulnerability. The TODO comment in the code explicitly acknowledges awareness of transaction rollback issues with the capMap (referencing GitHub issue #7805) but only addresses one direction of the problem (extra entries from `NewCapability`), not the reverse direction (missing entries from `ReleaseCapability`). This represents a new exploitable dimension of a known issue class.

### Citations

**File:** x/capability/keeper/keeper.go (L33-33)
```go
		capMap        map[uint64]*types.Capability
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

**File:** docs/ibc/overview.md (L53-56)
```markdown
### [Capabilities](./ocap.md)

IBC is intended to work in execution environments where modules do not necessarily trust each other. IBC must authenticate module actions on ports and channels so that only modules with the appropriate permissions can use the channels. This security is accomplished using [dynamic capabilities](../architecture/adr-003-dynamic-capability-store.md). Upon binding to a port or creating a channel for a module, IBC returns a dynamic capability that the module must claim to use that port or channel. This binding strategy prevents other modules from using that port or channel since those modules do not own the appropriate capability.

```

**File:** x/capability/keeper/keeper_test.go (L277-306)
```go
func (suite KeeperTestSuite) TestRevertCapability() {
	sk := suite.keeper.ScopeToModule(banktypes.ModuleName)

	ms := suite.ctx.MultiStore()

	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)

	capName := "revert"
	// Create capability on cached context
	cap, err := sk.NewCapability(cacheCtx, capName)
	suite.Require().NoError(err, "could not create capability")

	// Check that capability written in cached context
	gotCache, ok := sk.GetCapability(cacheCtx, capName)
	suite.Require().True(ok, "could not retrieve capability from cached context")
	suite.Require().Equal(cap, gotCache, "did not get correct capability from cached context")

	// Check that capability is NOT written to original context
	got, ok := sk.GetCapability(suite.ctx, capName)
	suite.Require().False(ok, "retrieved capability from original context before write")
	suite.Require().Nil(got, "capability not nil in original store")

	// Write to underlying memKVStore
	msCache.Write()

	got, ok = sk.GetCapability(suite.ctx, capName)
	suite.Require().True(ok, "could not retrieve capability from context")
	suite.Require().Equal(cap, got, "did not get correct capability from context")
}
```
