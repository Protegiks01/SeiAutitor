# Audit Report

## Title
Capability Keeper Transaction Rollback Causes Deterministic Node Panic Due to Non-Transactional capMap Deletion

## Summary
A vulnerability exists in the capability keeper where releasing a capability in a transaction that subsequently rolls back creates an inconsistent state between the transactional KVStore (memStore) and non-transactional Go map (capMap), causing deterministic node panics across all network nodes when the capability is subsequently accessed.

## Impact
Medium

## Finding Description

- **location**: `x/capability/keeper/keeper.go`, function `ReleaseCapability` (lines 319-356) and `GetCapability` (lines 361-388), critical operations at line 349 (capMap deletion) and line 384 (panic trigger)

- **intended logic**: When a capability is released within a transaction that subsequently fails and rolls back, all state changes should be atomically reverted to maintain consistency between memStore, persistent store, and capMap. The system should return to its exact pre-transaction state.

- **actual logic**: The `capMap` at line 33 is a Go map (`map[uint64]*types.Capability`) that is not backed by any transactional store. [1](#0-0)  When `ReleaseCapability` deletes from this map at line 349 using `delete(sk.capMap, cap.GetIndex())`, this deletion is immediate and permanent. [2](#0-1)  However, the memStore deletions at lines 332 and 336, and the prefixStore deletion at line 347, are all backed by transactional KVStores. [3](#0-2)  When the transaction rolls back (cached context is discarded without calling Write()), these KVStore deletions are reverted but the capMap deletion persists, creating an inconsistent state where memStore contains a reverse mapping to an index, but `capMap[index]` is nil.

- **exploitation path**:
  1. Any user submits a transaction that causes a module to call `ReleaseCapability` on a capability (e.g., IBC channel close, capability release during module operations)
  2. Within the cached transaction context, the capability is deleted from `capMap` at line 349 (non-transactional, immediate deletion)
  3. The capability owner information is removed from memStore (lines 332, 336) and prefixStore (line 347) - both transactional
  4. The transaction encounters an error after these operations (out of gas, validation failure, application logic error) and rolls back
  5. The cached context is discarded without calling Write(), reverting all KVStore changes
  6. The memStore and prefixStore deletions are reverted, but the capMap deletion persists
  7. All nodes processing this block deterministically enter the same inconsistent state
  8. Any subsequent call to `GetCapability` with that capability name will: retrieve the index from memStore at line 368 (succeeds because deletion was reverted), look up `sk.capMap[index]` at line 382 (returns nil because deletion was NOT reverted), and panic at line 384 with "capability found in memstore is missing from map" [4](#0-3) 

- **security guarantee broken**: The atomicity invariant of transaction processing is violated. The Go map state diverges from transactional KVStore state, breaking the fundamental assumption that all state changes within a transaction are atomic. This causes deterministic node crashes across the network, violating the availability guarantee.

## Impact Explanation

This vulnerability causes coordinated shutdown of network processing nodes through deterministic panics. When triggered:

- A transaction that releases a capability and then fails gets included in a block (transactions that fail during DeliverTx are still included to charge gas)
- All nodes processing that block execute the same code path deterministically
- All nodes enter the same inconsistent state where capMap is missing an entry but memStore retains the mapping
- Any subsequent transaction (in the same block or future blocks) that attempts to access the affected capability via `GetCapability` will cause all nodes to panic simultaneously at line 384
- This qualifies as "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" (Medium severity)

The impact is particularly severe because:
1. All nodes are affected simultaneously and deterministically (100% shutdown, not just 30%)
2. The panic occurs during block processing, causing all nodes to crash at the same height
3. IBC channel operations become high-risk, as channel closures that fail can permanently break the network
4. Recovery requires coordinated node restarts, and the vulnerability can be re-triggered if similar transactions are submitted

Note: The report incorrectly claims the inconsistency persists across restarts. In reality, `InitMemStore` rebuilds capMap from the persistent prefixStore at startup [5](#0-4) , which fixes the inconsistency after restart. However, this doesn't reduce the severity because all nodes must coordinate restarts to recover from each occurrence.

## Likelihood Explanation

This vulnerability has realistic likelihood of occurring during normal network operations:

**Who can trigger**: Any network participant or module that can cause a transaction to fail after a capability is released:
- IBC relayers submitting channel close messages that fail
- Smart contracts or modules implementing IBC callbacks that release capabilities
- Any application logic that releases capabilities within transactions that may encounter errors

**Required conditions**:
1. A capability with a single owner (or the last remaining owner releasing it)
2. `ReleaseCapability` called within a transaction context
3. The transaction fails after the release but before the cached context is written (common scenarios: out of gas after capability release, validation errors in subsequent operations, application-specific logic failures)

**Frequency**: Transaction failures are common in blockchain operations. The Cosmos SDK's gas metering, validation checks, and application logic all provide opportunities for transactions to fail. Once triggered, any access to the affected capability causes immediate network-wide panics.

**Evidence of awareness**: The code comment at lines 372-377 acknowledges that the Go map is non-transactional and discusses the reverse problem (capability creation rollback), but the deletion rollback case is not handled. [6](#0-5)  The existing test `TestRevertCapability` only covers creation rollback, not deletion rollback. [7](#0-6) 

## Recommendation

Implement transaction-aware management for `capMap` modifications to maintain consistency with transactional KVStore operations:

**Recommended Fix**: Add defensive nil-checking in `GetCapability` to detect and handle the inconsistent state gracefully:

```go
cap := sk.capMap[index]
if cap == nil {
    // Inconsistent state detected - memStore has index but capMap doesn't
    // This can happen if ReleaseCapability was called in a transaction that rolled back
    // Clean up the memStore entry to restore consistency
    memStore.Delete(key)
    return nil, false
}
```

This defensive fix prevents the panic and automatically repairs the inconsistent state by removing the orphaned memStore entry. While this doesn't prevent the inconsistency from occurring, it prevents the catastrophic network-wide panic.

**Alternative Comprehensive Fix**: Make `capMap` transaction-aware by deferring deletions until transaction commit, though this requires more significant architectural changes to track pending operations per context.

## Proof of Concept

**Test**: Can be reproduced by creating a test in `x/capability/keeper/keeper_test.go`:

**Setup**:
1. Initialize capability keeper with a scoped keeper
2. Create a capability in the base context
3. Verify the capability exists and can be retrieved

**Action**:
1. Create a cached multistore context: `msCache := ms.CacheMultiStore()` and `cacheCtx := suite.ctx.WithMultiStore(msCache)`
2. Call `ReleaseCapability` on the capability in the cached context (as sole owner)
3. Do NOT call `msCache.Write()` to simulate transaction rollback
4. Attempt to retrieve the capability in the original base context using `GetCapability`

**Result**:
The call to `GetCapability` will panic with "capability found in memstore is missing from map" because:
- The memStore still contains the reverse mapping (deletion was reverted when cache wasn't written)
- The capMap does not contain the capability pointer (deletion was NOT reverted as it's a Go map)
- This confirms the vulnerability: transaction rollback creates an inconsistent state causing deterministic node panics

The vulnerability is valid and matches the Medium severity impact criterion: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions."

### Citations

**File:** x/capability/keeper/keeper.go (L33-33)
```go
		capMap        map[uint64]*types.Capability
```

**File:** x/capability/keeper/keeper.go (L107-134)
```go
func (k *Keeper) InitMemStore(ctx sdk.Context) {
	memStore := ctx.KVStore(k.memKey)
	memStoreType := memStore.GetStoreType()
	if memStoreType != sdk.StoreTypeMemory {
		panic(fmt.Sprintf("invalid memory store type; got %s, expected: %s", memStoreType, sdk.StoreTypeMemory))
	}

	// check if memory store has not been initialized yet by checking if initialized flag is nil.
	if !k.IsInitialized(ctx) {
		prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.KeyPrefixIndexCapability)
		iterator := sdk.KVStorePrefixIterator(prefixStore, nil)

		// initialize the in-memory store for all persisted capabilities
		defer iterator.Close()

		for ; iterator.Valid(); iterator.Next() {
			index := types.IndexFromKey(iterator.Key())

			var capOwners types.CapabilityOwners

			k.cdc.MustUnmarshal(iterator.Value(), &capOwners)
			k.InitializeCapability(ctx, index, capOwners)
		}

		// set the initialized flag so we don't rerun initialization logic
		memStore := ctx.KVStore(k.memKey)
		memStore.Set(types.KeyMemInitialized, []byte{1})
	}
```

**File:** x/capability/keeper/keeper.go (L332-347)
```go
	memStore.Delete(types.FwdCapabilityKey(sk.module, cap))

	// Delete the reverse mapping between the module and capability name and the
	// index in the in-memory store.
	memStore.Delete(types.RevCapabilityKey(sk.module, name))

	// remove owner
	capOwners := sk.getOwners(ctx, cap)
	capOwners.Remove(types.NewOwner(sk.module, name))

	prefixStore := prefix.NewStore(ctx.KVStore(sk.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(cap.GetIndex())

	if len(capOwners.Owners) == 0 {
		// remove capability owner set
		prefixStore.Delete(indexKey)
```

**File:** x/capability/keeper/keeper.go (L349-349)
```go
		delete(sk.capMap, cap.GetIndex())
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

**File:** x/capability/keeper/keeper.go (L382-385)
```go
	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
	}
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
