## Audit Report

## Title
Node Crash Due to Non-Transactional capMap Deletion in ReleaseCapability

## Summary
The `ReleaseCapability` function deletes capabilities from the in-memory `capMap` using Go's `delete()` operation, which is not transactional and cannot be reverted when a transaction fails. This creates an inconsistent state where the memStore retains the capability index mapping (due to transaction rollback) but `capMap` has a nil entry (deletion is permanent), causing `GetCapability` to panic and crash the node. [1](#0-0) 

## Impact
**Medium to High**: Shutdown of network processing nodes without brute force actions.

## Finding Description

**Location:** 
- Module: `x/capability`
- File: `keeper/keeper.go`
- Functions: `ReleaseCapability` (lines 319-356) and `GetCapability` (lines 361-388)

**Intended Logic:**
When a transaction that releases a capability fails and gets reverted, all state changes should be rolled back atomically to maintain consistency between the persistent store, memory store (memStore), and the in-memory capability map (capMap).

**Actual Logic:**
The `ReleaseCapability` function performs three critical operations:
1. Deletes from memStore (transactional, can be reverted) [2](#0-1) 
2. Deletes from persistent store (transactional, can be reverted) [3](#0-2) 
3. Deletes from capMap using Go's `delete()` (NOT transactional, CANNOT be reverted) [4](#0-3) 

When a transaction fails, the Cosmos SDK's CacheMultiStore mechanism reverts operations 1 and 2, but operation 3 remains permanent because Go maps are not part of the transactional context. [5](#0-4) 

**Exploit Scenario:**
1. A module owns a capability as the sole owner
2. A transaction calls `ReleaseCapability` on this capability
3. After `ReleaseCapability` executes but before transaction commit, the transaction fails (out of gas, validation error, panic, etc.)
4. The transaction is reverted via `cacheTxContext` without calling `msCache.Write()`
5. Result: memStore still contains the `RevCapabilityKey` mapping (revert restored it), but `capMap[index]` is nil (delete was permanent)
6. Any subsequent call to `GetCapability` will:
   - Find the index in memStore [6](#0-5) 
   - Look up `cap := sk.capMap[index]` which returns nil [7](#0-6) 
   - Trigger panic: `"capability found in memstore is missing from map"` [8](#0-7) 

**Security Failure:**
This breaks the atomicity invariant of transaction execution, leading to an inconsistent state that causes node crashes through panic, resulting in a denial-of-service condition.

## Impact Explanation

**Affected Components:**
- Node availability and uptime
- Transaction processing capability
- Network reliability

**Severity:**
When triggered, this vulnerability causes an immediate node crash via panic. The inconsistent state persists until the node is restarted and `InitMemStore` repopulates the `capMap` from the persistent store. [9](#0-8) 

Multiple transactions could encounter this inconsistent state before a restart, causing repeated crashes and effectively creating a denial-of-service condition. If this affects a significant portion of validator nodes simultaneously, it could impact network liveness.

## Likelihood Explanation

**Who can trigger it:**
Any unprivileged user or contract that can initiate a transaction which:
1. Includes a capability release operation (e.g., IBC channel closing)
2. Subsequently fails for any reason (out of gas, validation failure, message execution error)

**Conditions required:**
- The capability must have only one owner (so `len(capOwners.Owners) == 0` after removal triggers the `delete()` path)
- The transaction must fail AFTER `ReleaseCapability` executes but BEFORE final commit
- This can happen during normal operation through legitimate transaction failures

**Frequency:**
This could occur whenever IBC channels are closed, ports are released, or any other capability management operation happens within a transaction that subsequently fails. Given that transaction failures are common (out of gas, validation errors, etc.), this vulnerability has a moderate to high likelihood of natural occurrence.

## Recommendation

Move the `delete(sk.capMap, cap.GetIndex())` operation outside the transactional context by deferring it until after successful transaction commit, or implement a transaction-aware cleanup mechanism that only removes from `capMap` when the transaction is definitively committed.

**Specific fix:**
Add a post-commit hook or deferred cleanup that only deletes from `capMap` after `msCache.Write()` succeeds. Alternatively, track deletions in a separate structure during transaction execution and apply them only on successful commit.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add the following test to the `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityPanicOnTransactionRevert() {
	sk1 := suite.keeper.ScopeToModule(banktypes.ModuleName)
	
	// Create a capability with a single owner
	cap, err := sk1.NewCapability(suite.ctx, "transfer")
	suite.Require().NoError(err)
	suite.Require().NotNil(cap)
	
	// Verify we can retrieve the capability
	got, ok := sk1.GetCapability(suite.ctx, "transfer")
	suite.Require().True(ok)
	suite.Require().Equal(cap, got)
	
	// Create a cached context to simulate a transaction that will be reverted
	ms := suite.ctx.MultiStore()
	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)
	
	// Release the capability in the cached context
	// This deletes from capMap (permanent) and from stores (temporary)
	err = sk1.ReleaseCapability(cacheCtx, cap)
	suite.Require().NoError(err)
	
	// Verify capability is gone in the cached context
	got, ok = sk1.GetCapability(cacheCtx, "transfer")
	suite.Require().False(ok)
	suite.Require().Nil(got)
	
	// DON'T write the cache - simulating transaction failure/revert
	// msCache.Write() is NOT called, so store changes are reverted
	// but capMap deletion is permanent
	
	// Now attempt to get the capability in the original context
	// This SHOULD panic because:
	// - memStore has the RevCapabilityKey (transaction rollback restored it)
	// - capMap[index] is nil (Go map delete is not transactional)
	suite.Require().Panics(func() {
		sk1.GetCapability(suite.ctx, "transfer")
	}, "Expected panic due to capability in memstore but nil in capMap")
}
```

**Setup:**
The test initializes a keeper with a scoped module and creates a capability with a single owner.

**Trigger:**
1. Create a cached context (simulating transaction execution)
2. Call `ReleaseCapability` which deletes from both stores and `capMap`
3. Do NOT call `msCache.Write()` (simulating transaction failure/revert)
4. Call `GetCapability` in the original context

**Observation:**
The test expects a panic with the message "capability found in memstore is missing from map" because the memStore was reverted (capability index restored) but `capMap` was not (deletion is permanent). This confirms the vulnerability where transaction rollback creates an inconsistent state leading to node crashes.

### Citations

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

**File:** x/capability/keeper/keeper.go (L319-356)
```go
func (sk ScopedKeeper) ReleaseCapability(ctx sdk.Context, cap *types.Capability) error {
	if cap == nil {
		return sdkerrors.Wrap(types.ErrNilCapability, "cannot release nil capability")
	}
	name := sk.GetCapabilityName(ctx, cap)
	if len(name) == 0 {
		return sdkerrors.Wrap(types.ErrCapabilityNotOwned, sk.module)
	}

	memStore := ctx.KVStore(sk.memKey)

	// Delete the forward mapping between the module and capability tuple and the
	// capability name in the memKVStore
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
		// since no one owns capability, we can delete capability from map
		delete(sk.capMap, cap.GetIndex())
	} else {
		// update capability owner set
		prefixStore.Set(indexKey, sk.cdc.MustMarshal(capOwners))
	}

	return nil
}
```

**File:** x/capability/keeper/keeper.go (L368-369)
```go
	indexBytes := memStore.Get(key)
	index := sdk.BigEndianToUint64(indexBytes)
```

**File:** x/capability/keeper/keeper.go (L382-382)
```go
	cap := sk.capMap[index]
```

**File:** x/capability/keeper/keeper.go (L383-385)
```go
	if cap == nil {
		panic("capability found in memstore is missing from map")
	}
```

**File:** baseapp/baseapp.go (L1015-1016)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
```
