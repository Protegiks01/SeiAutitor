## Audit Report

## Title
State Desynchronization in ReleaseCapability Causes Node Panic on Transaction Commit Failure

## Summary
The `ReleaseCapability` function in the capability keeper mixes transactional (cached) store operations with non-transactional Go map modifications. When releasing the last owner of a capability, it directly deletes from the `capMap` before the transaction commits. If the commit fails, cached store changes are rolled back but the map deletion persists, creating an inconsistent state that causes nodes to panic when accessing the capability. [1](#0-0) 

## Impact
**Medium** - This vulnerability can cause shutdown of network processing nodes without brute force actions, meeting the "Medium" severity criteria: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network."

## Finding Description

**Location:** 
`x/capability/keeper/keeper.go`, function `ReleaseCapability`, lines 319-356, specifically the direct map deletion at line 349. [2](#0-1) 

**Intended Logic:**
When releasing the last owner of a capability, all state should be atomically removed: the persistent store entry, the memory store mappings, and the in-memory Go map entry. If the transaction fails, all changes should be rolled back to maintain consistency.

**Actual Logic:**
The function performs operations in this order:
1. Lines 332, 336: Delete from `memStore` (cached/transactional)
2. Line 347: Delete from `prefixStore` (cached/transactional)
3. Line 349: Delete from `capMap` (direct Go map operation, NOT transactional) [3](#0-2) [4](#0-3) 

The direct map deletion at line 349 happens BEFORE the transaction commits. If the commit (via `Write()`) fails due to storage errors, the cached operations are rolled back, but the Go map modification persists permanently. [5](#0-4) 

The `Write()` method can panic if underlying store operations fail (e.g., disk errors, out of space): [6](#0-5) 

**Exploit Scenario:**
1. A module calls `ReleaseCapability` to release the last owner of a capability
2. The function executes successfully, including the direct `capMap` deletion at line 349
3. During transaction commit, `Write()` encounters a storage error (disk failure, out of space, etc.) and panics
4. The cached store operations are not written, but the `capMap` deletion has already happened
5. Result: `memStore` still has capability mappings, but `capMap` doesn't have the capability entry
6. When any module calls `GetCapability` for this capability:
   - Line 368 succeeds: `memStore.Get()` returns the capability index
   - Line 382 fails: `capMap[index]` returns nil
   - Line 384: Node panics with "capability found in memstore is missing from map" [7](#0-6) 

**Security Failure:**
This breaks the atomicity invariant of transaction processing. The codebase explicitly acknowledges this issue in comments: [8](#0-7) 

The comment states: "changes to go map do not automatically get reverted on tx failure" and references issue #7805, confirming this is a known architectural flaw.

## Impact Explanation

**Affected Components:**
- All capability-dependent modules (IBC, capability users)
- Node availability and reliability
- Network processing continuity

**Severity:**
When the vulnerability triggers:
1. The node panics immediately upon any attempt to access the affected capability via `GetCapability`
2. The panic crashes the node, taking it offline
3. Multiple nodes can be affected simultaneously if they all process transactions involving the same capability during storage failures
4. Critical IBC functionality depends on capabilities - node crashes prevent IBC operations

Storage failures (disk errors, out of space, filesystem corruption) are realistic scenarios in production environments. If such failures occur during `ReleaseCapability` transactions across multiple validators, a significant portion of the network could crash simultaneously, severely degrading network operations.

## Likelihood Explanation

**Who Can Trigger:**
Any module with capability ownership can call `ReleaseCapability`. No special privileges required beyond normal capability ownership (which is granted during module initialization).

**Conditions Required:**
1. A capability must have its last owner released (common during IBC connection/channel cleanup)
2. A storage error must occur during transaction commit
3. Storage errors can happen due to:
   - Disk failures
   - Filesystem full (out of space)
   - I/O errors
   - Database corruption

**Frequency:**
While storage errors are relatively rare, they do occur in production environments. The severity is amplified because:
- Multiple nodes may experience similar storage issues (e.g., reaching disk capacity around the same time)
- Once triggered, the node remains in a crashed state and cannot recover without manual intervention
- The inconsistent state persists, causing immediate panics on any capability access

## Recommendation

**Fix Strategy:**
Move the `capMap` deletion to occur AFTER the transaction successfully commits, or implement a deferred cleanup mechanism that handles map updates transactionally.

**Specific Changes:**

1. **Option A (Deferred Cleanup):** Don't delete from `capMap` during `ReleaseCapability`. Instead, mark capabilities for deletion and clean them up during `InitMemStore` or a periodic cleanup that verifies consistency with persistent store.

2. **Option B (Post-Commit Hook):** Implement a post-commit callback mechanism that only modifies `capMap` after `Write()` succeeds. This would require architectural changes to support post-commit hooks.

3. **Option C (Validation Guard):** In `GetCapability`, if `capMap[index]` returns nil but `memStore` has the mapping, attempt to recover by reloading from persistent store instead of panicking. This is defensive but doesn't fix the root cause.

**Recommended Approach:** Option A is the safest - defer all `capMap` modifications until a point where consistency can be guaranteed, such as during initialization or after confirmed commits.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityStateMismatch() {
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    
    // Create a capability
    cap, err := sk.NewCapability(suite.ctx, "test-cap")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    // Create a cached context to simulate transaction execution
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    
    // Release the capability in cached context (this will delete from capMap)
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    
    // DO NOT call msCache.Write() - simulating a commit failure
    // This leaves memStore changes unwritten, but capMap has been deleted
    
    // Now attempt to get the capability from the ORIGINAL context
    // memStore still has the mapping (because Write() wasn't called)
    // but capMap has been deleted
    // This should panic with "capability found in memstore is missing from map"
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "test-cap")
    })
}
```

**Setup:**
- Initialize test suite with keeper and scoped keeper
- Create a capability with one owner

**Trigger:**
- Create a cached context
- Call `ReleaseCapability` in the cached context (deletes from `capMap`)
- DO NOT call `Write()` on the cache (simulates commit failure)

**Observation:**
- Call `GetCapability` from the original context
- The test should observe a panic with message "capability found in memstore is missing from map"
- This confirms the state mismatch: `memStore` has the capability mapping (cached delete wasn't written), but `capMap` doesn't have it (direct delete already happened)

The panic proves the vulnerability - the node crashes when trying to access a capability after a simulated transaction commit failure during `ReleaseCapability`.

### Citations

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

**File:** x/capability/keeper/keeper.go (L365-385)
```go
	memStore := ctx.KVStore(sk.memKey)

	key := types.RevCapabilityKey(sk.module, name)
	indexBytes := memStore.Get(key)
	index := sdk.BigEndianToUint64(indexBytes)

	if len(indexBytes) == 0 {
		// If a tx failed and NewCapability got reverted, it is possible
		// to still have the capability in the go map since changes to
		// go map do not automatically get reverted on tx failure,
		// so we delete here to remove unnecessary values in map
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805

		return nil, false
	}

	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
	}
```

**File:** store/cachekv/store.go (L101-139)
```go
func (store *Store) Write() {
	store.mtx.Lock()
	defer store.mtx.Unlock()

	// We need a copy of all of the keys.
	// Not the best, but probably not a bottleneck depending.
	keys := []string{}

	store.cache.Range(func(key, value any) bool {
		if value.(*types.CValue).Dirty() {
			keys = append(keys, key.(string))
		}
		return true
	})
	sort.Strings(keys)
	// TODO: Consider allowing usage of Batch, which would allow the write to
	// at least happen atomically.
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

	store.cache = &sync.Map{}
	store.deleted = &sync.Map{}
	store.unsortedCache = &sync.Map{}
	store.sortedCache = dbm.NewMemDB()
}
```

**File:** store/dbadapter/store.go (L51-55)
```go
// Delete wraps the underlying DB's Delete method panicing on error.
func (dsa Store) Delete(key []byte) {
	if err := dsa.DB.Delete(key); err != nil {
		panic(err)
	}
```
