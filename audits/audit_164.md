## Title
Transaction Rollback Does Not Revert capMap Modifications, Causing Node Panic on Subsequent GetCapability Calls

## Summary
The capability keeper's `ReleaseCapability` function directly modifies the `capMap` Go map, which is not part of the cached transaction context. When a transaction containing `ReleaseCapability` is rolled back, store operations are reverted but the `capMap` deletion persists, creating an inconsistent state that causes a panic when `GetCapability` is called for that capability name. [1](#0-0) 

## Impact
**Medium to High**

## Finding Description

**Location:** 
- Primary vulnerability: `x/capability/keeper/keeper.go`, lines 319-356 (`ReleaseCapability` function)
- Panic trigger: `x/capability/keeper/keeper.go`, lines 382-384 (`GetCapability` function)
- Root cause: `x/capability/keeper/keeper.go`, line 349 (direct `capMap` modification) [2](#0-1) 

**Intended Logic:** 
When a transaction fails and is rolled back, all state changes within that transaction should be reverted to maintain consistency between the persistent store, memory store, and in-memory data structures. The `GetOwners` function should return data consistent with what `GetCapability` can retrieve. [3](#0-2) 

**Actual Logic:** 
The Cosmos SDK uses a `CacheMultiStore` pattern where store operations are buffered in a cache and only committed via `Write()` on success. However, the `capMap` is a plain Go map (not a store), so direct modifications to it at line 349 are immediate and permanent—they are NOT rolled back when a transaction fails. [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. A capability exists with one owner (e.g., an IBC channel capability owned by a single module)
2. An attacker crafts a transaction containing multiple messages:
   - Message 1: Calls functionality that triggers `ReleaseCapability` for that capability (e.g., closing an IBC channel where the module is the last owner)
   - Message 2: A message that will fail validation or execution (e.g., bank transfer with insufficient funds)
3. During execution in the cached context:
   - `ReleaseCapability` executes successfully, deleting memory store entries (lines 332, 336), persistent store entry (line 347), and crucially, deleting from `capMap` (line 349)
   - Message 2 fails, causing transaction rollback
4. Transaction rollback reverts store changes but NOT the `capMap` deletion
5. Post-rollback state:
   - Persistent store: Owners list restored (GetOwners returns the original owners)
   - Memory store: Forward/reverse mappings restored
   - `capMap`: Entry permanently deleted (inconsistent!)
6. When any module subsequently calls `GetCapability` for that capability name:
   - Line 368: Successfully retrieves index from memory store
   - Line 382: Looks up `capMap[index]`, which returns `nil`
   - Line 384: Executes `panic("capability found in memstore is missing from map")` [6](#0-5) 

**Security Failure:** 
This breaks the availability invariant. The panic crashes the node, creating a denial-of-service vulnerability. Multiple nodes processing this transaction will crash, potentially halting network consensus.

## Impact Explanation

**Affected Assets/Processes:**
- Node availability: Nodes crash when processing GetCapability calls for the corrupted capability
- Network consensus: If ≥30% of nodes crash, this impacts block production and network availability
- Transaction finality: Network slowdown or halt prevents transaction confirmation

**Severity:**
- Individual nodes: Immediate crash requiring restart
- Network-wide: If the attacker can force many nodes to process GetCapability for the affected capability (e.g., through subsequent IBC operations using that channel), multiple nodes crash
- The panic is unrecoverable within transaction execution—it terminates the entire process

**Why This Matters:**
This vulnerability undermines the atomicity guarantee of transactions. The capability keeper maintains three synchronized data structures (persistent store, memory store, capMap), and this vulnerability breaks that synchronization. The commenting at lines 372-377 acknowledges awareness of capMap persistence issues with NewCapability, but the fix was never applied, and the same issue affects ReleaseCapability with more severe consequences. [7](#0-6) 

## Likelihood Explanation

**Who Can Trigger:**
Any user who can submit a multi-message transaction where:
1. One message triggers `ReleaseCapability` (e.g., IBC channel close where they control the last owner)
2. Another message can be made to fail deterministically

**Conditions Required:**
- Attacker must control or influence a module that owns a capability exclusively
- Attacker must construct a transaction with deliberate failure after capability release
- In IBC context: This could occur during channel closure operations

**Frequency:**
- Can be triggered repeatedly by the same or different attackers
- Each successful exploit corrupts one capability, potentially affecting multiple nodes
- The corrupted state persists until nodes restart and reinitialize from genesis/snapshot

**Likelihood Assessment:** Medium to High
- Multi-message transactions are common in Cosmos SDK chains
- IBC operations naturally involve capability management
- Deliberately failing a subsequent message (insufficient funds, invalid signature) is trivial
- Once corrupted, any legitimate use of that capability crashes nodes

## Recommendation

Modify the capability keeper to track `capMap` changes in a transaction-aware manner. Two possible approaches:

**Approach 1 (Minimal Change):** 
Add a transaction-local cache for capMap operations that only commits on successful transaction completion:

```
// In ScopedKeeper, add:
type capMapChange struct {
    index uint64
    cap   *types.Capability
    isDelete bool
}

// Track pending changes in the context
// On transaction commit, apply changes
// On rollback, discard changes
```

**Approach 2 (Comprehensive Fix):**
Implement the TODO mentioned at line 376-377: Store a reverse lookup mapping in the memory store instead of relying on the Go map for synchronization. The memory store is automatically transaction-aware. [8](#0-7) 

**Immediate Mitigation:**
Add defensive checks in `GetCapability` to recover gracefully instead of panicking:
```
cap := sk.capMap[index]
if cap == nil {
    // Log the inconsistency and return nil instead of panicking
    return nil, false
}
```

However, this only prevents the crash, not the underlying consistency issue.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestReleaseCapabilityTransactionRollbackPanic`

**Setup:**
1. Initialize test suite with keeper and context
2. Create a scoped keeper for a test module
3. Create a capability and commit it (so it exists in all stores)

**Trigger:**
1. Create a cached context using `CacheMultiStore()`
2. Call `ReleaseCapability` in the cached context (releasing the last/only owner)
3. Do NOT call `msCache.Write()` to simulate transaction rollback
4. In the original (non-cached) context, call `GetCapability` for that capability name

**Observation:**
The test will panic at line 384 with message "capability found in memstore is missing from map", demonstrating that:
- The memory store still has the reverse mapping (transaction was rolled back)
- The capMap no longer has the entry (Go map change persisted)
- This inconsistency causes a panic

**Test Code:**
```go
func (suite *KeeperTestSuite) TestReleaseCapabilityTransactionRollbackPanic() {
    sk := suite.keeper.ScopeToModule("testmodule")
    
    // Create and commit a capability
    cap, err := sk.NewCapability(suite.ctx, "testcap")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    // Verify capability exists
    gotCap, ok := sk.GetCapability(suite.ctx, "testcap")
    suite.Require().True(ok)
    suite.Require().Equal(cap, gotCap)
    
    // Create cached context (simulating transaction execution)
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    
    // Release capability in cached context (last owner)
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    
    // Verify release succeeded in cached context
    gotCap, ok = sk.GetCapability(cacheCtx, "testcap")
    suite.Require().False(ok)
    suite.Require().Nil(gotCap)
    
    // DO NOT CALL msCache.Write() - simulating transaction rollback
    
    // Try to get capability in original context - this should panic
    // because memory store was rolled back but capMap deletion persisted
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "testcap")
    }, "Expected panic due to capMap inconsistency after rollback")
}
```

This test demonstrates the vulnerability by showing that after a transaction rollback, the memory store and capMap become inconsistent, causing a panic on subsequent `GetCapability` calls.

### Citations

**File:** x/capability/keeper/keeper.go (L177-189)
```go
func (k Keeper) GetOwners(ctx sdk.Context, index uint64) (types.CapabilityOwners, bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(index)

	// get owners for index from persistent store
	ownerBytes := prefixStore.Get(indexKey)
	if ownerBytes == nil {
		return types.CapabilityOwners{}, false
	}
	var owners types.CapabilityOwners
	k.cdc.MustUnmarshal(ownerBytes, &owners)
	return owners, true
}
```

**File:** x/capability/keeper/keeper.go (L259-260)
```go
	// Set the mapping from index from index to in-memory capability in the go map
	sk.capMap[index] = cap
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

**File:** x/capability/keeper/keeper.go (L361-388)
```go
func (sk ScopedKeeper) GetCapability(ctx sdk.Context, name string) (*types.Capability, bool) {
	if strings.TrimSpace(name) == "" {
		return nil, false
	}
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

	return cap, true
}
```
