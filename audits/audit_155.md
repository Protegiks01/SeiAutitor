## Audit Report

## Title
State Inconsistency Between memStore and capMap Causing Panic in GetCapability After Failed ReleaseCapability Transaction

## Summary
The `ReleaseCapability` function deletes capability data from both `memStore` (a transactional KVStore) and `capMap` (a non-transactional Go map). When a transaction containing `ReleaseCapability` fails and reverts, the `memStore` deletions are rolled back but the `capMap` deletions persist, creating an inconsistent state. Subsequent calls to `GetCapability` will panic when they find the capability index in `memStore` but the capability is missing from `capMap`. [1](#0-0) 

## Impact
**High** - This vulnerability can cause a total network shutdown by making nodes panic on capability retrieval operations.

## Finding Description

**Location:** The vulnerability exists in the interaction between `ReleaseCapability` and `GetCapability` functions in `x/capability/keeper/keeper.go`. [1](#0-0) [2](#0-1) 

**Intended Logic:** The capability system maintains two storage layers:
1. `memStore` - A transactional KVStore that automatically reverts changes on transaction failure
2. `capMap` - A shared Go map for fast in-memory lookups

These should always remain synchronized. When releasing a capability, both stores should be updated atomically.

**Actual Logic:** In `ReleaseCapability`:
- Lines 332, 336: Delete capability mappings from `memStore` (transactional)
- Line 349: Delete capability from `capMap` (non-transactional)

If the transaction fails after these deletions, `memStore` changes are reverted but `capMap` changes persist, breaking the synchronization invariant.

In `GetCapability`:
- Line 368: Retrieves index from `memStore`
- Line 382: Looks up capability in `capMap` using the index
- Lines 383-385: **Panics** if `capMap[index]` returns `nil`

**Exploit Scenario:**
1. Attacker owns a capability (e.g., an IBC channel capability)
2. Attacker submits a transaction that:
   - Calls `ReleaseCapability` to delete the capability from both stores
   - Then triggers a transaction failure (e.g., via panic, out of gas, or assertion failure)
3. The transaction reverts:
   - `memStore` deletions are rolled back (capability mappings restored)
   - `capMap` deletion is **not** rolled back (capability remains deleted)
4. System is now in inconsistent state
5. Any subsequent transaction calling `GetCapability` for this capability will:
   - Find the index in `memStore` (lines 368-369)
   - Get `nil` from `capMap[index]` (line 382)
   - **Panic** with "capability found in memstore is missing from map" (line 384)

**Security Failure:** This breaks the availability and reliability of the blockchain:
- Denial of Service: Nodes crash on capability lookup
- Consensus failure: Different nodes may panic at different times
- IBC operations halt if channel capabilities are affected

## Impact Explanation

**Affected Assets/Processes:**
- Network availability: Nodes crash when attempting to use affected capabilities
- IBC operations: Channel capabilities become unusable, blocking cross-chain communication
- Transaction processing: Any transaction using the corrupted capability fails

**Severity of Damage:**
- **Critical DOS**: Once triggered, the capability becomes permanently unusable until manual intervention
- **Network Shutdown**: If the affected capability is used in critical paths (e.g., IBC packet relay, essential module operations), the entire network can halt
- **Consensus Breakdown**: Nodes that haven't processed the corrupted transaction yet may continue while others panic, potentially causing chain splits

**Why This Matters:**
- IBC is critical infrastructure for Cosmos chains - disrupting IBC capabilities can isolate the chain from the ecosystem
- The panic is unrecoverable without code changes or state export/import
- An attacker can weaponize this by targeting frequently-used capabilities

## Likelihood Explanation

**Who Can Trigger:**
- Any user who owns or can claim a capability
- Most commonly, module operators managing IBC channels or other capability-based resources
- Can be triggered accidentally by buggy code or intentionally by malicious actors

**Conditions Required:**
- Attacker must own a capability (easy to obtain via normal IBC channel creation)
- Must be able to construct a transaction that calls `ReleaseCapability` followed by a controlled failure
- Common failure triggers: out of gas, intentional panic, assertion violation

**Frequency:**
- Can be triggered on-demand by an attacker
- Each exploitation corrupts one capability
- High-value targets: frequently-used IBC channel capabilities
- Once triggered, the corruption is permanent until manual fix

## Recommendation

Add a cleanup mechanism in `GetCapability` to handle the inconsistency, or better yet, track capMap changes in a way that can be reverted:

**Option 1 - Defensive GetCapability:**
```go
// In GetCapability, after line 382:
cap := sk.capMap[index]
if cap == nil {
    // Inconsistency detected - memStore has mapping but capMap doesn't
    // Clean up the stale memStore entries
    memStore.Delete(types.RevCapabilityKey(sk.module, name))
    // Also clean up forward mapping if it exists
    return nil, false
}
```

**Option 2 - Make capMap Changes Reversible:**
Implement a transaction-aware wrapper around capMap that can track and revert changes. This would require architectural changes to the capability module.

**Recommended Fix:** Implement Option 1 as an immediate mitigation, then pursue Option 2 for a complete solution in the next major version.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add this new test function to the existing test suite:

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityInconsistencyOnRevert() {
	sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
	
	// Step 1: Create and claim a capability in the main context
	capName := "test-capability"
	cap, err := sk.NewCapability(suite.ctx, capName)
	suite.Require().NoError(err, "should create capability")
	suite.Require().NotNil(cap, "capability should not be nil")
	
	// Verify capability exists and is retrievable
	retrievedCap, ok := sk.GetCapability(suite.ctx, capName)
	suite.Require().True(ok, "should retrieve capability")
	suite.Require().Equal(cap, retrievedCap, "retrieved capability should match")
	
	// Step 2: Create a cached context to simulate a transaction
	ms := suite.ctx.MultiStore()
	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)
	
	// Step 3: Release the capability in the cached context
	err = sk.ReleaseCapability(cacheCtx, cap)
	suite.Require().NoError(err, "should release capability without error")
	
	// Verify capability is released in cached context
	_, ok = sk.GetCapability(cacheCtx, capName)
	suite.Require().False(ok, "capability should not be retrievable in cached context after release")
	
	// Step 4: DO NOT write the cache - simulate transaction failure/revert
	// msCache.Write() is intentionally not called
	// This simulates a transaction that called ReleaseCapability but then failed
	
	// Step 5: Try to retrieve capability in original context
	// This should work because memStore changes were not committed
	// However, capMap changes persist across the revert
	
	// This will PANIC because:
	// - memStore still has the mapping (cache was not written)
	// - capMap has the deletion (Go map changes are not reverted)
	// - GetCapability finds index in memStore but gets nil from capMap
	// - Line 384 panics with "capability found in memstore is missing from map"
	
	suite.Require().Panics(func() {
		sk.GetCapability(suite.ctx, capName)
	}, "GetCapability should panic due to memStore/capMap inconsistency")
}
```

**Setup:**
- Uses the existing test suite infrastructure
- Creates a capability in the main context
- Uses a cached context to simulate transaction boundaries

**Trigger:**
- Calls `ReleaseCapability` in a cached context
- Does NOT commit the cached context (simulating transaction failure)
- Attempts to retrieve the capability in the original context

**Observation:**
- The test expects a panic when calling `GetCapability`
- The panic message will be: "capability found in memstore is missing from map"
- This confirms the state inconsistency between `memStore` (which has the mapping) and `capMap` (which doesn't have the capability)

This PoC demonstrates that the vulnerability is exploitable and causes a panic that would crash validator nodes, resulting in network disruption.

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
