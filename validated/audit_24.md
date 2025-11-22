# Audit Report

## Title
State Inconsistency Between memStore and capMap Causing Panic in GetCapability After Failed ReleaseCapability Transaction

## Summary
The capability keeper maintains state in both a transactional KVStore (`memStore`) and a non-transactional Go map (`capMap`). When `ReleaseCapability` is called within a transaction that subsequently fails, the `memStore` changes are rolled back but `capMap` modifications persist, creating an inconsistent state. This causes `GetCapability` to panic when it finds a capability index in `memStore` but the actual capability is missing from `capMap`, potentially causing network-wide node crashes. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- `ReleaseCapability` function at lines 319-356
- `GetCapability` function at lines 361-388 in `x/capability/keeper/keeper.go` [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The capability system should maintain atomic consistency between two storage layers:
1. `memStore` - A transactional KVStore that automatically reverts on transaction failure
2. `capMap` - A Go map for fast in-memory lookups

Both stores should remain synchronized at all times.

**Actual Logic:** 
In `ReleaseCapability`:
- Lines 332, 336 delete capability mappings from `memStore` (transactional, will be rolled back on tx failure)
- Line 349 deletes capability from `capMap` (non-transactional Go map, change persists even on tx failure)

When a transaction fails after calling `ReleaseCapability`, the `memStore` deletions are reverted but the `capMap` deletion persists.

In `GetCapability`:
- Line 368 retrieves the capability index from `memStore`
- Line 382 looks up the capability in `capMap` using that index
- Lines 383-385 panic if the capability is nil with message "capability found in memstore is missing from map"

**Exploitation Path:**
1. Attacker owns a capability as the sole owner (e.g., by creating an IBC channel)
2. Attacker submits a transaction that triggers `ReleaseCapability` (e.g., closing the channel)
3. The transaction fails after `ReleaseCapability` executes (via out-of-gas, panic, or assertion failure)
4. Transaction reverts: `memStore` changes are rolled back, but `capMap` deletion persists
5. System enters inconsistent state
6. Any subsequent transaction calling `GetCapability` for this capability will:
   - Find the index in `memStore` 
   - Get nil from `capMap[index]`
   - Panic and crash the node

**Security Guarantee Broken:** 
The atomicity and consistency of the capability storage system is violated. The panic breaks the availability guarantee of the blockchain network. [3](#0-2) 

## Impact Explanation

When this vulnerability is triggered:

1. **Node Crashes**: Any validator or full node attempting to retrieve the corrupted capability will panic and crash
2. **Network Halt**: If the corrupted capability is used in critical operations (such as IBC packet relay), all validators processing transactions that reference it will crash simultaneously
3. **Consensus Failure**: The network cannot produce new blocks if sufficient validators are unable to process transactions
4. **Permanent Corruption**: The inconsistent state persists until manual intervention (state export/import or code fix)

This matches the impact criteria: **"Network not being able to confirm new transactions (total network shutdown)"** - Medium severity.

The vulnerability is particularly severe for IBC capabilities, as disrupting IBC operations can isolate a chain from the broader Cosmos ecosystem.

## Likelihood Explanation

**Who Can Trigger:**
- Any user who can own a capability (e.g., by creating an IBC channel)
- Module developers through buggy code
- Attackers who identify vulnerable code paths in modules

**Conditions Required:**
1. Attacker must be the sole owner of a capability or the last owner releasing it
2. Must trigger module code that calls `ReleaseCapability`
3. Must cause the transaction to fail after the release (common methods: out of gas, subsequent panic, assertion failure)

**Realistic Attack Vectors:**
- **Out-of-gas attack**: Attacker sets gas limit to run out immediately after `ReleaseCapability` executes
- **Vulnerable module code paths**: Finding modules that release capabilities before operations that can fail
- **Accidental triggering**: Buggy module code that releases capabilities and then encounters errors

**Frequency:**
- Can be triggered on-demand by an attacker who identifies a suitable code path
- Each exploitation corrupts one capability
- High-value targets include frequently-used IBC channel capabilities
- Once triggered, corruption is permanent until manual fix

The out-of-gas scenario is particularly realistic and doesn't require finding buggy module code - the attacker simply needs to control the gas limit of their transaction.

## Recommendation

**Immediate Mitigation - Defensive GetCapability:**

Modify `GetCapability` to handle the inconsistency gracefully instead of panicking:

```go
// In GetCapability, replace lines 382-385 with:
cap := sk.capMap[index]
if cap == nil {
    // Inconsistency detected - clean up stale memStore entries
    memStore.Delete(types.RevCapabilityKey(sk.module, name))
    // Note: Forward mapping cleanup may also be needed
    return nil, false
}
```

**Long-term Solution - Transaction-Aware capMap:**

Implement a transaction-aware wrapper around `capMap` that can track and revert changes when transactions fail. This requires architectural changes to make the Go map behave transactionally, similar to how KVStores work with caching layers.

**Recommended Approach:**
1. Implement the defensive `GetCapability` fix immediately to prevent panics
2. Plan the transaction-aware `capMap` redesign for the next major version

## Proof of Concept

The vulnerability can be reproduced with the following test that should be added to `x/capability/keeper/keeper_test.go`:

**Test Function:** `TestReleaseCapabilityInconsistencyOnRevert`

**Setup:**
1. Create a capability in the main context using `NewCapability`
2. Verify the capability is retrievable
3. Create a cached context using `CacheMultiStore` to simulate transaction boundaries

**Action:**
1. Call `ReleaseCapability` in the cached context (this deletes from both `memStore` cache and shared `capMap`)
2. Verify capability is not retrievable in cached context
3. **Do NOT call `msCache.Write()`** - this simulates transaction failure/revert
4. Attempt to retrieve the capability in the original context

**Result:**
- The test should observe a panic with message "capability found in memstore is missing from map"
- This confirms the state inconsistency: `memStore` still has the mapping (cache wasn't written), but `capMap` doesn't have the capability (deletion persisted) [4](#0-3) 

The existing `TestRevertCapability` test demonstrates the opposite scenario (NewCapability revert) but does not test the ReleaseCapability revert scenario described in this vulnerability.

## Notes

The codebase contains a TODO comment at line 376 acknowledging that Go map changes don't revert on transaction failure, but this comment specifically addresses the `NewCapability` revert scenario, not the `ReleaseCapability` revert scenario described here. The developers are aware of the general issue category but the specific panic-inducing case for `ReleaseCapability` is not handled. [5](#0-4)

### Citations

**File:** x/capability/keeper/keeper.go (L29-50)
```go
	Keeper struct {
		cdc           codec.BinaryCodec
		storeKey      sdk.StoreKey
		memKey        sdk.StoreKey
		capMap        map[uint64]*types.Capability
		scopedModules map[string]struct{}
		sealed        bool
	}

	// ScopedKeeper defines a scoped sub-keeper which is tied to a single specific
	// module provisioned by the capability keeper. Scoped keepers must be created
	// at application initialization and passed to modules, which can then use them
	// to claim capabilities they receive and retrieve capabilities which they own
	// by name, in addition to creating new capabilities & authenticating capabilities
	// passed by other modules.
	ScopedKeeper struct {
		cdc      codec.BinaryCodec
		storeKey sdk.StoreKey
		memKey   sdk.StoreKey
		capMap   map[uint64]*types.Capability
		module   string
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
