# Audit Report

## Title
State Inconsistency Between Transactional memStore and Non-Transactional capMap Leading to Permanent Capability Corruption and Fund Freezing

## Summary
The capability keeper maintains state in both a transactional KVStore (`memStore`) and a non-transactional Go map (`capMap`). When `ReleaseCapability` is called within a transaction that subsequently fails, memStore changes are rolled back but capMap modifications persist, creating a permanent state inconsistency that renders the capability unusable and can freeze funds locked in IBC channels. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- `ReleaseCapability` function at lines 319-356
- `GetCapability` function at lines 361-388 in `x/capability/keeper/keeper.go` [2](#0-1) 

**Intended Logic:** 
The capability system should maintain atomic consistency between two storage layers:
1. `memStore` - A transactional KVStore that automatically reverts on transaction failure
2. `capMap` - An in-memory Go map for fast lookups

Both stores must remain synchronized to ensure capabilities remain accessible.

**Actual Logic:** 
In `ReleaseCapability`:
- Lines 332, 336: Delete capability mappings from `memStore` (transactional, will revert on tx failure)
- Line 349: Delete capability from `capMap` via `delete(sk.capMap, cap.GetIndex())` (non-transactional, persists even on tx failure) [3](#0-2) 

When a transaction calling `ReleaseCapability` fails, the memStore deletions are reverted but the capMap deletion persists, creating a permanent inconsistency.

In `GetCapability`:
- Line 368: Retrieves capability index from memStore  
- Line 382: Looks up capability in capMap using that index
- Lines 383-385: Panics if capability is nil with message "capability found in memstore is missing from map" [4](#0-3) 

**Exploitation Path:**
1. User creates a capability as sole owner (e.g., IBC channel with funds in escrow)
2. User submits a transaction that calls `ReleaseCapability` (e.g., channel close)
3. Transaction fails after `ReleaseCapability` executes (out-of-gas, panic, or other error)
4. Transaction reverts: memStore changes roll back, but capMap deletion persists
5. Capability is now permanently corrupted - index exists in memStore but not in capMap
6. All subsequent attempts to `GetCapability` for this capability:
   - Find the index in memStore
   - Get nil from capMap
   - Panic (recovered in transaction execution causing transaction failure)
7. The capability becomes permanently unusable
8. Any funds locked in escrow for an IBC channel using this capability are permanently frozen

**Security Guarantee Broken:** 
The atomicity and consistency of the capability storage system is violated. The permanent corruption breaks the availability of the capability and can cause permanent fund freezing.

## Impact Explanation

While the claim suggests node crashes, transaction execution has panic recovery that prevents node crashes during normal operation. [5](#0-4) 

However, the actual impact is more severe in terms of fund loss:

1. **Permanent Capability Corruption**: The capability becomes permanently unusable - the inconsistent state persists until manual intervention (state export/import or code fix).

2. **Transaction Failures**: Any transaction attempting to use the corrupted capability will panic and fail. The panic is recovered by the transaction execution framework, but the transaction consistently fails.

3. **IBC Fund Freezing**: If the corrupted capability is an IBC channel capability:
   - No packets can be sent or received on that channel
   - Funds locked in escrow for that channel cannot be released
   - This represents **permanent freezing of funds** requiring a hard fork to resolve

4. **Denial of Service**: The corrupted capability effectively disables whatever functionality it was protecting (e.g., an entire IBC connection).

This matches the impact criteria: **"Permanent freezing of funds (fix requires hard fork)"** - High severity.

## Likelihood Explanation

**Who Can Trigger:**
- Any user who can own a capability (creating IBC channels is permissionless in most chains)
- Can be triggered intentionally or accidentally through buggy module code

**Conditions Required:**
1. User must be the sole or last owner of a capability
2. Must trigger a transaction that calls `ReleaseCapability`
3. Must cause the transaction to fail after the release

**Realistic Attack Vectors:**
- **Out-of-gas attack**: User carefully sets gas limit to run out immediately after `ReleaseCapability` executes - this is highly reliable and doesn't require finding buggy code paths
- **Exploiting module bugs**: Finding code paths that release capabilities before operations that might fail
- **Accidental triggering**: Buggy module code that releases capabilities and then encounters errors

**Frequency:**
- Can be triggered on-demand by an attacker
- Each exploitation corrupts one capability
- High-value targets include IBC channels with significant funds in escrow
- Permanent until manual state correction

The out-of-gas scenario is particularly realistic as users have complete control over their transaction gas limits.

## Recommendation

**Immediate Mitigation - Defensive GetCapability:**

Modify `GetCapability` to handle inconsistency gracefully instead of panicking:

```go
cap := sk.capMap[index]
if cap == nil {
    // Inconsistency detected - clean up stale memStore entries
    memStore.Delete(types.RevCapabilityKey(sk.module, name))
    return nil, false
}
```

**Long-term Solution - Transaction-Aware capMap:**

Implement a transaction-aware wrapper around `capMap` that tracks changes in a cache layer and can revert changes when transactions fail, similar to how KVStores work with CacheMultiStore.

**Alternative Solution - Deferred capMap Updates:**

Only update capMap after transaction commit by using hooks or post-processing, ensuring capMap changes are never made speculatively during transaction execution.

## Proof of Concept

The vulnerability can be reproduced by adding this test to `x/capability/keeper/keeper_test.go`: [6](#0-5) 

**Test Function:** `TestReleaseCapabilityInconsistencyOnRevert`

**Setup:**
1. Create a capability in main context: `cap, err := sk.NewCapability(suite.ctx, "channel-0")`
2. Verify retrievable: `got, ok := sk.GetCapability(suite.ctx, "channel-0")`
3. Create cached context: `msCache := suite.ctx.MultiStore().CacheMultiStore()` and `cacheCtx := suite.ctx.WithMultiStore(msCache)`

**Action:**
1. Release in cached context: `err := sk.ReleaseCapability(cacheCtx, cap)`
2. Verify not retrievable in cache: `got, ok := sk.GetCapability(cacheCtx, "channel-0")` (should be false)
3. **Do NOT call `msCache.Write()`** - simulating transaction failure
4. Attempt to retrieve in original context: `got, ok := sk.GetCapability(suite.ctx, "channel-0")`

**Result:**
- The test will panic with message "capability found in memstore is missing from map"
- This confirms: memStore still has the mapping (cache not written), but capMap doesn't have the capability (deletion persisted)
- The panic demonstrates the permanent state inconsistency

## Notes

The existing TODO comment at line 376 acknowledges Go map transaction issues but only addresses the `NewCapability` revert scenario, not the `ReleaseCapability` revert scenario. [7](#0-6) 

The developers are aware of the general issue category but the specific panic-inducing case for `ReleaseCapability` with fund-freezing implications is not handled.

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

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
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
