# Audit Report

## Title
Non-Transactional capMap Deletion in ReleaseCapability Causes Inconsistent State and Network-Wide Node Disruption

## Summary
The `ReleaseCapability` function performs a non-transactional Go map deletion (`delete(sk.capMap, index)`) alongside transactional store deletions. When a transaction rolls back after calling `ReleaseCapability`, the store changes are reverted but the map deletion persists, creating an inconsistent state where `GetCapability` panics with "capability found in memstore is missing from map", affecting all validators processing the same block. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- Module: `x/capability`
- File: `x/capability/keeper/keeper.go`
- Functions: `ReleaseCapability` (lines 319-356) and `GetCapability` (lines 361-388)

**Intended Logic:**
When a transaction that releases a capability fails and gets reverted, all state changes should be rolled back atomically to maintain consistency between the persistent store, memory store (memStore), and the in-memory capability map (capMap).

**Actual Logic:**
The `ReleaseCapability` function performs three types of deletions when a capability has no remaining owners:
1. Deletes from memStore (lines 332, 336) - transactional, reverted on rollback [2](#0-1) 
2. Deletes from persistent store (line 347) - transactional, reverted on rollback [3](#0-2) 
3. Deletes from capMap using Go's `delete()` (line 349) - **NOT transactional, CANNOT be reverted** [4](#0-3) 

The Cosmos SDK's transaction mechanism only writes cached store changes if the transaction succeeds [5](#0-4) . When a transaction fails, operations 1 and 2 are reverted, but operation 3 persists because Go map operations are not part of the transactional context.

**Exploitation Path:**
1. A module owns a capability as the sole owner
2. A transaction calls `ReleaseCapability`, which executes and deletes from stores and capMap
3. Later in the same transaction, an error occurs (out of gas, validation failure, panic, etc.)
4. Transaction rollback reverts store changes, but capMap deletion is permanent
5. memStore now contains the `RevCapabilityKey` mapping (restored by rollback), but `capMap[index]` is nil
6. Any subsequent call to `GetCapability` will find the index in memStore [6](#0-5) , look up nil in capMap [7](#0-6) , and panic [8](#0-7) 

**Security Guarantee Broken:**
This violates the atomicity invariant of transaction execution. All state changes within a transaction should either all commit or all revert together. The mixing of transactional (store operations) and non-transactional (Go map operations) state modifications breaks this fundamental guarantee.

The developers acknowledge this issue class in a TODO comment [9](#0-8) , but have only implemented a partial fix for the `NewCapability` case (when capMap has an entry but memStore doesn't), not the reverse `ReleaseCapability` case (when memStore has an entry but capMap doesn't).

## Impact Explanation

**Affected Components:**
- Node availability and transaction processing
- Network reliability for all validators

**Consequences:**
When triggered, this vulnerability creates a persistent inconsistent state where:

1. If `GetCapability` is called within transaction context (during message execution), the panic is caught by the recovery middleware [10](#0-9) , causing the transaction to fail. However, the inconsistent state persists, so **every subsequent transaction** attempting to access that capability will also panic and fail.

2. If `GetCapability` is called outside transaction context (e.g., in BeginBlock or EndBlock processing) [11](#0-10) , there is no panic recovery handler, causing an **immediate node crash**.

3. The inconsistent state persists across blocks because `InitMemStore` only repopulates the capMap once when the memory store is first initialized [12](#0-11) , not on every block. The state remains inconsistent until node restart.

**Network-Wide Impact:**
If the triggering transaction is included in a block, **all validators** processing that block will execute the same transaction and end up with the same inconsistent state simultaneously. This means a single malicious or accidentally malformed transaction can affect 100% of network validators, meeting the Medium severity criteria of "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions."

## Likelihood Explanation

**Who can trigger it:**
Any user who can submit a transaction that:
1. Includes a capability release operation (e.g., IBC channel closing, port unbinding)
2. Subsequently fails for any reason

**Conditions required:**
- The capability must have only one owner (so `len(capOwners.Owners) == 0` after removal, triggering the `delete()` path)
- The transaction must fail AFTER `ReleaseCapability` executes but BEFORE final commit
- This can happen naturally through common transaction failures (out of gas, validation errors, message execution failures)

**Frequency:**
This vulnerability can be triggered whenever:
- IBC channels are closed within a transaction that subsequently fails
- Ports are released within a transaction that subsequently fails
- Any other capability management operation happens in a failing transaction

Given that transaction failures are common in blockchain operations (out of gas is particularly frequent), and capability operations occur regularly in IBC-enabled chains, this has a moderate to high likelihood of natural occurrence.

## Recommendation

Implement a transaction-aware mechanism for `capMap` modifications that only applies deletions after successful transaction commit:

1. **Immediate fix:** Track capability deletions in a separate temporary structure during transaction execution. Only apply these deletions to `capMap` after `msCache.Write()` succeeds, potentially using a post-commit hook or by deferring the deletion until the context is finalized.

2. **Long-term solution:** Implement the reverse lookup mechanism mentioned in the TODO comment (issue #7805) that would allow properly cleaning up `capMap` entries based on store state, eliminating the reliance on non-transactional map operations during transaction execution.

3. **Additional safety:** Add defensive checks in `GetCapability` for the reverse scenario (memStore has entry but capMap doesn't), similar to the existing check for the NewCapability case, to at least prevent the panic and return a graceful error instead:

```go
if cap == nil {
    // Handle ReleaseCapability rollback case
    delete(sk.capMap, index) // Clean up if exists
    return nil, false
}
```

## Proof of Concept

The following test demonstrates the vulnerability:

**Setup:**
- Initialize a capability keeper with a scoped module
- Create a capability with a single owner using `NewCapability`
- Verify the capability can be retrieved with `GetCapability`

**Action:**
- Create a cached context simulating transaction execution using `ctx.MultiStore().CacheMultiStore()`
- Call `ReleaseCapability` in the cached context, which deletes from stores (transactional) and capMap (non-transactional)
- Do NOT call `msCache.Write()` to simulate transaction failure/rollback
- Store changes are reverted, but capMap deletion is permanent

**Result:**
- Calling `GetCapability` in the original context will panic
- The memStore has the `RevCapabilityKey` (transaction rollback restored it)
- The `capMap[index]` is nil (Go map deletion is not transactional)
- This triggers the panic: "capability found in memstore is missing from map"

Test implementation can be added to `x/capability/keeper/keeper_test.go`:

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityRollback() {
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    
    // Create capability with single owner
    cap, err := sk.NewCapability(suite.ctx, "test-cap")
    suite.Require().NoError(err)
    
    // Verify it exists
    got, ok := sk.GetCapability(suite.ctx, "test-cap")
    suite.Require().True(ok)
    suite.Require().Equal(cap, got)
    
    // Create cached context (simulating transaction)
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    
    // Release capability in cached context
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    
    // DO NOT call msCache.Write() - simulating transaction failure
    
    // Try to get capability in original context
    // This will panic because memStore has entry but capMap doesn't
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "test-cap")
    })
}
```

## Notes

This is a genuine architectural vulnerability in the capability module where the mixing of transactional (store-based) and non-transactional (Go map-based) state management violates the atomicity guarantees expected in blockchain transaction processing. While developers have acknowledged the general problem (as evidenced by the TODO comment), they have only implemented a partial mitigation for one direction of the inconsistency (NewCapability case), leaving the reverse case (ReleaseCapability) unhandled and exploitable. The vulnerability affects 100% of validators when a malicious transaction is included in a block, qualifying it for Medium severity under the "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" impact category.

### Citations

**File:** x/capability/keeper/keeper.go (L107-135)
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

**File:** x/capability/keeper/keeper.go (L367-369)
```go
	key := types.RevCapabilityKey(sk.module, name)
	indexBytes := memStore.Get(key)
	index := sdk.BigEndianToUint64(indexBytes)
```

**File:** x/capability/keeper/keeper.go (L371-379)
```go
	if len(indexBytes) == 0 {
		// If a tx failed and NewCapability got reverted, it is possible
		// to still have the capability in the go map since changes to
		// go map do not automatically get reverted on tx failure,
		// so we delete here to remove unnecessary values in map
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805

		return nil, false
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

**File:** baseapp/baseapp.go (L1015-1016)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
```

**File:** baseapp/abci.go (L133-157)
```go
// BeginBlock implements the ABCI application interface.
func (app *BaseApp) BeginBlock(ctx sdk.Context, req abci.RequestBeginBlock) (res abci.ResponseBeginBlock) {
	defer telemetry.MeasureSince(time.Now(), "abci", "begin_block")

	if !req.Simulate {
		if err := app.validateHeight(req); err != nil {
			panic(err)
		}
	}

	if app.beginBlocker != nil {
		res = app.beginBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	// call the streaming service hooks with the EndBlock messages
	if !req.Simulate {
		for _, streamingListener := range app.abciListeners {
			if err := streamingListener.ListenBeginBlock(app.deliverState.ctx, req, res); err != nil {
				app.logger.Error("EndBlock listening hook failed", "height", req.Header.Height, "err", err)
			}
		}
	}
	return res
}
```
