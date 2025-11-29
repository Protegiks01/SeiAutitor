# Audit Report

## Title
Non-Transactional capMap Deletion in ReleaseCapability Causes Inconsistent State and Network Disruption

## Summary
The `ReleaseCapability` function in the x/capability keeper module performs non-transactional deletions on the in-memory `capMap` while performing transactional deletions on stores. When a transaction fails after calling `ReleaseCapability`, the store changes are rolled back but the Go map deletion persists, creating an inconsistent state that causes `GetCapability` to panic on subsequent access. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- File: `x/capability/keeper/keeper.go`
- Functions: `ReleaseCapability` (lines 319-356) and `GetCapability` (lines 361-388)

**Intended Logic:**
All state changes within a transaction should be atomic - either all changes commit together or all revert together when the transaction fails. The capability module should maintain consistency between the persistent store, memory store (memStore), and the in-memory capability map (capMap).

**Actual Logic:**
`ReleaseCapability` performs three types of deletions when a capability has no remaining owners:
1. Deletions from memStore (lines 332, 336) - these are transactional and get reverted on transaction failure
2. Deletion from persistent store (line 347) - this is transactional and gets reverted on transaction failure  
3. Deletion from capMap using Go's `delete()` (line 349) - this is NOT transactional and CANNOT be reverted [2](#0-1) [3](#0-2) 

When a transaction fails, the Cosmos SDK's CacheMultiStore only persists changes if the transaction succeeds: [4](#0-3) 

**Exploitation Path:**
1. A module owns a capability as the sole owner
2. A transaction calls `ReleaseCapability` on this capability
3. `ReleaseCapability` executes: deletes from memStore, persistent store (both cached), and capMap (immediate)
4. Later in the same transaction, an error occurs (out of gas, validation failure, panic, etc.)
5. Transaction rollback reverts the cached store deletions, but the capMap deletion is permanent
6. The memStore now contains the `RevCapabilityKey` mapping (restored by rollback), but `capMap[index]` is nil
7. Any subsequent call to `GetCapability` for that capability will:
   - Find the index in memStore [5](#0-4) 
   - Attempt to retrieve from capMap which returns nil [6](#0-5) 
   - Trigger a panic [7](#0-6) 

**Security Guarantee Broken:**
This violates the atomicity invariant of transaction execution. The mixing of transactional (store operations) and non-transactional (Go map operations) state modifications breaks the fundamental guarantee that all state changes within a transaction either all commit or all revert together.

The developers acknowledge this problem in a TODO comment that references issue #7805, but they only implemented a partial fix for the `NewCapability` case (when capMap has an entry but memStore doesn't), not the reverse `ReleaseCapability` case: [8](#0-7) 

## Impact Explanation

**Affected Components:**
- Node availability and transaction processing capability
- Network reliability for all validators
- IBC and other modules that use the capability system

**Consequences:**

1. **Persistent Transaction Failures:** When `GetCapability` is called within transaction context (during message execution), the panic is caught by the recovery middleware [9](#0-8) , causing the transaction to fail. However, the inconsistent state persists, so every subsequent transaction attempting to access that capability will also panic and fail.

2. **Potential Node Crashes:** If `GetCapability` is called outside transaction context (e.g., in BeginBlock or EndBlock processing) [10](#0-9) , there is no panic recovery handler, which would cause an immediate node crash.

3. **Network-Wide Impact:** If the triggering transaction is included in a block, all validators processing that block execute the same transaction and experience the same inconsistent state simultaneously. This means a single transaction can affect 100% of network validators.

4. **Persistence Until Restart:** The inconsistent state persists until the node is restarted, at which point `InitMemStore` repopulates the capMap from the persistent store, restoring consistency [11](#0-10) .

This maps to the Medium severity impact criteria: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" and "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger it:**
Any user who can submit a transaction that includes a capability release operation (e.g., IBC channel closing, port unbinding) followed by any failure condition.

**Conditions required:**
- The capability must have only one owner (so `len(capOwners.Owners) == 0` after removal, triggering the `delete()` path)
- The transaction must fail AFTER `ReleaseCapability` executes but BEFORE final commit
- This happens naturally through common transaction failures: out of gas, validation errors, message execution failures

**Frequency:**
This vulnerability can be triggered whenever:
- IBC channels are closed within a transaction that subsequently fails
- Ports are released within a transaction that subsequently fails
- Any other capability management operation happens in a failing transaction

Given that transaction failures (especially out of gas) are common in blockchain operations, and capability operations occur regularly in IBC-enabled chains, this has a moderate to high likelihood of natural occurrence.

## Recommendation

Implement a transaction-aware mechanism for `capMap` modifications:

1. **Immediate fix:** Track capability deletions in a separate temporary structure during transaction execution. Only apply these deletions to `capMap` after `msCache.Write()` succeeds, using a post-commit hook or deferred execution.

2. **Long-term solution:** Implement the reverse lookup mechanism mentioned in the TODO comment (issue #7805) that allows properly cleaning up `capMap` entries based on store state, eliminating the reliance on non-transactional map operations during transaction execution.

3. **Additional safety:** Add defensive checks in `GetCapability` for the reverse scenario (memStore has entry but capMap doesn't), similar to the existing check for the NewCapability case. Instead of panicking, return a graceful error or attempt recovery by checking the persistent store.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

**Setup:**
- Initialize a capability keeper with a scoped module
- Create a capability with a single owner using `NewCapability`
- Verify the capability can be retrieved with `GetCapability`

**Action:**
- Create a cached context simulating transaction execution: `cacheCtx, msCache := ctx.CacheContext()`
- Call `ReleaseCapability` on the cached context (deletes from cached stores and shared capMap)
- Do NOT call `msCache.Write()` to simulate transaction failure/rollback
- The cached store changes are discarded, but the capMap deletion persists

**Result:**
- Calling `GetCapability` in the original context will panic
- The memStore has the `RevCapabilityKey` mapping (because transaction rollback restored it)
- The `capMap[index]` is nil (because Go map deletion is not transactional)
- This triggers panic: "capability found in memstore is missing from map"

This test successfully reproduces the vulnerability and confirms the inconsistent state created by transaction rollback not reverting Go map operations.

## Notes

This is a genuine architectural issue in the capability module where mixing transactional (store-based) and non-transactional (Go map-based) state management violates the atomicity guarantees expected in blockchain transaction processing. The developers have acknowledged the general problem (as evidenced by the TODO comment referencing issue #7805), but have only implemented a partial mitigation for one direction of the inconsistency (NewCapability case), leaving the reverse case (ReleaseCapability) unhandled and exploitable. The vulnerability affects all chains using the Cosmos SDK capability module and can be triggered by common transaction failure scenarios without requiring any special privileges.

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

**File:** baseapp/baseapp.go (L1015-1017)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
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
