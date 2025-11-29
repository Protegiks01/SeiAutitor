# Audit Report

## Title
State Desynchronization in ReleaseCapability Causes Node Panic on Transaction Rollback

## Summary
The `ReleaseCapability` function in the capability keeper performs a direct Go map deletion that is not protected by transaction semantics. When a transaction containing `ReleaseCapability` is rolled back, the cached store deletions are reverted but the map deletion persists, creating a state inconsistency that causes node panics when the capability is subsequently accessed.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** When releasing a capability within a transaction context, all state modifications (persistent store, memory store, and in-memory map) should be atomic. If the transaction fails or is rolled back, all changes should revert together to maintain consistency across the three storage layers.

**Actual Logic:** The function mixes transactional and non-transactional operations. The deletions from `memStore` (lines 332, 336) and `prefixStore` (line 347) operate on cached stores that participate in transaction semantics. However, the deletion from `capMap` at line 349 is a direct Go map operation that executes immediately and irreversibly, regardless of whether the surrounding transaction commits or rolls back. [2](#0-1) 

The `capMap` is shared by reference across all scoped keepers [3](#0-2) , meaning modifications to it affect parent and cached contexts simultaneously.

**Exploitation Path:**
1. A module calls `ReleaseCapability` on the last owner of a capability within a transaction (creating a cached context via `CacheMultiStore()` [4](#0-3) )
2. The function executes successfully, deleting from `capMap` (line 349) and from cached stores (lines 332, 336, 347)
3. The transaction fails due to validation errors, gas exhaustion, or other errors
4. The cached context is discarded without calling `Write()` - store deletions are reverted but the map deletion has already occurred [5](#0-4) 
5. Result: `memStore` still contains the capability mappings (deletion was not written), but `capMap` no longer has the capability entry (deletion already happened)
6. When `GetCapability` is called for this capability, the function retrieves the index from `memStore` [6](#0-5) , then looks it up in `capMap` which returns nil [7](#0-6) , triggering a panic [8](#0-7) 

**Security Guarantee Broken:** Transaction atomicity and state consistency. The codebase explicitly acknowledges this class of issue in comments [9](#0-8) , which state "changes to go map do not automatically get reverted on tx failure" and reference issue #7805. However, the mitigation only handles the case where `NewCapability` adds to `capMap` but the transaction fails. The inverse case where `ReleaseCapability` removes from `capMap` but the transaction fails is not handled.

## Impact Explanation

This vulnerability creates a permanent desynchronization between storage layers that causes denial of service:

1. **State Inconsistency**: Creates permanent desynchronization between `memStore` and `capMap` until node restart, violating the invariant that these storage layers must remain synchronized

2. **Node Instability**: When `GetCapability` is called for the affected capability, the node panics. While transaction execution has panic recovery [10](#0-9) , the panic still causes transaction failures and potential node crashes if triggered in unrecovered code paths (e.g., BeginBlock/EndBlock operations)

3. **Module Disruption**: Capabilities are fundamental to IBC port/channel management and inter-module authentication. The inconsistency prevents all capability-based operations for the affected capability, causing denial of service for critical network functionality

4. **Multi-Node Impact**: If a transaction sequence triggering this condition is broadcast to the network, all nodes processing it similarly will experience the same inconsistency, potentially affecting a significant portion of the network simultaneously

5. **Persistent Until Restart**: The inconsistency persists in memory until the node is restarted and `InitMemStore` rebuilds the `capMap` from persistent storage

This qualifies as **Medium severity** under the impact criterion: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who Can Trigger:** Any module with capability ownership can trigger this by calling `ReleaseCapability` in a transaction that subsequently fails. No special privileges are required beyond normal capability ownership granted during module initialization.

**Conditions Required:**
1. A module releases the last owner of a capability via `ReleaseCapability`
2. The transaction containing the release fails after `ReleaseCapability` executes but before commit
3. A subsequent operation attempts to access the capability via `GetCapability`

**Frequency:** The likelihood is moderate to high because:
- Transaction failures are common occurrences (validation errors, gas limits, state conflicts)
- Capability operations occur regularly during channel lifecycle management
- The inconsistency persists, so any future access to the capability will trigger the panic
- An attacker could deliberately craft transactions that call `ReleaseCapability` and then induce failure, intentionally creating this condition

The design flaw is acknowledged in codebase comments, confirming it's a known architectural issue that hasn't been fully addressed.

## Recommendation

Implement deferred cleanup for `capMap` modifications to ensure transactional consistency:

**Recommended Approach:** Modify `ReleaseCapability` to not delete from `capMap` immediately. Instead:
1. Mark capabilities for deletion in a separate tracking structure during transaction execution
2. During `InitMemStore` or a periodic consistency check, verify `capMap` entries against persistent store
3. Remove entries from `capMap` only when confirmed they don't exist in persistent storage

Alternatively, add defensive handling in `GetCapability`: when `capMap[index]` returns nil but `memStore` has the mapping, attempt to reload the capability from persistent store or reconstruct it, instead of panicking. While this doesn't fix the root cause, it prevents the node crash.

The safest fix is aligned with the existing initialization pattern where `capMap` is rebuilt from authoritative persistent store, ensuring consistency by treating persistent store as the source of truth.

## Proof of Concept

The vulnerability can be demonstrated with the following test in `x/capability/keeper/keeper_test.go`:

**Setup:**
1. Initialize test suite with keeper and scoped keeper
2. Create a new capability with one owner using `NewCapability`

**Action:**
1. Create a cached context using `ctx.MultiStore().CacheMultiStore()` to simulate transaction execution
2. Create a new context with the cached multi-store
3. Call `ReleaseCapability` in the cached context
4. Do NOT call `msCache.Write()` to simulate transaction failure/rollback

**Result:**
1. Call `GetCapability` from the original (parent) context
2. The call panics with message "capability found in memstore is missing from map"
3. This confirms the state mismatch: the parent context's `memStore` still has the capability mapping (because the cached deletion wasn't written), but the shared `capMap` no longer has the entry (because the direct deletion already happened)

The panic demonstrates that the node experiences unintended behavior when attempting to access a capability after a transaction rollback during `ReleaseCapability`, validating the vulnerability.

### Citations

**File:** x/capability/keeper/keeper.go (L83-89)
```go
	return ScopedKeeper{
		cdc:      k.cdc,
		storeKey: k.storeKey,
		memKey:   k.memKey,
		capMap:   k.capMap,
		module:   moduleName,
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

**File:** x/capability/keeper/keeper.go (L372-377)
```go
		// If a tx failed and NewCapability got reverted, it is possible
		// to still have the capability in the go map since changes to
		// go map do not automatically get reverted on tx failure,
		// so we delete here to remove unnecessary values in map
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805
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

**File:** baseapp/baseapp.go (L836-851)
```go
func (app *BaseApp) cacheTxContext(ctx sdk.Context, checksum [32]byte) (sdk.Context, sdk.CacheMultiStore) {
	ms := ctx.MultiStore()
	// TODO: https://github.com/cosmos/cosmos-sdk/issues/2824
	msCache := ms.CacheMultiStore()
	if msCache.TracingEnabled() {
		msCache = msCache.SetTracingContext(
			sdk.TraceContext(
				map[string]interface{}{
					"txHash": fmt.Sprintf("%X", checksum),
				},
			),
		).(sdk.CacheMultiStore)
	}

	return ctx.WithMultiStore(msCache), msCache
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

**File:** baseapp/baseapp.go (L1008-1017)
```go
	runMsgCtx, msCache := app.cacheTxContext(ctx, checksum)

	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```
