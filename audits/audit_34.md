# Audit Report

## Title
State Desynchronization in ReleaseCapability Causes Node Panic on Transaction Rollback

## Summary
The `ReleaseCapability` function in the capability keeper contains a state inconsistency vulnerability where it directly modifies the shared Go map (`capMap`) while performing cached store operations. When a transaction calls `ReleaseCapability` and then fails or is rolled back, the cached store deletions are reverted but the Go map deletion persists, creating a desynchronized state that causes node panics when the capability is subsequently accessed. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ReleaseCapability` at lines 319-356, specifically the direct map deletion at line 349.

**Intended Logic:** When releasing the last owner of a capability within a transaction context, all state modifications (persistent store, memory store, and in-memory map) should be atomic. If the transaction fails or is rolled back, all changes should revert together to maintain consistency between the three storage layers.

**Actual Logic:** The function mixes transactional and non-transactional operations:
- Lines 332, 336: Delete from `memStore` (cached/transactional) [2](#0-1) 
- Line 347: Delete from `prefixStore` (cached/transactional) [3](#0-2) 
- Line 349: Delete from `capMap` (direct Go map operation, NOT transactional) [4](#0-3) 

The `capMap` is shared across all scoped keepers and contexts [5](#0-4) , meaning modifications to it affect parent and cached contexts simultaneously. When a cached context is discarded without calling `Write()`, the store operations are not committed, but the map deletion has already occurred permanently.

**Exploitation Path:**
1. A module calls `ReleaseCapability` within a transaction (creating a cached context)
2. The function successfully executes, deleting from `capMap` (line 349) and from cached stores
3. The transaction fails validation, runs out of gas, or encounters an error
4. The cached context is discarded without calling `Write()` - store deletions are reverted
5. Result: `memStore` still contains the capability mappings (deletion not written), but `capMap` no longer has the capability entry (deletion already happened)
6. When `GetCapability` is called for this capability:
   - Line 368: `memStore.Get()` succeeds and returns the capability index [6](#0-5) 
   - Line 382: `capMap[index]` returns nil [7](#0-6) 
   - Line 384: Node panics with "capability found in memstore is missing from map" [8](#0-7) 

**Security Guarantee Broken:** Transaction atomicity and state consistency. The codebase explicitly acknowledges this class of issue in comments at lines 372-377, which state "changes to go map do not automatically get reverted on tx failure" and reference issue #7805. [9](#0-8)  However, the code only handles one direction of the inconsistency (NewCapability case) and not the inverse (ReleaseCapability case).

## Impact Explanation

This vulnerability affects the availability and reliability of capability-dependent operations:

1. **State Inconsistency:** Creates a permanent desynchronization between `memStore` and `capMap` until node restart, violating the fundamental invariant that these storage layers must remain synchronized.

2. **Node Instability:** When `GetCapability` is called for the affected capability, the node panics. While transaction execution has panic recovery [10](#0-9) , the panic still causes transaction failures and potential node crashes if triggered in unrecovered paths (e.g., BeginBlock/EndBlock operations).

3. **IBC and Module Disruption:** Capabilities are fundamental to IBC port/channel management and inter-module authentication. The inconsistency prevents all capability-based operations for the affected capability, causing denial of service for critical network functionality.

4. **Multi-Node Impact:** If a transaction sequence that triggers this condition is broadcast to the network, all nodes processing it similarly will experience the same inconsistency, potentially affecting a significant portion of the network simultaneously.

5. **Persistent Until Restart:** The inconsistency persists in memory until the node is restarted, at which point `InitMemStore` rebuilds the `capMap` from persistent storage, recovering consistency. However, this requires manual intervention.

The vulnerability qualifies as **Medium severity** under the impact criteria: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who Can Trigger:** Any module with capability ownership can trigger this by calling `ReleaseCapability` in a transaction that subsequently fails. No special privileges are required beyond normal capability ownership granted during module initialization.

**Conditions Required:**
1. A module releases the last owner of a capability via `ReleaseCapability`
2. The transaction containing the release fails after `ReleaseCapability` executes but before commit
3. A subsequent operation attempts to access the capability via `GetCapability`

**Frequency:** The likelihood is moderate to high because:
- Transaction failures are common (validation errors, gas limits, state conflicts)
- IBC operations regularly create and release capabilities during channel lifecycle management
- The inconsistency persists, so any future access to the capability will trigger the panic
- An attacker could deliberately craft transactions that call `ReleaseCapability` and then fail, intentionally creating this condition

The design flaw is acknowledged in the codebase comments, confirming it's a known architectural issue that hasn't been addressed.

## Recommendation

**Recommended Fix:** Implement deferred cleanup for `capMap` modifications to ensure transactional consistency.

**Option A (Deferred Cleanup):** Modify `ReleaseCapability` to not delete from `capMap` immediately. Instead:
1. Mark capabilities for deletion in a separate tracking structure
2. During `InitMemStore` or a periodic consistency check, verify `capMap` entries against persistent store
3. Remove entries from `capMap` only when confirmed they don't exist in persistent storage

**Option B (Post-Commit Hook):** Implement a post-commit callback mechanism in the SDK that allows `capMap` modifications to be deferred until after `Write()` successfully completes. This would require architectural changes to support transactional hooks.

**Option C (Defensive Guard):** In `GetCapability`, when `capMap[index]` returns nil but `memStore` has the mapping, attempt to reload the capability from persistent store instead of panicking. This is defensive programming but doesn't fix the root cause.

**Recommended Approach:** Option A is the safest and most aligned with the existing initialization pattern. It ensures `capMap` consistency by rebuilding it from the authoritative persistent store.

## Proof of Concept

The provided PoC in the security report is valid and demonstrates the vulnerability:

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestReleaseCapabilityStateMismatch`

**Setup:**
1. Initialize test suite with keeper and scoped keeper for a test module
2. Create a new capability with one owner using `NewCapability`

**Action:**
1. Create a cached context using `ms.CacheMultiStore()` to simulate transaction execution
2. Call `ReleaseCapability` in the cached context, which deletes from the shared `capMap` and from cached stores
3. Do NOT call `msCache.Write()` to simulate transaction failure/rollback

**Result:**
1. Call `GetCapability` from the original (parent) context
2. The call should panic with message "capability found in memstore is missing from map"
3. This confirms the state mismatch: the parent context's `memStore` still has the capability mapping (because the cached deletion wasn't written), but the shared `capMap` no longer has the entry (because the direct deletion already happened)

The panic demonstrates that the node crashes when attempting to access a capability after a transaction rollback during `ReleaseCapability`, proving the vulnerability.

## Notes

The architectural design documented in ADR-003 explicitly acknowledges at line 330 that "go-map" changes don't revert on transaction failure. However, the mitigation implemented in `GetCapability` (lines 372-377) only handles the case where `NewCapability` adds to `capMap` but the transaction fails (leaving the entry in `capMap` but not in stores). The inverse case - where `ReleaseCapability` removes from `capMap` but the transaction fails (leaving entries in stores but not in `capMap`) - is not handled, creating this vulnerability.

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

**File:** x/capability/keeper/keeper.go (L368-369)
```go
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
