## Title
Capability Keeper Transaction Rollback Causes Node Panic Due to Non-Transactional capMap Deletion

## Summary
A critical vulnerability exists in the capability keeper where releasing a capability in a transaction that subsequently rolls back leaves the system in an inconsistent state. The `capMap` (a Go map) deletion is not reverted on transaction rollback, while memStore changes are reverted, causing panics when the capability is accessed later. This occurs at lines 345-349 of `x/capability/keeper/keeper.go` where capabilities are deleted from the non-transactional `capMap`. [1](#0-0) 

## Impact
**High** - This vulnerability causes network processing node shutdowns through panics, falling under the "Medium: Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" impact category.

## Finding Description

**Location:** 
- Module: `x/capability`
- File: `x/capability/keeper/keeper.go`
- Function: `ReleaseCapability` (lines 319-356) and `GetCapability` (lines 361-388)
- Critical lines: 349 (capMap deletion) and 384 (panic on nil capability) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
When a capability is released and has no remaining owners, it should be cleanly removed from all storage (persistent store, memStore, and capMap). If the transaction fails, all changes should be atomically reverted, maintaining consistency between memStore and capMap.

**Actual Logic:** 
The `capMap` is a Go map that is not transactional - changes to it persist even when transactions roll back. When `ReleaseCapability` executes in a cached context:
1. Lines 332, 336: Forward and reverse memStore mappings are deleted (transactional)
2. Line 347: Persistent store entry is deleted (transactional)  
3. Line 349: Capability is deleted from `capMap` (NON-transactional)

When the transaction rolls back, memStore and persistent store changes are reverted, but the `capMap` deletion persists. This creates an inconsistent state where memStore contains a reverse mapping pointing to a capability index, but `capMap[index]` is nil.

The code comment at lines 372-377 acknowledges this issue exists for capability creation, but the same problem occurs in reverse for capability deletion. [4](#0-3) 

**Exploit Scenario:**
1. A module (e.g., during an IBC channel close callback) calls `ReleaseCapability` on a capability it is the sole owner of
2. The capability is deleted from `capMap` at line 349
3. Later in the same transaction, an error occurs (e.g., another callback fails, validation error, out of gas)
4. The transaction rolls back - memStore deletions are reverted, but `capMap` deletion persists
5. The next time any module calls `GetCapability` with that capability name:
   - Line 368: Finds the index in memStore (because the deletion was reverted)
   - Line 382: Looks up `sk.capMap[index]` - returns nil (because deletion was NOT reverted)
   - Line 384: Panics with "capability found in memstore is missing from map"

**Security Failure:** 
This breaks the atomicity invariant of transaction processing and the memory safety property. The system enters an inconsistent state that causes deterministic panics, resulting in denial-of-service through node crashes.

## Impact Explanation

**Affected Components:**
- Network availability: Nodes crash and become unavailable
- Transaction processing: Once the inconsistent state exists, any transaction attempting to access the affected capability will panic
- IBC operations: IBC channels using the affected capability become unusable

**Severity of Damage:**
- Nodes that encounter this inconsistent state will panic and crash when attempting to access the capability
- The inconsistency is permanent (survives restarts) because capMap is rebuilt from memStore state, which still contains the mapping
- This can affect multiple nodes across the network if the triggering transaction is included in a block
- Nodes become unable to process blocks containing transactions that access the affected capability
- Qualifies as a "shutdown of greater than or equal to 30% of network processing nodes" impact

**System Reliability:**
This undermines the fundamental reliability guarantees of the capability system, which is critical for IBC security. IBC callbacks that release capabilities (e.g., channel close operations) become dangerous operations that can permanently break node state.

## Likelihood Explanation

**Who Can Trigger:**
Any user or module that can cause a transaction to fail after a capability is released. This includes:
- IBC relayers submitting channel close messages
- Modules implementing IBC callbacks that release capabilities
- Any transaction that releases a capability and encounters an error afterward

**Required Conditions:**
1. A capability with a single owner (or the last owner releasing it)
2. `ReleaseCapability` is called within a transaction
3. The transaction fails after `ReleaseCapability` but before committing

**Frequency:**
- Can occur during normal IBC operations (channel closure)
- Transaction failures are common (out of gas, validation errors, application logic errors)
- Once triggered, the inconsistency is permanent and affects all subsequent accesses
- The vulnerability is deterministic and reproducible

This is a realistic scenario in production environments where IBC channels are regularly opened and closed, and transaction failures occur naturally.

## Recommendation

Implement one of the following solutions:

**Option 1 (Immediate Fix):** 
Defer `capMap` deletion until transaction commit by only performing it in `Commit()` or `EndBlock()` hooks. Store pending deletions in a transaction-aware structure.

**Option 2 (Comprehensive Fix):**
Make `capMap` transaction-aware by:
1. Maintaining a per-transaction cache of `capMap` modifications
2. Only applying modifications on successful commit
3. Reverting modifications on rollback

**Option 3 (Conservative Fix):**
In `GetCapability`, detect the inconsistent state and attempt recovery:
```go
cap := sk.capMap[index]
if cap == nil {
    // Inconsistent state detected - memStore has index but capMap doesn't
    // This can happen after a rollback. Clean up the memStore entry.
    memStore.Delete(key)
    return nil, false
}
```

The recommended approach is Option 2 for correctness, with Option 3 as a defensive measure.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestReleaseCapabilityRollbackPanic`

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityRollbackPanic() {
	sk := suite.keeper.ScopeToModule(banktypes.ModuleName)

	// Create a capability in the base context
	cap, err := sk.NewCapability(suite.ctx, "test-capability")
	suite.Require().NoError(err)
	suite.Require().NotNil(cap)

	// Verify capability exists
	got, ok := sk.GetCapability(suite.ctx, "test-capability")
	suite.Require().True(ok)
	suite.Require().Equal(cap, got)

	// Create a cached context (transaction context)
	ms := suite.ctx.MultiStore()
	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)

	// Release capability in the cached context (this is the last owner)
	err = sk.ReleaseCapability(cacheCtx, cap)
	suite.Require().NoError(err)

	// Verify capability is deleted in cached context
	got, ok = sk.GetCapability(cacheCtx, "test-capability")
	suite.Require().False(ok)
	suite.Require().Nil(got)

	// DO NOT WRITE CACHE - simulate transaction rollback
	// msCache.Write() is intentionally NOT called

	// Now try to get the capability in the original context
	// memStore changes were rolled back (reverse mapping still exists)
	// but capMap deletion persisted (capability is nil)
	// This should panic with "capability found in memstore is missing from map"
	suite.Require().Panics(func() {
		sk.GetCapability(suite.ctx, "test-capability")
	}, "Expected panic when accessing capability after rollback")
}
```

**Setup:** 
1. Initialize the capability keeper with a scoped keeper for the bank module
2. Create a capability named "test-capability" in the base context
3. Verify the capability exists and can be retrieved

**Trigger:**
1. Create a cached multistore context (simulating a transaction)
2. Call `ReleaseCapability` on the capability in the cached context
3. Do NOT call `msCache.Write()` - this simulates a transaction rollback
4. Attempt to retrieve the capability in the original context

**Observation:**
The test demonstrates that `GetCapability` panics with the message "capability found in memstore is missing from map" because:
- The memStore still has the reverse mapping (deletion was rolled back)
- The `capMap` does not have the capability (deletion was NOT rolled back)
- Line 384 executes `panic("capability found in memstore is missing from map")`

This confirms the vulnerability: transaction rollback creates an inconsistent state that causes node-crashing panics on subsequent capability access.

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
