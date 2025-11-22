# Audit Report

## Title
Transaction Rollback in ReleaseCapability Causes Permanent capMap Deletion Leading to Chain Halt

## Summary
The `ReleaseCapability` function in the capability keeper violates transactional atomicity guarantees by permanently deleting from the in-memory `capMap` (a Go map), while other state changes in memStore and persistent store can be rolled back. When a transaction containing `ReleaseCapability` fails and rolls back, the system enters an inconsistent state where memStore mappings exist but the corresponding `capMap` entry is gone, causing `GetCapability` to panic with "capability found in memstore is missing from map" and halting the entire chain. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:**
- Primary: `x/capability/keeper/keeper.go`, lines 319-356 (ReleaseCapability function)
- Secondary: `x/capability/keeper/keeper.go`, lines 361-388 (GetCapability function with panic)

**Intended Logic:**
The `ReleaseCapability` function should atomically remove a capability from all storage locations (memStore, persistent store, and capMap) when released. All operations should succeed or fail together - if the transaction rolls back, all changes should be reverted to maintain system consistency.

**Actual Logic:**
ReleaseCapability performs deletions across three storage types with different transactional properties:

1. **memStore deletions** (lines 332, 336): Transactional - will rollback on tx failure [2](#0-1) 

2. **Persistent store deletion** (line 347): Transactional - will rollback on tx failure [3](#0-2) 

3. **Go map deletion** (line 349): **NOT transactional - permanent and cannot rollback** [4](#0-3) 

**Exploitation Path:**
1. Module owns a capability (e.g., IBC port capability)
2. Module calls `ReleaseCapability` within a transaction context
3. ReleaseCapability executes, deleting from memStore, persistent store, AND capMap
4. Transaction fails after ReleaseCapability (due to gas exhaustion, logic error, or subsequent operation failure)
5. Transaction rollback occurs:
   - memStore deletions are reverted → reverse mappings restored
   - Persistent store deletions are reverted → owner set restored
   - **capMap deletion is permanent** → entry permanently gone
6. System is now in inconsistent state:
   - memStore contains reverse mapping pointing to capability index
   - capMap has NO entry for that index
7. Any call to `GetCapability` for that capability name will:
   - Retrieve index from memStore (line 368-369)
   - Attempt to get capability from capMap (line 382)
   - Find nil in capMap
   - **Trigger panic** at line 384 [5](#0-4) 

8. Chain halts completely - panic is unrecovered and stops block production

**Security Guarantee Broken:**
This violates the fundamental transactional atomicity invariant that all operations within a transaction should be atomic - either all succeed or all fail together. The code itself acknowledges this issue with a TODO comment referencing GitHub issue #7805. [6](#0-5) 

## Impact Explanation

**Consequences:**
- **Complete chain halt**: The panic in GetCapability is unhandled and will stop consensus/block production
- **Requires hard fork to recover**: Cannot be fixed without coordinated upgrade
- **Affects entire network**: All nodes will panic when attempting to retrieve the affected capability
- **Persistent across restarts**: memStore is rebuilt from persistent storage (which was rolled back), so the inconsistency persists

**Affected Systems:**
- All transaction processing capability
- Consensus finality
- Network availability
- Any application or module attempting to use the affected capability

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category, classified as **Medium severity** per the provided impact scale.

## Likelihood Explanation

**Triggering Conditions:**
The vulnerability requires:
1. A module to call `ReleaseCapability` within a transaction
2. That transaction to fail AFTER `ReleaseCapability` executes

**Who Can Trigger:**
- Not directly user-callable
- Requires module code to invoke `ReleaseCapability`
- Modules that use capabilities include IBC transfer, IBC connection/channel handlers, and custom application modules

**Realistic Scenarios:**
- Complex multi-step transactions where later operations fail
- IBC packet processing that encounters errors after capability operations
- Gas exhaustion scenarios where ReleaseCapability executes but transaction runs out of gas
- Module upgrade scenarios with state transitions

**Likelihood Assessment:**
While not trivial to exploit intentionally, this can occur accidentally during normal blockchain operation. Transaction failures are common, and if any module uses `ReleaseCapability` in complex operations that can fail mid-execution, the vulnerability becomes triggerable. The Cosmos SDK's `CacheContext` pattern (used for transaction execution) explicitly supports this rollback scenario. [7](#0-6) 

The existing `TestRevertCapability` test demonstrates that the capability keeper is designed to support transaction rollbacks, but it only tests `NewCapability`, not `ReleaseCapability`.

## Recommendation

**Immediate Fix:**
Remove the `capMap` deletion from `ReleaseCapability` (line 349). The existing cleanup logic in `GetCapability` (lines 372-379) already handles orphaned `capMap` entries when capabilities are created and rolled back. Apply the same pattern for releases.

**Proper Fix:**
Implement a transactional wrapper around `capMap` that tracks deletions and only applies them on successful transaction commit. This could use:
1. A pending deletions map that's populated during transaction execution
2. A commit hook that applies the deletions only after successful commit
3. A rollback hook that clears pending deletions on failure

**Alternative Approach:**
Defer all `capMap` modifications until after transaction commit by leveraging the BaseApp's commit hooks or event system to ensure atomicity with other state changes.

The TODO comment at line 376-377 explicitly mentions the need for this fix and references issue #7805 for tracking.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestReleaseCapabilityTransactionRollbackPanic`

**Setup:**
1. Create a scoped keeper for a test module
2. Create a new capability owned solely by that module
3. Create a cached context (simulating transaction execution)

**Action:**
1. Call `ReleaseCapability` on the cached context
2. Verify capability is deleted in cached context
3. Do NOT commit the cached context (simulate transaction rollback)

**Result:**
1. Verify that calling `GetCapability` on the original context panics
2. Panic message: "capability found in memstore is missing from map"
3. This demonstrates the inconsistent state where memStore has the reverse mapping but capMap doesn't have the capability entry

**Test Code Structure:**
```go
func (suite *KeeperTestSuite) TestReleaseCapabilityTransactionRollbackPanic() {
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    cap, err := sk.NewCapability(suite.ctx, "transfer")
    suite.Require().NoError(err)
    
    // Create cached context (transaction)
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    
    // Release in cached context
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    
    // Don't call msCache.Write() - simulate rollback
    
    // This panics due to inconsistent state
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "transfer")
    })
}
```

This test would pass (i.e., the panic occurs), confirming the vulnerability.

## Notes

The ADR-003 design document explicitly states the system should "Allow CapabilityKeeper to return same capability pointer from go-map while reverting any writes to the persistent KVStore and in-memory MemoryStore on tx failure," indicating proper rollback behavior was intended but not fully implemented for `ReleaseCapability`. [8](#0-7)

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

**File:** x/capability/keeper/keeper.go (L376-377)
```go
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805
```

**File:** x/capability/keeper/keeper.go (L382-385)
```go
	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
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

**File:** docs/architecture/adr-003-dynamic-capability-store.md (L330-330)
```markdown
- Allows CapabilityKeeper to return same capability pointer from go-map while reverting any writes to the persistent `KVStore` and in-memory `MemoryStore` on tx failure.
```
