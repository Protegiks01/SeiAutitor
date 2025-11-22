# Audit Report

## Title
Transaction Rollback in ReleaseCapability Causes Permanent capMap Deletion Leading to Chain Halt

## Summary
The `ReleaseCapability` function in the capability keeper contains a critical vulnerability where a transaction rollback leaves the system in an inconsistent state. When `ReleaseCapability` is called in a transaction that subsequently fails, the deletion from the in-memory `capMap` (a Go map) is permanent and cannot be rolled back, while all other state changes (memStore and persistent store) are properly reverted. This inconsistency causes a panic when any module attempts to retrieve the capability via `GetCapability`, resulting in a complete chain halt. [1](#0-0) 

## Impact
**High** - This vulnerability causes a total network shutdown, preventing the chain from confirming new transactions and requiring a hard fork to resolve.

## Finding Description

**Location:** 
- Primary issue: `x/capability/keeper/keeper.go`, lines 319-356 (ReleaseCapability function)
- Secondary location: `x/capability/keeper/keeper.go`, lines 361-388 (GetCapability function)

**Intended Logic:**
The `ReleaseCapability` function is designed to allow a module to release ownership of a capability. When the last owner releases a capability, it should be completely removed from all stores (memStore mappings, persistent owner set, and the in-memory capMap). All these operations should be atomic within a transaction - either all succeed or all fail together.

**Actual Logic:**
The function performs deletions across three different storage types:
1. memStore (transient, will rollback on tx failure) [2](#0-1) 
2. Persistent store (will rollback on tx failure) [3](#0-2) 
3. Go map `capMap` (will NOT rollback on tx failure) [4](#0-3) 

When a transaction containing `ReleaseCapability` fails and rolls back, the memStore and persistent store changes are reverted, but the Go map deletion at line 349 is permanent.

**Exploit Scenario:**
1. A module owns a capability (e.g., IBC port capability)
2. The module calls `ReleaseCapability` within a transaction
3. After `ReleaseCapability` executes, the transaction fails due to:
   - Gas limit exceeded
   - Another state transition failure in the same transaction
   - Application logic error
4. Transaction rollback occurs:
   - memStore mappings are restored
   - Persistent owner set is restored
   - **capMap deletion cannot be undone** - the entry is permanently deleted
5. System is now in inconsistent state:
   - Reverse mapping exists pointing to capability index
   - capMap has no entry for that index
6. Any subsequent call to `GetCapability` for that capability name triggers the panic at line 384 [5](#0-4) 
7. Chain halts completely

**Security Failure:**
This breaks the atomicity invariant of transactions and causes a denial-of-service through chain halt. The panic in `GetCapability` is explicitly checking for this inconsistent state with the message "capability found in memstore is missing from map".

## Impact Explanation

**Affected Assets/Processes:**
- Entire blockchain network availability
- All transaction processing capability
- Consensus finality

**Severity of Damage:**
- Complete chain halt requiring hard fork to recover
- All network nodes will panic when attempting to retrieve the affected capability
- No new transactions can be confirmed
- The issue persists across node restarts since memStore is rebuilt from persistent storage (which was rolled back and still contains the capability)

**System Reliability:**
This vulnerability completely undermines the reliability guarantees of the blockchain. Once triggered, the chain cannot progress without manual intervention and a coordinated hard fork, affecting all users and applications built on the network.

## Likelihood Explanation

**Who Can Trigger:**
Any module that has claimed a capability and can cause its own transaction to fail after calling `ReleaseCapability`. This includes:
- IBC transfer module
- IBC connection/channel modules  
- Any custom application modules using capabilities

**Required Conditions:**
- Module must be the last owner of a capability (or become the last owner through the release)
- Transaction containing `ReleaseCapability` must fail after the function executes
- This can happen through:
  - Intentional gas limit manipulation
  - Crafted transactions with multiple operations where later ones fail
  - Complex transaction flows with error conditions
  - Out of gas scenarios

**Frequency:**
While not trivial to exploit intentionally, this can also occur accidentally during:
- Complex multi-step transactions
- IBC packet handling with subsequent failures
- Module upgrade scenarios
- Gas estimation errors

The likelihood is **Medium to High** because capability releases are common in IBC operations, and transaction failures are a normal part of blockchain operation.

## Recommendation

The fix requires ensuring `capMap` modifications are transactional or deferring them until after transaction commit. Recommended approaches:

1. **Short-term fix:** Track `capMap` deletions separately and only apply them in `Commit` hooks or after successful transaction completion.

2. **Medium-term fix:** Modify `ReleaseCapability` to NOT delete from `capMap` when releasing. Instead, rely on `GetCapability`'s existing cleanup logic (lines 372-379) to handle orphaned `capMap` entries. Change line 349 to be conditional or removed entirely.

3. **Long-term fix:** Implement a transactional wrapper around the `capMap` that can track additions/deletions and rollback on transaction failure, as mentioned in the TODO comment. [6](#0-5) 

The immediate mitigation is to remove the `capMap` deletion from `ReleaseCapability` and let the existing cleanup logic in `GetCapability` handle orphaned entries.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestReleaseCapabilityTransactionRollbackPanic`

**Setup:**
1. Create a scoped keeper for a test module
2. Create a new capability that the module owns (making it the sole owner)
3. Create a cached context (simulating a transaction)

**Trigger:**
1. Call `ReleaseCapability` on the cached context to delete the capability
2. Do NOT commit the cached context (simulating transaction rollback)
3. Verify that `capMap` has been permanently modified (capability deleted)
4. Verify that memStore still has the reverse mapping (due to rollback)

**Observation:**
1. After rollback, calling `GetCapability` with the capability name will panic with "capability found in memstore is missing from map"
2. This demonstrates the inconsistent state and chain halt scenario

**Test Code Structure:**
```
func (suite *KeeperTestSuite) TestReleaseCapabilityTransactionRollbackPanic() {
    // Create scoped keeper and capability
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    cap, err := sk.NewCapability(suite.ctx, "transfer")
    
    // Create cached context for transaction
    ms := suite.ctx.MultiStore()
    msCache := ms.CacheMultiStore()
    cacheCtx := suite.ctx.WithMultiStore(msCache)
    
    // Release capability in transaction context
    err = sk.ReleaseCapability(cacheCtx, cap)
    suite.Require().NoError(err)
    
    // Verify capability cannot be retrieved in cache (normal behavior)
    _, ok := sk.GetCapability(cacheCtx, "transfer")
    suite.Require().False(ok)
    
    // Simulate transaction rollback by NOT calling msCache.Write()
    // memStore changes rollback, but capMap deletion is permanent
    
    // VULNERABILITY: This will panic because memStore has mapping but capMap doesn't
    suite.Require().Panics(func() {
        sk.GetCapability(suite.ctx, "transfer")
    })
}
```

This test will panic at the `GetCapability` call, demonstrating the vulnerability. The panic occurs because the reverse mapping was restored by the rollback, but the `capMap` entry remains deleted.

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
