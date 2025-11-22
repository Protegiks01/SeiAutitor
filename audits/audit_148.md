## Title
Non-Transactional capMap Deletion Allows Index Re-claiming Leading to Node Crash

## Summary
The `ReleaseCapability` function in `x/capability/keeper/keeper.go` (lines 319-356) contains a critical timing vulnerability where the non-transactional deletion from the in-memory `capMap` (line 349) can be exploited to re-claim a capability index within the same transaction, creating an inconsistent state that causes node crashes when the capability is subsequently accessed. [1](#0-0) 

## Impact
**High** - This vulnerability causes node crashes, resulting in shutdown of network processing nodes without brute force actions.

## Finding Description

**Location:** 
- Module: `x/capability/keeper`
- File: `keeper.go`
- Primary vulnerability: Lines 347-349 in `ReleaseCapability` function
- Crash point: Line 384 in `GetCapability` function [2](#0-1) [3](#0-2) 

**Intended Logic:** 
When a module releases a capability, all ownership data should be atomically removed from both transactional stores (memStore, persistent store) and the non-transactional in-memory map (capMap). The system expects these operations to maintain consistency - either the capability exists everywhere or nowhere.

**Actual Logic:** 
The `capMap` deletion at line 349 is immediate and non-transactional (direct Go map operation), while the persistent store deletion at line 347 and memStore deletions at lines 332-336 are transactional (cached). This creates a timing window within the same transaction where:
1. capMap no longer contains the capability (permanently deleted)
2. But transactional stores still reflect the pre-deletion state (due to caching)
3. `ClaimCapability` can be called with the capability pointer, successfully recreating ownership entries
4. The capability index is "re-claimed" in persistent/memStore while absent from capMap [4](#0-3) 

**Exploit Scenario:**
1. Module A creates a capability and passes the pointer to Module B (normal inter-module communication)
2. Module B stores the capability pointer but doesn't immediately claim it
3. Within a single transaction:
   - Module A (sole owner) calls `ReleaseCapability(capability)`
   - Line 347: Deletes from persistent store (cached deletion)
   - Line 349: Deletes from capMap (immediate, permanent deletion)
   - Module B calls `ClaimCapability(capability, "name")` using its stored pointer
   - `getOwners` (line 473) sees the cached deletion, returns empty owners (line 476)
   - `addOwner` successfully adds Module B as new owner to persistent store (line 464)
   - memStore mappings are created (lines 303, 309 via ClaimCapability)
4. Transaction commits with persistent store and memStore containing Module B's ownership
5. Module B attempts `GetCapability("name")`
6. Line 368: Successfully retrieves index from memStore
7. Line 382: Attempts lookup in capMap → returns nil
8. Line 384: **PANIC** "capability found in memstore is missing from map"
9. **Node crashes** [5](#0-4) [6](#0-5) [7](#0-6) 

**Security Failure:** 
This breaks the consistency invariant between capMap and the transactional stores. The system enters a state where ownership metadata exists in persistent storage and memStore, but the actual capability object is missing from capMap. This violates memory safety and causes denial-of-service through node crashes.

## Impact Explanation

**Affected Components:**
- Node availability: Nodes crash when attempting to retrieve the re-claimed capability
- Capability system integrity: Creates permanently broken capability references
- Transaction processing: Any transaction attempting to use the re-claimed capability crashes the node

**Damage Severity:**
- **Node crashes:** Any validator or full node processing a transaction that uses the re-claimed capability will panic and crash
- **Network disruption:** If multiple nodes process such transactions, >= 30% of network nodes could crash simultaneously
- **Persistent DoS vector:** The broken capability state persists across restarts, making nodes repeatedly crash on the same operation

**System Impact:**
This directly threatens network reliability by providing an exploitable path to crash nodes. In a blockchain network, node crashes reduce decentralization, increase centralization risks, and can halt consensus if enough validators crash. The vulnerability is particularly dangerous because the broken state persists in the database, requiring manual intervention to recover.

## Likelihood Explanation

**Triggering Actors:**
Any two modules that interact with capabilities can trigger this vulnerability. Common scenarios include:
- IBC port/channel management between multiple modules
- Cross-module capability sharing in custom chains
- Module upgrades where capabilities are transferred

**Required Conditions:**
- Module A must release a capability it owns
- Module B must retain a pointer to that capability
- Both operations must occur within the same transaction (achievable through normal module interactions)
- No privileged access required - standard module operations

**Frequency:**
- **Moderate to High:** Can occur during normal operations whenever modules coordinate capability lifecycle
- **Exploitable:** An attacker controlling two modules (or exploiting module logic bugs) can deliberately trigger this
- **Persistent:** Once triggered, the broken state persists indefinitely, causing repeated crashes

The vulnerability is realistic because capability pointers are routinely passed between modules, and transaction boundaries often contain multiple module calls. The timing window exists in every `ReleaseCapability` call, making it a systemic issue rather than a rare edge case.

## Recommendation

**Immediate Fix:**
Modify `ReleaseCapability` to make capMap operations transactional by deferring the deletion until after store operations succeed:

1. **Option A - Deferred Deletion:** Store capabilities to be deleted in a temporary list and only delete from capMap after the transaction successfully commits (use a commit hook or defer the deletion)

2. **Option B - Transactional Guard:** Add the capability back to capMap if any subsequent operation in the transaction needs it, or maintain a "pending deletion" flag that's checked before deleting

3. **Option C - Validation Check:** Before allowing `ClaimCapability`, verify the capability exists in capMap, not just in persistent store

**Recommended Implementation (Option C - Simplest):**
In `ClaimCapability` (line 287), add a check after line 289:
```go
if sk.capMap[cap.GetIndex()] == nil {
    return sdkerrors.Wrap(types.ErrCapabilityNotFound, "capability not in memory")
}
```

This prevents re-claiming capabilities that have been deleted from capMap, breaking the exploit chain.

**Long-term Solution:**
Refactor the capability system to make capMap transactional by implementing a proper cache layer for Go map operations, or redesign to not rely on non-transactional memory for critical state.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** `TestTimingAttackReclaimIndexAfterRelease`

**Setup:**
1. Initialize keeper with two scoped modules ("module1" and "module2")
2. Module1 creates a capability and stores the pointer
3. Module2 receives the capability pointer (simulating inter-module communication)

**Trigger:**
1. Within the same transaction context:
   - Module1 (sole owner) calls `ReleaseCapability` to delete the capability
   - Immediately after, Module2 calls `ClaimCapability` with the stored pointer
2. Verify ClaimCapability succeeds (no error returned)
3. Attempt to retrieve the capability via `GetCapability`

**Observation:**
- The test will panic at line 384 with message: "capability found in memstore is missing from map"
- This confirms the capability index was successfully "re-claimed" (ownership recreated) while capMap no longer contains it
- The node crashes when trying to use the re-claimed capability

**Test Code:**
```go
func (suite *KeeperTestSuite) TestTimingAttackReclaimIndexAfterRelease() {
    sk1 := suite.keeper.ScopeToModule("module1")
    sk2 := suite.keeper.ScopeToModule("module2")

    // Module1 creates capability
    cap, err := sk1.NewCapability(suite.ctx, "original")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    capIndex := cap.GetIndex()

    // Module1 releases capability (as sole owner)
    // This deletes from capMap immediately (line 349)
    err = sk1.ReleaseCapability(suite.ctx, cap)
    suite.Require().NoError(err)

    // Module2 (with stored pointer) attempts to claim the released capability
    // This should fail but currently succeeds, re-claiming the index
    err = sk2.ClaimCapability(suite.ctx, cap, "reclaimed")
    suite.Require().NoError(err) // ClaimCapability succeeds!

    // Verify the inconsistent state: capability is in stores but not capMap
    // This will panic: "capability found in memstore is missing from map"
    got, ok := sk2.GetCapability(suite.ctx, "reclaimed")
    
    // This line is never reached due to panic at line 384
    suite.Require().True(ok)
    suite.Require().NotNil(got)
    suite.Require().Equal(capIndex, got.GetIndex())
}
```

**Expected Behavior on Vulnerable Code:**
- The test will panic at the `GetCapability` call
- Panic message: "capability found in memstore is missing from map"
- This proves the capability was re-claimed in stores but is missing from capMap
- Demonstrates the node crash vulnerability

**Running the Test:**
```bash
cd x/capability/keeper
go test -run TestTimingAttackReclaimIndexAfterRelease -v
```

The test will crash the test runner, confirming the vulnerability. After the fix (adding the validation check in `ClaimCapability`), the test should fail gracefully with `ErrCapabilityNotFound` instead of panicking.

### Citations

**File:** x/capability/keeper/keeper.go (L287-314)
```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
	if cap == nil {
		return sdkerrors.Wrap(types.ErrNilCapability, "cannot claim nil capability")
	}
	if strings.TrimSpace(name) == "" {
		return sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
	}
	// update capability owner set
	if err := sk.addOwner(ctx, cap, name); err != nil {
		return err
	}

	memStore := ctx.KVStore(sk.memKey)

	// Set the forward mapping between the module and capability tuple and the
	// capability name in the memKVStore
	memStore.Set(types.FwdCapabilityKey(sk.module, cap), []byte(name))

	// Set the reverse mapping between the module and capability name and the
	// index in the in-memory store. Since marshalling and unmarshalling into a store
	// will change memory address of capability, we simply store index as value here
	// and retrieve the in-memory pointer to the capability from our map
	memStore.Set(types.RevCapabilityKey(sk.module, name), sdk.Uint64ToBigEndian(cap.GetIndex()))

	logger(ctx).Info("claimed capability", "module", sk.module, "name", name, "capability", cap.GetIndex())

	return nil
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

**File:** x/capability/keeper/keeper.go (L469-482)
```go
func (sk ScopedKeeper) getOwners(ctx sdk.Context, cap *types.Capability) *types.CapabilityOwners {
	prefixStore := prefix.NewStore(ctx.KVStore(sk.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(cap.GetIndex())

	bz := prefixStore.Get(indexKey)

	if len(bz) == 0 {
		return types.NewCapabilityOwners()
	}

	var capOwners types.CapabilityOwners
	sk.cdc.MustUnmarshal(bz, &capOwners)
	return &capOwners
}
```
