## Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the capability keeper does not prevent a module from claiming the same capability multiple times under different names. This causes forward-map corruption, breaking capability authentication and leaving orphaned state that cannot be cleaned up properly. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ClaimCapability` (lines 287-314)

**Intended Logic:** The ClaimCapability function should prevent a module from claiming the same capability object more than once, regardless of the name used. The forward mapping should maintain consistency with all claimed names for authentication purposes.

**Actual Logic:** ClaimCapability only checks if the exact (module, name) pair already exists as an owner [2](#0-1) , but does NOT check if the same module is claiming the same capability under a different name. When a module claims the same capability with a second different name:
1. The `addOwner` call succeeds because the new (module, name2) pair is different from the existing (module, name1) pair [3](#0-2) 
2. The forward mapping `FwdCapabilityKey(module, cap)` gets overwritten to point to the new name instead of the original name [4](#0-3) 
3. Both reverse mappings remain in memory, but only the last forward mapping is retained

**Exploit Scenario:**
1. Module "foo" receives a capability and claims it: `ClaimCapability(ctx, cap, "channel-1")`
   - Forward map: `foo/fwd/0xCAP` → "channel-1"
   - Reverse map: `foo/rev/channel-1` → cap.Index()
   - Owners: [("foo", "channel-1")]

2. Due to a bug, retry logic, or state confusion, module "foo" claims the same capability again: `ClaimCapability(ctx, cap, "channel-2")`
   - Forward map: `foo/fwd/0xCAP` → "channel-2" **[OVERWRITES!]**
   - Reverse map: `foo/rev/channel-2` → cap.Index()
   - Owners: [("foo", "channel-1"), ("foo", "channel-2")]

3. Authentication now fails for the original name:
   - `AuthenticateCapability(ctx, cap, "channel-1")` returns `false` because `GetCapabilityName(ctx, cap)` returns "channel-2" instead of "channel-1" [5](#0-4) 

4. Releasing the capability creates permanent orphaned state:
   - `ReleaseCapability(ctx, cap)` uses `GetCapabilityName` which returns "channel-2" [6](#0-5) 
   - Only deletes reverse mapping for "channel-2" and removes owner ("foo", "channel-2") [7](#0-6) 
   - The reverse mapping `foo/rev/channel-1` and owner ("foo", "channel-1") are never cleaned up

**Security Failure:** This breaks the capability authentication invariant and creates permanent state corruption. Modules cannot properly authenticate capabilities they legitimately own, and cleanup operations leave orphaned data in the store.

## Impact Explanation

This vulnerability affects the capability module's core security mechanism used throughout the Cosmos SDK, particularly in IBC:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name can no longer authenticate it, as `AuthenticateCapability` will fail. This could prevent legitimate IBC channel operations or other capability-protected actions.

2. **Permanent State Corruption:** When a module releases a capability claimed under multiple names, only the last claimed name is properly cleaned up. The reverse mappings and owner entries for earlier names remain permanently orphaned in the state, consuming storage and creating inconsistent state that cannot be recovered without a chain upgrade.

3. **Resource Leaks:** The orphaned reverse mappings and owner entries consume memory and storage resources that can never be reclaimed, potentially accumulating over time.

This fits the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the capability module is core infrastructure that can cause module misbehavior, though funds are not directly at risk.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can be triggered whenever:
- A module has buggy logic that doesn't properly track which capabilities it has already claimed
- Retry or error recovery logic attempts to re-claim a capability that was already claimed
- State confusion in complex IBC handshake scenarios (e.g., crossing hellos with retries)
- A module implementation doesn't check if it already owns a capability before claiming it

The vulnerability requires specific module behavior (claiming the same capability twice), but:
- No special privileges are required - any module can trigger this
- It can happen during normal operation if module code has bugs or edge-case handling issues
- IBC channel handshakes involve complex state transitions where this could occur
- Once triggered, the corruption is permanent and cannot self-heal

## Recommendation

Add a check in `ClaimCapability` to verify that the calling module hasn't already claimed the capability under any name before allowing a new claim:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    // ... existing validation ...
    
    // Check if this module already owns this capability under any name
    existingName := sk.GetCapabilityName(ctx, cap)
    if existingName != "" {
        return sdkerrors.Wrapf(types.ErrCapabilityTaken, 
            "module %s already owns capability under name %s", sk.module, existingName)
    }
    
    // ... rest of function ...
}
```

This prevents forward-map corruption by ensuring each module can only claim a given capability object once, regardless of the name used.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add this test to the existing test suite:

```go
func (suite *KeeperTestSuite) TestClaimCapabilityTwiceDifferentNames() {
    sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
    
    // Create a capability
    cap, err := sk.NewCapability(suite.ctx, "original")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    // Verify it works with original name
    suite.Require().True(sk.AuthenticateCapability(suite.ctx, cap, "original"))
    
    // Claim the SAME capability under a different name - this should fail but currently succeeds
    err = sk.ClaimCapability(suite.ctx, cap, "duplicate")
    suite.Require().NoError(err) // BUG: This succeeds when it should fail!
    
    // VULNERABILITY 1: Authentication for original name is now broken
    authenticated := sk.AuthenticateCapability(suite.ctx, cap, "original")
    suite.Require().False(authenticated, "BUG: Cannot authenticate with original name after claiming under different name")
    
    // Verify forward map was corrupted - it now points to "duplicate" instead of "original"
    retrievedName := sk.GetCapabilityName(suite.ctx, cap)
    suite.Require().Equal("duplicate", retrievedName, "Forward map was overwritten")
    
    // Both reverse mappings exist
    cap1, ok1 := sk.GetCapability(suite.ctx, "original")
    suite.Require().True(ok1)
    suite.Require().Equal(cap, cap1)
    
    cap2, ok2 := sk.GetCapability(suite.ctx, "duplicate")
    suite.Require().True(ok2)
    suite.Require().Equal(cap, cap2)
    
    // VULNERABILITY 2: Releasing capability leaves orphaned state
    err = sk.ReleaseCapability(suite.ctx, cap)
    suite.Require().NoError(err)
    
    // "duplicate" was cleaned up
    _, ok := sk.GetCapability(suite.ctx, "duplicate")
    suite.Require().False(ok, "duplicate was cleaned up")
    
    // BUG: "original" is still accessible but orphaned!
    capOrphaned, okOrphaned := sk.GetCapability(suite.ctx, "original")
    suite.Require().True(okOrphaned, "BUG: original reverse mapping was NOT cleaned up - orphaned state!")
    suite.Require().Equal(cap, capOrphaned)
    
    // Verify ownership state is corrupted
    owners, _ := sk.GetOwners(suite.ctx, "original")
    if owners != nil {
        suite.Require().NotEqual(0, len(owners.Owners), "BUG: original owner entry was NOT removed - state corruption!")
    }
}
```

**Setup:** Uses existing test infrastructure with a single scoped keeper for `banktypes.ModuleName`.

**Trigger:** 
1. Create a capability with name "original"
2. Claim the same capability object with name "duplicate"

**Observation:** 
1. The second ClaimCapability succeeds (should fail)
2. `AuthenticateCapability(cap, "original")` returns false (authentication broken)
3. After `ReleaseCapability`, the "original" reverse mapping still exists (orphaned state)
4. The owner entry for "original" remains in the owner set (state corruption)

This test will pass on the current vulnerable code, demonstrating the bug. After applying the recommended fix, ClaimCapability would properly reject the duplicate claim attempt.

### Citations

**File:** x/capability/keeper/keeper.go (L275-280)
```go
func (sk ScopedKeeper) AuthenticateCapability(ctx sdk.Context, cap *types.Capability, name string) bool {
	if strings.TrimSpace(name) == "" || cap == nil {
		return false
	}
	return sk.GetCapabilityName(ctx, cap) == name
}
```

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

**File:** x/capability/keeper/keeper.go (L323-326)
```go
	name := sk.GetCapabilityName(ctx, cap)
	if len(name) == 0 {
		return sdkerrors.Wrap(types.ErrCapabilityNotOwned, sk.module)
	}
```

**File:** x/capability/keeper/keeper.go (L336-340)
```go
	memStore.Delete(types.RevCapabilityKey(sk.module, name))

	// remove owner
	capOwners := sk.getOwners(ctx, cap)
	capOwners.Remove(types.NewOwner(sk.module, name))
```

**File:** x/capability/keeper/keeper.go (L453-467)
```go
func (sk ScopedKeeper) addOwner(ctx sdk.Context, cap *types.Capability, name string) error {
	prefixStore := prefix.NewStore(ctx.KVStore(sk.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(cap.GetIndex())

	capOwners := sk.getOwners(ctx, cap)

	if err := capOwners.Set(types.NewOwner(sk.module, name)); err != nil {
		return err
	}

	// update capability owner set
	prefixStore.Set(indexKey, sk.cdc.MustMarshal(capOwners))

	return nil
}
```

**File:** x/capability/types/types.go (L46-58)
```go
func (co *CapabilityOwners) Set(owner Owner) error {
	i, ok := co.Get(owner)
	if ok {
		// owner already exists at co.Owners[i]
		return sdkerrors.Wrapf(ErrOwnerClaimed, owner.String())
	}

	// owner does not exist in the set of owners, so we insert at position i
	co.Owners = append(co.Owners, Owner{}) // expand by 1 in amortized O(1) / O(n) worst case
	copy(co.Owners[i+1:], co.Owners[i:])
	co.Owners[i] = owner

	return nil
```
