# Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function allows a module to claim the same capability multiple times under different names, causing forward-map corruption that breaks authentication and creates permanent orphaned state. This occurs in `x/capability/keeper/keeper.go` at the `ClaimCapability` function. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ClaimCapability` (lines 287-314)

**Intended Logic:** The ClaimCapability function should prevent a module from claiming the same capability object more than once, regardless of the name used. Each module should maintain a single, consistent forward mapping to authenticate capabilities.

**Actual Logic:** ClaimCapability only checks if the exact (module, name) pair already exists as an owner, but does NOT check if the same module is already claiming the same capability under a different name. The vulnerability occurs because:

1. The owner validation in `addOwner` checks for duplicate (module, name) pairs via `CapabilityOwners.Set`: [2](#0-1) 

The owner key is "module/name", so Owner("foo", "channel-1") and Owner("foo", "channel-2") are considered different and both succeed.

2. The forward mapping uses only (module, capability) as the key, so it gets overwritten on each claim: [3](#0-2) 

3. Each reverse mapping is created independently without cleanup: [4](#0-3) 

**Exploitation Path:**
1. Module "foo" claims capability: `ClaimCapability(ctx, cap, "channel-1")`
   - Forward map: `foo/fwd/0xCAP` → "channel-1"
   - Reverse map: `foo/rev/channel-1` → index
   - Owners: [("foo", "channel-1")]

2. Module "foo" claims same capability again: `ClaimCapability(ctx, cap, "channel-2")`
   - Owner check passes (different name)
   - Forward map OVERWRITES: `foo/fwd/0xCAP` → "channel-2"
   - New reverse map created: `foo/rev/channel-2` → index
   - Owners: [("foo", "channel-1"), ("foo", "channel-2")]

3. Authentication now fails: `AuthenticateCapability(ctx, cap, "channel-1")` [5](#0-4) 

Returns false because `GetCapabilityName` returns "channel-2" instead of "channel-1".

4. Release creates orphaned state: `ReleaseCapability(ctx, cap)` [6](#0-5) 

Only cleans up "channel-2" mappings and owner, leaving "channel-1" reverse mapping and owner permanently orphaned.

**Security Guarantee Broken:** The capability authentication invariant is violated - modules cannot authenticate capabilities they legitimately own, and the cleanup mechanism leaves permanent state corruption.

## Impact Explanation

This vulnerability affects the capability module's core security mechanism used throughout the Cosmos SDK, particularly in IBC:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name can no longer authenticate it. `AuthenticateCapability` will fail, potentially preventing legitimate IBC channel operations or other capability-protected actions.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last claimed name is properly cleaned up. The reverse mappings and owner entries for earlier names remain permanently orphaned, consuming storage and creating inconsistent state that cannot be recovered without a chain upgrade.

3. **Resource Leaks:** Orphaned reverse mappings and owner entries accumulate in memory and storage, consuming resources that can never be reclaimed.

This fits the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the capability module is core infrastructure that can cause module misbehavior, though funds are not directly at risk.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered whenever:
- A module has buggy logic that doesn't properly track which capabilities it has already claimed
- Retry or error recovery logic attempts to re-claim a capability that was already claimed
- State confusion occurs in complex IBC handshake scenarios (e.g., crossing hellos with retries)
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

**Test Location:** `x/capability/keeper/keeper_test.go`

**Setup:** 
- Create a scoped keeper for a module
- Create a capability with initial name "original"

**Action:**
1. Claim the same capability object with a different name "duplicate"
2. Verify authentication behavior
3. Release the capability

**Result:**
1. The second ClaimCapability succeeds (should fail)
2. `AuthenticateCapability(cap, "original")` returns false (authentication broken)
3. After `ReleaseCapability`, the "original" reverse mapping still exists (orphaned state)
4. The owner entry for "original" remains in the owner set (state corruption)

The vulnerability is confirmed by tracing through the code:
- Forward map at line 303 uses only (module, cap) as key, causing overwrite
- Reverse map at line 309 creates new entries without cleanup
- Authentication at line 279 relies on the overwritten forward map
- Release at lines 323-340 only cleans up the last claimed name

**Notes**

The existing test suite does not cover this scenario. The `TestClaimCapability` function only tests claiming with the same name by the same module (which correctly fails) and claiming by different modules (which correctly succeeds), but does not test the same module claiming with different names. [7](#0-6)

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

**File:** x/capability/keeper/keeper.go (L323-340)
```go
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

**File:** x/capability/keeper/keeper_test.go (L156-178)
```go
func (suite *KeeperTestSuite) TestClaimCapability() {
	sk1 := suite.keeper.ScopeToModule(banktypes.ModuleName)
	sk2 := suite.keeper.ScopeToModule(stakingtypes.ModuleName)
	sk3 := suite.keeper.ScopeToModule("foo")

	cap, err := sk1.NewCapability(suite.ctx, "transfer")
	suite.Require().NoError(err)
	suite.Require().NotNil(cap)

	suite.Require().Error(sk1.ClaimCapability(suite.ctx, cap, "transfer"))
	suite.Require().NoError(sk2.ClaimCapability(suite.ctx, cap, "transfer"))

	got, ok := sk1.GetCapability(suite.ctx, "transfer")
	suite.Require().True(ok)
	suite.Require().Equal(cap, got)

	got, ok = sk2.GetCapability(suite.ctx, "transfer")
	suite.Require().True(ok)
	suite.Require().Equal(cap, got)

	suite.Require().Error(sk3.ClaimCapability(suite.ctx, cap, "  "))
	suite.Require().Error(sk3.ClaimCapability(suite.ctx, nil, "transfer"))
}
```
