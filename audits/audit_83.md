# Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the Cosmos SDK capability module allows a single module to claim the same capability object multiple times under different names. This causes forward-mapping corruption that breaks authentication invariants and creates permanent orphaned state in both memory and persistent storage. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ClaimCapability` (lines 287-314)

**Intended Logic:** The ClaimCapability function should enforce a one-to-one relationship between a module and capability pair. Each module should maintain exactly one forward mapping per capability to enable consistent authentication. The capability module's design assumes that `AuthenticateCapability` will reliably verify ownership based on the forward mapping.

**Actual Logic:** ClaimCapability only validates that the exact (module, name) tuple doesn't already exist in the owners set, but fails to check if the same module has already claimed the same capability under a different name. The vulnerability occurs because:

1. Owner validation in `addOwner` checks for duplicate (module, name) pairs via `CapabilityOwners.Set`: [2](#0-1) 

The owner key is constructed as "module/name", so Owner("foo", "channel-1") and Owner("foo", "channel-2") are treated as distinct owners.

2. The forward mapping key uses only (module, capability) as the composite key: [3](#0-2) 

This causes overwrites when the same module claims the same capability with a different name.

3. Each reverse mapping is created independently without cleanup of previous mappings: [4](#0-3) 

**Exploitation Path:**

1. Module "foo" claims capability: `ClaimCapability(ctx, cap, "channel-1")`
   - Forward map: `foo/fwd/0xCAP` → "channel-1"
   - Reverse map: `foo/rev/channel-1` → index
   - Owners: [("foo", "channel-1")]

2. Module "foo" claims same capability again: `ClaimCapability(ctx, cap, "channel-2")`
   - Owner validation passes (different name means different owner key)
   - Forward map **OVERWRITES**: `foo/fwd/0xCAP` → "channel-2" 
   - New reverse map created: `foo/rev/channel-2` → index
   - Owners: [("foo", "channel-1"), ("foo", "channel-2")]

3. Authentication breaks for the original name: [5](#0-4) 

`AuthenticateCapability(ctx, cap, "channel-1")` returns false because `GetCapabilityName` now returns "channel-2" instead of "channel-1".

4. Release creates permanent orphaned state: [6](#0-5) 

`ReleaseCapability` only cleans up the current forward-mapped name ("channel-2"), leaving the "channel-1" reverse mapping and owner entry permanently orphaned.

**Security Guarantee Broken:** The capability authentication invariant is violated—modules cannot authenticate capabilities they legitimately own, and the cleanup mechanism leaves permanent inconsistent state.

## Impact Explanation

This vulnerability affects the capability module's core security mechanism used throughout the Cosmos SDK, particularly in IBC (Inter-Blockchain Communication):

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name can no longer authenticate it. `AuthenticateCapability` will fail, preventing legitimate IBC channel operations and other capability-protected actions from executing correctly.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last claimed name is properly cleaned up. The reverse mappings and owner entries for earlier names remain permanently orphaned in both the memory store and persistent storage, creating inconsistent state that cannot be recovered without a chain upgrade.

3. **Resource Leaks:** Orphaned reverse mappings and owner entries accumulate in memory and on-chain storage, consuming resources that can never be reclaimed through normal operations.

This fits the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"—the capability module is core Cosmos SDK infrastructure that can cause module misbehavior, though funds are not directly at risk.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered during normal chain operations:
- Buggy module logic that doesn't properly track claimed capabilities
- Retry or error recovery mechanisms attempting to re-claim already-claimed capabilities
- State confusion in complex IBC handshake scenarios (e.g., crossing hellos with retries)
- Module implementations that don't verify capability ownership before claiming

The vulnerability requires specific conditions (claiming the same capability twice with different names), but:
- No special privileges are required—any module can trigger this through normal operations
- Can occur during legitimate operations if module code has edge-case handling issues
- IBC channel handshakes involve complex state transitions where this could manifest
- Once triggered, the corruption is permanent and cannot self-heal

## Recommendation

Add a check in `ClaimCapability` to verify that the calling module hasn't already claimed the capability under any name:

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
- Create a scoped keeper for a test module
- Use `NewCapability` to create an initial capability with name "original"

**Action:**
1. Call `ClaimCapability(ctx, cap, "duplicate")` to claim the same capability object with a different name
2. Verify that `AuthenticateCapability(ctx, cap, "original")` returns false (authentication broken)
3. Call `ReleaseCapability(ctx, cap)`
4. Verify that the "original" reverse mapping still exists in the memory store (orphaned state)
5. Verify that Owner("module", "original") remains in the persistent owner set (state corruption)

**Result:**
The vulnerability is confirmed by the code flow:
- Forward map at line 303 uses only (module, cap) as key → overwrites on second claim
- Reverse map at line 309 creates new entries without cleanup → accumulates orphaned mappings  
- Authentication at line 279 relies on the overwritten forward map → fails for first name
- Release at lines 323-340 only cleans up the last claimed name → leaves orphaned state

**Notes:**

The existing test suite does not cover this scenario: [7](#0-6) 

The `TestClaimCapability` function only tests claiming with the same name by the same module (which correctly fails at line 165) and claiming by different modules (which correctly succeeds at line 166), but does not test the same module claiming with different names—the exact vulnerability scenario.

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

**File:** x/capability/types/keys.go (L35-37)
```go
func RevCapabilityKey(module, name string) []byte {
	return []byte(fmt.Sprintf("%s/rev/%s", module, name))
}
```

**File:** x/capability/types/keys.go (L41-50)
```go
func FwdCapabilityKey(module string, cap *Capability) []byte {
	// encode the key to a fixed length to avoid breaking consensus state machine
	// it's a hacky backport of https://github.com/cosmos/cosmos-sdk/pull/11737
	// the length 10 is picked so it's backward compatible on common architectures.
	key := fmt.Sprintf("%#010p", cap)
	if len(key) > 10 {
		key = key[len(key)-10:]
	}
	return []byte(fmt.Sprintf("%s/fwd/0x%s", module, key))
}
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
