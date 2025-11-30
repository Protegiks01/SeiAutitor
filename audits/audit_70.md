After thorough analysis of the code and execution flow, I can confirm this is a **valid vulnerability**.

# Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the capability keeper allows a module to claim the same capability multiple times under different names, causing forward-map corruption that breaks capability authentication and creates permanent orphaned state. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ClaimCapability` (lines 287-314)

**Intended Logic:** The capability module should enforce a one-to-one mapping between a module and a capability, ensuring each module can claim a given capability only once. The forward mapping should consistently identify the name associated with a capability for authentication purposes.

**Actual Logic:** The `ClaimCapability` function only checks if the exact (module, name) pair already exists in the owner set. The check occurs in `CapabilityOwners.Set()` which compares `Owner.Key()` returning "module/name", so it only prevents duplicate claims with the **same** name. [2](#0-1) [3](#0-2) 

When a module claims the same capability with a different name:
1. The `addOwner` call succeeds because `Owner{Module: "foo", Name: "name2"}` is different from `Owner{Module: "foo", Name: "name1"}`
2. The forward mapping `FwdCapabilityKey(module, cap)` gets **overwritten** to point to the new name instead of the original name (line 303)
3. Both reverse mappings remain in memory, but only the last forward mapping is retained [4](#0-3) 

**Exploitation Path:**
1. Module "foo" claims a capability: `ClaimCapability(ctx, cap, "channel-1")`
   - Forward: `foo/fwd/0xCAP` → "channel-1"
   - Reverse: `foo/rev/channel-1` → index
2. Module "foo" claims the same capability again: `ClaimCapability(ctx, cap, "channel-2")`
   - Forward: `foo/fwd/0xCAP` → "channel-2" [OVERWRITES]
   - Reverse: `foo/rev/channel-2` → index [NEW entry]
3. Authentication fails: `AuthenticateCapability(cap, "channel-1")` returns false because `GetCapabilityName` returns "channel-2" [5](#0-4) [6](#0-5) 

4. Cleanup is incomplete: `ReleaseCapability` only removes "channel-2" mappings, leaving "channel-1" orphaned [7](#0-6) 

**Security Guarantee Broken:** The capability authentication invariant is violated - modules cannot authenticate capabilities they legitimately own under the original name.

## Impact Explanation

This vulnerability affects the core security mechanism of the capability module used throughout Cosmos SDK:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name can no longer authenticate it, blocking legitimate IBC channel operations or other capability-protected actions.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last claimed name is cleaned up. The reverse mappings and owner entries for earlier names remain permanently orphaned, consuming storage and creating inconsistent state that requires a chain upgrade to fix.

3. **Resource Leaks:** Orphaned reverse mappings and owner entries accumulate over time, consuming memory and storage that can never be reclaimed through normal operations.

This fits the Medium severity impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Likelihood: Medium**

This can be triggered in realistic scenarios:

- **Module Bugs:** A module that doesn't properly track claimed capabilities may attempt to claim the same capability multiple times with different names
- **Complex State Management:** IBC channel handshakes involve multiple steps (INIT, TRY, ACK, CONFIRM) where retry logic or state confusion could cause re-claiming with different identifiers
- **No Defensive Checks:** While IBC documentation shows defensive patterns using `AuthenticateCapability` before claiming, this only prevents claiming with the same name, not different names

The vulnerability requires no special privileges - any module can trigger this during normal operation. The existing test suite only tests claiming with the same name (which correctly fails) but not with different names. [8](#0-7) 

## Recommendation

Add a check in `ClaimCapability` to verify the calling module hasn't already claimed the capability under any name:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    if cap == nil {
        return sdkerrors.Wrap(types.ErrNilCapability, "cannot claim nil capability")
    }
    if strings.TrimSpace(name) == "" {
        return sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
    }
    
    // Check if this module already owns this capability under any name
    existingName := sk.GetCapabilityName(ctx, cap)
    if existingName != "" {
        return sdkerrors.Wrapf(types.ErrCapabilityTaken, 
            "module %s already owns capability under name %s", sk.module, existingName)
    }
    
    // update capability owner set
    if err := sk.addOwner(ctx, cap, name); err != nil {
        return err
    }
    // ... rest of function
}
```

This prevents forward-map corruption by ensuring each module can only claim a given capability once.

## Proof of Concept

**Setup:** 
- Create a scoped keeper for a module
- Have the module create a new capability with name "original"

**Action:**
1. Module creates capability with `NewCapability(ctx, "original")`
2. Module claims the **same capability** with different name: `ClaimCapability(ctx, cap, "duplicate")`

**Result:**
1. The second `ClaimCapability` succeeds (should fail)
2. `AuthenticateCapability(cap, "original")` returns false - authentication broken for original name
3. `GetCapabilityName(cap)` returns "duplicate" instead of "original" - forward map was overwritten
4. After `ReleaseCapability(cap)`, the reverse mapping `module/rev/original` still exists - orphaned state
5. The owner entry for "original" remains in the persistent store - permanent state corruption

The test would demonstrate successful duplicate claim, authentication failure, and incomplete cleanup leaving orphaned state.

## Notes

The architectural issue is that `FwdCapabilityKey(module, cap)` creates a key based only on module and capability pointer, not the name. This allows only one forward mapping per (module, capability) pair, but the owner set can contain multiple (module, name) entries for the same capability. This mismatch between the forward mapping (single value) and owner set (multiple entries) creates the vulnerability when a module claims the same capability multiple times with different names.

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

**File:** x/capability/keeper/keeper.go (L392-399)
```go
func (sk ScopedKeeper) GetCapabilityName(ctx sdk.Context, cap *types.Capability) string {
	if cap == nil {
		return ""
	}
	memStore := ctx.KVStore(sk.memKey)

	return string(memStore.Get(types.FwdCapabilityKey(sk.module, cap)))
}
```

**File:** x/capability/types/types.go (L29-32)
```go
// Key returns a composite key for an Owner.
func (o Owner) Key() string {
	return fmt.Sprintf("%s/%s", o.Module, o.Name)
}
```

**File:** x/capability/types/types.go (L46-59)
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
