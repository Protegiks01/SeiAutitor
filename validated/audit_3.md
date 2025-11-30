# Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the Cosmos SDK capability module fails to prevent a single module from claiming the same capability multiple times under different names, resulting in forward-map corruption that breaks authentication and creates permanent orphaned state in the capability tracking system.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The ClaimCapability function should prevent a module from claiming the same capability object more than once. Each (module, capability) pair should maintain exactly one forward mapping to ensure authentication consistency. The forward mapping structure is inherently designed to support only one name per (module, capability) pair.

**Actual Logic:** ClaimCapability only validates whether the exact (module, name) pair exists as an owner. Since the owner key format is "module/name" [2](#0-1) , different names create different owner keys (e.g., "module/name1" vs "module/name2"), allowing both to pass the ownership check [3](#0-2) .

However, the forward mapping key `FwdCapabilityKey` is based solely on (module, capability) [4](#0-3) , meaning only ONE forward mapping can exist per (module, capability) pair. When the same module claims the same capability with a different name, the forward mapping gets overwritten while the owners list and reverse mappings accumulate multiple entries.

**Exploitation Path:**
1. Module claims capability with name "channel-1"
   - Forward map: `module/fwd/0xCAP` → "channel-1"
   - Reverse map: `module/rev/channel-1` → index
   - Owners: [("module", "channel-1")]

2. Module claims same capability with name "channel-2"
   - Owner check passes (different key "module/channel-2" vs "module/channel-1")
   - Forward map OVERWRITES: `module/fwd/0xCAP` → "channel-2"
   - New reverse map: `module/rev/channel-2` → index
   - Owners: [("module", "channel-1"), ("module", "channel-2")]

3. Authentication fails: `AuthenticateCapability` checks if `GetCapabilityName` returns "channel-1", but it returns "channel-2" [5](#0-4) 

4. `ReleaseCapability` only cleans up the last claimed name, leaving "channel-1" reverse mapping and owner entry permanently orphaned [6](#0-5) 

**Security Guarantee Broken:** The capability authentication invariant is violated - modules cannot authenticate capabilities they legitimately own, and the cleanup mechanism creates permanent state corruption that cannot be recovered without a chain upgrade.

## Impact Explanation

This vulnerability affects the core capability authentication mechanism used throughout the Cosmos SDK, particularly in IBC:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name can no longer authenticate it, potentially blocking IBC channel operations or other capability-protected actions.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last name's mappings get cleaned up. Previous names' reverse mappings and owner entries remain permanently orphaned in storage, creating inconsistent state that cannot be recovered without a hard fork or chain upgrade.

3. **Resource Leaks:** Orphaned reverse mappings and owner entries accumulate in memory and persistent storage, consuming resources that can never be reclaimed through normal operations.

This qualifies as **Medium** severity: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the capability module is core Cosmos SDK infrastructure that causes module misbehavior without directly risking funds.

## Likelihood Explanation

**Likelihood: Medium**

While the capability module is used by trusted on-chain modules, this vulnerability can be inadvertently triggered during normal operation when:
- Module code has bugs in capability tracking logic
- Retry or error recovery logic attempts to re-claim an already-claimed capability
- Complex state transitions in IBC handshakes (e.g., crossing hellos scenarios) cause confusion about which capabilities are already owned
- A module implementation doesn't check ownership before claiming

The IBC module documentation explicitly shows defensive code checking `AuthenticateCapability` before claiming [7](#0-6) , indicating this is a known concern that module developers must guard against. However, the capability module itself should enforce this invariant rather than relying on all callers to implement defensive checks. Once triggered, the corruption is permanent and cannot self-heal, requiring a chain upgrade to fix the corrupted state.

## Recommendation

Add a check in `ClaimCapability` to verify the calling module hasn't already claimed the capability under any name:

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

This ensures each module can only claim a given capability once, preventing forward-map corruption and maintaining the authentication invariant.

## Proof of Concept

**Test File:** `x/capability/keeper/keeper_test.go`

**Setup:**
- Create a scoped keeper for a test module
- Create a new capability with name "original" using `NewCapability`
- Verify initial authentication works

**Action:**
1. Call `ClaimCapability(ctx, cap, "duplicate")` with the same capability but different name
2. Attempt `AuthenticateCapability(ctx, cap, "original")`
3. Call `ReleaseCapability(ctx, cap)`
4. Check for orphaned state in reverse mappings

**Result:**
1. The second `ClaimCapability` succeeds (demonstrates the bug allows duplicate claims)
2. `AuthenticateCapability(cap, "original")` returns false (proves forward map was overwritten and authentication is broken)
3. After `ReleaseCapability`, the reverse mapping for "original" still exists while "duplicate" was cleaned up (confirms orphaned state)
4. The owners list still contains the "original" owner entry (proves permanent state corruption)

The existing test suite confirms this scenario is not covered [8](#0-7)  - `TestClaimCapability` only tests claiming with the same name (correctly fails) and different modules claiming (correctly succeeds), but not the same module claiming with different names.

## Notes

This is a defensive programming issue in core Cosmos SDK infrastructure. While it requires a module to inadvertently call `ClaimCapability` twice with different names, the consequences are severe and permanent: broken authentication and unrecoverable state corruption. The capability module should enforce its own invariants rather than relying on all calling modules to implement defensive checks, as evidenced by the IBC module's explicit protection against this scenario in the crossing hellos case. The vulnerability matches the Medium impact criteria as "a bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

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

**File:** docs/ibc/custom.md (L77-86)
```markdown
    // Module may have already claimed capability in OnChanOpenInit in the case of crossing hellos
    // (ie chainA and chainB both call ChanOpenInit before one of them calls ChanOpenTry)
    // If the module can already authenticate the capability then the module already owns it so we don't need to claim
    // Otherwise, module does not have channel capability and we must claim it from IBC
    if !k.AuthenticateCapability(ctx, chanCap, host.ChannelCapabilityPath(portID, channelID)) {
        // Only claim channel capability passed back by IBC module if we do not already own it
        if err := k.scopedKeeper.ClaimCapability(ctx, chanCap, host.ChannelCapabilityPath(portID, channelID)); err != nil {
            return err
        }
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
