# Audit Report

## Title
ClaimCapability Forward-Map Corruption Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the capability keeper allows a module to claim the same capability multiple times under different names, causing forward-map corruption that breaks capability authentication and creates permanent orphaned state.

## Impact
Medium

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ClaimCapability` (lines 287-314)

**Intended Logic:** The capability module should enforce that each module can claim a given capability only once. The forward mapping should consistently identify the single name associated with a capability for that module to enable proper authentication.

**Actual Logic:** The `ClaimCapability` function only validates whether the exact (module, name) tuple already exists in the owner set. The validation occurs in `CapabilityOwners.Set()` which checks `Owner.Key()` returning "module/name", preventing only duplicate claims with the identical name. [1](#0-0) 

The architectural flaw lies in how keys are generated:
- Forward key depends only on module and capability pointer (not name): [2](#0-1) 
- Owner key includes both module and name: [3](#0-2) 

This mismatch allows multiple owner entries per module while only one forward mapping can exist.

**Exploitation Path:**
1. Module "ibc" claims capability: `ClaimCapability(ctx, cap, "channel-1")`
   - Owner set: `[{ibc, channel-1}]`
   - Forward: `ibc/fwd/0xCAP` → "channel-1"
   - Reverse: `ibc/rev/channel-1` → index

2. Module "ibc" claims same capability with different name: `ClaimCapability(ctx, cap, "channel-2")`
   - `addOwner` succeeds (different name, so different owner key)
   - Owner set: `[{ibc, channel-1}, {ibc, channel-2}]`
   - Forward: `ibc/fwd/0xCAP` → "channel-2" [OVERWRITES at line 303] [4](#0-3) 
   - Reverse: `ibc/rev/channel-2` → index [NEW entry at line 309] [5](#0-4) 

3. Authentication fails for original name:
   - `AuthenticateCapability(cap, "channel-1")` calls `GetCapabilityName` which returns "channel-2" [6](#0-5) 
   - Comparison "channel-2" != "channel-1" returns false [7](#0-6) 

4. Incomplete cleanup:
   - `ReleaseCapability` retrieves name from forward map ("channel-2") [8](#0-7) 
   - Deletes only "channel-2" mappings, leaving "channel-1" reverse mapping and owner entry permanently orphaned [9](#0-8) 

**Security Guarantee Broken:** The capability authentication invariant is violated - modules lose the ability to authenticate capabilities they legitimately own under the original name.

## Impact Explanation

This vulnerability affects the core security mechanism of the capability module used throughout Cosmos SDK:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name cannot authenticate it, potentially blocking IBC channel operations or other capability-protected actions. The authentication check explicitly compares the forward-mapped name with the requested name, and this comparison fails after the forward map is overwritten.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last claimed name's mappings are cleaned up. The reverse mappings and owner entries for earlier names remain permanently orphaned in both memory and persistent storage, creating inconsistent state that cannot be fixed without a chain upgrade.

3. **Resource Leaks:** Orphaned reverse mappings and owner entries accumulate in storage over time, consuming resources that cannot be reclaimed through normal operations.

This fits the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Likelihood: Medium**

This can be triggered in realistic scenarios:

- **Module Implementation Bugs:** A module that doesn't properly track claimed capabilities may attempt to claim the same capability multiple times with different names during error recovery or state reconstruction.

- **IBC Channel Handshake Complexity:** The multi-step IBC channel handshake (INIT, TRY, ACK, CONFIRM) with retry logic could cause re-claiming with different channel identifiers if state management is not carefully implemented.

- **Insufficient Defensive Checks:** While IBC documentation shows the defensive pattern of using `AuthenticateCapability` before claiming, this only prevents claiming with the same name. [10](#0-9)  No check exists to prevent claiming with a different name.

The vulnerability requires no special privileges - any module can trigger this during normal operation. The existing test suite only validates that claiming with the same name fails, but does not test claiming with different names. [11](#0-10) 

## Recommendation

Add a defensive check in `ClaimCapability` to verify the calling module hasn't already claimed the capability under any name:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    // ... existing nil and empty name checks ...
    
    // Check if this module already owns this capability under any name
    existingName := sk.GetCapabilityName(ctx, cap)
    if existingName != "" {
        return sdkerrors.Wrapf(types.ErrCapabilityTaken, 
            "module %s already owns capability under name %s", sk.module, existingName)
    }
    
    // ... rest of function ...
}
```

This prevents forward-map corruption by ensuring each module can only claim a given capability once, maintaining the one-to-one invariant between module and capability.

## Proof of Concept

**Setup:** Create a scoped keeper for a module

**Action:**
1. Module creates capability: `cap, _ := sk.NewCapability(ctx, "original")`
2. Module claims same capability with different name: `sk.ClaimCapability(ctx, cap, "duplicate")`

**Expected Result:**
- Second `ClaimCapability` should fail (module already owns capability)

**Actual Result:**
1. Second `ClaimCapability` succeeds (vulnerability)
2. `AuthenticateCapability(cap, "original")` returns false - authentication broken
3. `GetCapabilityName(cap)` returns "duplicate" instead of "original" - forward map overwritten
4. After `ReleaseCapability(cap)`, reverse mapping `module/rev/original` remains - orphaned state
5. Owner entry `{module, "original"}` remains in persistent store - permanent corruption

**Notes**

The vulnerability stems from an architectural mismatch: `FwdCapabilityKey` creates keys based only on module and capability pointer (not name), allowing only one forward mapping per (module, capability) pair, while the owner set can contain multiple (module, name) entries for the same capability. This mismatch enables the corruption when a module claims the same capability multiple times with different names. While this requires a module bug to trigger, the capability module as core security infrastructure should defend against such misuse to prevent permanent state corruption.

### Citations

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

**File:** x/capability/keeper/keeper.go (L275-280)
```go
func (sk ScopedKeeper) AuthenticateCapability(ctx sdk.Context, cap *types.Capability, name string) bool {
	if strings.TrimSpace(name) == "" || cap == nil {
		return false
	}
	return sk.GetCapabilityName(ctx, cap) == name
}
```

**File:** x/capability/keeper/keeper.go (L303-303)
```go
	memStore.Set(types.FwdCapabilityKey(sk.module, cap), []byte(name))
```

**File:** x/capability/keeper/keeper.go (L309-309)
```go
	memStore.Set(types.RevCapabilityKey(sk.module, name), sdk.Uint64ToBigEndian(cap.GetIndex()))
```

**File:** x/capability/keeper/keeper.go (L323-326)
```go
	name := sk.GetCapabilityName(ctx, cap)
	if len(name) == 0 {
		return sdkerrors.Wrap(types.ErrCapabilityNotOwned, sk.module)
	}
```

**File:** x/capability/keeper/keeper.go (L332-340)
```go
	memStore.Delete(types.FwdCapabilityKey(sk.module, cap))

	// Delete the reverse mapping between the module and capability name and the
	// index in the in-memory store.
	memStore.Delete(types.RevCapabilityKey(sk.module, name))

	// remove owner
	capOwners := sk.getOwners(ctx, cap)
	capOwners.Remove(types.NewOwner(sk.module, name))
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

**File:** x/capability/keeper/keeper_test.go (L165-166)
```go
	suite.Require().Error(sk1.ClaimCapability(suite.ctx, cap, "transfer"))
	suite.Require().NoError(sk2.ClaimCapability(suite.ctx, cap, "transfer"))
```
