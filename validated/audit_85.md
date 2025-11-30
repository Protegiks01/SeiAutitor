After thorough analysis of the code and tracing the execution paths, I can validate this security claim.

# Audit Report

## Title
Forward-Map Corruption in ClaimCapability Through Duplicate Claims Under Different Names

## Summary
The `ClaimCapability` function in the capability keeper contains an architectural flaw that allows a module to claim the same capability multiple times under different names, causing forward-map corruption, authentication failures, and permanent orphaned state in both memory and persistent storage. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, lines 287-314, function `ClaimCapability`

**Intended logic:** The capability keeper should enforce a one-to-one mapping between each (module, capability) pair and a single name. Each module should only be able to claim a given capability once to maintain consistency between the forward mapping and owner set.

**Actual logic:** The validation only checks if the exact (module, name) tuple exists in the owner set by comparing `Owner.Key()` which returns "module/name". [2](#0-1) 

The architectural flaw stems from key generation mismatch:
- Forward key uses only module and capability pointer: [3](#0-2) 
- Owner key uses both module and name: [2](#0-1) 

This allows multiple owner entries per module while only one forward mapping can exist per (module, capability) pair.

**Exploitation path:**
1. Module creates capability: `cap, _ := sk.NewCapability(ctx, "channel-1")`
   - Owner set: `[{module, channel-1}]`
   - Forward map: `module/fwd/0xCAP` → "channel-1"
   - Reverse map: `module/rev/channel-1` → index

2. Module claims same capability with different name: `sk.ClaimCapability(ctx, cap, "channel-2")`
   - `addOwner` calls `capOwners.Set()` which checks `Owner.Key()` [4](#0-3) 
   - Since "module/channel-2" != "module/channel-1", validation passes
   - Owner set becomes: `[{module, channel-1}, {module, channel-2}]`
   - Forward map overwrites at line 303: [5](#0-4) 
   - New reverse mapping at line 309: [6](#0-5) 
   - Result: `module/fwd/0xCAP` → "channel-2" (OVERWRITTEN), `module/rev/channel-1` remains (ORPHANED)

3. Authentication breaks:
   - `AuthenticateCapability(cap, "channel-1")` calls `GetCapabilityName` [7](#0-6) 
   - `GetCapabilityName` returns "channel-2" from forward map [8](#0-7) 
   - Comparison fails: "channel-2" != "channel-1"

4. Incomplete cleanup on release:
   - `ReleaseCapability` retrieves name from forward map [9](#0-8) 
   - Only deletes mappings for retrieved name ("channel-2") [10](#0-9) 
   - Orphaned: `module/rev/channel-1` reverse mapping and `{module, channel-1}` owner entry

**Security guarantee broken:** The capability authentication invariant is violated - modules cannot authenticate capabilities they legitimately own under the original name.

## Impact Explanation

This affects the core security mechanism of the capability module used throughout Cosmos SDK:

1. **Authentication Failure:** Modules that legitimately own a capability under the first claimed name cannot authenticate it, potentially blocking IBC channel operations or other capability-protected actions.

2. **Permanent State Corruption:** When releasing a capability claimed under multiple names, only the last claimed name's mappings are cleaned up. Reverse mappings and owner entries for earlier names remain permanently orphaned in both memory and persistent storage, creating inconsistent state requiring a chain upgrade to fix.

3. **Resource Leaks:** Orphaned mappings accumulate in storage over time, consuming resources that cannot be reclaimed through normal operations.

This matches the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Likelihood: Medium**

While triggering requires a module implementation bug, this can occur in realistic scenarios:

- **Module Implementation Bugs:** Error recovery or state reconstruction logic may attempt to claim the same capability with different names if state tracking is incorrect.

- **IBC Channel Handshake Complexity:** The multi-step handshake with retry logic could cause re-claiming with different identifiers if state management is imperfect.

- **Insufficient Defensive Checks:** The existing defensive pattern checks `AuthenticateCapability` before claiming [11](#0-10) , but this only prevents claiming with the same name, not different names.

The existing test suite only validates that claiming with the same name fails, not different names: [12](#0-11) 

As security infrastructure, the capability keeper should defend against misuse even if modules are trusted components.

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

This enforces the one-to-one invariant between module and capability, preventing forward-map corruption.

## Proof of Concept

**Setup:** Create a scoped keeper for a module

**Action:**
1. Module creates capability: `cap, _ := sk.NewCapability(ctx, "original")`
2. Module claims same capability with different name: `err := sk.ClaimCapability(ctx, cap, "duplicate")`

**Expected Result:**
- Second `ClaimCapability` should fail with error indicating module already owns capability

**Actual Result:**
1. Second `ClaimCapability` succeeds (no error returned) - vulnerability confirmed
2. `sk.AuthenticateCapability(ctx, cap, "original")` returns false - authentication broken for original name
3. `sk.GetCapabilityName(ctx, cap)` returns "duplicate" instead of "original" - forward map overwritten
4. After `sk.ReleaseCapability(ctx, cap)`, the reverse mapping `module/rev/original` remains in memory store - orphaned state
5. Owner entry `{module, "original"}` remains in persistent store - permanent corruption

The vulnerability stems from an architectural mismatch where `FwdCapabilityKey` creates keys based only on module and capability pointer, allowing only one forward mapping per (module, capability) pair, while the owner set can contain multiple (module, name) entries for the same capability when the same module claims it under different names.

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

**File:** x/capability/keeper/keeper_test.go (L165-166)
```go
	suite.Require().Error(sk1.ClaimCapability(suite.ctx, cap, "transfer"))
	suite.Require().NoError(sk2.ClaimCapability(suite.ctx, cap, "transfer"))
```
