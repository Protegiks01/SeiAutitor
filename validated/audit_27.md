After thorough analysis of the codebase, I have validated this security claim. Here is my assessment:

# Audit Report

## Title
Capability Ownership Bypass Through Forged Capability Struct Cloning

## Summary
The `ClaimCapability` function in the capability keeper does not validate that the capability pointer provided is the canonical pointer stored in `capMap`. This allows any module to forge a capability struct with a known index and successfully claim ownership of capabilities they never legitimately received, completely bypassing the object-capability security model.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The capability system implements an object-capability model where capabilities can only be obtained through legitimate channels: creating them via `NewCapability`, receiving them from another module that passes the canonical pointer, or retrieving previously claimed capabilities via `GetCapability`. The security relies on pointer identity - each capability has a unique memory address that serves as its unforgeable identifier. [3](#0-2) 

**Actual Logic:** 
The `ClaimCapability` function only validates that the capability is not nil and the name is not empty. It then calls `addOwner` which uses `cap.GetIndex()` to identify the capability and update the persistent owner set. There is no validation that the provided capability pointer matches the canonical pointer stored in `capMap[cap.GetIndex()]`. The `NewCapability` function is public and allows anyone to create a capability struct with any index. [4](#0-3) 

**Exploitation Path:**
1. Module A creates a capability with index N (canonical pointer at 0xAAA)
2. Malicious Module M observes index N (indices are sequential and stored in state)
3. Module M creates forged capability: `forged := types.NewCapability(N)` at memory address 0xBBB
4. Module M calls `ClaimCapability(ctx, forged, "stolen")`
5. `addOwner` adds Module M to the persistent owner set using only the index
6. Forward mapping `FwdCapabilityKey("moduleM", 0xBBB)` is set to "stolen"
7. Reverse mapping `RevCapabilityKey("moduleM", "stolen")` is set to index N
8. Module M calls `GetCapability(ctx, "stolen")` which returns `capMap[N]` - the canonical pointer
9. Module M now has full access to the capability and is listed as a legitimate owner [5](#0-4) 

**Security Guarantee Broken:** 
The fundamental invariant that "capabilities can only be obtained through legitimate channels" is violated. The object-capability authorization model that underpins IBC security is completely bypassed.

## Impact Explanation

This vulnerability has critical implications for IBC protocol security:

- **IBC Port/Channel Hijacking**: Malicious modules can claim ownership of IBC ports and channels they were never authorized to access, enabling them to send unauthorized packets, bind to sensitive ports, or impersonate legitimate modules.

- **Cross-chain Asset Theft**: Unauthorized IBC operations could enable direct theft of funds through unauthorized cross-chain transfers or manipulation of IBC-connected assets.

- **Complete Security Model Bypass**: The capability system is the foundation of access control in IBC. Its compromise affects all protocols and modules that depend on it for security. [6](#0-5) 

The severity is HIGH because it enables direct loss of funds through unauthorized IBC operations and completely undermines the security architecture of the system.

## Likelihood Explanation

**High Likelihood:**
- Any module running on the chain can exploit this vulnerability
- Capability indices are sequential (0, 1, 2, ...) and easily discoverable by iterating or observing state
- The attack requires no special privileges beyond having a ScopedKeeper, which all modules receive
- Third-party modules are common in Cosmos SDK chains (IBC apps, DeFi protocols, etc.)
- A single compromised or buggy third-party module can exploit this
- The attack can be executed during normal chain operation

The barrier to exploitation is simply having a module deployed on the chain, which is a realistic scenario given the prevalence of third-party modules in production Cosmos SDK chains.

## Recommendation

Add validation in `ClaimCapability` to ensure the capability pointer is the canonical one from `capMap`:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    if cap == nil {
        return sdkerrors.Wrap(types.ErrNilCapability, "cannot claim nil capability")
    }
    
    // Validate capability pointer is canonical
    canonicalCap := sk.capMap[cap.GetIndex()]
    if canonicalCap == nil {
        return sdkerrors.Wrap(types.ErrCapabilityNotFound, "capability does not exist")
    }
    if canonicalCap != cap {
        return sdkerrors.Wrap(types.ErrInvalidCapability, "capability pointer is not canonical")
    }
    
    if strings.TrimSpace(name) == "" {
        return sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
    }
    
    // ... rest of existing logic
}
```

This ensures only legitimate capability pointers (those stored in the canonical `capMap`) can be claimed, preventing forged capabilities from bypassing the security model.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Setup:** 
- Create two scoped keepers for different modules (sk1 for "bank", sk2 for "staking")
- sk1 creates a legitimate capability with some index N
- sk1 NEVER passes this capability to sk2

**Action:**
- sk2 creates a forged capability: `forged := types.NewCapability(N)`
- sk2 calls `ClaimCapability(ctx, forged, "stolen")`

**Result:**
- The claim succeeds (no error returned) - proving no validation exists
- sk2 is now listed as an owner in persistent storage - proving unauthorized ownership was granted
- sk2 can authenticate the forged capability - proving the forward mapping was created
- sk2 can call `GetCapability("stolen")` to retrieve the canonical pointer - proving full access [7](#0-6) 

The existing test at line 125-127 demonstrates that developers were aware of forged capability risks and tested that authentication fails for unclaimed forged capabilities. However, they did not test or prevent the claiming attack vector, which is the core vulnerability.

## Notes

The capability system's entire purpose is to provide isolation between modules through object-capability security. The fact that any module can bypass this isolation by forging capability structs represents a fundamental failure in the security design. While modules are typically added through governance, the security model should not assume all modules are perfectly trustworthy - defense in depth requires that even if a malicious or buggy module exists, it cannot compromise capabilities owned by other modules. This vulnerability enables exactly that compromise.

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

**File:** docs/architecture/adr-003-dynamic-capability-store.md (L10-20)
```markdown
Full implementation of the [IBC specification](https://github.com/cosmos/ibs) requires the ability to create and authenticate object-capability keys at runtime (i.e., during transaction execution),
as described in [ICS 5](https://github.com/cosmos/ibc/tree/master/spec/core/ics-005-port-allocation#technical-specification). In the IBC specification, capability keys are created for each newly initialised
port & channel, and are used to authenticate future usage of the port or channel. Since channels and potentially ports can be initialised during transaction execution, the state machine must be able to create
object-capability keys at this time.

At present, the Cosmos SDK does not have the ability to do this. Object-capability keys are currently pointers (memory addresses) of `StoreKey` structs created at application initialisation in `app.go` ([example](https://github.com/cosmos/gaia/blob/dcbddd9f04b3086c0ad07ee65de16e7adedc7da4/app/app.go#L132))
and passed to Keepers as fixed arguments ([example](https://github.com/cosmos/gaia/blob/dcbddd9f04b3086c0ad07ee65de16e7adedc7da4/app/app.go#L160)). Keepers cannot create or store capability keys during transaction execution — although they could call `NewKVStoreKey` and take the memory address
of the returned struct, storing this in the Merklised store would result in a consensus fault, since the memory address will be different on each machine (this is intentional — were this not the case, the keys would be predictable and couldn't serve as object capabilities).

Keepers need a way to keep a private map of store keys which can be altered during transaction execution, along with a suitable mechanism for regenerating the unique memory addresses (capability keys) in this map whenever the application is started or restarted, along with a mechanism to revert capability creation on tx failure.
This ADR proposes such an interface & mechanism.
```

**File:** x/capability/types/types.go (L14-16)
```go
func NewCapability(index uint64) *Capability {
	return &Capability{Index: index}
}
```

**File:** docs/ibc/custom.md (L75-93)
```markdown
    counterpartyVersion string,
) error {
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

    // ... do custom initialization logic

    // Use above arguments to determine if we want to abort handshake
    err := checkArguments(args)
    return err
}
```

**File:** x/capability/keeper/keeper_test.go (L125-127)
```go
	forgedCap := types.NewCapability(cap1.Index) // index should be the same index as the first capability
	suite.Require().False(sk1.AuthenticateCapability(suite.ctx, forgedCap, "transfer"))
	suite.Require().False(sk2.AuthenticateCapability(suite.ctx, forgedCap, "transfer"))
```
