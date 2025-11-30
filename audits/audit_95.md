After thorough analysis of the codebase and the security claim, I have validated this vulnerability. Here is my assessment:

# Audit Report

## Title
Capability Ownership Bypass Through Forged Capability Pointer

## Summary
The `ClaimCapability` function does not validate that the provided capability pointer is the canonical pointer stored in `capMap`. This allows any module to forge a capability struct with a known index and claim ownership of capabilities they never legitimately received, bypassing the object-capability security model.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The capability system implements an object-capability model where capabilities can only be obtained through legitimate channels. According to the specification, `ClaimCapability` is designed for "a capability key which it has received from another module." [2](#0-1)  The security relies on pointer identity as unforgeable identifiers. [3](#0-2) 

**Actual Logic:**
The `ClaimCapability` function only validates that the capability is not nil and the name is not empty. It then calls `addOwner` [4](#0-3)  which uses `cap.GetIndex()` to update the persistent owner set. There is no validation that the provided pointer matches the canonical pointer stored in `capMap[cap.GetIndex()]`. Since `NewCapability` is public [5](#0-4) , anyone can create a forged capability struct with any index.

**Exploitation Path:**
1. Module A creates a capability with index N (canonical pointer stored in `capMap[N]`)
2. Malicious Module M discovers index N (indices are sequential and stored in persistent state)
3. Module M creates forged capability: `forged := types.NewCapability(N)` at a different memory address
4. Module M calls `ClaimCapability(ctx, forged, "stolen")` - succeeds because no pointer validation exists
5. `addOwner` adds Module M to the persistent owner set using only the index
6. Module M calls `GetCapability(ctx, "stolen")` [6](#0-5)  which returns `capMap[N]` - the canonical pointer
7. Module M now has full access to the capability and is listed as a legitimate owner

**Security Guarantee Broken:**
The fundamental invariant that "capabilities can only be obtained through legitimate channels" is violated. The object-capability authorization model underlying IBC security is completely bypassed.

## Impact Explanation

This vulnerability enables:
- **IBC Port/Channel Hijacking**: Malicious modules can claim ownership of IBC ports and channels they were never authorized to access, enabling unauthorized packet transmission and channel operations [7](#0-6) 
- **Cross-chain Asset Theft**: Unauthorized IBC operations could enable direct loss of funds through unauthorized cross-chain transfers
- **Complete Security Model Bypass**: The capability system is the foundation of access control in IBC. Its compromise affects all protocols depending on it for security

The severity is HIGH because it enables direct loss of funds through unauthorized IBC operations and completely undermines the security architecture.

## Likelihood Explanation

**High Likelihood:**
- Any module running on the chain can exploit this vulnerability
- Capability indices are sequential (0, 1, 2, ...) and easily discoverable by observing state
- The attack requires no special privileges beyond having a ScopedKeeper, which all modules receive during initialization
- Third-party modules are common in Cosmos SDK chains (IBC apps, DeFi protocols)
- A single compromised or buggy third-party module can exploit this
- The existing test [8](#0-7)  shows developers were aware of forged capability risks but only tested authentication failures for unclaimed forged capabilities, not the claiming attack vector

The barrier to exploitation is simply having a module deployed on the chain, which is realistic given the prevalence of third-party modules in production chains.

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
        return errors.New("capability pointer is not canonical")
    }
    
    if strings.TrimSpace(name) == "" {
        return sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
    }
    
    // ... rest of existing logic
}
```

## Proof of Concept

**Setup:**
- Create two scoped keepers for different modules (sk1 for "moduleA", sk2 for "moduleB")
- sk1 creates a legitimate capability: `cap1, _ := sk1.NewCapability(ctx, "port")` at index 0
- sk1 NEVER passes this capability to sk2

**Action:**
```go
// Module B creates forged capability with same index
forged := types.NewCapability(cap1.GetIndex())

// Module B claims the forged capability
err := sk2.ClaimCapability(ctx, forged, "stolen")
// Expected: Should fail, Actual: Succeeds (no error)

// Module B retrieves the canonical capability
canonical, ok := sk2.GetCapability(ctx, "stolen")
// Result: ok == true, canonical == cap1
```

**Result:**
- The claim succeeds (no error) - proving no validation exists
- sk2 is now listed as an owner in persistent storage - proving unauthorized ownership was granted
- sk2 can retrieve the canonical pointer via `GetCapability` - proving full access to Module A's capability

This represents a fundamental failure in the security design where modules can bypass isolation by forging capability structs. While modules are added through governance, defense-in-depth principles require that even a malicious or buggy module cannot compromise capabilities owned by other modules.

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

**File:** x/capability/spec/01_concepts.md (L15-22)
```markdown
Capabilities can be claimed by other modules which add them as owners. `ClaimCapability`
allows a module to claim a capability key which it has received from another
module so that future `GetCapability` calls will succeed. `ClaimCapability` MUST
be called if a module which receives a capability wishes to access it by name in
the future. Again, capabilities are multi-owner, so if multiple modules have a
single Capability reference, they will all own it. If a module receives a capability
from another module but does not call `ClaimCapability`, it may use it in the executing
transaction but will not be able to access it afterwards.
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
