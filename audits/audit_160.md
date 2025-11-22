## Audit Report

## Title
Capability Ownership Bypass Through Forged Capability Struct Cloning

## Summary
A malicious module can claim ownership of any capability by creating a forged capability struct with a target index, bypassing the object-capability security model. The `ClaimCapability` function does not validate that the capability pointer is the canonical one stored in `capMap`, allowing unauthorized modules to gain ownership of capabilities they never legitimately received. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The capability system implements an object-capability security model where capabilities can only be obtained through legitimate channels: (1) creating them via `NewCapability`, (2) receiving them from another module that passes the capability pointer, or (3) retrieving previously claimed capabilities via `GetCapability`. Capability identity relies on pointer addresses to ensure uniqueness and unforgeability. [4](#0-3) 

**Actual Logic:** 
The `ClaimCapability` function uses `cap.GetIndex()` to identify capabilities but never validates that the capability pointer passed is the canonical pointer stored in `capMap[cap.GetIndex()]`. The `Capability` struct has a public `Index` field that can be read and used to create forged capability structs. When `addOwner` is called, it uses only the index to update the persistent owner set, without verifying pointer authenticity. [5](#0-4) 

**Exploit Scenario:**
1. Module A creates a capability for a sensitive resource (e.g., IBC port) with index N
2. Module M (malicious) observes or guesses index N (indices are sequential and stored in persistent state)
3. Module M creates a forged capability: `forged := &types.Capability{Index: N}`
4. Module M calls `ClaimCapability(ctx, forged, "stolen")`
5. `ClaimCapability` adds Module M as an owner in persistent storage using the index
6. `ClaimCapability` creates forward/reverse mappings for the forged pointer in memstore
7. Module M can now authenticate the forged capability and is listed as an official owner
8. Module M has gained unauthorized ownership without ever receiving the capability legitimately

**Security Failure:** 
The object-capability authorization model is broken. A malicious module can claim ownership of any capability by forging capability structs, violating the fundamental security invariant that capabilities should only be obtainable through legitimate channels.

## Impact Explanation

This vulnerability affects critical IBC protocol security:

- **IBC Port Security:** Malicious modules can claim ownership of IBC ports they were never authorized to access, allowing them to send unauthorized packets, bind to sensitive ports, or impersonate legitimate modules.
- **IBC Channel Security:** Unauthorized modules can claim channel capabilities and perform channel operations they shouldn't have access to.
- **Cross-chain Asset Security:** This could enable unauthorized cross-chain transfers or manipulation of IBC-connected assets, potentially leading to direct loss of funds. [6](#0-5) 

The severity is HIGH because it completely bypasses the capability-based access control system that underpins IBC security, potentially enabling direct loss of funds through unauthorized IBC operations.

## Likelihood Explanation

**High Likelihood:**
- Any module running on the chain can exploit this vulnerability
- Capability indices are sequential and observable in state
- The attack requires no special privileges beyond being a deployed module
- Modules can iterate through indices or observe other modules' capabilities to discover valid targets
- The attack can be executed during normal chain operation without unusual conditions

The vulnerability is trivially exploitable once a malicious module is deployed. Given that many chains allow permissionless smart contract deployment or have multiple third-party modules, the barrier to exploitation is low.

## Recommendation

Add validation in `ClaimCapability` and `addOwner` to ensure the capability pointer is the canonical one from `capMap`:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    if cap == nil {
        return sdkerrors.Wrap(types.ErrNilCapability, "cannot claim nil capability")
    }
    
    // Validate capability is canonical
    canonicalCap := sk.capMap[cap.GetIndex()]
    if canonicalCap == nil || canonicalCap != cap {
        return sdkerrors.Wrap(types.ErrInvalidCapability, "capability pointer is not canonical")
    }
    
    // ... rest of existing logic
}
```

This ensures only legitimate capability pointers (those stored in the canonical `capMap`) can be claimed, preventing forged capabilities from bypassing the security model.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add the following test to the `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestForgedCapabilityBypass() {
    sk1 := suite.keeper.ScopeToModule(banktypes.ModuleName)
    sk2 := suite.keeper.ScopeToModule(stakingtypes.ModuleName)

    // Setup: sk1 creates a capability and NEVER passes it to sk2
    cap, err := sk1.NewCapability(suite.ctx, "port/transfer")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap)
    
    capturedIndex := cap.GetIndex()

    // Trigger: sk2 forges a capability with the same index
    forgedCap := types.NewCapability(capturedIndex)
    
    // sk2 should NOT be able to claim this capability since it never received it
    err = sk2.ClaimCapability(suite.ctx, forgedCap, "stolen-port")
    
    // Observation: Currently this succeeds (vulnerability)
    // After fix, this should fail with an error
    suite.Require().NoError(err) // This passes, proving the vulnerability
    
    // Verify sk2 is now an unauthorized owner
    owners, ok := suite.keeper.GetOwners(suite.ctx, capturedIndex)
    suite.Require().True(ok)
    
    // sk2 should NOT be in the owner list, but it is (vulnerability confirmed)
    foundSk2 := false
    for _, owner := range owners.Owners {
        if owner.Module == stakingtypes.ModuleName {
            foundSk2 = true
            break
        }
    }
    suite.Require().True(foundSk2) // This passes, confirming sk2 gained unauthorized ownership
    
    // sk2 can now authenticate its forged capability
    suite.Require().True(sk2.AuthenticateCapability(suite.ctx, forgedCap, "stolen-port"))
}
```

**Observation:** This test demonstrates that a module can claim ownership of a capability it never received by forging a capability struct with a known index. The test will pass on the current vulnerable code, proving that `ClaimCapability` accepts forged capabilities and grants unauthorized ownership.

### Citations

**File:** x/capability/types/types.go (L14-16)
```go
func NewCapability(index uint64) *Capability {
	return &Capability{Index: index}
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

**File:** x/capability/types/capability.pb.go (L28-30)
```go
type Capability struct {
	Index uint64 `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty" yaml:"index"`
}
```

**File:** docs/ibc/custom.md (L40-63)
```markdown
```go
// Called by IBC Handler on MsgOpenInit
func (k Keeper) OnChanOpenInit(ctx sdk.Context,
    order channeltypes.Order,
    connectionHops []string,
    portID string,
    channelID string,
    channelCap *capabilitytypes.Capability,
    counterparty channeltypes.Counterparty,
    version string,
) error {
    // OpenInit must claim the channelCapability that IBC passes into the callback
    if err := k.ClaimCapability(ctx, chanCap, host.ChannelCapabilityPath(portID, channelID)); err != nil {
			return err
	}

    // ... do custom initialization logic

    // Use above arguments to determine if we want to abort handshake
    // Examples: Abort if order == UNORDERED,
    // Abort if version is unsupported
    err := checkArguments(args)
    return err
}
```
