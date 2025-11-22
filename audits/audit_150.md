## Title
Capability Ownership Theft via Name Collision in RevCapabilityKey

## Summary
The `RevCapabilityKey` function in `x/capability/types/keys.go` generates lookup keys by concatenating module and capability names with a "/rev/" separator, but does not validate against special characters in the inputs. This allows crafted module or capability names containing "/rev/" to create key collisions, enabling one module to steal capabilities owned by another module.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

The vulnerability exists in the capability key generation and validation logic across:
- Key generation: [1](#0-0) 
- Module scoping: [2](#0-1) 
- Capability creation: [3](#0-2) 
- Capability claiming: [4](#0-3) 

**Intended Logic:** 
The `RevCapabilityKey` function is designed to create unique lookup keys mapping from (module, capability_name) pairs to capability indices in the memory store. Each module should have its own isolated namespace for capability names, preventing modules from accessing or manipulating each other's capabilities.

**Actual Logic:** 
The function creates keys using string concatenation: `module/rev/name`. However, neither module names nor capability names are validated to prevent "/" characters. This creates ambiguous keys when:
- Module "A" with capability "B/rev/C" generates key: "A/rev/B/rev/C"
- Module "A/rev/B" with capability "C" generates key: "A/rev/B/rev/C"

These identical keys cause the second module to retrieve and potentially claim ownership of the first module's capability.

The validation only checks for empty strings: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. During application initialization, module "ibc" is scoped and creates a capability named "transfer/rev/port-1"
2. Later, the app developer adds a new module with name "ibc/rev/transfer" (perhaps from a third-party package or auto-generated naming)
3. Module "ibc/rev/transfer" calls `GetCapability(ctx, "port-1")`, which successfully retrieves the capability created by module "ibc"
4. Module "ibc/rev/transfer" calls `ClaimCapability(ctx, cap, "port-1")` and becomes a co-owner
5. The malicious module now has authenticated access to capabilities intended only for the "ibc" module

**Security Failure:** 
This breaks the isolation and authentication properties of the capability system. Capabilities are the fundamental security primitive for inter-module authentication in Cosmos SDK, particularly for IBC port and channel ownership. A module stealing another module's capabilities can impersonate that module and perform unauthorized actions.

## Impact Explanation

**Affected Assets:**
- IBC port and channel capabilities used for cross-chain token transfers
- Module-specific capabilities controlling access to privileged operations
- Any capability-protected resources in the blockchain

**Severity:**
- **Direct loss of funds:** A malicious module could steal IBC transfer capabilities and redirect cross-chain token transfers to attacker-controlled addresses
- **Authorization bypass:** Modules could bypass intended access controls by stealing capabilities from privileged modules
- **Protocol integrity:** The capability authentication system, which is fundamental to Cosmos SDK security architecture, becomes unreliable

**Why This Matters:**
Capabilities in Cosmos SDK serve the same role as capabilities in object-capability security models—they are unforgeable tokens proving authorization. If capabilities can be stolen through name manipulation, the entire security model collapses. This is particularly critical for IBC, where capability ownership determines who can send tokens across chains.

## Likelihood Explanation

**Who Can Trigger:**
- Application developers integrating third-party modules with crafted names
- Modules creating capabilities with "/" in names (no validation prevents this)
- Attackers who can influence module naming through configuration or package names

**Conditions Required:**
1. A module creates a capability with "/" characters in the name
2. A module is registered with a name containing "/rev/" that creates a collision
3. OR vice versa: a module with "/" in its name exists, and another module creates a capability that collides

**Frequency:**
- Low immediate likelihood due to conventional naming practices (modules typically use simple names like "bank", "staking")
- However, hierarchical naming schemes (e.g., "ibc/transfer", "x/bank/keeper") are conceptually reasonable and could be adopted
- No warnings or validation prevent this, making it a latent vulnerability
- Risk increases as the ecosystem grows and more third-party modules are integrated

## Recommendation

Add validation to prevent "/" characters in both module names and capability names:

1. In `ScopeToModule`, add validation:
```go
if strings.Contains(moduleName, "/") {
    panic("module name cannot contain '/' character")
}
```

2. In `NewCapability` and `ClaimCapability`, add validation:
```go
if strings.Contains(name, "/") {
    return nil, sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot contain '/' character")
}
```

3. Add a genesis validation check to ensure no existing capabilities violate this constraint: [7](#0-6) 

Modify to check:
```go
if strings.Contains(owner.Module, "/") {
    return fmt.Errorf("owner's module cannot contain '/': %s", owner)
}
if strings.Contains(owner.Name, "/") {
    return fmt.Errorf("owner's name cannot contain '/': %s", owner)
}
```

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add the following test to demonstrate the collision:

```go
func (suite *KeeperTestSuite) TestCapabilityNameCollision() {
    // Create first module and capability with slash in name
    sk1 := suite.keeper.ScopeToModule("alice")
    cap1, err := sk1.NewCapability(suite.ctx, "bob/rev/charlie")
    suite.Require().NoError(err)
    suite.Require().NotNil(cap1)
    
    // Verify alice owns the capability
    got1, ok := sk1.GetCapability(suite.ctx, "bob/rev/charlie")
    suite.Require().True(ok)
    suite.Require().Equal(cap1, got1)
    
    // Create second module with name containing /rev/
    sk2 := suite.keeper.ScopeToModule("alice/rev/bob")
    
    // VULNERABILITY: sk2 can retrieve sk1's capability using a different name!
    got2, ok := sk2.GetCapability(suite.ctx, "charlie")
    suite.Require().True(ok)
    suite.Require().Equal(cap1, got2, "Module 'alice/rev/bob' retrieved capability owned by 'alice'")
    
    // VULNERABILITY: sk2 can claim ownership of sk1's capability!
    err = sk2.ClaimCapability(suite.ctx, got2, "charlie")
    suite.Require().NoError(err, "Module 'alice/rev/bob' successfully claimed 'alice' module's capability")
    
    // Verify both modules now own the same capability
    owners, ok := sk1.GetOwners(suite.ctx, "bob/rev/charlie")
    suite.Require().True(ok)
    suite.Require().Equal(2, len(owners.Owners), "Capability should have 2 owners after theft")
    
    // The collision key demonstrates the vulnerability
    key1 := types.RevCapabilityKey("alice", "bob/rev/charlie")
    key2 := types.RevCapabilityKey("alice/rev/bob", "charlie")
    suite.Require().Equal(key1, key2, "Keys collide: both resolve to 'alice/rev/bob/rev/charlie'")
}
```

**Setup:** 
The test uses the existing test suite infrastructure with a fresh keeper instance per test.

**Trigger:** 
1. Create module "alice" and have it create capability "bob/rev/charlie"
2. Create module "alice/rev/bob"
3. Module "alice/rev/bob" calls `GetCapability("charlie")`

**Observation:** 
The test demonstrates that:
- Module "alice/rev/bob" successfully retrieves a capability it never created
- The retrieved capability is the same object (same memory address and index) as module "alice"'s capability
- Module "alice/rev/bob" can claim ownership using `ClaimCapability`
- Both RevCapabilityKey calls produce identical byte arrays, proving the collision
- The capability ends up with two owners despite being created by only one module

This proves the vulnerability allows capability theft through name collision, violating the isolation guarantees of the capability system.

### Citations

**File:** x/capability/types/keys.go (L35-37)
```go
func RevCapabilityKey(module, name string) []byte {
	return []byte(fmt.Sprintf("%s/rev/%s", module, name))
}
```

**File:** x/capability/keeper/keeper.go (L69-90)
```go
func (k *Keeper) ScopeToModule(moduleName string) ScopedKeeper {
	if k.sealed {
		panic("cannot scope to module via a sealed capability keeper")
	}
	if strings.TrimSpace(moduleName) == "" {
		panic("cannot scope to an empty module name")
	}

	if _, ok := k.scopedModules[moduleName]; ok {
		panic(fmt.Sprintf("cannot create multiple scoped keepers for the same module name: %s", moduleName))
	}

	k.scopedModules[moduleName] = struct{}{}

	return ScopedKeeper{
		cdc:      k.cdc,
		storeKey: k.storeKey,
		memKey:   k.memKey,
		capMap:   k.capMap,
		module:   moduleName,
	}
}
```

**File:** x/capability/keeper/keeper.go (L225-265)
```go
func (sk ScopedKeeper) NewCapability(ctx sdk.Context, name string) (*types.Capability, error) {
	if strings.TrimSpace(name) == "" {
		return nil, sdkerrors.Wrap(types.ErrInvalidCapabilityName, "capability name cannot be empty")
	}
	store := ctx.KVStore(sk.storeKey)

	if _, ok := sk.GetCapability(ctx, name); ok {
		return nil, sdkerrors.Wrapf(types.ErrCapabilityTaken, fmt.Sprintf("module: %s, name: %s", sk.module, name))
	}

	// create new capability with the current global index
	index := types.IndexFromKey(store.Get(types.KeyIndex))
	cap := types.NewCapability(index)

	// update capability owner set
	if err := sk.addOwner(ctx, cap, name); err != nil {
		return nil, err
	}

	// increment global index
	store.Set(types.KeyIndex, types.IndexToKey(index+1))

	memStore := ctx.KVStore(sk.memKey)

	// Set the forward mapping between the module and capability tuple and the
	// capability name in the memKVStore
	memStore.Set(types.FwdCapabilityKey(sk.module, cap), []byte(name))

	// Set the reverse mapping between the module and capability name and the
	// index in the in-memory store. Since marshalling and unmarshalling into a store
	// will change memory address of capability, we simply store index as value here
	// and retrieve the in-memory pointer to the capability from our map
	memStore.Set(types.RevCapabilityKey(sk.module, name), sdk.Uint64ToBigEndian(index))

	// Set the mapping from index from index to in-memory capability in the go map
	sk.capMap[index] = cap

	logger(ctx).Info("created new capability", "module", sk.module, "name", name)

	return cap, nil
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

**File:** x/capability/types/genesis.go (L37-45)
```go
		for _, owner := range genOwner.IndexOwners.Owners {
			if strings.TrimSpace(owner.Module) == "" {
				return fmt.Errorf("owner's module cannot be blank: %s", owner)
			}

			if strings.TrimSpace(owner.Name) == "" {
				return fmt.Errorf("owner's name cannot be blank: %s", owner)
			}
		}
```
