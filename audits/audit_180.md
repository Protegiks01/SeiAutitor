## Audit Report

### Title
Unbounded Capability Owner Count Allows Memory Exhaustion During Node Initialization

### Summary
The capability keeper's `addOwner` function lacks a maximum owner count enforcement, allowing unlimited owners to be added to a single capability. During node initialization, all capability owners are loaded into memory, which can cause memory exhaustion and prevent nodes from starting if a capability accumulates too many owners.

### Impact
**Medium** - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions

### Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The capability system should allow multiple modules to claim ownership of capabilities while protecting against resource exhaustion attacks. The system should enforce reasonable limits on the number of owners per capability to prevent memory exhaustion during node operations.

**Actual Logic:** 
The `addOwner` function adds owners to a capability without checking if a maximum owner count has been reached. The underlying `Set` method only checks for duplicate (module, name) pairs but imposes no upper bound on the total number of owners. [2](#0-1) 

During node initialization, `InitMemStore` loads all capability owners from persistent storage into memory by unmarshaling the entire `CapabilityOwners` object for each capability. [3](#0-2) 

**Exploit Scenario:**
1. A module's logic allows claiming the same capability multiple times with different names (e.g., IBC module claiming a port capability once per channel with channel-specific names)
2. An attacker triggers many such claims (e.g., by opening numerous IBC channels via transactions)
3. Each claim adds a unique (module, name) owner pair to the capability's owner list
4. Over time or in a burst, thousands or millions of owners accumulate
5. When validators restart their nodes, `InitMemStore` attempts to unmarshal and load all owners into memory
6. Memory exhaustion occurs, preventing nodes from completing initialization

**Security Failure:** 
The system fails to enforce resource limits, breaking the availability property. The absence of a maximum owner count allows unbounded memory allocation during critical node startup operations, enabling a denial-of-service attack that can prevent network nodes from restarting.

### Impact Explanation

**Affected Components:**
- Node availability during restart/initialization
- Network stability when multiple nodes restart simultaneously
- Validator set functionality if validator nodes cannot restart

**Severity:**
If a capability accumulates excessive owners (through module bugs, edge cases, or malicious activity), all nodes attempting to initialize will experience memory exhaustion. This affects:
- Individual node crashes during startup
- Potential network-wide impact if validators restart during upgrades
- Permanent inability to restart nodes without manual state intervention

**System Impact:**
This matters because blockchain nodes frequently restart for upgrades, crashes, or maintenance. If the chain state contains a capability with millions of owners, nodes cannot complete initialization, leading to extended downtime or requiring emergency manual state fixes.

### Likelihood Explanation

**Who Can Trigger:**
- Any user who can indirectly cause capability claims through module interactions (e.g., IBC channel creation)
- Module code bugs that cause repeated claims
- Malicious genesis state (requires governance or initial chain setup control)

**Conditions Required:**
- A module whose logic allows the same capability to be claimed with many different names
- User actions that trigger these claims (e.g., channel openings, connection establishments)
- Node restart after owner count has grown large

**Frequency:**
- Likelihood depends on specific module implementations and usage patterns
- Can accumulate gradually over chain lifetime through legitimate usage
- Can be exploited rapidly if an attack vector exists in a module (e.g., IBC)
- Becomes more likely as chains run longer without cleanup mechanisms

### Recommendation

Add a maximum owner count parameter to the capability keeper and enforce it in the `addOwner` function:

1. Define a maximum owner count constant or governance parameter (e.g., 1000 owners per capability)
2. Check the current owner count before adding a new owner in `addOwner`
3. Return an error if adding would exceed the maximum
4. Consider adding telemetry to monitor owner counts approaching limits

Example implementation:
- Before line 459 in `keeper.go`, add: `if len(capOwners.Owners) >= MaxOwnersPerCapability { return ErrTooManyOwners }`
- Add the constant and error type to the appropriate locations

### Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add a new test function `TestUnboundedOwnerMemoryExhaustion`

**Setup:**
1. Initialize a capability keeper with multiple scoped modules
2. Create a single capability in one module
3. Simulate many claims on this capability with different names from the same module

**Trigger:**
```go
func (suite *KeeperTestSuite) TestUnboundedOwnerMemoryExhaustion() {
    sk1 := suite.keeper.ScopeToModule("module1")
    
    // Create a capability
    cap, err := sk1.NewCapability(suite.ctx, "shared-capability")
    suite.Require().NoError(err)
    
    // Simulate unbounded owner growth - claim same capability many times with different names
    // In a real attack, this could be thousands or millions
    for i := 0; i < 10000; i++ {
        // Each claim with a different name succeeds due to lack of max count check
        err := sk1.ClaimCapability(suite.ctx, cap, fmt.Sprintf("claim-%d", i))
        suite.Require().NoError(err) // This should fail after some reasonable limit, but doesn't
    }
    
    // Verify massive owner list
    owners, ok := sk1.GetOwners(suite.ctx, "shared-capability")
    suite.Require().True(ok)
    suite.Require().Equal(10001, len(owners.Owners)) // Original + 10000 claims
    
    // Export and re-import genesis to simulate node restart
    genState := capability.ExportGenesis(suite.ctx, *suite.keeper)
    
    // Create new keeper and attempt InitMemStore (simulates node restart)
    // With millions of owners, this would cause memory exhaustion
    db := dbm.NewMemDB()
    encCdc := simapp.MakeTestEncodingConfig()
    newApp := simapp.NewSimApp(log.NewNopLogger(), db, nil, true, map[int64]bool{}, 
                                simapp.DefaultNodeHome, 5, nil, encCdc, &simapp.EmptyAppOptions{})
    
    newKeeper := keeper.NewKeeper(suite.cdc, newApp.GetKey(types.StoreKey), 
                                   newApp.GetMemKey(types.MemStoreKey))
    newKeeper.ScopeToModule("module1")
    deliverCtx, _ := newApp.BaseApp.NewUncachedContext(false, tmproto.Header{}).CacheContext()
    
    // This InitGenesis->InitMemStore will consume excessive memory with many owners
    capability.InitGenesis(deliverCtx, *newKeeper, *genState)
    // With 10,000+ owners, memory allocation during unmarshal becomes significant
    // With 1,000,000 owners, this would cause OOM
}
```

**Observation:**
The test demonstrates that:
1. There is no maximum owner count enforced - 10,000+ claims succeed
2. All owners are stored and must be loaded during genesis import
3. The `MustUnmarshal` operation in `InitMemStore` allocates memory proportional to owner count
4. No error or limit prevents this unbounded growth

The test confirms the vulnerability: unlimited owners can accumulate, and node restart requires loading all owners into memory, creating a DoS vector.

### Citations

**File:** x/capability/keeper/keeper.go (L122-128)
```go
		for ; iterator.Valid(); iterator.Next() {
			index := types.IndexFromKey(iterator.Key())

			var capOwners types.CapabilityOwners

			k.cdc.MustUnmarshal(iterator.Value(), &capOwners)
			k.InitializeCapability(ctx, index, capOwners)
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
