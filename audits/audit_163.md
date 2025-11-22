# Audit Report

## Title
Capability Migration Panic During IBC Upgrades Due to Uninitialized capMap

## Summary
The `ClaimCapability` function in the capability keeper does not populate the in-memory capability map (`capMap`) when claiming capabilities. During chain upgrades, if an upgrade handler attempts to claim and immediately retrieve a capability before the capability module's `BeginBlocker` initializes the memory store, the system will panic, causing complete network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: `x/capability/keeper/keeper.go` lines 287-314 (`ClaimCapability` function)
- Related code: `x/capability/keeper/keeper.go` lines 361-388 (`GetCapability` function)
- BeginBlock ordering: `simapp/app.go` line 366 [1](#0-0) 

**Intended Logic:** 
During capability migration in IBC upgrades, modules should be able to reclaim existing capabilities that were persisted in the capability store before the upgrade. The capability module's `InitMemStore` is supposed to load all capabilities from persistent storage into the in-memory `capMap` before any module attempts to use them.

**Actual Logic:**
The `ClaimCapability` function updates the persistent store and sets forward/reverse mappings in the memory store, but critically does NOT add the capability object to the shared `capMap` (line 287-314 shows no `capMap` assignment). [1](#0-0) 

When `GetCapability` is subsequently called, it retrieves the capability index from memStore but then attempts to fetch the actual capability object from `capMap`. If the capability is not in `capMap`, the code panics with "capability found in memstore is missing from map". [2](#0-1) 

The BeginBlock execution order shows upgrade module runs before capability module: [3](#0-2) 

This means upgrade handlers execute before `InitMemStore` populates `capMap`. [4](#0-3) 

**Exploit Scenario:**
1. A chain schedules an upgrade that includes IBC capability migration logic
2. At the upgrade height, nodes restart with the new binary
3. The upgrade BeginBlocker executes first, running the upgrade handler
4. The upgrade handler attempts to claim an existing IBC port/channel capability (common during IBC migrations)
5. `ClaimCapability` succeeds and sets memStore mappings, but doesn't populate `capMap`
6. The handler immediately tries to retrieve or validate the capability using `GetCapability`
7. `GetCapability` finds the memStore entry but `capMap[index]` returns `nil`
8. The code panics at line 384, halting all nodes on the network

**Security Failure:**
This is a denial-of-service vulnerability that breaks network availability. The panic during upgrade execution causes all validator nodes to halt simultaneously, resulting in total network shutdown. The network cannot process blocks or finalize transactions until the upgrade logic is fixed and redeployed.

## Impact Explanation

**Affected Components:**
- Network availability: Complete halt of block production
- IBC functionality: Cannot complete IBC upgrades requiring capability migration
- Chain governance: Upgrade mechanism becomes unreliable

**Severity:**
All validator nodes will panic simultaneously during the upgrade, causing:
- Complete network shutdown (0% uptime)
- No new blocks confirmed
- All transactions frozen
- Requires emergency rollback or hotfix deployment
- Potential loss of validator rewards during downtime
- Reputational damage to the chain

This directly matches the in-scope "High: Network not being able to confirm new transactions (total network shutdown)" impact criterion.

## Likelihood Explanation

**Who Can Trigger:**
This vulnerability is triggered automatically during chain upgrades if the upgrade handler contains IBC capability migration logic. No attacker action is required - it's triggered by the upgrade itself.

**Conditions Required:**
- A scheduled chain upgrade with an upgrade handler
- The handler attempts to claim and retrieve a capability before `InitMemStore` runs
- Common scenario: IBC module upgrades that need to reclaim port/channel capabilities

**Frequency:**
- Occurs during every upgrade that involves IBC capability migration
- Guaranteed to trigger if the upgrade handler pattern described above is used
- High likelihood given that IBC upgrades are common in Cosmos chains

## Recommendation

**Immediate Fix:**
Modify `ClaimCapability` to add the capability to `capMap` after setting memStore mappings:

```go
func (sk ScopedKeeper) ClaimCapability(ctx sdk.Context, cap *types.Capability, name string) error {
    // ... existing validation and persistent store updates ...
    
    memStore.Set(types.RevCapabilityKey(sk.module, name), sdk.Uint64ToBigEndian(cap.GetIndex()))
    
    // ADD THIS LINE: Ensure capability is in capMap
    sk.capMap[cap.GetIndex()] = cap
    
    logger(ctx).Info("claimed capability", "module", sk.module, "name", name, "capability", cap.GetIndex())
    return nil
}
```

**Additional Safeguards:**
1. Add documentation warning that upgrade handlers should not interact with capabilities before `InitMemStore` runs
2. Consider enforcing that capability BeginBlocker runs before upgrade BeginBlocker
3. Add a check in `GetCapability` to provide a clearer error message instead of panic

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add `TestClaimCapabilityBeforeInitMemStore`

**Setup:**
1. Create a new keeper with fresh stores
2. Manually set up a capability in the persistent store (simulating pre-upgrade state)
3. Create a capability object with the same index
4. Do NOT call `InitMemStore` (simulating upgrade handler running before capability BeginBlocker)

**Trigger:**
1. Call `ClaimCapability` with the manually created capability object
2. Immediately call `GetCapability` to retrieve it

**Observation:**
The test will panic at line 384 of `keeper.go` with message "capability found in memstore is missing from map", demonstrating that the capability was set in memStore by `ClaimCapability` but not added to `capMap`, causing `GetCapability` to fail.

**Test Code:**
```go
func (suite *KeeperTestSuite) TestClaimCapabilityBeforeInitMemStore() {
    // Setup: Create a fresh keeper to simulate post-upgrade state
    app := simapp.Setup(false)
    cdc := app.AppCodec()
    keeper := keeper.NewKeeper(cdc, app.GetKey(types.StoreKey), app.GetMemKey(types.MemStoreKey))
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Simulate existing capability in persistent store (from before upgrade)
    index := uint64(1)
    owner := types.NewOwner("ibc", "port")
    owners := types.NewCapabilityOwners()
    owners.Set(owner)
    keeper.SetOwners(ctx, index, *owners)
    
    // Create scoped keeper for IBC module
    sk := keeper.ScopeToModule("ibc")
    
    // Simulate upgrade handler claiming the capability before InitMemStore runs
    // This mimics the vulnerability scenario
    cap := types.NewCapability(index)
    err := sk.ClaimCapability(ctx, cap, "port")
    suite.Require().NoError(err, "ClaimCapability should succeed")
    
    // Now try to retrieve the capability - this should panic
    // because capMap was not populated by ClaimCapability
    suite.Require().Panics(func() {
        _, _ = sk.GetCapability(ctx, "port")
    }, "GetCapability should panic when capability not in capMap")
}
```

The test demonstrates that `ClaimCapability` successfully completes but leaves the system in an inconsistent state where the capability is in memStore but not in `capMap`, causing subsequent `GetCapability` calls to panic. This exact scenario occurs during chain upgrades when the upgrade handler runs before the capability module's `InitMemStore`.

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

**File:** x/capability/keeper/keeper.go (L382-385)
```go
	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
	}
```

**File:** simapp/app.go (L365-367)
```go
	app.mm.SetOrderBeginBlockers(
		upgradetypes.ModuleName, capabilitytypes.ModuleName, minttypes.ModuleName, distrtypes.ModuleName, slashingtypes.ModuleName,
		evidencetypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/capability/abci.go (L17-21)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.InitMemStore(ctx)
}
```
