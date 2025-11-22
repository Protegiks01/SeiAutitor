## Audit Report

## Title
Chain Halt During Upgrade Due to Missing Capability Module in Version Map

## Summary
When upgrading a chain to the version map system for the first time, if the upgrade handler fails to include the capability module in the manually constructed `fromVM` (version map), the upgrade will cause the capability module's `InitGenesis` to be called on an already-initialized module. This triggers a panic in `InitializeIndex` that halts the entire network.

## Impact
High

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Trigger mechanism: [2](#0-1) 
- Genesis initialization: [3](#0-2) 

**Intended Logic:** 
When a chain upgrades to the version map system (v0.43+) for the first time, the upgrade handler should manually include all existing modules in the `fromVM` parameter with version 1 to indicate they are already initialized and should not run `InitGenesis` again. [4](#0-3) 

**Actual Logic:** 
If a module is not present in the `fromVM` during `RunMigrations`, it is treated as a new module and `InitGenesis` is called with default genesis state. [5](#0-4)  The capability module's `InitGenesis` calls `InitializeIndex`, which explicitly panics if the index is already set. [6](#0-5) 

**Exploit Scenario:**
1. A chain running pre-v0.43 has the capability module operational with capabilities registered (index > 0 in persistent storage)
2. Governance approves an upgrade to v0.44+ to adopt the version map system
3. The developer writing the upgrade handler creates a manual `fromVM` map but accidentally omits the capability module: [7](#0-6) 
4. During upgrade execution, `RunMigrations` sees capability is not in `fromVM` and treats it as a new module
5. `RunMigrations` calls `module.InitGenesis(ctx, cdc, module.DefaultGenesis(cdc))` with `Index: 1` for capability module [8](#0-7) 
6. `InitGenesis` calls `k.InitializeIndex(ctx, 1)` [9](#0-8) 
7. `InitializeIndex` detects that `latest > 0` (capability module was already running) and panics with "SetIndex requires index to not be set" [10](#0-9) 
8. The panic causes the upgrade to fail and the network to halt completely

**Security Failure:** 
Network availability is compromised. The panic during the upgrade prevents any further block production, causing a complete network shutdown that requires a hard fork to recover.

## Impact Explanation

- **Affected processes:** All network operations - block production, transaction confirmation, consensus participation
- **Severity of damage:** Complete network shutdown. No new blocks can be produced, no transactions can be confirmed, and the chain remains halted until a corrected upgrade handler is deployed via hard fork
- **System reliability impact:** This represents a critical failure mode where a programming error in privileged code (upgrade handler) causes cascading failure that affects all network participants. The capability module is fundamental infrastructure used by IBC and other core protocols, making this a systemic risk during upgrades

## Likelihood Explanation

**Who can trigger:** Only governance can schedule upgrades and only developers can write upgrade handlers. However, this is classified as an accidental programming error rather than malicious behavior.

**Required conditions:** 
- Chain must be performing first upgrade to version map system (v0.43+)
- Developer must manually construct `fromVM` map
- Developer must omit capability module from the map (easy mistake given 15+ modules to track)

**Frequency:** This would occur once per chain during the critical first version map upgrade. The official upgrade guide explicitly warns about this pattern [11](#0-10)  but requires manual developer action, making human error likely. Multiple modules are at risk if omitted, not just capability.

## Recommendation

Modify `InitializeIndex` to gracefully handle re-initialization attempts instead of panicking:

```go
func (k Keeper) InitializeIndex(ctx sdk.Context, index uint64) error {
    if index == 0 {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "capability index must be greater than 0")
    }
    latest := k.GetLatestIndex(ctx)
    if latest > 0 {
        // Already initialized - skip re-initialization instead of panicking
        return nil
    }
    
    store := ctx.KVStore(k.storeKey)
    store.Set(types.KeyIndex, types.IndexToKey(index))
    return nil
}
```

Alternatively, add validation in `RunMigrations` to verify all currently active modules are present in `fromVM` before proceeding, with a descriptive error message if modules are missing.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add new test `TestUpgradeVersionMismatchPanic`

**Setup:**
1. Initialize a test chain with capability module active
2. Create and register some capabilities through a scoped keeper (simulating IBC or other module usage)
3. Verify that `GetLatestIndex(ctx) > 0` to confirm module has state

**Trigger:**
1. Create an upgrade handler that constructs a manual `fromVM` map excluding the capability module
2. Simulate calling `app.mm.RunMigrations(ctx, cfg, fromVM)` where `fromVM` does not contain "capability"
3. This triggers the `RunMigrations` logic path that treats capability as a new module

**Observation:**
The test should panic with message "SetIndex requires index to not be set" when `InitGenesis` attempts to call `InitializeIndex` on an already-initialized capability module. This confirms that omitting an existing module from the version map during upgrade causes a catastrophic panic that would halt the network.

```go
func (suite *KeeperTestSuite) TestUpgradeVersionMismatchPanic() {
    // Setup: Initialize capability module with some state
    sk := suite.keeper.ScopeToModule("ibc")
    _, err := sk.NewCapability(suite.ctx, "port/transfer")
    suite.Require().NoError(err)
    
    // Verify module has state
    index := suite.keeper.GetLatestIndex(suite.ctx)
    suite.Require().Greater(index, uint64(0))
    
    // Trigger: Simulate upgrade that omits capability from version map
    // This would happen in RunMigrations when capability is not in fromVM
    genState := types.DefaultGenesis() // Index: 1
    
    // This should panic with "SetIndex requires index to not be set"
    suite.Require().Panics(func() {
        InitGenesis(suite.ctx, *suite.keeper, *genState)
    })
}
```

This test demonstrates that re-initializing an already-active capability module causes a panic, confirming the vulnerability in upgrade scenarios where the module is accidentally omitted from the version map.

### Citations

**File:** x/capability/keeper/keeper.go (L146-153)
```go
func (k Keeper) InitializeIndex(ctx sdk.Context, index uint64) error {
	if index == 0 {
		panic("SetIndex requires index > 0")
	}
	latest := k.GetLatestIndex(ctx)
	if latest > 0 {
		panic("SetIndex requires index to not be set")
	}
```

**File:** types/module/module.go (L570-589)
```go
		if exists {
			err := c.runModuleMigrations(ctx, moduleName, fromVersion, toVersion)
			if err != nil {
				return nil, err
			}
		} else {
			cfgtor, ok := cfg.(configurator)
			if !ok {
				// Currently, the only implementator of Configurator (the interface)
				// is configurator (the struct).
				return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
			}

			moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))
			ctx.Logger().Info(fmt.Sprintf("adding a new module: %s", moduleName))
			// The module manager assumes only one module will update the
			// validator set, and that it will not be by a new module.
			if len(moduleValUpdates) > 0 {
				return nil, sdkerrors.Wrapf(sdkerrors.ErrLogic, "validator InitGenesis updates already set by a previous module")
			}
```

**File:** x/capability/genesis.go (L11-14)
```go
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	if err := k.InitializeIndex(ctx, genState.Index); err != nil {
		panic(err)
	}
```

**File:** docs/migrations/chain-upgrade-guide-044.md (L161-181)
```markdown
	app.UpgradeKeeper.SetUpgradeHandler("v0.44", func(ctx sdk.Context, plan upgradetypes.Plan, _ module.VersionMap) (module.VersionMap, error) {
		// 1st-time running in-store migrations, using 1 as fromVersion to
		// avoid running InitGenesis.
		fromVM := map[string]uint64{
			"auth":         1,
			"bank":         1,
			"capability":   1,
			"crisis":       1,
			"distribution": 1,
			"evidence":     1,
			"gov":          1,
			"mint":         1,
			"params":       1,
			"slashing":     1,
			"staking":      1,
			"upgrade":      1,
			"vesting":      1,
			"ibc":          1,
			"genutil":      1,
			"transfer":     1,
		}
```

**File:** x/capability/types/genesis.go (L12-16)
```go
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Index:  DefaultIndex,
		Owners: []GenesisOwners{},
	}
```
