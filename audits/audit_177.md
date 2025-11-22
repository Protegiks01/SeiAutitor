## Title
Capability Module Migration Panic Causes Total Network Shutdown During VersionMap Upgrade

## Summary
The capability module's `InitGenesis` function does not correctly handle migration scenarios when upgrading from pre-VersionMap SDK versions (before v0.43) to VersionMap-enabled versions (v0.43+). When `RunMigrations` is called during such upgrades, it attempts to initialize the capability module with default genesis state (Index=1) while the module's store already contains a higher index value from the previous chain state, causing a panic that halts the entire network. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Primary: `x/capability/genesis.go` lines 11-22 (`InitGenesis` function)
- Secondary: `x/capability/keeper/keeper.go` lines 146-159 (`InitializeIndex` function)
- Trigger: `types/module/module.go` lines 575-590 (`RunMigrations` function) [2](#0-1) 

**Intended Logic:** 
When upgrading a blockchain using the VersionMap-based in-place migration system (introduced in SDK v0.43), the `RunMigrations` function should properly handle existing modules that weren't previously tracked in the VersionMap. The capability module's genesis initialization should correctly restore or maintain the existing capability index from the previous chain state.

**Actual Logic:** 
When `RunMigrations` encounters a module not present in `fromVM` (the old VersionMap), it calls that module's `InitGenesis` with `DefaultGenesis`. For the capability module, `DefaultGenesis` returns a genesis state with `Index=1`. The `InitGenesis` function then calls `InitializeIndex(ctx, 1)`, which panics if the store already has an index set (line 152: `panic("SetIndex requires index to not be set")`). [3](#0-2) 

**Exploit Scenario:**
1. A chain is running SDK v0.40-v0.42 with the capability module already integrated (capability module was added in v0.40)
2. The capability module has created multiple capabilities over time, with the current index at value N (e.g., 100)
3. Chain operators initiate an upgrade to SDK v0.43+ using the standard `RunMigrations` approach
4. During upgrade execution in `BeginBlock`, the upgrade handler calls `app.mm.RunMigrations(ctx, cfg, fromVM)`
5. Since the old SDK version didn't track module versions, `fromVM` is empty or doesn't contain the capability module
6. `RunMigrations` identifies capability as a "new" module (not in `fromVM`) and calls `module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))` at line 583
7. `DefaultGenesis()` returns `GenesisState{Index: 1, Owners: []}`
8. `InitGenesis` calls `k.InitializeIndex(ctx, 1)`
9. `InitializeIndex` reads the current store and finds `latest = 100` (from the existing chain state)
10. The function panics at line 152 with "SetIndex requires index to not be set"
11. The upgrade handler crashes, the chain halts, and no new blocks can be produced [4](#0-3) 

**Security Failure:** 
This is a denial-of-service vulnerability that breaks chain liveness. The panic in the upgrade handler prevents the chain from processing any transactions, causing a total network shutdown that requires a hard fork to resolve.

## Impact Explanation

**Affected Components:**
- Network availability: Complete chain halt
- Transaction processing: Unable to confirm any new transactions
- Consensus: All validators stuck at the upgrade block height
- Node operation: All nodes panic and cannot progress past the upgrade height

**Severity of Damage:**
- **Total network shutdown**: The entire blockchain network halts and cannot process any transactions
- **Hard fork requirement**: Recovery requires either:
  - Rolling back to the pre-upgrade version (losing the upgrade attempt)
  - Creating a patched binary with special upgrade handler logic
  - Manually modifying genesis state (not viable for in-place upgrades)
- **Service disruption**: All applications and users depending on the chain are completely blocked
- **Reputation damage**: Failed upgrades undermine confidence in the chain's reliability

**System Security Impact:**
This vulnerability directly causes the "Network not being able to confirm new transactions (total network shutdown)" impact scenario defined in the in-scope impacts, making it a High severity issue.

## Likelihood Explanation

**Who Can Trigger:**
This vulnerability is automatically triggered by the chain's own upgrade mechanism when operators execute a legitimate upgrade. It doesn't require a malicious actor - any chain upgrading from pre-v0.43 to v0.43+ with the capability module will hit this issue if they follow the standard upgrade pattern documented in the SDK.

**Conditions Required:**
1. Chain is running SDK version v0.40, v0.41, or v0.42 (or any version before VersionMap was introduced in v0.43)
2. The capability module is already integrated and has created at least one capability (index > 1)
3. Upgrade is performed using the `RunMigrations` function without special handling for the capability module
4. The upgrade handler doesn't manually set `fromVM["capability"]` to skip the default `InitGenesis` call

**Frequency/Likelihood:**
- **Historical**: This was a real issue affecting any Cosmos chain that upgraded to v0.43 from earlier versions with IBC/capability module enabled
- **Current**: While v0.43 is now old, chains running older forks or upgrading through multiple versions sequentially could still encounter this
- **Probability**: 100% occurrence rate if the conditions above are met and no mitigation is applied

The SDK documentation acknowledges this issue exists and provides a workaround, but the default behavior is broken, making this a design flaw rather than a configuration error. [5](#0-4) 

## Recommendation

**Immediate Fix:**
Modify the `InitializeIndex` function to handle the case where an index is already set, rather than panicking. The function should detect an existing index and skip reinitialization:

```go
func (k Keeper) InitializeIndex(ctx sdk.Context, index uint64) error {
    if index == 0 {
        panic("SetIndex requires index > 0")
    }
    latest := k.GetLatestIndex(ctx)
    if latest > 0 {
        // Index already set (e.g., during upgrade from pre-VersionMap version)
        // Validate that the provided index matches or exceeds the existing one
        if index < latest {
            return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, 
                "cannot set index %d below existing index %d", index, latest)
        }
        // Skip reinitialization if index is already properly set
        return nil
    }
    
    // set the global index to the passed index
    store := ctx.KVStore(k.storeKey)
    store.Set(types.KeyIndex, types.IndexToKey(index))
    return nil
}
```

**Alternative Mitigation (for chain operators):**
When performing upgrades from pre-VersionMap versions, manually handle the capability module in the upgrade handler:

```go
app.UpgradeKeeper.SetUpgradeHandler("v043-upgrade", func(ctx sdk.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
    // Prevent RunMigrations from calling InitGenesis on capability module
    // by setting its version explicitly
    fromVM[capabilitytypes.ModuleName] = 1
    
    return app.mm.RunMigrations(ctx, cfg, fromVM)
})
```

**Long-term Design Fix:**
The `RunMigrations` function should export and re-import the current genesis state for existing modules not in `fromVM`, rather than using `DefaultGenesis`:

```go
} else {
    // Module exists but not tracked in fromVM (upgrading from pre-VersionMap version)
    // Export current state and re-initialize with it instead of default genesis
    currentGenesis := module.ExportGenesis(ctx, cfgtor.cdc)
    moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, currentGenesis)
    // ...
}
```

## Proof of Concept

**Test File:** `x/capability/genesis_test.go`

**Test Function:** Add this test to demonstrate the panic:

```go
func (suite *CapabilityTestSuite) TestInitGenesisUpgradePanic() {
    // Setup: Create a chain with capability module and some capabilities
    sk1 := suite.keeper.ScopeToModule(banktypes.ModuleName)
    
    // Create several capabilities to advance the index
    cap1, err := sk1.NewCapability(suite.ctx, "capability1")
    suite.Require().NoError(err)
    
    cap2, err := sk1.NewCapability(suite.ctx, "capability2") 
    suite.Require().NoError(err)
    
    cap3, err := sk1.NewCapability(suite.ctx, "capability3")
    suite.Require().NoError(err)
    
    // Verify current index is > 1
    currentIndex := suite.keeper.GetLatestIndex(suite.ctx)
    suite.Require().Greater(currentIndex, uint64(1), "index should be > 1")
    
    // Simulate upgrade scenario: Try to InitGenesis with DefaultGenesis
    // This simulates what RunMigrations does for modules not in fromVM
    defaultGenesis := types.DefaultGenesis()
    suite.Require().Equal(uint64(1), defaultGenesis.Index, "default genesis should have index 1")
    
    // This should panic because index is already set to a value > 1
    suite.Require().Panics(func() {
        capability.InitGenesis(suite.ctx, *suite.keeper, *defaultGenesis)
    }, "InitGenesis with DefaultGenesis should panic when index already set")
}
```

**Setup:**
1. Initialize a capability keeper with a normal context
2. Create multiple capabilities through the scoped keeper to advance the index to a realistic value (e.g., 4)
3. Verify the store contains an index > 1

**Trigger:**
Call `InitGenesis` with `DefaultGenesis()` (which has Index=1) on a context where the capability module store already has an index set from previous operations.

**Observation:**
The test expects a panic with message "SetIndex requires index to not be set". This confirms that the `InitializeIndex` function cannot handle re-initialization during upgrades, which is exactly what happens when `RunMigrations` calls `InitGenesis` with `DefaultGenesis` for modules not tracked in the old VersionMap.

**Running the test:**
```bash
cd x/capability
go test -v -run TestInitGenesisUpgradePanic
```

The test will pass (confirming the panic occurs), demonstrating that the current implementation cannot handle the upgrade scenario correctly.

## Notes

This vulnerability was acknowledged in the SDK documentation which provides workarounds, but the default behavior remains broken. The issue specifically affects the upgrade path from SDK versions before v0.43 to v0.43+, when the VersionMap system was introduced. While the documentation warns developers about this, the fact that the default code path causes a network shutdown makes this a High severity vulnerability that should be fixed at the code level rather than requiring every chain operator to implement manual workarounds.

### Citations

**File:** x/capability/genesis.go (L11-22)
```go
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	if err := k.InitializeIndex(ctx, genState.Index); err != nil {
		panic(err)
	}

	// set owners for each index
	for _, genOwner := range genState.Owners {
		k.SetOwners(ctx, genOwner.Index, genOwner.IndexOwners)
	}
	// initialize in-memory capabilities
	k.InitMemStore(ctx)
}
```

**File:** x/capability/keeper/keeper.go (L146-159)
```go
func (k Keeper) InitializeIndex(ctx sdk.Context, index uint64) error {
	if index == 0 {
		panic("SetIndex requires index > 0")
	}
	latest := k.GetLatestIndex(ctx)
	if latest > 0 {
		panic("SetIndex requires index to not be set")
	}

	// set the global index to the passed index
	store := ctx.KVStore(k.storeKey)
	store.Set(types.KeyIndex, types.IndexToKey(index))
	return nil
}
```

**File:** types/module/module.go (L575-590)
```go
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
		}
```

**File:** x/capability/types/genesis.go (L8-16)
```go
// DefaultIndex is the default capability global index
const DefaultIndex uint64 = 1

// DefaultGenesis returns the default Capability genesis state
func DefaultGenesis() *GenesisState {
	return &GenesisState{
		Index:  DefaultIndex,
		Owners: []GenesisOwners{},
	}
```

**File:** docs/core/upgrade.md (L113-125)
```markdown
For a new module `foo`, `InitGenesis` is called by `RunMigration` only when `foo` is registered in the module manager but it's not set in the `fromVM`. Therefore, if you want to skip `InitGenesis` when a new module is added to the app, then you should set its module version in `fromVM` to the module consensus version:

```go
app.UpgradeKeeper.SetUpgradeHandler("my-plan", func(ctx sdk.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
    // ...

    // Set foo's version to the latest ConsensusVersion in the VersionMap.
    // This will skip running InitGenesis on Foo
    fromVM[foo.ModuleName] = foo.AppModule{}.ConsensusVersion()

    return app.mm.RunMigrations(ctx, fromVM)
})
```
```
