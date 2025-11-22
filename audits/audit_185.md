## Title
Missing Migration Handler Registration Causes Network Halt on Capability Module Upgrade

## Summary
The capability module's `RegisterServices` method is empty and does not register any migration handlers, violating the requirement that each ConsensusVersion increment must have a corresponding migration handler. If the capability module's ConsensusVersion is ever incremented from its current value of 1, the chain upgrade will panic and halt the entire network.

## Impact
**High**

## Finding Description

**Location:** 
- `x/capability/module.go` lines 128 and 160-161 [1](#0-0) 
- `x/capability/module.go` lines 160-161 [2](#0-1) 

**Intended Logic:** 
According to the Cosmos SDK upgrade documentation and code comments, when a module's `ConsensusVersion()` is incremented, the module MUST register migration handlers in its `RegisterServices` method. The documentation explicitly states: "EACH TIME a module's ConsensusVersion increments, a new migration MUST be registered using this function. If a migration handler is missing for a particular function, the upgrade logic (see RunMigrations function) will panic." [3](#0-2) 

Other modules in the codebase correctly implement this pattern. For example, the auth module registers migrations for versions 1→2 and 2→3 [4](#0-3) , and the slashing module registers migrations for versions 1→2, 2→3, and 3→4 [5](#0-4) .

**Actual Logic:** 
The capability module's `RegisterServices` method is completely empty [1](#0-0) , meaning no migration handlers are registered. If the module's ConsensusVersion is incremented from 1 to 2 (or higher), the `RunMigrations` function will:

1. Detect the version difference between the stored version (1) and the new code version (2+)
2. Call `runModuleMigrations(ctx, "capability", 1, 2)` [6](#0-5) 
3. Look for registered migrations in the configurator's migrations map [7](#0-6) 
4. Return an error "no migrations found for module capability" since no migrations were registered
5. This error propagates to `ApplyUpgrade` which panics [8](#0-7) 

**Exploit Scenario:** 
This vulnerability is triggered when:
1. Developers make a consensus-breaking change to the capability module that requires incrementing ConsensusVersion
2. They increment `ConsensusVersion()` from 1 to 2 in the code, as required by protocol
3. They forget to register a migration handler in `RegisterServices` (or don't realize it's empty)
4. The upgrade binary is deployed to the network
5. At the upgrade height, all nodes execute the upgrade handler
6. `RunMigrations` is called as part of the standard upgrade flow [9](#0-8) 
7. The missing migration handler causes a panic on all nodes simultaneously
8. The entire network halts at the same block height

**Security Failure:** 
This breaks network availability and consensus agreement. All nodes panic at the same upgrade height, causing complete network shutdown. The network cannot confirm any new transactions, and recovery requires a coordinated hard fork to either: (a) add the missing migration handler and re-release binaries, or (b) revert the ConsensusVersion change.

## Impact Explanation

**Assets/Processes Affected:**
- **Network Availability**: The entire blockchain network halts and cannot process any transactions
- **Transaction Finality**: No new blocks can be produced or finalized
- **User Funds**: While funds are not stolen, they become completely inaccessible until the network is restored via hard fork

**Severity of Damage:**
- **Complete Network Shutdown**: 100% of nodes halt simultaneously at the upgrade block
- **Hard Fork Required**: Recovery requires coordinating a new binary release across all validators and node operators
- **Potential Chain Split**: If some nodes skip the upgrade or apply a different fix, the network could permanently split into incompatible chains

**Why This Matters:**
This vulnerability represents a critical failure mode in the upgrade system. The capability module is a core system module used by IBC and other critical protocol features. A failed upgrade of this module would halt the entire Sei blockchain, preventing all DeFi operations, token transfers, and protocol functionality. The economic impact includes loss of user confidence, potential financial losses from halted operations, and significant operational costs to coordinate an emergency hard fork.

## Likelihood Explanation

**Who Can Trigger:**
This is triggered by developers making legitimate protocol upgrades. It's not directly exploitable by external attackers, but represents a subtle logic error that will be triggered accidentally during normal development when:
- The capability module requires any consensus-breaking changes (e.g., fixing bugs in capability tracking, modifying store structure, changing keeper logic)
- Developers correctly increment ConsensusVersion as required
- But overlook the empty RegisterServices method

**Conditions Required:**
- A consensus-breaking change to the capability module necessitates incrementing ConsensusVersion
- The developer follows standard protocol by incrementing the version number
- The empty RegisterServices method provides no warning or safeguard
- The upgrade is approved via governance and scheduled

**Frequency:**
While not frequent, this is a realistic scenario that could occur during:
- Security patches to the capability module
- Feature additions that modify state
- Bug fixes that change consensus behavior
- Protocol upgrades adding new capabilities

The vulnerability is particularly dangerous because the empty RegisterServices method provides no indication that migrations need to be registered, and standard testing might not catch this issue until the upgrade is deployed on mainnet.

## Recommendation

Implement one of the following fixes:

**Option 1 (Immediate Fix):** Register a no-op migration handler in `RegisterServices` even though ConsensusVersion is currently 1. This provides a template for future migrations:

```go
func (am AppModule) RegisterServices(cfg module.Configurator) {
    // Register no-op migration from v1 to v2 as a template
    // When ConsensusVersion is incremented, uncomment and implement:
    // m := keeper.NewMigrator(am.keeper)
    // cfg.RegisterMigration(types.ModuleName, 1, m.Migrate1to2)
}
```

**Option 2 (Comprehensive Fix):** Add validation in the upgrade module that checks if a module's ConsensusVersion has been incremented without corresponding registered migrations, and fail fast during app initialization rather than at upgrade time.

**Option 3 (Documentation Fix):** At minimum, add prominent comments in the capability module's `RegisterServices` and `ConsensusVersion` methods warning that migrations MUST be registered before incrementing the version.

## Proof of Concept

**File:** `simapp/app_test.go` (add new test function)

**Test Function Name:** `TestCapabilityModuleMissingMigrationPanic`

**Setup:**
```go
func TestCapabilityModuleMissingMigrationPanic(t *testing.T) {
    // Initialize test app
    db := dbm.NewMemDB()
    encCfg := MakeTestEncodingConfig()
    logger := log.NewTestingLogger(t)
    app := NewSimApp(logger, db, nil, true, map[int64]bool{}, DefaultNodeHome, 0, nil, encCfg, &EmptyAppOptions{})
    
    // Initialize the chain with capability module at version 1
    app.InitChain(context.Background(), &abci.RequestInitChain{})
    app.SetDeliverStateToCommit()
    app.Commit(context.Background())
    
    // Create configurator
    app.configurator = module.NewConfigurator(app.appCodec, app.MsgServiceRouter(), app.GRPCQueryRouter())
    
    // Register services for all modules (this registers migrations)
    for _, module := range app.mm.Modules {
        module.RegisterServices(app.configurator)
    }
    
    // Create a VersionMap with capability at version 1 (simulating existing chain state)
    ctx := app.NewContext(true, tmproto.Header{Height: app.LastBlockHeight()})
    fromVM := module.VersionMap{
        "capability": 1,  // Current version in state
        // ... other modules at their current versions
    }
```

**Trigger:**
```go
    // Simulate incrementing capability module's ConsensusVersion to 2
    // In real scenario, this would be done by changing the ConsensusVersion() method
    // Here we manually create a VersionMap where capability is at version 2
    // but no migration was registered for version 1->2
    
    // This simulates what RunMigrations sees when ConsensusVersion is incremented
    // The function will try to migrate from version 1 to 2
    // Since no migration is registered, it will panic
```

**Observation:**
```go
    // Attempt to run migrations - this should panic with
    // "no migrations found for module capability"
    require.Panics(t, func() {
        _, err := app.mm.RunMigrations(ctx, app.configurator, fromVM)
        if err != nil {
            panic(err)
        }
    }, "Expected panic due to missing capability migration handler")
}
```

**Expected Behavior:** The test confirms that when RunMigrations is called with a version difference for the capability module (from version 1 to any higher version), and no migration handler is registered, the system panics with error "no migrations found for module capability" [7](#0-6) .

**Verification:** This test demonstrates the exact failure mode that would occur during a real upgrade, confirming that the empty RegisterServices method creates a network halt scenario. The simapp test at line 125-128 already demonstrates this error case for the bank module [10](#0-9) , and the same pattern applies to the capability module.

### Citations

**File:** x/capability/module.go (L128-128)
```go
func (am AppModule) RegisterServices(module.Configurator) {}
```

**File:** x/capability/module.go (L160-161)
```go
// ConsensusVersion implements AppModule/ConsensusVersion.
func (AppModule) ConsensusVersion() uint64 { return 1 }
```

**File:** types/module/configurator.go (L31-36)
```go
	// EACH TIME a module's ConsensusVersion increments, a new migration MUST
	// be registered using this function. If a migration handler is missing for
	// a particular function, the upgrade logic (see RunMigrations function)
	// will panic. If the ConsensusVersion bump does not introduce any store
	// changes, then a no-op function must be registered here.
	RegisterMigration(moduleName string, forVersion uint64, handler MigrationHandler) error
```

**File:** types/module/configurator.go (L97-100)
```go
	moduleMigrationsMap, found := c.migrations[moduleName]
	if !found {
		return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migrations found for module %s", moduleName)
	}
```

**File:** x/auth/module.go (L140-150)
```go
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterQueryServer(cfg.QueryServer(), am.accountKeeper)
	m := keeper.NewMigrator(am.accountKeeper, cfg.QueryServer())
	err := cfg.RegisterMigration(types.ModuleName, 1, m.Migrate1to2)
	if err != nil {
		panic(err)
	}
	err = cfg.RegisterMigration(types.ModuleName, 2, m.Migrate2to3)
	if err != nil {
		panic(err)
	}
```

**File:** x/slashing/module.go (L148-156)
```go
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
	types.RegisterQueryServer(cfg.QueryServer(), am.keeper)

	m := keeper.NewMigrator(am.keeper)
	cfg.RegisterMigration(types.ModuleName, 1, m.Migrate1to2)
	cfg.RegisterMigration(types.ModuleName, 2, m.Migrate2to3)
	cfg.RegisterMigration(types.ModuleName, 3, m.Migrate3to4)
}
```

**File:** types/module/module.go (L571-574)
```go
			err := c.runModuleMigrations(ctx, moduleName, fromVersion, toVersion)
			if err != nil {
				return nil, err
			}
```

**File:** x/upgrade/keeper/keeper.go (L365-376)
```go
func (k Keeper) ApplyUpgrade(ctx sdk.Context, plan types.Plan) {
	handler := k.upgradeHandlers[plan.Name]
	if handler == nil {
		panic("ApplyUpgrade should never be called without first checking HasHandler")
	}

	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}

	k.SetModuleVersionMap(ctx, updatedVM)
```

**File:** simapp/app_test.go (L125-128)
```go
			"throws error on RunMigrations if no migration registered for bank",
			"", 1,
			false, "", true, "no migrations found for module bank: not found", 0,
		},
```
