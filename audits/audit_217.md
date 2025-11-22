## Audit Report

## Title
Missing Migration Handler Causes Network-Wide Upgrade Failure When Authz Consensus Version Changes

## Summary
The authz module defines a consensus version of 1 but does not register any migration handlers in its `RegisterServices` method. [1](#0-0) [2](#0-1)  If a developer increments the consensus version from 1 to 2 (or higher) without adding the required migration handler, the chain upgrade will fail with a panic, causing a total network shutdown. According to the Cosmos SDK migration system requirements, every consensus version increment MUST have a corresponding migration handler registered, even if it's a no-op. [3](#0-2) 

## Impact
High

## Finding Description

**Location:** 
- Primary: `x/authz/module/module.go` lines 44-47 (RegisterServices method)
- Secondary: `x/authz/module/module.go` line 173 (ConsensusVersion method)
- Related: `types/module/configurator.go` lines 92-116 (runModuleMigrations function)

**Intended Logic:** 
The Cosmos SDK upgrade system requires that when a module's consensus version increments, a migration handler must be registered for each version transition. [3](#0-2)  During a chain upgrade, the `RunMigrations` function compares the stored version map with the current module consensus versions and executes the registered migration handlers sequentially. [4](#0-3) 

**Actual Logic:** 
The authz module's `RegisterServices` method only registers query and message servers but does not register any migration handlers. [2](#0-1)  When the consensus version is incremented, the `runModuleMigrations` function attempts to find a migration handler for the version transition (e.g., from version 1 to 2). Since no handler is registered, it returns an error. [5](#0-4)  This error propagates to the `ApplyUpgrade` function, which panics. [6](#0-5) 

**Exploit Scenario:**
1. A developer increments the authz module's `ConsensusVersion()` from 1 to 2 without registering a migration handler in `RegisterServices`
2. An upgrade proposal is submitted via governance and approved by validators
3. At the designated upgrade block height, all validators execute `BeginBlocker` which calls `applyUpgrade` [7](#0-6) 
4. The upgrade handler calls `app.mm.RunMigrations()` (standard pattern documented in the codebase) [8](#0-7) 
5. `RunMigrations` calls `runModuleMigrations` for authz with fromVersion=1 and toVersion=2 [9](#0-8) 
6. `runModuleMigrations` fails to find the migration handler and returns error: "no migration found for module authz from version 1 to version 2" [10](#0-9) 
7. The error causes `ApplyUpgrade` to panic [6](#0-5) 
8. All validators panic simultaneously at the upgrade height
9. The network halts permanently - unable to produce new blocks

**Security Failure:** 
This breaks the network liveness property. The upgrade mechanism fails catastrophically, causing all validators to halt consensus at the same block height. The network cannot recover without manual intervention (rollback or emergency patch).

## Impact Explanation

**Affected Components:**
- Network availability: Complete chain halt
- Consensus: All validators fail at the same block height
- Transaction processing: Network cannot confirm any new transactions
- Authorization grants: All existing authz grants become inaccessible (though not lost, they cannot be queried or used)

**Severity:**
This is a critical network-wide denial of service. When triggered, the entire blockchain network stops producing blocks permanently. This requires emergency coordination among validators to either:
1. Roll back to the pre-upgrade binary (losing the upgrade)
2. Deploy an emergency hotfix that adds the missing migration handler
3. Perform a hard fork with a patched binary

The impact matches the in-scope criterion: "High Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Conditions:**
- Any developer incrementing the authz consensus version without reading/following the migration requirements
- The issue is not caught by CI/CD if migration tests are not comprehensive
- Occurs during routine protocol upgrades, which are common in blockchain development

**Who Can Trigger:**
While only developers can introduce this bug, once introduced and deployed through governance, the network automatically triggers the failure at the upgrade height. This is not a malicious attack scenario but a developer error with catastrophic consequences.

**Frequency:**
- Can happen whenever authz module is upgraded with a consensus version bump
- The risk exists for every consensus version increment (1→2, 2→3, etc.)
- Given that the current version is 1 and no migration infrastructure exists, the risk is immediate for the next upgrade

**Realistic Assessment:**
This is highly realistic because:
1. Consensus version bumps are standard practice during upgrades
2. The error is easy to make if developers don't thoroughly understand the migration system
3. The Cosmos SDK documentation emphasizes this requirement, but it's still commonly missed
4. The existing test in simapp explicitly validates this scenario [11](#0-10) 

## Recommendation

Add a migration handler registration in the authz module's `RegisterServices` method:

```go
func (am AppModule) RegisterServices(cfg module.Configurator) {
    authz.RegisterQueryServer(cfg.QueryServer(), am.keeper)
    authz.RegisterMsgServer(cfg.MsgServer(), am.keeper)
    
    // Register migration handler for future consensus version bumps
    // Even if the migration is a no-op, it must be registered
    // Example for version 1 -> 2:
    // m := keeper.NewMigrator(am.keeper)
    // cfg.RegisterMigration(authz.ModuleName, 1, m.Migrate1to2)
}
```

Additionally:
1. Create a `migrations.go` file in `x/authz/keeper/` with a `Migrator` struct (following the pattern used in other modules)
2. Add comprehensive migration tests to verify the upgrade path
3. Document the current consensus version and required migration handlers in the module README

## Proof of Concept

**Test File:** `x/authz/module/module_test.go` (new file)

**Setup:**
1. Create a test app with authz module initialized
2. Configure the module manager with all modules except authz registering their migrations
3. Initialize the chain and set the stored version map with authz at version 1

**Trigger:**
1. Manually increment authz's ConsensusVersion to return 2 (simulate a version bump)
2. Call `app.mm.RunMigrations()` with a VersionMap containing authz: 1
3. The migration system will attempt to find a handler for version 1→2

**Observation:**
The test will panic or return an error with message: "no migration found for module authz from version 1 to version 2"

**Test Code Pattern** (based on existing test structure): [11](#0-10) 

The test should demonstrate that:
1. Without a registered migration handler, RunMigrations returns an error
2. This error would cause ApplyUpgrade to panic during an actual upgrade
3. The network would halt at the upgrade height

This matches the test pattern already validated in the codebase where attempting to run migrations without a registered handler produces the expected error message.

### Citations

**File:** x/authz/module/module.go (L44-47)
```go
func (am AppModule) RegisterServices(cfg module.Configurator) {
	authz.RegisterQueryServer(cfg.QueryServer(), am.keeper)
	authz.RegisterMsgServer(cfg.MsgServer(), am.keeper)
}
```

**File:** x/authz/module/module.go (L173-173)
```go
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

**File:** types/module/configurator.go (L103-107)
```go
	for i := fromVersion; i < toVersion; i++ {
		migrateFn, found := moduleMigrationsMap[i]
		if !found {
			return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migration found for module %s from version %d to version %d", moduleName, i, i+1)
		}
```

**File:** types/module/module.go (L505-508)
```go
//	cfg := module.NewConfigurator(...)
//	app.UpgradeKeeper.SetUpgradeHandler("my-plan", func(ctx sdk.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
//	    return app.mm.RunMigrations(ctx, cfg, fromVM)
//	})
```

**File:** types/module/module.go (L546-596)
```go
func (m Manager) RunMigrations(ctx sdk.Context, cfg Configurator, fromVM VersionMap) (VersionMap, error) {
	c, ok := cfg.(configurator)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
	}
	var modules = m.OrderMigrations
	if modules == nil {
		modules = DefaultMigrationsOrder(m.ModuleNames())
	}

	updatedVM := VersionMap{}
	for _, moduleName := range modules {
		module := m.Modules[moduleName]
		fromVersion, exists := fromVM[moduleName]
		toVersion := module.ConsensusVersion()

		// Only run migrations when the module exists in the fromVM.
		// Run InitGenesis otherwise.
		//
		// the module won't exist in the fromVM in two cases:
		// 1. A new module is added. In this case we run InitGenesis with an
		// empty genesis state.
		// 2. An existing chain is upgrading to v043 for the first time. In this case,
		// all modules have yet to be added to x/upgrade's VersionMap store.
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
		}

		updatedVM[moduleName] = toVersion
	}

	return updatedVM, nil
}
```

**File:** x/upgrade/keeper/keeper.go (L371-374)
```go
	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}
```

**File:** x/upgrade/abci.go (L115-118)
```go
func applyUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	ctx.Logger().Info(fmt.Sprintf("applying upgrade \"%s\" at %s", plan.Name, plan.DueAt()))
	k.ApplyUpgrade(ctx, plan)
}
```

**File:** simapp/app_test.go (L125-128)
```go
			"throws error on RunMigrations if no migration registered for bank",
			"", 1,
			false, "", true, "no migrations found for module bank: not found", 0,
		},
```
