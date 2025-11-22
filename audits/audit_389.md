# Audit Report

## Title
Unvalidated Module Version Map Allows Migration Skip Leading to State Corruption

## Summary
The `ApplyUpgrade` function in `x/upgrade/keeper/keeper.go` at line 371 accepts a version map returned by an upgrade handler without validating that the versions match the modules' actual consensus versions. This allows an upgrade handler to persist incorrect module versions to state, which causes subsequent upgrades to skip critical store migrations, resulting in state corruption and potential consensus failures.

## Impact
Medium to High

## Finding Description

**Location:** 
- Primary issue: `x/upgrade/keeper/keeper.go`, function `ApplyUpgrade`, line 371-376
- Secondary issue: `types/module/configurator.go`, function `runModuleMigrations`, line 91-117

**Intended Logic:** 
When an upgrade handler executes, it should return a version map where each module's version accurately reflects the state of that module's store after migrations have been applied. The system should ensure that module versions in the persisted version map correspond to the actual state versions, maintaining the invariant that `storedVersion == actualStateVersion`. [1](#0-0) 

**Actual Logic:** 
The `ApplyUpgrade` function directly persists whatever version map the upgrade handler returns without any validation. An upgrade handler can manually construct or modify a version map to set module versions to arbitrary values, including values higher than the module's actual state version. This breaks the invariant between stored version and actual state version. [2](#0-1) 

When `runModuleMigrations` executes with `fromVersion > toVersion`, the loop condition at line 103 (`i < toVersion`) is never satisfied, causing the function to return successfully without running any migrations. [3](#0-2) 

**Exploit Scenario:**
1. Initial state: Module "bank" is at actual state version 2, stored version map contains `{"bank": 2}`
2. An upgrade handler with a coding error returns `{"bank": 10}` instead of calling `RunMigrations` properly
3. This incorrect version map is persisted to state via `SetModuleVersionMap`
4. Next upgrade: Bank module's `ConsensusVersion()` returns 3
   - `fromVersion` = 10 (retrieved from state)
   - `toVersion` = 3 (from module)
   - `runModuleMigrations` is called with (ctx, "bank", 10, 3)
   - Loop condition `10 < 3` is false, no migrations execute
   - Function returns nil (success)
5. The migration from version 2→3 is skipped, but the version map is updated to 3
6. The chain continues with the store at version 2 but the version map claiming version 3 [4](#0-3) 

**Security Failure:**
This breaks the state integrity invariant by allowing the stored version map to diverge from the actual module state version. Skipped migrations can contain critical consensus-breaking changes, data structure updates, or security fixes. This leads to:
- State corruption (store structure doesn't match expected version)
- Consensus failures (nodes may have inconsistent state)
- Undefined behavior if subsequent code assumes migration effects occurred

## Impact Explanation

**Affected Components:**
- Module store state integrity
- Cross-node consensus on state
- Chain upgrade reliability

**Severity:**
When a migration is skipped:
1. **State Corruption**: If the migration included store structure changes (key format changes, data migrations), the store remains in the old format while code expects the new format
2. **Consensus Failures**: Different nodes may process transactions differently if they have inconsistent state, leading to chain halts or splits requiring hard fork recovery
3. **Security Vulnerabilities**: If the skipped migration fixed a security issue (e.g., validation bug, overflow fix), that vulnerability remains exploitable
4. **Financial Impact**: If migrations involve financial logic (fee calculations, token accounting), incorrect state could lead to fund loss or minting errors

This qualifies as **Medium**: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" and could escalate to **High**: "Unintended permanent chain split requiring hard fork" depending on the nature of the skipped migration.

## Likelihood Explanation

**Who can trigger:** 
Only developers who write upgrade handlers can trigger this, as `SetUpgradeHandler` is called during application initialization in code. [5](#0-4) 

**Trigger conditions:**
- A developer writes an upgrade handler that manually modifies the version map instead of (or in addition to) calling `RunMigrations`
- A developer accidentally returns an incorrect version map due to logic errors
- A third-party module provides a buggy upgrade helper function

The documentation explicitly shows patterns where developers manually modify version maps, making this error realistic: [6](#0-5) 

**Frequency:**
While this requires developer error, such errors are realistic because:
1. Manual version map modification is a documented pattern for skipping InitGenesis
2. Complex upgrade handlers may have logic bugs
3. No validation or warnings exist to catch these errors
4. The error manifests in a subsequent upgrade, not immediately, making it hard to detect during testing

## Recommendation

Add validation in `ApplyUpgrade` after the handler returns to ensure the returned version map is valid:

1. **Validate version map constraints:**
   - Check that no module version is 0 (versions must start at 1)
   - Check that no module version exceeds its `ConsensusVersion()`
   - Warn or error if a module version in the returned map is lower than the stored version

2. **Add explicit check in `runModuleMigrations`:**
   - Before the migration loop, add: `if fromVersion > toVersion { return sdkerrors.Wrapf(..., "fromVersion %d cannot be greater than toVersion %d for module %s", fromVersion, toVersion, moduleName) }`
   - This provides an explicit error instead of silently succeeding

3. **Enhance documentation:**
   - Add warnings in upgrade handler documentation about the risks of manually modifying version maps
   - Provide helper functions that safely modify version maps with built-in validation

## Proof of Concept

**File:** `x/upgrade/keeper/keeper_test.go`

**Test Function:** `TestVersionMapViolationSkipsMigrations`

**Setup:**
1. Initialize a test app with the upgrade keeper
2. Set initial module version map with bank module at version 2: `{"bank": 2}`
3. Create a malformed upgrade handler that returns an incorrect version map with bank at version 10

**Trigger:**
1. Execute first upgrade with the malformed handler
2. Verify the incorrect version (10) is persisted to state
3. Create a second upgrade that calls `RunMigrations` normally (simulating the next upgrade cycle)
4. Execute the second upgrade with bank module's actual `ConsensusVersion()` at 3

**Observation:**
1. The first upgrade persists version 10 to state without error
2. The second upgrade:
   - Retrieves `fromVersion = 10` from state
   - Gets `toVersion = 3` from the module
   - Calls `runModuleMigrations(ctx, "bank", 10, 3)`
   - The loop `for i := 10; i < 3; i++` never executes
   - Returns success without running any migrations
3. The migration from version 2→3 is skipped
4. Store remains at actual version 2, but version map claims version 3
5. This demonstrates the state corruption: `actualStateVersion (2) != storedVersion (3)`

The test should add assertions to verify:
- After first upgrade: `GetModuleVersionMap` returns `{"bank": 10}` (incorrect value persisted)
- After second upgrade: No migration functions were called (can be verified by adding a counter in mock migration)
- The version map now shows `{"bank": 3}` but the actual store state is still at version 2

This proves that upgrade handlers can persist invalid version maps that cause subsequent migrations to be skipped, corrupting chain state.

### Citations

**File:** x/upgrade/keeper/keeper.go (L64-69)
```go
// SetUpgradeHandler sets an UpgradeHandler for the upgrade specified by name. This handler will be called when the upgrade
// with this name is applied. In order for an upgrade with the given name to proceed, a handler for this upgrade
// must be set even if it is a no-op function.
func (k Keeper) SetUpgradeHandler(name string, upgradeHandler types.UpgradeHandler) {
	k.upgradeHandlers[name] = upgradeHandler
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

**File:** x/upgrade/types/handler.go (L8-26)
```go
// UpgradeHandler specifies the type of function that is called when an upgrade
// is applied.
//
// `fromVM` is a VersionMap of moduleName to fromVersion (unit64), where
// fromVersion denotes the version from which we should migrate the module, the
// target version being the module's latest version in the return VersionMap,
// let's call it `toVM`.
//
// `fromVM` is retrieved from x/upgrade's store, whereas `toVM` is chosen
// arbitrarily by the app developer (and persisted to x/upgrade's store right
// after the upgrade handler runs). In general, `toVM` should map all modules
// to their latest ConsensusVersion so that x/upgrade can track each module's
// latest ConsensusVersion; `fromVM` can be left as-is, but can also be
// modified inside the upgrade handler, e.g. to skip running InitGenesis or
// migrations for certain modules when calling the `module.Manager#RunMigrations`
// function.
//
// Please also refer to docs/core/upgrade.md for more information.
type UpgradeHandler func(ctx sdk.Context, plan Plan, fromVM module.VersionMap) (module.VersionMap, error)
```

**File:** types/module/configurator.go (L91-117)
```go
func (c configurator) runModuleMigrations(ctx sdk.Context, moduleName string, fromVersion, toVersion uint64) error {
	// No-op if toVersion is the initial version or if the version is unchanged.
	if toVersion <= 1 || fromVersion == toVersion {
		return nil
	}

	moduleMigrationsMap, found := c.migrations[moduleName]
	if !found {
		return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migrations found for module %s", moduleName)
	}

	// Run in-place migrations for the module sequentially until toVersion.
	for i := fromVersion; i < toVersion; i++ {
		migrateFn, found := moduleMigrationsMap[i]
		if !found {
			return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migration found for module %s from version %d to version %d", moduleName, i, i+1)
		}
		ctx.Logger().Info(fmt.Sprintf("migrating module %s from version %d to version %d", moduleName, i, i+1))

		err := migrateFn(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** x/upgrade/keeper/keeper_test.go (L217-235)
```go
func (s *KeeperTestSuite) TestMigrations() {
	initialVM := module.VersionMap{"bank": uint64(1)}
	s.app.UpgradeKeeper.SetModuleVersionMap(s.ctx, initialVM)
	vmBefore := s.app.UpgradeKeeper.GetModuleVersionMap(s.ctx)
	s.app.UpgradeKeeper.SetUpgradeHandler("dummy", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
		// simulate upgrading the bank module
		vm["bank"] = vm["bank"] + 1
		return vm, nil
	})
	dummyPlan := types.Plan{
		Name:   "dummy",
		Info:   "some text here",
		Height: 123450000,
	}

	s.app.UpgradeKeeper.ApplyUpgrade(s.ctx, dummyPlan)
	vm := s.app.UpgradeKeeper.GetModuleVersionMap(s.ctx)
	s.Require().Equal(vmBefore["bank"]+1, vm["bank"])
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
