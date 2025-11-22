# Audit Report

## Title
Stale Module Versions Persist After Module Deletion, Causing State Initialization Failure on Re-addition

## Summary
The `SetModuleVersionMap` function in the upgrade keeper does not delete version entries for modules that are absent from the provided version map. When a module is removed during an upgrade and later re-added, the stale version entry causes `RunMigrations` to skip `InitGenesis`, leaving the re-added module in an uninitialized state that can cause chain halts.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
When a module is deleted during a chain upgrade, its consensus version should be removed from the version map stored in the x/upgrade module's state. Later, if a module with the same name is re-added as a new module, `RunMigrations` should detect it as new (absent from fromVM) and call `InitGenesis` to initialize its state properly.

**Actual Logic:** 
The `SetModuleVersionMap` function only writes keys for modules present in the provided map [3](#0-2) . It does not delete keys for modules that are absent from the map. When a module is removed and `RunMigrations` returns a version map without that module [4](#0-3) , the old version entry persists in state. If the module is later re-added, `RunMigrations` retrieves the stale version from fromVM [5](#0-4) , treats it as an existing module [6](#0-5) , and skips `InitGenesis` [7](#0-6) .

**Exploit Scenario:**
1. Initial state: Module "tokenfactory" exists at consensus version 2, tracked in the version map
2. Upgrade removes "tokenfactory" (via `StoreUpgrades.Deleted` and removal from module manager)
3. Physical store is deleted [8](#0-7) , but version entry "tokenfactory": 2 remains in x/upgrade's version map due to the bug
4. Later upgrade re-adds "tokenfactory" as a brand new module at version 1
5. `RunMigrations` retrieves fromVM containing the stale entry "tokenfactory": 2 [9](#0-8) 
6. Since `exists=true` in fromVM, `RunMigrations` calls `runModuleMigrations(ctx, "tokenfactory", 2, 1)` instead of `InitGenesis` [6](#0-5) 
7. `runModuleMigrations` returns early because `toVersion <= 1` [10](#0-9) , performing no initialization
8. Module "tokenfactory" is now active in the module manager but has completely uninitialized state
9. First transaction attempting to use "tokenfactory" causes nil pointer panic or accesses uninitialized storage, halting the chain

**Security Failure:** 
State consistency invariant violation - all active modules must have their state properly initialized before processing transactions. The chain cannot safely process transactions for the uninitialized module, leading to network shutdown.

## Impact Explanation
When a re-added module's `InitGenesis` is skipped due to this bug, the module operates with completely uninitialized state. This causes:
- Nil pointer dereferences when the module attempts to read expected state structures
- Panics during transaction processing that involve the uninitialized module  
- Complete chain halt if the affected module is critical to transaction processing (e.g., auth, bank, staking)
- Inability for the network to confirm any new transactions (total network shutdown)

This directly meets the "High" severity impact criterion: **"Network not being able to confirm new transactions (total network shutdown)"** as specified in the scope.

## Likelihood Explanation
This vulnerability triggers automatically during normal upgrade operations when:
1. Any chain upgrade removes a module via `StoreUpgrades.Deleted` [11](#0-10) 
2. A subsequent upgrade re-adds a module with the same name

No special privileges, malicious intent, or attacker involvement is required. This is a logic bug in the core upgrade mechanism that will trigger during legitimate governance-approved upgrade procedures. While module removal and re-addition is not a frequent operation, when it does occur, the failure is guaranteed and deterministic. The impact is severe enough that this represents a critical reliability issue for chain upgrades.

## Recommendation
Modify `SetModuleVersionMap` to clear all existing module version entries before writing the new version map. This ensures deleted modules are properly removed from the version map:

Before writing new entries, iterate through all existing version map entries and delete them, then write the new map. Alternatively, maintain a separate deletion list and explicitly delete entries for modules not present in the new version map. This ensures the version map accurately reflects only the currently active modules.

## Proof of Concept

**File:** `x/upgrade/keeper/keeper_test.go`

**Test Function:** Add the following test function to the `KeeperTestSuite`:

```go
func (s *KeeperTestSuite) TestDeletedModuleVersionPersistsAndBreaksReaddition() {
    // Setup: Create initial version map with three modules
    initialVM := module.VersionMap{
        "auth":    uint64(1),
        "bank":    uint64(1),
        "staking": uint64(1),
    }
    s.app.UpgradeKeeper.SetModuleVersionMap(s.ctx, initialVM)
    
    // First upgrade: Update bank to version 2
    s.app.UpgradeKeeper.SetUpgradeHandler("upgrade1", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        vm["bank"] = 2
        return vm, nil
    })
    s.app.UpgradeKeeper.ApplyUpgrade(s.ctx, types.Plan{Name: "upgrade1", Height: 11})
    
    vm := s.app.UpgradeKeeper.GetModuleVersionMap(s.ctx)
    s.Require().Equal(uint64(2), vm["bank"])
    
    // Second upgrade: Remove bank module (simulates module deletion)
    // In real scenario, bank would be removed from module manager
    // and RunMigrations would not include it in returned VersionMap
    s.app.UpgradeKeeper.SetUpgradeHandler("upgrade2", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        // Simulate RunMigrations returning a map WITHOUT bank
        return module.VersionMap{
            "auth":    uint64(1),
            "staking": uint64(1),
            // bank intentionally omitted - it was deleted
        }, nil
    })
    s.app.UpgradeKeeper.ApplyUpgrade(s.ctx, types.Plan{Name: "upgrade2", Height: 12})
    
    // Retrieve version map after "deletion"
    vm = s.app.UpgradeKeeper.GetModuleVersionMap(s.ctx)
    
    // This assertion exposes the bug: bank should NOT be in the map
    bankVersion, exists := vm["bank"]
    s.Require().False(exists, "VULNERABILITY: bank module version persists after deletion - should have been removed from version map")
    s.Require().Equal(uint64(0), bankVersion)
}
```

**Setup:** Uses the existing `KeeperTestSuite` test infrastructure which initializes a test app and upgrade keeper.

**Trigger:** Executes two sequential upgrades - first updating a module version, then "removing" the module by returning a version map without it (simulating what happens when a module is deleted from the module manager and `RunMigrations` is called).

**Observation:** The test retrieves the version map after the deletion and asserts that the deleted module's version entry should not exist. The test will **FAIL**, demonstrating that the bank module's version 2 still exists in state even though it was removed from the returned version map. This confirms the vulnerability - stale version entries persist and would cause `InitGenesis` to be skipped if the module were re-added.

**Execution:** Run `go test ./x/upgrade/keeper/... -run TestDeletedModuleVersionPersistsAndBreaksReaddition -v`

The test failure proves that `SetModuleVersionMap` does not delete absent module entries, creating dangerous state inconsistency during upgrades with module deletions.

### Citations

**File:** x/upgrade/keeper/keeper.go (L94-116)
```go
func (k Keeper) SetModuleVersionMap(ctx sdk.Context, vm module.VersionMap) {
	if len(vm) > 0 {
		store := ctx.KVStore(k.storeKey)
		versionStore := prefix.NewStore(store, []byte{types.VersionMapByte})
		// Even though the underlying store (cachekv) store is sorted, we still
		// prefer a deterministic iteration order of the map, to avoid undesired
		// surprises if we ever change stores.
		sortedModNames := make([]string, 0, len(vm))

		for key := range vm {
			sortedModNames = append(sortedModNames, key)
		}
		sort.Strings(sortedModNames)

		for _, modName := range sortedModNames {
			ver := vm[modName]
			nameBytes := []byte(modName)
			verBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(verBytes, ver)
			versionStore.Set(nameBytes, verBytes)
		}
	}
}
```

**File:** x/upgrade/keeper/keeper.go (L371-371)
```go
	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
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

**File:** store/rootmulti/store.go (L293-298)
```go
		if upgrades.IsDeleted(key.Name()) {
			deleteKVStore(store.(types.KVStore))
			// drop deleted KV store from stores
			delete(newStores, key)
			delete(rs.keysByName, key.Name())
			delete(rs.storesParams, key)
```

**File:** types/module/configurator.go (L92-95)
```go
	// No-op if toVersion is the initial version or if the version is unchanged.
	if toVersion <= 1 || fromVersion == toVersion {
		return nil
	}
```

**File:** store/types/store.go (L47-51)
```go
type StoreUpgrades struct {
	Added   []string      `json:"added"`
	Renamed []StoreRename `json:"renamed"`
	Deleted []string      `json:"deleted"`
}
```
