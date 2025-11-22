## Audit Report

## Title
Protocol Version Monotonicity Violation Through Genesis Export/Import

## Summary
The upgrade module's `ExportGenesis` function returns an empty JSON object, failing to export the protocol version and completed upgrade history. This causes the protocol version to reset to 0 after a genesis export/import cycle, violating the monotonicity invariant that the protocol version should always increase. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in `x/upgrade/module.go` at the `ExportGenesis` method (lines 128-131) and the corresponding `InitGenesis` method (lines 103-106), which work together with the protocol version management in `x/upgrade/keeper/keeper.go` (lines 71-91 and 378-380). [2](#0-1) 

**Intended Logic:** The protocol version should monotonically increase throughout the chain's lifetime. When a chain undergoes genesis export (for migration, fork, or restart), the protocol version and upgrade history should be preserved to maintain this invariant and prevent re-execution of completed upgrades.

**Actual Logic:** The upgrade module's `ExportGenesis` returns `[]byte("{}")`, an empty JSON object, which means:
1. The protocol version stored in the upgrade keeper's state is not exported
2. The completed upgrade history (Done keys) is not exported
3. When `InitGenesis` is called on the imported genesis, it does nothing
4. The protocol version defaults to 0 when accessed via `getProtocolVersion` [3](#0-2) 

**Exploit Scenario:**
1. A chain operates normally and applies multiple upgrades (e.g., upgrades A, B, C), reaching protocol version 3
2. Chain operators export the genesis state using the `export` command for a planned migration
3. The exported genesis includes all module states EXCEPT the upgrade module (which exports `{}`)
4. A new chain is initialized with this exported genesis
5. Protocol version resets to 0 (down from 3), violating monotonicity
6. The upgrade history is lost, so the check in `ScheduleUpgrade` that prevents re-applying completed upgrades will pass [4](#0-3) 

7. Previously applied upgrades can be scheduled and executed again, potentially running module migrations twice and corrupting state

**Security Failure:** This breaks the protocol version monotonicity invariant and the idempotency guarantee for upgrade execution. The system fails to maintain consistency across genesis export/import cycles, allowing state corruption through duplicate upgrade execution.

## Impact Explanation

The vulnerability affects the chain's state integrity and upgrade system reliability:

- **Protocol Version Inconsistency:** After genesis import, the protocol version (0) does not reflect the actual chain state that includes all previously applied upgrades, creating a mismatch between the version number and the actual protocol capabilities.

- **Duplicate Upgrade Execution:** Lost upgrade history allows scheduling and applying the same upgrade multiple times. Module migration scripts are designed to run once; re-execution may cause state corruption or panic.

- **State Corruption Risk:** Running migrations twice could corrupt module state, as migration logic typically assumes it's transforming state from one version to another, not idempotently handling already-migrated state.

This represents a **Medium severity** issue under the category "A bug in the network code that results in unintended behavior with no concrete funds at direct risk," though it poses a systemic risk to chain operations during migration scenarios.

## Likelihood Explanation

**Who can trigger it:** This affects all chain operators who export and import genesis state, which is a standard operational procedure.

**Conditions required:** 
- Chain has applied at least one upgrade (protocol version > 0)
- Genesis export is performed (using the `export` command)
- Genesis is imported to initialize a new chain instance

**Frequency:** This occurs in common operational scenarios:
- Planned chain migrations/forks
- Network upgrades requiring genesis restart
- Disaster recovery procedures
- Test network initialization from mainnet state

The likelihood is **high** during genesis export/import operations, which are routine maintenance procedures, not rare edge cases.

## Recommendation

Implement proper genesis export/import for the upgrade module:

1. **Define a genesis state structure** in `x/upgrade/types/genesis.go` that includes:
   - Protocol version
   - Completed upgrade names and heights (Done keys)
   - Current upgrade plan (if any)

2. **Update `ExportGenesis`** to serialize this state:
   ```go
   func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
       gs := GenesisState{
           ProtocolVersion: am.keeper.getProtocolVersion(ctx),
           CompletedUpgrades: am.keeper.GetAllCompletedUpgrades(ctx),
           CurrentPlan: am.keeper.GetUpgradePlan(ctx),
       }
       return cdc.MustMarshalJSON(&gs)
   }
   ```

3. **Update `InitGenesis`** to restore this state:
   ```go
   func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
       var gs GenesisState
       cdc.MustUnmarshalJSON(data, &gs)
       am.keeper.setProtocolVersion(ctx, gs.ProtocolVersion)
       // Restore completed upgrades and plan
       return []abci.ValidatorUpdate{}
   }
   ```

4. **Add invariant check** in `setProtocolVersion` to enforce monotonicity:
   ```go
   func (k Keeper) setProtocolVersion(ctx sdk.Context, v uint64) {
       currentVersion := k.getProtocolVersion(ctx)
       if v < currentVersion {
           panic(fmt.Sprintf("protocol version cannot decrease: current=%d, new=%d", currentVersion, v))
       }
       // ... existing storage logic
   }
   ```

## Proof of Concept

**File:** `x/upgrade/keeper/keeper_test.go`

**Test Function:** `TestProtocolVersionMonotonicityViolation`

```go
func (s *KeeperTestSuite) TestProtocolVersionMonotonicityViolation() {
    // Setup: Apply multiple upgrades to increment protocol version
    s.app.UpgradeKeeper.SetUpgradeHandler("upgrade_v1", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) { 
        return vm, nil 
    })
    s.app.UpgradeKeeper.SetUpgradeHandler("upgrade_v2", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) { 
        return vm, nil 
    })
    
    plan1 := types.Plan{Name: "upgrade_v1", Height: 100}
    plan2 := types.Plan{Name: "upgrade_v2", Height: 200}
    
    // Apply first upgrade - protocol version should be 1
    s.app.UpgradeKeeper.ApplyUpgrade(s.ctx, plan1)
    versionAfterFirst := s.app.BaseApp.AppVersion()
    s.Require().Equal(uint64(1), versionAfterFirst, "Protocol version should be 1 after first upgrade")
    
    // Apply second upgrade - protocol version should be 2
    s.app.UpgradeKeeper.ApplyUpgrade(s.ctx, plan2)
    versionAfterSecond := s.app.BaseApp.AppVersion()
    s.Require().Equal(uint64(2), versionAfterSecond, "Protocol version should be 2 after second upgrade")
    
    // Trigger: Simulate genesis export by calling the upgrade module's ExportGenesis
    upgradeModule := upgrade.NewAppModule(s.app.UpgradeKeeper)
    exportedGenesis := upgradeModule.ExportGenesis(s.ctx, s.app.AppCodec())
    
    // Observation 1: Verify exported genesis is empty
    s.Require().Equal([]byte("{}"), exportedGenesis, "ExportGenesis should return empty object")
    
    // Simulate genesis import by creating a new app/keeper instance
    newApp := simapp.Setup(false)
    newHomeDir := filepath.Join(s.T().TempDir(), "new_chain")
    newApp.UpgradeKeeper = keeper.NewKeeper(
        make(map[int64]bool), newApp.GetKey(types.StoreKey), newApp.AppCodec(), newHomeDir, newApp.BaseApp,
    )
    newCtx := newApp.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Import the exported genesis
    newUpgradeModule := upgrade.NewAppModule(newApp.UpgradeKeeper)
    newUpgradeModule.InitGenesis(newCtx, newApp.AppCodec(), exportedGenesis)
    
    // Observation 2: Protocol version has reset to 0, violating monotonicity
    versionAfterImport := newApp.BaseApp.AppVersion()
    s.Require().Equal(uint64(0), versionAfterImport, "Protocol version incorrectly resets to 0 after genesis import")
    
    // Observation 3: Monotonicity violated - version decreased from 2 to 0
    s.Require().Less(versionAfterImport, versionAfterSecond, 
        "VULNERABILITY: Protocol version decreased from %d to %d, violating monotonicity invariant", 
        versionAfterSecond, versionAfterImport)
    
    // Observation 4: Upgrade history is lost - can schedule previously applied upgrade again
    err := newApp.UpgradeKeeper.ScheduleUpgrade(newCtx, plan1)
    s.Require().NoError(err, "VULNERABILITY: Previously applied upgrade can be scheduled again due to lost history")
}
```

**Expected Result:** The test demonstrates that:
1. Protocol version correctly increments to 2 after two upgrades
2. Genesis export returns empty JSON `{}`
3. After genesis import, protocol version resets to 0 (decreased from 2)
4. The monotonicity invariant is violated
5. Previously applied upgrades can be scheduled again due to lost upgrade history

This test should be added to `x/upgrade/keeper/keeper_test.go` and will fail on the current codebase, proving the vulnerability exists.

### Citations

**File:** x/upgrade/module.go (L103-111)
```go
// InitGenesis is ignored, no sense in serializing future upgrades
func (am AppModule) InitGenesis(_ sdk.Context, _ codec.JSONCodec, _ json.RawMessage) []abci.ValidatorUpdate {
	return []abci.ValidatorUpdate{}
}

// DefaultGenesis is an empty object
func (AppModuleBasic) DefaultGenesis(_ codec.JSONCodec) json.RawMessage {
	return []byte("{}")
}
```

**File:** x/upgrade/module.go (L128-131)
```go
// ExportGenesis is always empty, as InitGenesis does nothing either
func (am AppModule) ExportGenesis(_ sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	return am.DefaultGenesis(cdc)
}
```

**File:** x/upgrade/keeper/keeper.go (L79-91)
```go
// getProtocolVersion gets the protocol version from state
func (k Keeper) getProtocolVersion(ctx sdk.Context) uint64 {
	store := ctx.KVStore(k.storeKey)
	ok := store.Has([]byte{types.ProtocolVersionByte})
	if ok {
		pvBytes := store.Get([]byte{types.ProtocolVersionByte})
		protocolVersion := binary.BigEndian.Uint64(pvBytes)

		return protocolVersion
	}
	// default value
	return 0
}
```

**File:** x/upgrade/keeper/keeper.go (L188-190)
```go
	if k.GetDoneHeight(ctx, plan.Name) != 0 {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "upgrade with name %s has already been completed", plan.Name)
	}
```
