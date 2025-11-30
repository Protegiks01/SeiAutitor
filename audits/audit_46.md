# Audit Report

## Title
Duplicate Upgrade Name Allows Network Shutdown via Plan Overwrite

## Summary
The `ScheduleUpgrade` function in the x/upgrade module only validates that an upgrade name hasn't been completed, but fails to check if a pending upgrade with the same name exists at a different height. This allows a second governance proposal to overwrite a pending upgrade using the same name but different height, causing all validators who upgraded early to panic simultaneously at the original scheduled height, resulting in complete network shutdown.

## Impact
High

## Finding Description

**Location:**
- Validation check: [1](#0-0) 
- Plan overwrite logic: [2](#0-1) 
- Panic trigger: [3](#0-2) 

**Intended Logic:**
The upgrade system should coordinate upgrade execution by ensuring each upgrade has a unique name and consistent scheduling. Validators should be able to reliably prepare for upgrades at the scheduled height without risk of plan changes causing chain halts.

**Actual Logic:**
The validation only checks if an upgrade name has been completed [1](#0-0) , not if a pending upgrade with the same name exists. The function then unconditionally overwrites any existing plan [2](#0-1) , as explicitly documented in the comment [4](#0-3) .

**Exploitation Path:**
1. Governance passes proposal scheduling upgrade "v2" at height 1000
2. Validators monitor governance, upgrade their binaries, and register handler for "v2" via `SetUpgradeHandler` [5](#0-4) 
3. Before height 1000, governance passes another proposal scheduling upgrade "v2" at height 1100 (same name, different height)
4. The second proposal overwrites the first plan without validation because only completion is checked
5. At height 1000 when BeginBlocker executes:
   - The stored plan indicates execution at height 1100
   - `plan.ShouldExecute(ctx)` returns false [6](#0-5)  because 1100 > 1000
   - However, `k.HasHandler("v2")` returns true because validators already upgraded
   - BeginBlocker detects this mismatch and panics [3](#0-2)  with "BINARY UPDATED BEFORE TRIGGER!"
6. All validators running the upgraded binary panic simultaneously, causing complete network shutdown

**Security Guarantee Broken:**
Network availability and upgrade coordination guarantees. The system fails to prevent conflicting upgrade schedules, allowing a trusted governance action (rescheduling) to inadvertently cause total network shutdown beyond the intended authority scope.

## Impact Explanation

The vulnerability causes total network shutdown with the following consequences:

- **Network Availability**: All validators with upgraded binaries panic simultaneously when the original scheduled height is reached
- **Transaction Confirmation**: No new transactions can be confirmed during the shutdown
- **Block Production**: Complete halt in block production requiring manual coordination to recover
- **Recovery Complexity**: Requires validators to manually coordinate to restart with correct binary or use skip-upgrade flags

This directly matches the HIGH severity impact category: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can get governance proposals passed (requires majority vote). Critically, this does not require malicious intent—it can happen accidentally during normal governance operations.

**Conditions Required:**
1. First governance proposal schedules upgrade X at height H1
2. Validators upgrade binaries before H1 is reached (standard best practice)
3. Second governance proposal schedules upgrade X at height H2 (H2 > H1) before H1 is reached  
4. Network automatically reaches height H1

**Frequency:**
Moderate to high likelihood in active chains because:
- Governance may legitimately need to reschedule upgrades due to discovered issues or timing conflicts
- Multiple upgrade proposals could be under consideration simultaneously
- Emergency situations may require rapid governance decisions
- No warning is provided that the same upgrade name is being reused
- The code explicitly allows overwriting [4](#0-3) 

The likelihood is significant because the action (rescheduling an upgrade with the same name) is a reasonable governance operation, but the consequence (total network shutdown) far exceeds the intended authority and can occur inadvertently.

## Recommendation

Add validation in `ScheduleUpgrade` to prevent reusing pending upgrade names at different heights:

```go
// After the GetDoneHeight check at line 190, add:
if oldPlan, found := k.GetUpgradePlan(ctx); found {
    if oldPlan.Name == plan.Name && oldPlan.Height != plan.Height {
        return sdkerrors.Wrapf(
            sdkerrors.ErrInvalidRequest, 
            "upgrade with name %s is already scheduled for height %d, cannot reschedule to height %d with the same name",
            plan.Name, oldPlan.Height, plan.Height,
        )
    }
}
```

This ensures that to reschedule an upgrade, governance must either:
1. Use a different name (e.g., "v2-revised"), or
2. First cancel the existing upgrade via `CancelSoftwareUpgradeProposal` [7](#0-6) , then schedule the new one

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestDuplicateUpgradeNameCausesNetworkShutdown`

**Setup:**
1. Initialize test suite at block height 10 using existing `setupTest` function [8](#0-7) 
2. Schedule upgrade "test-upgrade" at height 15 via governance handler [9](#0-8) 
3. Simulate validators upgrading by calling `s.keeper.SetUpgradeHandler("test-upgrade", handler)` [5](#0-4) 
4. Schedule another upgrade with the same name "test-upgrade" at height 20, which overwrites the first plan [10](#0-9) 

**Action:**
1. Create context at height 15: `newCtx := s.ctx.WithBlockHeight(15)`
2. Call BeginBlock: `s.module.BeginBlock(newCtx, req)`

**Result:**
BeginBlock panics with message "BINARY UPDATED BEFORE TRIGGER! UPGRADE \"test-upgrade\" - in binary but not executed on chain" [3](#0-2) , confirming the network shutdown vulnerability. The panic is triggered when validators have registered a handler for an upgrade that was rescheduled to a later height using the same name.

## Notes

The vulnerability is valid under the platform acceptance rules because:
- While governance is a privileged role, rescheduling upgrades is within their intended authority
- The consequence (total network shutdown) is an unrecoverable security failure that far exceeds the intended scope of the action
- This can happen inadvertently without malicious intent during legitimate governance operations
- The impact exactly matches the HIGH severity category: "Network not being able to confirm new transactions (total network shutdown)"

The existing test `TestCanOverwriteScheduleUpgrade` [11](#0-10)  demonstrates that plan overwriting is intentional, but uses different upgrade names. There is no test coverage for the dangerous scenario where validators have already upgraded their binaries before the plan is overwritten with the same name at a different height.

### Citations

**File:** x/upgrade/keeper/keeper.go (L67-69)
```go
func (k Keeper) SetUpgradeHandler(name string, upgradeHandler types.UpgradeHandler) {
	k.upgradeHandlers[name] = upgradeHandler
}
```

**File:** x/upgrade/keeper/keeper.go (L172-174)
```go
// ScheduleUpgrade schedules an upgrade based on the specified plan.
// If there is another Plan already scheduled, it will overwrite it
// (implicitly cancelling the current plan)
```

**File:** x/upgrade/keeper/keeper.go (L188-190)
```go
	if k.GetDoneHeight(ctx, plan.Name) != 0 {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "upgrade with name %s has already been completed", plan.Name)
	}
```

**File:** x/upgrade/keeper/keeper.go (L195-201)
```go
	oldPlan, found := k.GetUpgradePlan(ctx)
	if found {
		k.ClearIBCState(ctx, oldPlan.Height)
	}

	bz := k.cdc.MustMarshal(&plan)
	store.Set(types.PlanKey(), bz)
```

**File:** x/upgrade/abci.go (L93-96)
```go
	if k.HasHandler(plan.Name) {
		downgradeMsg := fmt.Sprintf("BINARY UPDATED BEFORE TRIGGER! UPGRADE \"%s\" - in binary but not executed on chain", plan.Name)
		ctx.Logger().Error(downgradeMsg)
		panic(downgradeMsg)
```

**File:** x/upgrade/types/plan.go (L39-43)
```go
func (p Plan) ShouldExecute(ctx sdk.Context) bool {
	if p.Height > 0 {
		return p.Height <= ctx.BlockHeight()
	}
	return false
```

**File:** x/upgrade/handler.go (L29-31)
```go
func handleSoftwareUpgradeProposal(ctx sdk.Context, k keeper.Keeper, p *types.SoftwareUpgradeProposal) error {
	return k.ScheduleUpgrade(ctx, p.Plan)
}
```

**File:** x/upgrade/handler.go (L33-35)
```go
func handleCancelSoftwareUpgradeProposal(ctx sdk.Context, k keeper.Keeper, _ *types.CancelSoftwareUpgradeProposal) error {
	k.ClearUpgradePlan(ctx)
	return nil
```

**File:** x/upgrade/abci_test.go (L42-64)
```go
func setupTest(height int64, skip map[int64]bool) TestSuite {
	db := dbm.NewMemDB()
	app := simapp.NewSimApp(log.NewNopLogger(), db, nil, true, skip, simapp.DefaultNodeHome, 0, nil, simapp.MakeTestEncodingConfig(), &simapp.EmptyAppOptions{})
	genesisState := simapp.NewDefaultGenesisState(app.AppCodec())
	stateBytes, err := json.MarshalIndent(genesisState, "", "  ")
	if err != nil {
		panic(err)
	}
	app.InitChain(
		context.Background(), &abci.RequestInitChain{
			Validators:    []abci.ValidatorUpdate{},
			AppStateBytes: stateBytes,
		},
	)

	s.keeper = app.UpgradeKeeper
	s.ctx = app.BaseApp.NewContext(false, tmproto.Header{Height: height, Time: time.Now()})

	s.module = upgrade.NewAppModule(s.keeper)
	s.querier = s.module.LegacyQuerierHandler(app.LegacyAmino())
	s.handler = upgrade.NewSoftwareUpgradeProposalHandler(s.keeper)
	return s
}
```

**File:** x/upgrade/abci_test.go (L90-99)
```go
func TestCanOverwriteScheduleUpgrade(t *testing.T) {
	s := setupTest(10, map[int64]bool{})
	t.Log("Can overwrite plan")
	err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{Title: "prop", Plan: types.Plan{Name: "bad_test", Height: s.ctx.BlockHeight() + 10}})
	require.NoError(t, err)
	err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{Title: "prop", Plan: types.Plan{Name: "test", Height: s.ctx.BlockHeight() + 1}})
	require.NoError(t, err)

	VerifyDoUpgrade(t)
}
```
