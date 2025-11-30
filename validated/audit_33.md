# Audit Report

## Title
Duplicate Upgrade Name Allows Network Shutdown via Plan Overwrite

## Summary
The `ScheduleUpgrade` function in the x/upgrade module permits overwriting a pending upgrade plan using the same upgrade name but at a different execution height. When validators prepare binaries for the originally scheduled height and the plan is rescheduled to a later height using the same name, all validators executing the new binary at the original height will panic simultaneously, causing complete network shutdown.

## Impact
High

## Finding Description

**Location:** 
- [1](#0-0)  (insufficient validation - only checks if upgrade completed, not if pending plan exists)
- [2](#0-1)  (unconditional plan overwrite without name conflict detection)
- [3](#0-2)  (panic trigger when handler exists for non-ready upgrade)

**Intended Logic:**
The upgrade system should ensure consistent coordination across all validators. When governance schedules an upgrade at a specific height, validators should be able to safely prepare and execute the upgrade at that height without risk of plan changes causing chain halts. Each upgrade name should correspond to a single, deterministic execution height.

**Actual Logic:**
The `ScheduleUpgrade` function only validates whether an upgrade name has already been completed [1](#0-0) , but does not check if a pending upgrade with the same name exists at a different height. The function then unconditionally overwrites any existing plan [2](#0-1) , as explicitly documented in the comments [4](#0-3) .

**Exploitation Path:**

1. Governance passes proposal scheduling upgrade "v2" at height 1000 via [5](#0-4) 
2. Validators observe the scheduled upgrade and prepare new binaries that include [6](#0-5)  in their application code
3. Before height 1000 is reached, governance passes a second proposal scheduling upgrade "v2" at height 1100 (same name, different height)
4. The second proposal overwrites the first plan without validation because only completion status is checked, not pending plan conflicts
5. At height 1000, validators execute their planned binary switches (based on original coordination)
6. BeginBlocker executes with the new binary at height 1000:
   - `GetUpgradePlan` returns plan with height 1100 (the overwritten plan)
   - [7](#0-6)  returns false because 1100 > 1000
   - `k.HasHandler("v2")` returns true because the new binary has the handler registered
   - BeginBlocker detects handler exists for non-ready, non-minor upgrade and panics [3](#0-2)  with "BINARY UPDATED BEFORE TRIGGER!"
7. All validators running the upgraded binary panic simultaneously, causing complete consensus failure and network shutdown

**Security Guarantee Broken:**
The network availability guarantee is violated. The upgrade coordination mechanism fails to prevent conflicting upgrade schedules, allowing governance to inadvertently trigger total network shutdown through a reasonable operational action (rescheduling an upgrade) that produces consequences far exceeding their intended authority scope.

## Impact Explanation

This vulnerability causes total network shutdown with severe consequences:

- **Network Availability**: All validators who switched to the new binary at the originally scheduled height panic simultaneously, halting block production
- **Transaction Processing**: No new transactions can be confirmed during the shutdown period
- **Consensus Failure**: Complete halt in consensus requiring manual coordination across all validators to recover
- **Recovery Complexity**: Recovery requires validators to either restart with the old binary, use skip-upgrade flags, or coordinate to wait until the rescheduled height—all requiring off-chain coordination

This directly matches the HIGH severity impact category from the provided criteria: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can pass governance proposals (requires majority vote through standard governance mechanisms). Critically, this vulnerability can manifest without malicious intent through legitimate governance operations.

**Conditions Required:**
1. First governance proposal schedules upgrade "X" at height H1
2. Validators prepare binary switches for height H1 (standard practice)
3. Second governance proposal schedules upgrade "X" at height H2 where H2 > H1, using the same upgrade name
4. Validators execute planned binary switches at height H1 based on their original coordination

**Likelihood Assessment:**
Moderate to high probability because:
- Governance may legitimately need to reschedule upgrades due to discovered bugs, timing conflicts, or coordination issues
- The code explicitly permits plan overwriting [4](#0-3)  without warnings about reusing names
- No system warnings indicate when an upgrade name is being reused at a different height
- Validators typically commit to upgrade timing based on governance decisions and may not continuously monitor for last-minute changes
- The action (rescheduling using the same name) appears reasonable but has catastrophic consequences

The likelihood is significant because the triggering condition (governance rescheduling with same name) is a plausible operational scenario where the impact (total network shutdown) vastly exceeds the expected consequences.

## Recommendation

Add validation in `ScheduleUpgrade` to prevent reusing pending upgrade names at different heights:

```go
// After the GetDoneHeight check, add:
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
1. Use a different upgrade name (e.g., "v2-revised" instead of "v2"), which forces validators to rebuild binaries with the new handler name, or
2. First cancel the existing upgrade via [8](#0-7) , then schedule the new upgrade

This approach maintains governance flexibility while preventing the catastrophic scenario where validators execute based on stale coordination information.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestDuplicateUpgradeNameCausesNetworkShutdown`

**Setup:**
1. Initialize test suite at block height 10 using [9](#0-8) 
2. Schedule upgrade "test-upgrade" at height 15 via governance handler
3. Simulate validators upgrading by registering handler using `SetUpgradeHandler`
4. Schedule second upgrade with same name at height 20, which overwrites the first plan

**Action:**
1. Create context at original scheduled height 15
2. Call BeginBlock at height 15

**Result:**
BeginBlock panics with message "BINARY UPDATED BEFORE TRIGGER! UPGRADE \"test-upgrade\" - in binary but not executed on chain", confirming the network shutdown vulnerability. The panic is triggered because the handler is registered (simulating validators who switched binaries at the original height), but the stored plan indicates execution at height 20 instead of height 15.

## Notes

While the existing test [10](#0-9)  demonstrates that plan overwriting is intentional behavior, it uses different upgrade names ("bad_test" then "test") and does not test the dangerous scenario where validators have already registered a handler before the plan is overwritten with the same name at a different height.

This vulnerability satisfies platform acceptance criteria because while governance is a privileged role, rescheduling upgrades is within their intended authority, but the consequence (total network shutdown requiring manual recovery) is an unrecoverable security failure that far exceeds the intended scope of the governance action. The issue can occur inadvertently during legitimate operations and matches the HIGH severity impact criterion: "Network not being able to confirm new transactions (total network shutdown)".

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

**File:** x/upgrade/abci.go (L92-97)
```go
	// if we have a handler for a non-minor upgrade, that means it updated too early and must stop
	if k.HasHandler(plan.Name) {
		downgradeMsg := fmt.Sprintf("BINARY UPDATED BEFORE TRIGGER! UPGRADE \"%s\" - in binary but not executed on chain", plan.Name)
		ctx.Logger().Error(downgradeMsg)
		panic(downgradeMsg)
	}
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

**File:** x/upgrade/types/plan.go (L39-44)
```go
func (p Plan) ShouldExecute(ctx sdk.Context) bool {
	if p.Height > 0 {
		return p.Height <= ctx.BlockHeight()
	}
	return false
}
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
