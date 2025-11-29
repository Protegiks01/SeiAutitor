# Audit Report

## Title
Duplicate Upgrade Name Allows Network Shutdown via Plan Overwrite

## Summary
The `ScheduleUpgrade` function only validates that an upgrade name hasn't been completed but fails to check if a pending upgrade with the same name exists. This allows a second governance proposal to overwrite a pending upgrade using the same name but different height, causing validators who upgraded early to trigger a chain-wide panic and complete network shutdown at the original scheduled height.

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
2. Validators monitor governance, upgrade their binaries, and register handler for "v2" (via `SetUpgradeHandler`)
3. Before height 1000, governance passes another proposal scheduling upgrade "v2" at height 1100 (same name, different height)
4. The second proposal overwrites the first plan without validation
5. At height 1000 when BeginBlocker executes:
   - The stored plan indicates execution at height 1100
   - `plan.ShouldExecute(ctx)` returns false [5](#0-4)  (1100 > 1000)
   - However, `k.HasHandler("v2")` returns true (validators already upgraded)
   - BeginBlocker detects this mismatch and panics [3](#0-2)  with "BINARY UPDATED BEFORE TRIGGER!"
6. All validators running the upgraded binary panic simultaneously

**Security Guarantee Broken:**
Network availability and upgrade coordination guarantees. The system fails to prevent conflicting upgrade schedules, allowing a trusted governance action (rescheduling) to inadvertently cause total network shutdown beyond the intended authority.

## Impact Explanation

The vulnerability causes total network shutdown with the following consequences:

- **Network Availability**: All validators with upgraded binaries panic simultaneously when the original scheduled height is reached
- **Transaction Confirmation**: No new transactions can be confirmed during the shutdown
- **Block Production**: Complete halt in block production requiring manual coordination
- **Recovery Complexity**: Requires validators to manually coordinate to restart with correct binary or use skip-upgrade flags

This directly matches the HIGH severity impact category: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can get governance proposals passed (requires majority vote). Critically, this does not require malicious intent—it can happen accidentally during normal governance operations.

**Conditions Required:**
1. First governance proposal schedules upgrade X at height H1
2. Validators upgrade binaries before H1 is reached (standard practice)
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

Add validation in `ScheduleUpgrade` to prevent reusing pending upgrade names:

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
2. First cancel the existing upgrade via `CancelSoftwareUpgradeProposal` [6](#0-5) , then schedule the new one

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestDuplicateUpgradeNameCausesNetworkShutdown`

**Setup:**
1. Initialize test suite at block height 10 (using existing `setupTest` function)
2. Schedule upgrade "test-upgrade" at height 15 via governance handler
3. Simulate validators upgrading by calling `s.keeper.SetUpgradeHandler("test-upgrade", handler)`
4. Schedule another upgrade with the same name "test-upgrade" at height 20 (overwrites first plan)

**Action:**
1. Create context at height 15: `newCtx := s.ctx.WithBlockHeight(15)`
2. Call BeginBlock: `s.module.BeginBlock(newCtx, req)`

**Result:**
BeginBlock panics with message "BINARY UPDATED BEFORE TRIGGER! UPGRADE \"test-upgrade\" - in binary but not executed on chain", confirming the network shutdown vulnerability. The panic is triggered at [3](#0-2)  when validators have registered a handler for an upgrade that was rescheduled to a later height using the same name.

## Notes

The vulnerability is valid under the platform acceptance rules because:
- While governance is a privileged role, rescheduling upgrades is within their intended authority
- The consequence (total network shutdown) is an unrecoverable security failure that far exceeds the intended scope of the action
- This can happen inadvertently without malicious intent during legitimate governance operations
- The impact exactly matches the HIGH severity category: "Network not being able to confirm new transactions (total network shutdown)"

The existing test `TestCanOverwriteScheduleUpgrade` demonstrates that plan overwriting is intentional, but there is no test coverage for the dangerous scenario where validators have already upgraded their binaries before the plan is overwritten.

### Citations

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

**File:** x/upgrade/handler.go (L33-35)
```go
func handleCancelSoftwareUpgradeProposal(ctx sdk.Context, k keeper.Keeper, _ *types.CancelSoftwareUpgradeProposal) error {
	k.ClearUpgradePlan(ctx)
	return nil
```
