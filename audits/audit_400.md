# Audit Report

## Title
Duplicate Upgrade Name Allows Network Shutdown via Plan Overwrite

## Summary
The `ScheduleUpgrade` function in `keeper.go` only validates that an upgrade name hasn't been completed, but fails to check if there's a pending upgrade with the same name. This allows a second governance proposal to overwrite a pending upgrade plan using the same name but a different execution height, causing validators who upgraded early to trigger a chain-wide panic and network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Panic trigger: [2](#0-1) 
- Plan overwrite: [3](#0-2) 

**Intended Logic:** 
The upgrade system should prevent confusion and coordination failures by ensuring each upgrade has a unique name and execution height. Validators should be able to reliably prepare for upgrades at the scheduled height without risk of plan changes causing chain halts.

**Actual Logic:** 
The validation at lines 188-190 only checks `GetDoneHeight(ctx, plan.Name) != 0` to prevent reusing completed upgrade names. However, it does not check if there's already a pending (not yet executed) upgrade with the same name. Lines 195-201 unconditionally overwrite any existing plan, allowing a new proposal with the same upgrade name but different height to silently replace the original plan.

**Exploit Scenario:**
1. Governance passes a proposal scheduling upgrade "v2" at height 1000
2. Validators monitor governance and upgrade their binaries, registering the handler for "v2"
3. Before height 1000 is reached, another governance proposal passes scheduling upgrade "v2" at height 1100 (same name, later height)
4. The second proposal overwrites the first plan without any warning or validation
5. At height 1000:
   - The stored plan now indicates execution should occur at height 1100
   - `plan.ShouldExecute(ctx)` returns false (since 1000 < 1100)
   - However, validators have already registered the handler: `k.HasHandler("v2")` returns true
   - BeginBlocker detects this mismatch and executes the panic at lines 93-96: "BINARY UPDATED BEFORE TRIGGER!"
6. All validators running the upgraded binary panic simultaneously, causing total network shutdown

**Security Failure:** 
This breaks consensus availability guarantees. The system fails to coordinate upgrade execution correctly, causing a denial-of-service where no new blocks can be produced and the network cannot progress.

## Impact Explanation

**Affected Components:** Network availability, consensus participation, block production

**Severity of Damage:** 
- The entire network halts when validators with upgraded binaries reach the original scheduled height
- No new transactions can be confirmed
- Block production stops completely
- Requires manual coordination among validators to recover (restart with correct binary or skip-upgrade flag)

**System Impact:** 
This directly causes "Network not being able to confirm new transactions (total network shutdown)" which is classified as **High** severity in the impact scope. The vulnerability allows governance proposals (which require only majority voting, not universal agreement) to inadvertently cause complete network failure.

## Likelihood Explanation

**Who Can Trigger:** 
Any participant who can get governance proposals passed (requires majority vote). This doesn't require malicious intent - it can happen accidentally if governance participants don't realize the risks of reusing upgrade names.

**Conditions Required:** 
1. First governance proposal schedules an upgrade with name X at height H1
2. Validators upgrade their binaries before H1
3. Second governance proposal schedules an upgrade with the same name X at height H2 > H1 before H1 is reached
4. The condition triggers automatically when block height reaches H1

**Frequency:** 
This could occur during normal governance operations, especially when:
- Governance needs to delay an upgrade and creates a new proposal with the same name
- Multiple upgrade proposals are being considered and pass with overlapping names
- Emergency situations require rapid governance action without proper validation

The likelihood is moderate to high in active chains with frequent governance activity.

## Recommendation

Add validation in `ScheduleUpgrade` to check if a pending upgrade exists with the same name:

```go
// After line 190, add:
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

This ensures that if an upgrade needs to be rescheduled, it must either:
1. Use a different name (e.g., "v2-revised"), or
2. First cancel the existing upgrade via `CancelSoftwareUpgradeProposal`, then schedule the new one

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestDuplicateUpgradeNameCausesNetworkShutdown`

**Setup:**
1. Initialize test suite with block height 10
2. Schedule upgrade "test-upgrade" at height 15
3. Simulate validators upgrading their binary by registering the handler for "test-upgrade"
4. Before height 15, schedule another upgrade with the same name "test-upgrade" at height 20 (overwrites first plan)

**Trigger:**
1. Advance context to height 15 (the original scheduled height)
2. Call `BeginBlock` with the updated context

**Observation:**
The test will observe a panic with message "BINARY UPDATED BEFORE TRIGGER! UPGRADE \"test-upgrade\" - in binary but not executed on chain", confirming that the chain halts due to the duplicate name confusion.

**Test Code:**
```go
func TestDuplicateUpgradeNameCausesNetworkShutdown(t *testing.T) {
    s := setupTest(10, map[int64]bool{})
    
    // Step 1: Schedule upgrade "test-upgrade" at height 15
    err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "First Upgrade", 
        Plan: types.Plan{Name: "test-upgrade", Height: 15},
    })
    require.NoError(t, err)
    
    // Step 2: Validators upgrade their binary (register handler)
    s.keeper.SetUpgradeHandler("test-upgrade", func(ctx sdk.Context, plan types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    // Step 3: Before height 15, schedule another upgrade with SAME name at height 20
    err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Rescheduled Upgrade", 
        Plan: types.Plan{Name: "test-upgrade", Height: 20},
    })
    require.NoError(t, err) // This should succeed, demonstrating the vulnerability
    
    // Step 4: Advance to height 15 (original scheduled height)
    newCtx := s.ctx.WithBlockHeight(15).WithBlockTime(time.Now())
    req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
    
    // Step 5: BeginBlock panics with "BINARY UPDATED BEFORE TRIGGER"
    require.Panics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }, "Expected panic due to duplicate upgrade name causing early binary detection")
}
```

This test demonstrates that the vulnerability allows network shutdown through duplicate upgrade name scheduling, which is a High severity issue per the impact scope.

### Citations

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
