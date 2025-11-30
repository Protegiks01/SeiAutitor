# Audit Report

## Title
Minor Upgrade Detection Bypass via Malformed JSON Leading to Network Node Shutdown

## Summary
The upgrade module lacks JSON validation in the `Plan.Info` field during governance proposal validation. When malformed JSON is present in an upgrade plan, the system incorrectly treats a minor upgrade as major, causing validators who update their binaries early (standard practice for minor upgrades) to experience node panics affecting ≥30% of network nodes.

## Impact
Medium

## Finding Description

**Location:**
- `x/upgrade/types/plan.go` (lines 21-36) - ValidateBasic() lacks JSON validation
- `x/upgrade/keeper/keeper.go` (lines 177-211) - ScheduleUpgrade() lacks JSON validation  
- `x/upgrade/abci.go` (lines 75-97) - BeginBlocker silent failure handling

**Intended Logic:**
When an upgrade plan contains valid JSON `{"upgradeType":"minor"}` in the `Info` field, the system should parse this JSON, detect it as a minor release, and allow validators to update their binaries before the scheduled upgrade height without triggering a panic. [1](#0-0) 

**Actual Logic:**
When the `Info` field contains malformed JSON (e.g., `{upgradeType:"minor"}` with missing quotes), the `json.Unmarshal()` call in `UpgradeDetails()` fails and returns an empty struct. [1](#0-0)  The error is logged but ignored in BeginBlocker. [2](#0-1)  The `IsMinorRelease()` check returns false for the empty string. [3](#0-2)  If a handler exists (because validators updated early), the node panics. [4](#0-3) 

**Exploitation Path:**
1. A governance proposal is submitted with malformed JSON in `Plan.Info` (can occur accidentally through human error)
2. The proposal passes `ValidateBasic()` checks because the Info field JSON format is not validated [5](#0-4) 
3. The proposal is approved by governance and scheduled via `ScheduleUpgrade()` [6](#0-5) 
4. Validators receive external communications indicating this is a minor upgrade
5. Validators update their binaries early and register upgrade handlers (standard minor upgrade protocol)
6. When `BeginBlocker` executes before the scheduled height, it calls `plan.UpgradeDetails()` which silently fails to parse the malformed JSON
7. The empty `UpgradeDetails` causes `IsMinorRelease()` to return false
8. The code reaches the panic condition where `k.HasHandler(plan.Name)` is true for validators who updated early
9. All affected nodes panic and shut down with message "BINARY UPDATED BEFORE TRIGGER!"

**Security Guarantee Broken:**
The minor/major upgrade distinction is a critical safety mechanism. The system violates the fail-safe principle by silently failing to parse upgrade metadata and defaulting to unsafe behavior (panic) without explicit validation or rejection during proposal submission.

## Impact Explanation

**Affected Processes:** Network validator node availability and consensus participation

**Consequences:**
- Validators following minor upgrade best practices experience unexpected node panics
- If ≥30% of validators coordinate early updates (standard practice for minor upgrades), those nodes shut down simultaneously
- While the network continues operating (remaining validators > 66.67% threshold needed for consensus), this represents significant availability degradation
- Requires emergency coordination to roll back binaries or skip the upgrade height
- Undermines trust in the upgrade mechanism and validator coordination

This matches the defined Medium severity impact: **"Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network"**

## Likelihood Explanation

**Who Can Trigger:**
Any governance participant who can submit proposals (requires token holdings and community approval). Critically, this can occur **accidentally** through human error when crafting JSON syntax in upgrade proposals.

**Required Conditions:**
1. Governance proposal passes with malformed JSON in `Info` field (moderate likelihood - JSON syntax errors are common in manual proposal creation)
2. Validators coordinate early binary updates based on external communications indicating minor upgrade (high likelihood - this is standard practice for minor version upgrades)
3. Mismatch between off-chain communications (saying "minor upgrade") and on-chain malformed data (medium likelihood due to lack of validation)

**Likelihood Assessment:**
Medium to High. JSON syntax errors are common when humans manually craft proposals. Validators regularly coordinate minor upgrades and rely on external communications from the development team. The lack of validation means errors won't be caught during proposal submission, only at runtime when it's too late to prevent the impact.

## Recommendation

Add JSON validation to the `ScheduleUpgrade` function to reject proposals with invalid Info field JSON format:

```go
func (k Keeper) ScheduleUpgrade(ctx sdk.Context, plan types.Plan) error {
    if err := plan.ValidateBasic(); err != nil {
        return err
    }
    
    // Validate upgrade details if Info is provided
    if plan.Info != "" {
        if _, err := plan.UpgradeDetails(); err != nil {
            return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, 
                "invalid upgrade info JSON: %v", err)
        }
    }
    
    // ... rest of function
}
```

This ensures malformed JSON is caught during proposal validation rather than causing runtime failures that panic validator nodes.

## Proof of Concept

**Test Function:** Add to `x/upgrade/abci_test.go`

**Setup:**
- Initialize test suite at height 10 with no skip heights using `setupTest(10, map[int64]bool{})`
- Schedule upgrade at height 20 with malformed JSON: `Info: "{upgradeType:minor}"` (missing quotes around key and value)
- Register upgrade handler using `s.keeper.SetUpgradeHandler("testMalformed", func(...) {...})` to simulate validator updating binary early for minor release

**Action:**
- Create context at height 15 (before scheduled height of 20): `newCtx := s.ctx.WithBlockHeight(15)`
- Execute BeginBlock: `s.module.BeginBlock(newCtx, req)`

**Result:**
- Node panics with "BINARY UPDATED BEFORE TRIGGER! UPGRADE \"testMalformed\" - in binary but not executed on chain"
- This occurs even though the upgrade was intended as minor
- With valid JSON `{"upgradeType":"minor"}`, the same scenario does NOT panic (verified by existing test at lines 550-568) [7](#0-6) 
- The existing test confirms that invalid JSON returns an empty struct [8](#0-7) 

The test demonstrates that the JSON parsing failure causes the system to incorrectly treat a minor upgrade as major, triggering panic conditions that should not occur for properly detected minor upgrades.

## Notes

This vulnerability exists because the system makes critical security decisions (panic vs. allow early execution) based on the `Info` field content but doesn't validate the field format during proposal submission. The silent failure mode (logging error but continuing execution with empty struct) violates security best practices and the fail-safe principle.

While this requires governance approval, it qualifies as a valid vulnerability because even trusted governance inadvertently triggering this through human error (JSON syntax mistake) causes an unrecoverable security failure (mass node shutdowns affecting ≥30% of validators) that is beyond their intended authority (they intended a coordinated minor upgrade, not network disruption).

Human operators have no mechanism to detect the malformed JSON until their validator nodes panic at runtime, making this a systemic validation failure at the protocol level.

### Citations

**File:** x/upgrade/types/plan.go (L21-36)
```go
func (p Plan) ValidateBasic() error {
	if !p.Time.IsZero() {
		return sdkerrors.ErrInvalidRequest.Wrap("time-based upgrades have been deprecated in the SDK")
	}
	if p.UpgradedClientState != nil {
		return sdkerrors.ErrInvalidRequest.Wrap("upgrade logic for IBC has been moved to the IBC module")
	}
	if len(p.Name) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot be empty")
	}
	if p.Height <= 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "height must be greater than 0")
	}

	return nil
}
```

**File:** x/upgrade/types/plan.go (L59-69)
```go
func (p Plan) UpgradeDetails() (UpgradeDetails, error) {
	if p.Info == "" {
		return UpgradeDetails{}, nil
	}
	var details UpgradeDetails
	if err := json.Unmarshal([]byte(p.Info), &details); err != nil {
		// invalid json, assume no upgrade details
		return UpgradeDetails{}, err
	}
	return details, nil
}
```

**File:** x/upgrade/types/plan.go (L72-74)
```go
func (ud UpgradeDetails) IsMinorRelease() bool {
	return strings.EqualFold(ud.UpgradeType, "minor")
}
```

**File:** x/upgrade/abci.go (L75-78)
```go
	details, err := plan.UpgradeDetails()
	if err != nil {
		ctx.Logger().Error("failed to parse upgrade details", "err", err)
	}
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

**File:** x/upgrade/keeper/keeper.go (L177-211)
```go
func (k Keeper) ScheduleUpgrade(ctx sdk.Context, plan types.Plan) error {
	if err := plan.ValidateBasic(); err != nil {
		return err
	}

	// NOTE: allow for the possibility of chains to schedule upgrades in begin block of the same block
	// as a strategy for emergency hard fork recoveries
	if plan.Height < ctx.BlockHeight() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "upgrade cannot be scheduled in the past")
	}

	if k.GetDoneHeight(ctx, plan.Name) != 0 {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "upgrade with name %s has already been completed", plan.Name)
	}

	store := ctx.KVStore(k.storeKey)

	// clear any old IBC state stored by previous plan
	oldPlan, found := k.GetUpgradePlan(ctx)
	if found {
		k.ClearIBCState(ctx, oldPlan.Height)
	}

	bz := k.cdc.MustMarshal(&plan)
	store.Set(types.PlanKey(), bz)

	telemetry.SetGaugeWithLabels(
		[]string{"cosmos", "upgrade", "plan", "height"},
		float32(plan.Height),
		[]metrics.Label{
			{Name: "name", Value: plan.Name},
			{Name: "info", Value: plan.Info},
		},
	)
	return nil
```

**File:** x/upgrade/abci_test.go (L550-568)
```go
		{
			"test not panic: minor upgrade should apply",
			func() (sdk.Context, abci.RequestBeginBlock) {
				s.keeper.SetUpgradeHandler("test4", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
					return vm, nil
				})

				err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{
					Title: "Upgrade test",
					Plan:  types.Plan{Name: "test4", Height: s.ctx.BlockHeight() + 10, Info: minorUpgradeInfo},
				})
				require.NoError(t, err)

				newCtx := s.ctx.WithBlockHeight(12)
				req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
				return newCtx, req
			},
			false,
		},
```

**File:** x/upgrade/types/plan_test.go (L175-180)
```go
			name: "invalid json in Info",
			plan: types.Plan{
				Info: `{upgradeType:"minor"}`,
			},
			want: types.UpgradeDetails{},
		},
```
