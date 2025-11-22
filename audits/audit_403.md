## Title
Minor Upgrade Detection Bypass via Malformed JSON Leading to Network Shutdown

## Summary
Malformed JSON in the `Plan.Info` field causes minor upgrade detection to fail silently, incorrectly treating a minor upgrade as a major upgrade. This leads to nodes panicking with "BINARY UPDATED BEFORE TRIGGER!" when validators update their binaries early (following the minor upgrade protocol), potentially causing network shutdown if ≥30% of validators are affected.

## Impact
**High** - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions.

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
When an upgrade plan specifies `{"upgradeType":"minor"}` in the `Info` field, the upgrade should be detected as a minor release. Minor releases allow validators to update their binaries before the scheduled upgrade height without causing a panic. The `UpgradeDetails()` function should parse the JSON and `IsMinorRelease()` should return true, allowing the code to return early and avoid the "BINARY UPDATED BEFORE TRIGGER!" panic.

**Actual Logic:** 
When malformed JSON is provided in the `Info` field (e.g., `{upgradeType:"minor"}` missing quotes, or other invalid JSON), the `json.Unmarshal` call fails. However, the error is only logged and ignored. The function returns an empty `UpgradeDetails{}` struct with `UpgradeType == ""`. When `IsMinorRelease()` is called on this empty struct, it returns false because the empty string does not equal "minor". The code then falls through to the major upgrade logic, and if a handler exists (because validators updated early for what they thought was a minor release), the node panics.

**Exploit Scenario:**
1. A governance proposal schedules an upgrade with malformed JSON in the `Info` field (e.g., `{upgradeType:"minor"}` instead of `{"upgradeType":"minor"}`)
2. Validators, believing this is a minor release (perhaps based on external communications), update their binaries before the scheduled height
3. When BeginBlock executes before the scheduled height, the malformed JSON causes parsing to fail silently
4. The upgrade is treated as a major release
5. The code detects that a handler exists for a "major" upgrade before its scheduled time and panics
6. If ≥30% of validators are affected, the network halts

**Security Failure:** 
This breaks the availability guarantee of the network. The minor/major upgrade distinction is a critical security mechanism that allows for safe early updates. By silently failing to parse the upgrade type and defaulting to major upgrade behavior, the system violates its own protocol guarantees and can cause widespread node crashes.

## Impact Explanation

**Affected Processes:** Network availability and validator node operation

**Severity of Damage:** 
- Validators following the minor upgrade protocol will experience node panics
- If ≥30% of validators update early and encounter this issue, the network cannot reach consensus and halts
- The network shutdown persists until validators either roll back their binaries or skip the upgrade height
- This requires emergency coordination and potential chain recovery procedures

**Why This Matters:** 
The upgrade mechanism is critical infrastructure for blockchain evolution. A silent failure in upgrade type detection can cause catastrophic network outages. The issue is particularly severe because it can be triggered through standard governance procedures and affects validators following documented best practices for minor upgrades.

## Likelihood Explanation

**Who Can Trigger:** 
Any participant who can submit governance proposals (requires governance token holdings and community support). The malformed JSON could also be introduced accidentally through human error when crafting proposals.

**Required Conditions:**
1. Governance proposal passes with malformed JSON in the `Info` field
2. Validators update their binaries early, believing it's a minor release
3. BeginBlock executes before the scheduled upgrade height

**Frequency:**
This could occur during any upgrade cycle if the JSON is malformed. Given that governance proposals are human-crafted and JSON syntax errors are common, this has moderate to high likelihood. The issue is particularly dangerous because validators have no way to detect the malformed JSON until it's too late—the error is only logged at runtime, not caught during proposal validation.

## Recommendation

Add validation of the `Info` field JSON during upgrade plan validation to ensure it can be parsed correctly. If the JSON is invalid and non-empty, reject the upgrade plan during `ScheduleUpgrade`:

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

Alternatively, if allowing malformed JSON is intended, change the BeginBlocker logic to treat parsing errors as non-minor releases explicitly, but this is less safe.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** Add this test to demonstrate the vulnerability:

```go
func TestMalformedJSONBypassesMinorUpgradeDetection(t *testing.T) {
    s := setupTest(10, map[int64]bool{})
    
    // Malformed JSON that is INTENDED to be a minor upgrade
    // Missing quotes around key and value
    malformedMinorUpgradeInfo := `{upgradeType:minor}`
    
    // Schedule upgrade with malformed JSON at height 20
    err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Minor Upgrade Test",
        Plan: types.Plan{
            Name:   "test_minor",
            Height: 20,
            Info:   malformedMinorUpgradeInfo,
        },
    })
    require.NoError(t, err)
    
    // Validator updates binary early (at height 15), following minor upgrade protocol
    s.keeper.SetUpgradeHandler("test_minor", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    // Execute BeginBlock at height 15 (before scheduled height of 20)
    // For a proper minor release, this should NOT panic
    // But due to malformed JSON, it will be treated as major and WILL panic
    newCtx := s.ctx.WithBlockHeight(15)
    req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
    
    // This SHOULD NOT panic for a minor release, but DOES panic due to the bug
    require.Panics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }, "Node panics when validator updates early due to malformed JSON bypassing minor release detection")
    
    // Verify that with VALID JSON, the same scenario does NOT panic
    s2 := setupTest(10, map[int64]bool{})
    validMinorUpgradeInfo := `{"upgradeType":"minor"}`
    
    err = s2.handler(s2.ctx, &types.SoftwareUpgradeProposal{
        Title: "Minor Upgrade Test Valid",
        Plan: types.Plan{
            Name:   "test_minor_valid",
            Height: 20,
            Info:   validMinorUpgradeInfo,
        },
    })
    require.NoError(t, err)
    
    s2.keeper.SetUpgradeHandler("test_minor_valid", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    newCtx2 := s2.ctx.WithBlockHeight(15)
    req2 := abci.RequestBeginBlock{Header: newCtx2.BlockHeader()}
    
    // With valid JSON, no panic should occur
    require.NotPanics(t, func() {
        s2.module.BeginBlock(newCtx2, req2)
    }, "Node does NOT panic with valid minor upgrade JSON")
}
```

**Setup:** Initialize test suite at height 10 with no skip heights.

**Trigger:** 
1. Schedule an upgrade at height 20 with malformed JSON: `{upgradeType:minor}` (missing quotes)
2. Set upgrade handler (simulating validator updating binary early for minor release)
3. Execute BeginBlock at height 15 (before scheduled height)

**Observation:** 
The test demonstrates that with malformed JSON, the node panics with "BINARY UPDATED BEFORE TRIGGER!" even though the upgrade was intended to be a minor release. The test then shows that with valid JSON `{"upgradeType":"minor"}`, the same scenario does not panic, confirming that the malformed JSON bypasses the minor upgrade detection mechanism.

**Run Command:** `go test -v ./x/upgrade -run TestMalformedJSONBypassesMinorUpgradeDetection`

### Citations

**File:** x/upgrade/abci.go (L75-78)
```go
	details, err := plan.UpgradeDetails()
	if err != nil {
		ctx.Logger().Error("failed to parse upgrade details", "err", err)
	}
```

**File:** x/upgrade/abci.go (L82-97)
```go
	if details.IsMinorRelease() {
		// if not yet present, then emit a scheduled log (every 100 blocks, to reduce logs)
		if !k.HasHandler(plan.Name) && !k.IsSkipHeight(plan.Height) {
			if ctx.BlockHeight()%100 == 0 {
				ctx.Logger().Info(BuildUpgradeScheduledMsg(plan))
			}
		}
		return
	}

	// if we have a handler for a non-minor upgrade, that means it updated too early and must stop
	if k.HasHandler(plan.Name) {
		downgradeMsg := fmt.Sprintf("BINARY UPDATED BEFORE TRIGGER! UPGRADE \"%s\" - in binary but not executed on chain", plan.Name)
		ctx.Logger().Error(downgradeMsg)
		panic(downgradeMsg)
	}
```

**File:** x/upgrade/types/plan.go (L57-69)
```go
// UpgradeDetails parses and returns a details struct from the Info field of a Plan
// The upgrade.pb.go is generated from proto, so this is separated here
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
