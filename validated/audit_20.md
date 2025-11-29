# Audit Report

## Title
Minor Upgrade Detection Bypass via Malformed JSON Leading to Network Shutdown

## Summary
The upgrade module fails to validate JSON syntax in the `Plan.Info` field during governance proposal submission. When malformed JSON is present, the `UpgradeDetails()` parsing silently fails, returning an empty struct that causes the upgrade to be incorrectly treated as a major release. Validators who update their binaries early (following the documented minor upgrade protocol) will experience node panics, potentially causing network-wide shutdown if ≥30% of validators are affected.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Intended Logic:**
When an upgrade plan specifies `{"upgradeType":"minor"}` in the `Info` field, the `UpgradeDetails()` function should successfully parse this JSON. The `IsMinorRelease()` check should return true, allowing validators to safely update their binaries before the scheduled upgrade height without triggering a panic. The `Plan.ValidateBasic()` function should ensure that only valid upgrade plans are accepted through governance.

**Actual Logic:**
The `Plan.ValidateBasic()` function validates the plan's name, height, and deprecated fields but does NOT validate the JSON syntax in the `Info` field. [1](#0-0)  When `BeginBlocker` executes, it calls `plan.UpgradeDetails()` which attempts to parse the JSON. [3](#0-2)  If the JSON is malformed (e.g., `{upgradeType:minor}` missing quotes), `json.Unmarshal` fails and returns an error along with an empty `UpgradeDetails{}` struct. [2](#0-1)  The error is only logged and ignored. The empty struct has `UpgradeType = ""`, causing `IsMinorRelease()` to return false. The code then falls through to the major upgrade logic, and if a handler exists (because validators updated early), the node panics with "BINARY UPDATED BEFORE TRIGGER!". [6](#0-5) 

**Exploitation Path:**
1. An attacker (or accidental human error) submits a governance proposal with malformed JSON in the `Info` field (e.g., `{upgradeType:minor}` instead of `{"upgradeType":"minor"}`)
2. The proposal passes validation because `ValidateBasic()` doesn't check JSON syntax [1](#0-0) 
3. The governance proposal is approved through standard voting
4. The upgrade plan is scheduled via `ScheduleUpgrade()`, which also doesn't validate JSON [5](#0-4) 
5. Validators, believing the upgrade is minor (based on proposal description or external communications), update their binaries before the scheduled height
6. When `BeginBlocker` executes before the scheduled height, the JSON parsing fails silently [3](#0-2) 
7. The upgrade is incorrectly classified as major release
8. Each validator node with the updated handler panics [6](#0-5) 
9. If ≥30% of validators are affected, the network experiences severe degradation or halts consensus (if >33% are affected)

**Security Guarantee Broken:**
The upgrade type detection mechanism is a critical security feature that allows safe early binary updates for minor releases. By silently failing to parse upgrade type information and defaulting to restrictive major upgrade behavior, the system violates the documented minor upgrade protocol and creates a vector for network-wide availability attacks.

## Impact Explanation

The impact affects network availability and validator node operation:

- **Validator Panics:** All validators who updated their binaries early (following documented minor upgrade best practices) will experience node crashes with the "BINARY UPDATED BEFORE TRIGGER!" panic message
- **Network Degradation:** If 30-33% of validators are affected, the network continues operating but with degraded consensus quality and reduced safety margins below the Byzantine fault tolerance threshold
- **Network Halt:** If >33% of validators are affected, the network cannot reach the 2/3+ consensus threshold and completely halts, unable to produce new blocks
- **Recovery Complexity:** Affected validators must either roll back their binaries or coordinate to skip the upgrade height, requiring emergency off-chain coordination
- **Economic Impact:** Network downtime affects all users, dApps, and economic activity on the chain

This matches the Medium severity impact: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network" (for 30-33% affected) or potentially "Network not being able to confirm new transactions (total network shutdown)" (for >33% affected).

## Likelihood Explanation

**Triggering Parties:**
- Any participant who can submit and pass governance proposals (requires governance token holdings and community support - this is a public democratic process, not privileged access)
- Accidental trigger through human error when crafting proposals (JSON syntax errors are common)

**Required Conditions:**
1. Governance proposal containing malformed JSON in the `Info` field must be submitted and approved
2. Validators must believe the upgrade is a minor release (through proposal description, official communications, documentation)
3. Validators must update their binaries before the scheduled upgrade height (standard practice for minor upgrades)
4. `BeginBlock` must execute with the updated handlers present

**Likelihood Assessment:**
- **Moderate to High:** JSON syntax errors are common in human-crafted text. Missing quotes, trailing commas, or incorrect escaping are frequent mistakes
- **Realistic Scenario:** Validators rely on external communications and documentation to determine upgrade types. If the proposal description states "minor upgrade" but the JSON is malformed, validators have no way to detect the issue until runtime
- **No Early Warning:** The malformed JSON is only detected when `BeginBlocker` executes, not during proposal validation or submission [3](#0-2) 
- **Coordination Problem:** Validators typically update in batches before minor releases, making it likely that multiple validators would be affected simultaneously

## Recommendation

Add JSON validation to the upgrade plan validation flow to reject malformed JSON early. Either enhance `Plan.ValidateBasic()` to include JSON validation:

```go
func (p Plan) ValidateBasic() error {
    // ... existing validations ...
    
    // Validate JSON syntax in Info field if present
    if p.Info != "" {
        if _, err := p.UpgradeDetails(); err != nil {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, 
                fmt.Sprintf("invalid JSON in Info field: %v", err))
        }
    }
    
    return nil
}
```

Or add validation in `ScheduleUpgrade()`:

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

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Setup:** 
- Initialize test suite at height 10 with no skip heights
- Schedule upgrade at height 20 with malformed JSON: `{upgradeType:minor}` (missing quotes around key and value)

**Action:**
1. Submit governance proposal with malformed JSON upgrade info
2. Register upgrade handler (simulating validator updating binary early for minor release)
3. Execute `BeginBlock` at height 15 (before scheduled height of 20)

**Expected Result (Bug):**
- Node panics with "BINARY UPDATED BEFORE TRIGGER!" message
- This demonstrates that malformed JSON bypasses minor release detection and triggers major upgrade panic logic

**Test Function:**
```go
func TestMalformedJSONBypassesMinorUpgradeDetection(t *testing.T) {
    s := setupTest(10, map[int64]bool{})
    malformedMinorUpgradeInfo := `{upgradeType:minor}` // Missing quotes
    
    err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Minor Upgrade Test",
        Plan: types.Plan{Name: "test_minor", Height: 20, Info: malformedMinorUpgradeInfo},
    })
    require.NoError(t, err) // Proposal accepted despite malformed JSON
    
    s.keeper.SetUpgradeHandler("test_minor", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    newCtx := s.ctx.WithBlockHeight(15)
    req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
    
    // PANICS due to malformed JSON bypassing minor release detection
    require.Panics(t, func() {
        s.module.BeginBlock(newCtx, req)
    })
}
```

**Comparison Test (Valid JSON):**
The same scenario with valid JSON `{"upgradeType":"minor"}` should NOT panic, proving the issue is specifically the malformed JSON handling.

## Notes

This vulnerability is particularly dangerous because:

1. **Silent Failure:** The JSON parsing error is only logged, not caught during validation [3](#0-2) , providing no early warning to operators

2. **Documented Protocol Violation:** The minor/major upgrade distinction is documented behavior that validators rely on for safe binary updates

3. **Coordination Attack Surface:** The issue can cause widespread simultaneous panics if multiple validators act on the same malformed proposal

4. **Human Error Vector:** JSON syntax errors are common and could occur accidentally, making this a realistic non-adversarial failure mode

5. **Beyond Governance Authority:** Even though governance is a trusted process, the silent failure causes unintended network shutdown that is beyond the intended authority of a minor upgrade proposal - governance intends to schedule a safe minor upgrade, but malformed JSON causes catastrophic validator panics

The fix is straightforward: add JSON syntax validation during the proposal validation phase to reject malformed upgrade plans before they can be scheduled.

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

**File:** x/upgrade/keeper/keeper.go (L177-180)
```go
func (k Keeper) ScheduleUpgrade(ctx sdk.Context, plan types.Plan) error {
	if err := plan.ValidateBasic(); err != nil {
		return err
	}
```
