# Audit Report

## Title
Network Halt Due to Insufficient Validation of Upgrade Plan Names Allowing Whitespace

## Summary
The upgrade module's `ValidateBasic()` function only validates that plan names are non-empty but does not check for whitespace-only names or names with leading/trailing whitespace. This validation gap allows governance proposals to schedule upgrades with malformed names that cause a complete network halt when exact string matching fails during handler lookup at the upgrade height.

## Impact
Medium

## Finding Description

**Location:**
- Validation: [1](#0-0) 
- Handler registration: [2](#0-1) 
- Handler lookup: [3](#0-2) 
- Scheduling validation: [4](#0-3) 
- Panic trigger: [5](#0-4) 
- Panic function: [6](#0-5) 
- Governance validation: [7](#0-6) 

**Intended Logic:**
The validation should ensure upgrade plan names are valid, non-empty identifiers that can reliably match registered upgrade handlers. When an upgrade height is reached, the system should successfully match the scheduled plan name with a registered handler and execute the upgrade without network disruption.

**Actual Logic:**
The current validation only checks `len(p.Name) == 0`, which rejects empty strings but accepts whitespace-only names (e.g., `" "`, `"  "`) and names with leading/trailing whitespace (e.g., `" v2.0"`, `"v2.0 "`). The handler lookup in `HasHandler()` performs exact string matching using Go map lookup without any trimming or normalization. When a mismatch occurs between the scheduled plan name and registered handler name, the system triggers a deterministic panic across all validator nodes.

**Exploitation Path:**
1. A governance proposal is submitted with an upgrade plan containing a name with whitespace (could be leading/trailing spaces or invisible Unicode whitespace characters like U+200B zero-width space or U+00A0 non-breaking space)
2. The proposal passes `ValidateBasic()` validation because the length check only rejects empty strings: `len(" v2.0") = 5 ≠ 0`
3. The proposal goes through governance voting and passes (whitespace may be invisible in blockchain explorers and governance UIs, or go unnoticed by voters)
4. The upgrade is scheduled via `ScheduleUpgrade()` which calls the insufficient `ValidateBasic()` validation
5. Developers register an upgrade handler using the trimmed name `"v2.0"` following standard clean naming conventions
6. At the upgrade height, `BeginBlocker()` retrieves the plan and checks if a handler exists for `" v2.0"` (with space)
7. The `HasHandler()` lookup fails because `" v2.0" != "v2.0"` (exact string comparison in Go map)
8. All validator nodes execute `panicUpgradeNeeded()` simultaneously in their `BeginBlocker()`
9. The entire network stops producing blocks, requiring coordinated manual intervention

**Security Guarantee Broken:**
The network liveness guarantee is violated. The blockchain enters a complete denial-of-service state where no transactions can be processed, breaking the fundamental property of continued block production.

## Impact Explanation

**Affected Process:** Network consensus and block production across all validator nodes

**Consequences:**
When all validator nodes panic at the same block height due to the handler name mismatch, the blockchain cannot produce new blocks, resulting in:
- Complete halt of transaction processing network-wide
- No new blocks produced across the entire network
- Requires coordinated manual intervention by all validators to recover (either skip the upgrade height via node restart with `--unsafe-skip-upgrades` flag, or deploy new binaries with matching handler names including the whitespace)
- Potential loss of user confidence and economic damage from extended network downtime
- Service disruption for all applications and users depending on the chain
- Emergency coordination overhead for validator operators

This directly matches the explicitly listed Medium severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit governance proposals (requires minimum deposit amount achievable by any community member) and achieve voting approval through the standard democratic governance process. Governance participation is not a privileged action - it is designed to be accessible to the community.

**Conditions Required:**
- A governance proposal with a plan name containing whitespace must be submitted (can happen accidentally)
- The proposal must pass the voting threshold through normal governance approval
- Developers must register handlers with different names (typically trimmed versions following standard clean code practices)
- The blockchain must reach the scheduled upgrade height

**Likelihood:**
While governance upgrades occur infrequently, the risk of whitespace introduction is realistic and non-trivial for several reasons:

- **Invisible Unicode whitespace**: Characters like zero-width spaces (U+200B), non-breaking spaces (U+00A0), and other Unicode whitespace are invisible in most UIs but cause the exact string match to fail
- **Copy-paste artifacts**: Copying upgrade names from Slack, Discord, documentation, terminal output, or web pages frequently introduces leading/trailing whitespace unintentionally
- **UI limitations**: Many blockchain explorers and governance UIs automatically trim whitespace for display purposes or don't clearly show it, making it difficult for voters and developers to detect the issue
- **Standard developer practices**: Developers naturally follow clean naming conventions without whitespace and may not perform byte-level verification of on-chain plan names
- **No validation warnings**: The system provides no warning that whitespace will cause critical network failure

Once triggered (either accidentally through invisible characters or unintentionally via copy-paste), the result is deterministic: complete network halt requiring emergency coordination across all validators.

## Recommendation

Add comprehensive whitespace validation to the `ValidateBasic()` function in `x/upgrade/types/plan.go`:

```go
func (p Plan) ValidateBasic() error {
    if !p.Time.IsZero() {
        return sdkerrors.ErrInvalidRequest.Wrap("time-based upgrades have been deprecated in the SDK")
    }
    if p.UpgradedClientState != nil {
        return sdkerrors.ErrInvalidRequest.Wrap("upgrade logic for IBC has been moved to the IBC module")
    }
    
    // Trim whitespace and validate
    trimmedName := strings.TrimSpace(p.Name)
    if len(trimmedName) == 0 {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot be empty or contain only whitespace")
    }
    
    // Reject names with leading/trailing whitespace
    if trimmedName != p.Name {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot have leading or trailing whitespace")
    }
    
    if p.Height <= 0 {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "height must be greater than 0")
    }

    return nil
}
```

This ensures plan names are validated for both content (non-empty after trimming) and format (no leading/trailing whitespace), preventing the network halt scenario before the proposal can be submitted.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Setup:**
1. Use the existing `setupTest()` helper function from the test file to initialize a test environment with the upgrade keeper
2. Initialize the test suite with block height 10 and empty skip map

**Action:**
```go
func TestWhitespaceNameCausesNetworkHalt(t *testing.T) {
    // Setup test environment
    s := setupTest(10, map[int64]bool{})
    
    // Test 1: Whitespace-only name passes validation incorrectly
    planWithSpaces := types.Plan{Name: "   ", Height: 15}
    err := planWithSpaces.ValidateBasic()
    require.NoError(t, err) // BUG: Should fail but passes because len("   ") = 3
    
    // Test 2: Schedule upgrade with leading whitespace
    planWithLeading := types.Plan{Name: " test-upgrade", Height: 15}
    err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Test Proposal", 
        Description: "Test",
        Plan: planWithLeading,
    })
    require.NoError(t, err) // Proposal accepted through governance
    
    // Test 3: Developer registers handler with trimmed name (standard practice)
    s.keeper.SetUpgradeHandler("test-upgrade", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    // Test 4: Advance to upgrade height
    newCtx := s.ctx.WithBlockHeight(15)
    req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
    
    // Test 5: BeginBlocker panics due to handler name mismatch
    require.Panics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }) // VULNERABILITY: All validators panic simultaneously, network halts
    
    // Test 6: Verify it only works with exact match including whitespace
    s.keeper.SetUpgradeHandler(" test-upgrade", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    require.NotPanics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }) // Works only when whitespace matches exactly (non-intuitive)
}
```

**Result:**
The test demonstrates that:
1. Whitespace-only names (e.g., `"   "`) incorrectly pass `ValidateBasic()` validation
2. Names with leading/trailing whitespace are accepted through governance proposal validation
3. When handlers are registered with trimmed names (standard developer practice), the `BeginBlock()` function panics at upgrade height
4. This panic occurs simultaneously on all validator nodes since BeginBlocker execution is deterministic, causing complete network shutdown
5. Recovery requires either skipping the upgrade height or deploying binaries with handler names that exactly match the whitespace, which is non-intuitive and error-prone

The PoC can be executed with: `go test -v -run TestWhitespaceNameCausesNetworkHalt ./x/upgrade/`

## Notes

This vulnerability exists because the validation layer insufficiently checks the format of upgrade plan names, allowing whitespace that causes exact string matching to fail during handler lookup. The issue is particularly insidious because:

1. **Invisible characters**: Unicode whitespace characters (U+200B, U+00A0, etc.) are valid in Go strings but invisible in most user interfaces
2. **Copy-paste scenarios**: Real-world upgrade coordination often involves copying names between tools, introducing whitespace accidentally
3. **No defensive checks**: Neither the validation layer nor the handler lookup includes defensive trimming or normalization

The fix is straightforward: enhance validation to reject whitespace-only names and names with leading/trailing whitespace at the proposal submission stage, preventing the catastrophic network halt scenario.

### Citations

**File:** x/upgrade/types/plan.go (L28-30)
```go
	if len(p.Name) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot be empty")
	}
```

**File:** x/upgrade/keeper/keeper.go (L67-69)
```go
func (k Keeper) SetUpgradeHandler(name string, upgradeHandler types.UpgradeHandler) {
	k.upgradeHandlers[name] = upgradeHandler
}
```

**File:** x/upgrade/keeper/keeper.go (L177-180)
```go
func (k Keeper) ScheduleUpgrade(ctx sdk.Context, plan types.Plan) error {
	if err := plan.ValidateBasic(); err != nil {
		return err
	}
```

**File:** x/upgrade/keeper/keeper.go (L359-362)
```go
func (k Keeper) HasHandler(name string) bool {
	_, ok := k.upgradeHandlers[name]
	return ok
}
```

**File:** x/upgrade/abci.go (L68-70)
```go
		if !k.HasHandler(plan.Name) {
			panicUpgradeNeeded(k, ctx, plan)
		}
```

**File:** x/upgrade/abci.go (L101-112)
```go
func panicUpgradeNeeded(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	// Write the upgrade info to disk. The UpgradeStoreLoader uses this info to perform or skip
	// store migrations.
	err := k.DumpUpgradeInfoWithInfoToDisk(ctx.BlockHeight(), plan.Name, plan.Info)
	if err != nil {
		panic(fmt.Errorf("unable to write upgrade info to filesystem: %s", err.Error()))
	}

	upgradeMsg := BuildUpgradeNeededMsg(plan)
	ctx.Logger().Error(upgradeMsg)

	panic(upgradeMsg)
```

**File:** x/upgrade/types/proposal.go (L32-36)
```go
func (sup *SoftwareUpgradeProposal) ValidateBasic() error {
	if err := sup.Plan.ValidateBasic(); err != nil {
		return err
	}
	return gov.ValidateAbstract(sup)
```
