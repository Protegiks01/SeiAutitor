# Audit Report

## Title
Network Halt Due to Insufficient Validation of Upgrade Plan Names Allowing Whitespace

## Summary
The upgrade module's `ValidateBasic()` function only validates that plan names are non-empty but does not check for whitespace-only names or names with leading/trailing whitespace. This allows governance proposals to schedule upgrades with malformed names that cause a complete network halt when exact string matching fails during handler lookup at the upgrade height.

## Impact
Medium

## Finding Description

**Location:**
- Validation: [1](#0-0) 
- Handler registration: [2](#0-1) 
- Handler lookup: [3](#0-2) 
- Panic trigger: [4](#0-3) 
- Panic function: [5](#0-4) 
- Governance validation: [6](#0-5) 
- Scheduling validation: [7](#0-6) 

**Intended Logic:**
The validation should ensure upgrade plan names are valid, non-empty identifiers that can reliably match registered upgrade handlers. When an upgrade height is reached, the system should successfully match the scheduled plan name with a registered handler and execute the upgrade without network disruption.

**Actual Logic:**
The current validation only checks `len(p.Name) == 0`, which rejects empty strings but accepts whitespace-only names (e.g., `" "`, `"  "`) and names with leading/trailing whitespace (e.g., `" v2.0"`, `"v2.0 "`). The handler lookup in `HasHandler()` performs exact string matching using Go map lookup without any trimming or normalization. When a mismatch occurs between the scheduled plan name and registered handler name, the system triggers a panic.

**Exploitation Path:**
1. A governance proposal is submitted with an upgrade plan containing a name with whitespace (e.g., `" v2.0"` with leading space or invisible Unicode whitespace)
2. The proposal passes `ValidateBasic()` validation because `len(" v2.0") = 5 ≠ 0`
3. The proposal goes through governance voting and passes (whitespace may be invisible in UIs or go unnoticed)
4. The upgrade is scheduled via `ScheduleUpgrade()` which calls the insufficient `ValidateBasic()`
5. Developers register an upgrade handler using the trimmed name `"v2.0"` following standard naming conventions
6. At the upgrade height, `BeginBlocker()` in `abci.go` checks if a handler exists for `" v2.0"` (with space)
7. The `HasHandler()` lookup fails because `" v2.0" != "v2.0"` (exact string match in map)
8. All validator nodes execute `panicUpgradeNeeded()` and halt simultaneously
9. The entire network stops producing blocks, requiring coordinated manual intervention

**Security Guarantee Broken:**
The network availability guarantee is violated. The system enters a complete denial-of-service state where no transactions can be processed, breaking the fundamental blockchain property of liveness.

## Impact Explanation

**Affected Process:** Network consensus and block production

**Consequences:**
When all validator nodes panic at the same block height due to handler name mismatch, the blockchain cannot produce new blocks, resulting in:
- Complete halt of transaction processing
- No new blocks produced across the entire network
- Requires coordinated manual intervention by all validators to recover (either skip the upgrade height via node restart with skip flags, or deploy binaries with matching handler names including whitespace)
- Potential loss of user confidence and economic damage from network downtime
- Service disruption for all applications and users depending on the chain

This directly matches the explicitly listed impact: "Network not being able to confirm new transactions (total network shutdown)" which is classified as Medium severity.

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit governance proposals (requires minimum deposit amount) and achieve voting approval through the democratic governance process. This is not a privileged action - governance is designed to be accessible to the community.

**Conditions Required:**
- A governance proposal with a plan name containing whitespace must be submitted
- The proposal must pass the voting threshold (requires community approval)
- Developers must register handlers with different names (typically trimmed versions, which is standard practice)
- The blockchain must reach the scheduled upgrade height

**Likelihood:**
While governance upgrades happen infrequently, the risk of whitespace introduction is realistic and non-trivial:
- **Invisible whitespace**: Zero-width spaces (U+200B), non-breaking spaces (U+00A0), and other Unicode whitespace characters are invisible in most UIs but would cause the exact string match to fail
- **Copy-paste artifacts**: Copying upgrade names from Slack, Discord, documentation, or terminal output frequently introduces leading/trailing whitespace unintentionally
- **UI limitations**: Many blockchain explorers and governance UIs trim or don't clearly display leading/trailing whitespace, making it difficult for voters and developers to notice
- **Standard developer practices**: Developers follow clean naming conventions without whitespace and may not perform byte-level verification of on-chain plan names
- **No validation warnings**: The system provides no warning that whitespace will cause critical issues

Once triggered (either accidentally or maliciously), the result is deterministic: complete network halt requiring emergency coordination.

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

This ensures plan names are validated for both content (non-empty after trimming) and format (no leading/trailing whitespace), preventing the network halt scenario.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Setup:**
1. Use the existing `setupTest()` helper function to initialize a test environment with the upgrade keeper
2. Initialize the test suite with appropriate block height and empty skip map

**Action:**
```go
func TestWhitespaceNameCausesNetworkHalt(t *testing.T) {
    // Setup test environment
    s := setupTest(10, map[int64]bool{})
    
    // Test 1: Whitespace-only name passes validation incorrectly
    planWithSpaces := types.Plan{Name: "   ", Height: 15}
    err := planWithSpaces.ValidateBasic()
    require.NoError(t, err) // BUG: Should fail but passes
    
    // Test 2: Schedule upgrade with leading whitespace
    planWithLeading := types.Plan{Name: " test-upgrade", Height: 15}
    err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Test Proposal", 
        Plan: planWithLeading,
    })
    require.NoError(t, err) // Proposal accepted
    
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
    }) // VULNERABILITY: All validators panic, network halts
    
    // Test 6: Verify it only works with exact match including whitespace
    s.keeper.SetUpgradeHandler(" test-upgrade", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    require.NotPanics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }) // Works only when whitespace matches exactly
}
```

**Result:**
The test demonstrates that:
1. Whitespace-only names (`"   "`) incorrectly pass `ValidateBasic()` 
2. Names with leading/trailing whitespace are accepted through governance
3. When handlers are registered with trimmed names (standard developer practice), `BeginBlock()` panics at upgrade height
4. This panic occurs simultaneously on all validator nodes, causing complete network shutdown
5. Recovery requires exact string match including whitespace, which is non-intuitive and error-prone

The PoC can be executed with: `go test -v -run TestWhitespaceNameCausesNetworkHalt ./x/upgrade/`

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
