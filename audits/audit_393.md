# Audit Report

## Title
Network Halt Due to Insufficient Validation of Upgrade Plan Names Allowing Whitespace

## Summary
The `ValidateBasic()` function in the upgrade module only checks if the plan name is empty (length zero) but does not validate against whitespace-only names or names with leading/trailing whitespace. This allows governance proposals to schedule upgrades with names like `" v2.0"` or `"  "` (spaces), which will cause a complete network halt when the exact string match fails during handler lookup at the upgrade height. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Validation: `x/upgrade/types/plan.go`, lines 28-30 in `ValidateBasic()` function
- Handler lookup: `x/upgrade/keeper/keeper.go`, lines 359-362 in `HasHandler()` function  
- Panic trigger: `x/upgrade/abci.go`, lines 68-70 in `BeginBlocker()` function

**Intended Logic:** 
The validation should ensure that upgrade plan names are valid, non-empty identifiers that can reliably be used to look up registered upgrade handlers. When an upgrade height is reached, the system should be able to match the scheduled plan name with a registered handler and execute the upgrade.

**Actual Logic:** 
The current validation only checks `len(p.Name) == 0`, which rejects empty strings but accepts:
- Whitespace-only names: `" "`, `"  "`, `"\t"`, `"\n"`
- Names with leading/trailing whitespace: `" upgrade"`, `"upgrade "`, `" upgrade "` [1](#0-0) 

The handler lookup performs exact string matching without any trimming: [2](#0-1) 

**Exploit Scenario:**
1. A governance proposal is submitted through the normal channels with an upgrade plan containing a name with whitespace (e.g., `" v2.0"` with a leading space, or `"v2.0 "` with trailing space) - this can happen accidentally through copy-paste errors
2. The proposal passes `ValidateBasic()` because `len(" v2.0") = 5`, which is not zero [3](#0-2) 

3. The proposal goes through governance voting and passes
4. The upgrade is scheduled in state via `ScheduleUpgrade()`, which calls `ValidateBasic()` [4](#0-3) 

5. Developers prepare the new binary and register an upgrade handler using the trimmed name `"v2.0"` (without whitespace), as is standard practice [5](#0-4) 

6. At the upgrade height, `BeginBlocker()` checks if a handler exists for `" v2.0"` (with space)
7. The `HasHandler()` lookup fails because `" v2.0" != "v2.0"` (exact string match) [6](#0-5) 

8. All validator nodes panic with the "UPGRADE NEEDED" message [7](#0-6) 

9. The entire network halts as all nodes stop producing blocks

**Security Failure:** 
This breaks the availability guarantee of the blockchain. The system enters a denial-of-service state where no new transactions can be processed, and the network cannot progress until all validators manually intervene to either skip the upgrade height or update their binaries with a matching handler name (including the whitespace).

## Impact Explanation

**Affected Process:** Network availability and block production

**Severity of Damage:** Complete network shutdown. When all validator nodes panic at the same block height due to the missing handler, the blockchain cannot produce new blocks. This results in:
- No new transactions can be confirmed
- Complete halt of all on-chain operations
- Requires coordinated manual intervention by all validators to recover
- Potential loss of user confidence and economic impact

**Why It Matters:** 
This vulnerability can cause a High-severity outage ("Network not being able to confirm new transactions (total network shutdown)") from what appears to be a simple oversight - an accidental space character in a governance proposal. The impact is catastrophic despite the simplicity of the trigger condition.

## Likelihood Explanation

**Who Can Trigger:** Any participant who can submit governance proposals (requires deposit) and get them voted through. However, the vulnerability is most likely to be triggered accidentally rather than maliciously.

**Conditions Required:**
- A governance proposal must be submitted with a plan name containing whitespace
- The proposal must pass the voting threshold
- Developers must register handlers with trimmed/different names (standard practice)
- The blockchain must reach the scheduled upgrade height

**Frequency:** 
While governance upgrades happen infrequently (typically every few months), the risk of accidental whitespace introduction is non-trivial:
- Copy-paste from documentation or chat messages can introduce whitespace
- Manual typing errors can add trailing/leading spaces
- Different text editors may handle whitespace differently
- The validation provides no warning that whitespace will cause issues

Once triggered, it results in complete network halt every time, making this a high-impact vulnerability despite moderate likelihood.

## Recommendation

Add whitespace validation to the `ValidateBasic()` function in `x/upgrade/types/plan.go`:

1. Trim the plan name and check if it's empty after trimming
2. Reject names that contain only whitespace
3. Optionally reject names with leading/trailing whitespace, or automatically trim them during validation

Example fix:
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
    
    // Optionally reject names with leading/trailing whitespace
    if trimmedName != p.Name {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot have leading or trailing whitespace")
    }
    
    if p.Height <= 0 {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "height must be greater than 0")
    }

    return nil
}
```

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func TestWhitespaceNameCausesNetworkHalt(t *testing.T) {
    s := setupTest(10, map[int64]bool{})
    
    // Test 1: Whitespace-only name passes validation
    t.Log("Test that whitespace-only name passes validation incorrectly")
    whitespacePlan := types.Plan{
        Name:   "   ",  // Three spaces
        Height: 15,
    }
    err := whitespacePlan.ValidateBasic()
    require.NoError(t, err, "Whitespace-only name should fail validation but doesn't")
    
    // Test 2: Name with leading whitespace passes validation
    t.Log("Test that name with leading whitespace passes validation")
    leadingSpacePlan := types.Plan{
        Name:   " test-upgrade",  // Leading space
        Height: 20,
    }
    err = leadingSpacePlan.ValidateBasic()
    require.NoError(t, err, "Name with leading space passes validation")
    
    // Test 3: Schedule upgrade with leading space via governance
    t.Log("Schedule upgrade with name containing leading space")
    err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Upgrade with whitespace",
        Plan:  leadingSpacePlan,
    })
    require.NoError(t, err)
    
    // Test 4: Developer registers handler with trimmed name (standard practice)
    t.Log("Register handler with trimmed name (without the leading space)")
    s.keeper.SetUpgradeHandler("test-upgrade", func(ctx sdk.Context, plan types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    // Test 5: At upgrade height, node panics due to handler name mismatch
    t.Log("Verify that node panics at upgrade height due to name mismatch")
    newCtx := s.ctx.WithBlockHeight(20).WithBlockTime(time.Now())
    req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
    
    // This demonstrates the network halt: all nodes will panic
    require.Panics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }, "Node should panic because ' test-upgrade' != 'test-upgrade'")
    
    // Test 6: Verify that with matching whitespace in handler, it would work
    t.Log("Verify that with exact name match (including whitespace), upgrade would succeed")
    s.keeper.SetUpgradeHandler(" test-upgrade", func(ctx sdk.Context, plan types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    require.NotPanics(t, func() {
        s.module.BeginBlock(newCtx, req)
    }, "With exact name match including whitespace, upgrade succeeds")
}
```

**Setup:** The test uses the existing `setupTest()` helper to initialize a test environment with the upgrade keeper.

**Trigger:** 
1. Creates upgrade plans with whitespace-only and whitespace-padded names
2. Verifies these pass validation (demonstrating the bug)
3. Schedules an upgrade via governance with a name containing leading whitespace
4. Registers a handler with the trimmed version of the name
5. Advances to the upgrade height

**Observation:** 
The test demonstrates that:
1. Whitespace-only and whitespace-padded names incorrectly pass validation
2. When the handler is registered with a trimmed name (standard practice), the node panics at upgrade height
3. This panic would occur on all validator nodes simultaneously, causing complete network halt
4. Only when the handler name exactly matches (including whitespace) does the upgrade succeed

This PoC can be run with: `go test -v -run TestWhitespaceNameCausesNetworkHalt ./x/upgrade/`

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

**File:** x/upgrade/types/proposal.go (L32-36)
```go
func (sup *SoftwareUpgradeProposal) ValidateBasic() error {
	if err := sup.Plan.ValidateBasic(); err != nil {
		return err
	}
	return gov.ValidateAbstract(sup)
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
