## Title
DowngradeVerified Check Bypass via Scheduled Upgrade Timing

## Summary
The downgrade verification check in the upgrade module's BeginBlocker can be bypassed when a node starts at exactly the block height of a scheduled upgrade. This allows validators to run incompatible binaries missing handlers for previously applied upgrades, potentially causing consensus failures and chain splits. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** The vulnerability exists in `x/upgrade/abci.go` in the `BeginBlocker` function, specifically in the conditional logic that determines when to verify the downgrade check. [1](#0-0) 

**Intended Logic:** The downgrade verification is meant to ensure that any binary running on the chain has upgrade handlers for ALL previously applied upgrades. This prevents validators from running downgraded or incompatible binaries that lack critical migration logic or consensus-breaking changes from past upgrades.

**Actual Logic:** The check only validates the last applied upgrade handler IF one of these conditions is true:
1. No scheduled upgrade exists (`!planFound`)
2. The scheduled upgrade is not ready (`!plan.ShouldExecute(ctx)`)  
3. The scheduled upgrade is ready but the height is skipped (`plan.ShouldExecute(ctx) && k.IsSkipHeight(ctx.BlockHeight())`)

However, when a scheduled upgrade IS ready to execute AND is NOT in the skip list, the entire downgrade verification is bypassed. The condition evaluates to `false || false || false = false`, causing the check at line 40 to never execute. [2](#0-1) 

**Exploit Scenario:**
1. Chain has completed upgrade "A" at height 100, which introduced consensus-critical changes
2. Governance schedules upgrade "B" for height 200
3. A validator (malicious or misconfigured) restarts their node at exactly height 200 with a binary that:
   - Contains the handler for upgrade "B" (to pass subsequent checks)
   - Does NOT contain the handler for upgrade "A" (missing historical upgrade logic)
4. At height 200 when BeginBlocker executes:
   - `planFound = true` (upgrade "B" exists)
   - `plan.ShouldExecute(ctx) = true` (200 <= 200)
   - `k.IsSkipHeight(200) = false` (not in skip list)
   - The downgrade check is completely skipped
5. Control flows to line 68 which only validates handler for "B" exists
6. The node proceeds with an incompatible binary [3](#0-2) 

**Security Failure:** This breaks the consensus agreement invariant. Validators running binaries without historical upgrade handlers will have different consensus logic and produce different state roots than validators running correct binaries, causing an unintended chain split.

## Impact Explanation

This vulnerability affects the fundamental consensus layer of the blockchain:

- **Consensus Breakdown:** Validators running incompatible binaries will compute different state transitions, producing divergent state roots and causing the chain to split into multiple incompatible forks.

- **Chain Split Requiring Hard Fork:** Once validators are running different binary versions that produce different state roots, the chain cannot recover without manual intervention. This requires a coordinated hard fork to restore consensus.

- **Network Availability:** If a significant portion of validators (>33%) run incompatible binaries, the chain may be unable to reach consensus and halt entirely.

- **Re-sync Failures:** Nodes running downgraded binaries cannot properly re-sync from genesis or snapshots because they lack the migration handlers needed to replay historical upgrade logic.

This directly maps to the "High: Unintended permanent chain split requiring hard fork" impact category in scope.

## Likelihood Explanation

This vulnerability has **medium to high likelihood** of being triggered:

**Who can trigger it:** Any validator can trigger this vulnerability, either maliciously or through misconfiguration. No special privileges beyond being a validator are required.

**Conditions required:**
- A scheduled upgrade must exist (common during normal chain operations)
- The validator must restart their node at exactly the upgrade height (very common, as validators coordinate restarts for upgrades)
- The validator must use a binary missing historical upgrade handlers (can happen through misconfiguration, using outdated binaries, or malicious intent)

**Frequency:** This can occur during any scheduled upgrade, which typically happens multiple times per year on active chains. The timing requirement (restart at upgrade height) is not difficult to achieve since validators typically coordinate to restart exactly at upgrade heights.

The presence of a TODO comment at line 445 in the test file indicates this scenario was recognized but never properly tested: [4](#0-3) 

## Recommendation

Modify the downgrade verification logic to ALWAYS check for the last applied upgrade handler, regardless of scheduled upgrade status. The check should be:

```go
if !k.DowngradeVerified() {
    k.SetDowngradeVerified(true)
    lastAppliedPlan, _ := k.GetLastCompletedUpgrade(ctx)
    
    // Always verify the binary has handler for last applied upgrade
    if lastAppliedPlan != "" && !k.HasHandler(lastAppliedPlan) {
        panic(fmt.Sprintf("Wrong app version %d, upgrade handler is missing for %s upgrade plan", 
            ctx.ConsensusParams().Version.AppVersion, lastAppliedPlan))
    }
}
```

Remove the conditional that checks for scheduled upgrade status, as this creates the bypass vulnerability. The downgrade check should be unconditional on first block after node startup.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** Add this test to the existing test suite:

```go
func TestDowngradeCheckBypassAtUpgradeHeight(t *testing.T) {
    s := setupTest(10, map[int64]bool{})
    
    // Setup: Apply upgrade "A" at height 12
    s.keeper.SetUpgradeHandler("upgradeA", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{
        Title: "Upgrade A",
        Plan:  types.Plan{Name: "upgradeA", Height: 12},
    })
    require.NoError(t, err)
    
    ctx12 := s.ctx.WithBlockHeight(12)
    req12 := abci.RequestBeginBlock{Header: ctx12.BlockHeader()}
    
    // Apply upgrade A
    require.NotPanics(t, func() {
        s.module.BeginBlock(ctx12, req12)
    })
    
    // Verify upgrade A was completed
    lastUpgrade, _ := s.keeper.GetLastCompletedUpgrade(ctx12)
    require.Equal(t, "upgradeA", lastUpgrade)
    
    // Schedule upgrade "B" for height 20
    s.keeper.SetUpgradeHandler("upgradeB", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    err = s.handler(ctx12, &types.SoftwareUpgradeProposal{
        Title: "Upgrade B", 
        Plan:  types.Plan{Name: "upgradeB", Height: 20},
    })
    require.NoError(t, err)
    
    // Simulate node restart at height 20 with fresh keeper (downgradeVerified = false)
    // This binary has handler for upgradeB but NOT for upgradeA (simulating downgrade)
    s2 := setupTest(20, map[int64]bool{})
    
    // Set done marker for upgradeA in state to simulate it was applied
    s2.keeper.SetDone(s2.ctx, "upgradeA")
    
    // Schedule upgradeB in the new keeper
    err = s2.handler(s2.ctx, &types.SoftwareUpgradeProposal{
        Title: "Upgrade B",
        Plan:  types.Plan{Name: "upgradeB", Height: 20},
    })
    require.NoError(t, err)
    
    // Add handler for upgradeB only (NOT upgradeA - this is the downgrade)
    s2.keeper.SetUpgradeHandler("upgradeB", func(_ sdk.Context, _ types.Plan, vm module.VersionMap) (module.VersionMap, error) {
        return vm, nil
    })
    
    // Create context at height 20 where upgrade should execute
    ctx20 := s2.ctx.WithBlockHeight(20)
    req20 := abci.RequestBeginBlock{Header: ctx20.BlockHeader()}
    
    // VULNERABILITY: This should panic because handler for upgradeA is missing,
    // but it doesn't panic because the downgrade check is bypassed when 
    // a plan is ready to execute
    require.NotPanics(t, func() {
        s2.module.BeginBlock(ctx20, req20)
    })
    
    // The test demonstrates the vulnerability: a binary missing the handler
    // for a previously applied upgrade (upgradeA) is able to run and apply
    // a new upgrade (upgradeB) without triggering the downgrade check
}
```

**Setup:** The test creates a chain that has applied upgrade "A" at height 12, then schedules upgrade "B" for height 20.

**Trigger:** A fresh keeper is created simulating a node restart at height 20. This keeper has the handler for upgrade "B" but NOT for upgrade "A", simulating a downgraded binary. The BeginBlock is called at height 20.

**Observation:** The test expects a panic due to the missing handler for "upgradeA", but no panic occurs. This demonstrates that the downgrade check is bypassed when starting at the exact height of a scheduled upgrade. The vulnerability allows an incompatible binary to continue operation, which would cause consensus failures in a real network.

### Citations

**File:** x/upgrade/abci.go (L31-44)
```go
	if !k.DowngradeVerified() {
		k.SetDowngradeVerified(true)
		lastAppliedPlan, _ := k.GetLastCompletedUpgrade(ctx)
		// This check will make sure that we are using a valid binary.
		// It'll panic in these cases if there is no upgrade handler registered for the last applied upgrade.
		// 1. If there is no scheduled upgrade.
		// 2. If the plan is not ready.
		// 3. If the plan is ready and skip upgrade height is set for current height.
		if !planFound || !plan.ShouldExecute(ctx) || (plan.ShouldExecute(ctx) && k.IsSkipHeight(ctx.BlockHeight())) {
			if lastAppliedPlan != "" && !k.HasHandler(lastAppliedPlan) {
				panic(fmt.Sprintf("Wrong app version %d, upgrade handler is missing for %s upgrade plan", ctx.ConsensusParams().Version.AppVersion, lastAppliedPlan))
			}
		}
	}
```

**File:** x/upgrade/abci.go (L61-72)
```go
	if plan.ShouldExecute(ctx) {
		// If skip upgrade has been set for current height, we clear the upgrade plan
		if k.IsSkipHeight(ctx.BlockHeight()) {
			skipUpgrade(k, ctx, plan)
			return
		}
		// If we don't have an upgrade handler for this upgrade name, then we need to shutdown
		if !k.HasHandler(plan.Name) {
			panicUpgradeNeeded(k, ctx, plan)
		}
		applyUpgrade(k, ctx, plan)
		return
```

**File:** x/upgrade/types/plan.go (L38-44)
```go
// ShouldExecute returns true if the Plan is ready to execute given the current context
func (p Plan) ShouldExecute(ctx sdk.Context) bool {
	if p.Height > 0 {
		return p.Height <= ctx.BlockHeight()
	}
	return false
}
```

**File:** x/upgrade/abci_test.go (L445-445)
```go
// TODO: add testcase to for `no upgrade handler is present for last applied upgrade`.
```
