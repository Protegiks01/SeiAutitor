# Audit Report

## Title
Consensus Failure Due to Non-Deterministic skipUpgradeHeights Configuration Causing Permanent Chain Split

## Summary
The upgrade module's `skipUpgradeHeights` configuration allows validators to bypass scheduled upgrades using the `--unsafe-skip-upgrades` CLI flag. However, this per-node configuration causes non-deterministic state transitions during BeginBlock execution: validators with the skip configured clear the upgrade plan from consensus state and continue, while validators without it panic and halt. This creates an unrecoverable consensus failure and permanent network partition requiring a hard fork to resolve.

## Impact
**High**

## Finding Description

**Location:** 
- Primary divergence point: [1](#0-0) 
- State modification in skip path: [2](#0-1) 
- State deletion: [3](#0-2) 
- Local configuration storage: [4](#0-3) 
- Configuration parsing: [5](#0-4) 

**Intended Logic:**
The upgrade module ensures all validators execute scheduled upgrades at the same block height to maintain consensus. The `skipUpgradeHeights` is documented as an emergency mechanism where validators coordinate to bypass problematic upgrades. Documentation states: "If over two-thirds run their nodes with this flag on the old binary, it will allow the chain to continue" [6](#0-5)  - implying coordinated use.

**Actual Logic:**
The `skipUpgradeHeights` is a local per-node configuration map populated from the `--unsafe-skip-upgrades` CLI flag with no validation ensuring all validators share the same configuration. During BeginBlock execution at an upgrade height:

1. Validators with the height in `skipUpgradeHeights` call `IsSkipHeight()` which returns true, then execute `skipUpgrade()` which calls `ClearUpgradePlan(ctx)`, modifying consensus state by deleting the upgrade plan from the KV store
2. Validators without the height in `skipUpgradeHeights` skip the skip path, find no registered handler, and panic via `panicUpgradeNeeded()`

**Exploitation Path:**
1. Governance schedules an upgrade at height H
2. Before height H, due to miscommunication or emergency response, some validators configure `--unsafe-skip-upgrades=H` while others don't
3. At height H, validators execute BeginBlock:
   - Validators with skip: Clear upgrade plan from state, continue processing, commit state, produce AppHash without plan
   - Validators without skip: Panic before state commit, cannot participate in consensus
4. Network partitions based on validator configuration:
   - If >2/3 voting power has skip: Chain continues, other validators permanently stuck at height H-1
   - If <2/3 voting power has skip: Chain cannot reach consensus, total halt
5. No recovery mechanism exists; requires hard fork to resolve

**Security Guarantee Broken:**
Consensus determinism - all validators must execute identical state transitions for the same block height. The `skipUpgradeHeights` allows different validators to execute different code paths with different state outcomes, violating the fundamental consensus invariant.

## Impact Explanation

**Affected Components:**
- Network consensus integrity
- Chain continuity 
- Validator participation
- Transaction finality

**Consequences:**
- **Permanent chain split**: Validators diverge into incompatible state machines at the upgrade height
- **Voting power dependency**: 
  - If >2/3 voting power skips: Chain continues without non-skipping validators (they're permanently excluded)
  - If <2/3 voting power skips: Chain halts entirely (cannot reach 2/3 consensus)
- **Requires hard fork**: No in-protocol recovery mechanism exists; social consensus and coordinated hard fork required
- **Transaction risk**: All transactions processed during partition period are at risk of being invalidated

This matches the HIGH severity impact: "Unintended permanent chain split requiring hard fork (network partition requiring hard fork)"

## Likelihood Explanation

**Trigger Conditions:**
1. A scheduled upgrade exists in state
2. Validators use `--unsafe-skip-upgrades` flag with the upgrade height
3. Not all validators use identical skip configurations
4. The upgrade height is reached

**Probability:**
- **Moderate to High** during upgrade emergencies when validators attempt to skip problematic upgrades
- The flag name suggests emergency use ("unsafe"), precisely when coordination is most difficult
- No validation prevents configuration mismatch
- Could be triggered by:
  - Miscommunication during emergency response
  - Validators acting independently without full coordination
  - Social engineering convincing subset of validators to skip
  - Time zone differences in emergency communications

**Who Can Trigger:**
Validator operators through node configuration. While validators are privileged actors, this represents accidental misconfiguration rather than intentional attack, and the consequence (permanent chain split) exceeds validators' intended authority.

## Recommendation

**Primary Fix - Remove State Modification from Skip Path:**
When skipping an upgrade, do not call `ClearUpgradePlan(ctx)`. Instead:
```go
func skipUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
    skipUpgradeMsg := fmt.Sprintf("UPGRADE \"%s\" SKIPPED at %d: %s", plan.Name, plan.Height, plan.Info)
    ctx.Logger().Info(skipUpgradeMsg)
    // DO NOT clear the plan - keep it in state for determinism
    // k.ClearUpgradePlan(ctx)
}
```
The upgrade plan remains in consensus state but is locally ignored by nodes with skip configured, maintaining state consistency across all validators.

**Alternative Fix - Governance-Based Skip:**
Include skip decisions in the upgrade plan itself via governance parameters, ensuring all validators agree on which upgrades to skip before reaching that height.

**Immediate Mitigation:**
- Add prominent documentation warning that ALL validators MUST coordinate on identical `--unsafe-skip-upgrades` values
- Add startup validation warning when skip heights are configured
- Consider adding consensus checks or requiring governance approval for skip decisions

## Proof of Concept

**Test File:** `x/upgrade/abci_test.go`

**Setup:**
Create two validator instances with different skip configurations to simulate network partition:
- Validator A: `setupTest(10, map[int64]bool{15: true})` - has skip configured
- Validator B: `setupTest(10, map[int64]bool{})` - no skip configured
- Both schedule the same upgrade at height 15 via governance

**Action:**
Both validators reach height 15 and execute BeginBlock:
- Validator A executes `BeginBlock(ctx.WithBlockHeight(15), req)`
- Validator B executes `BeginBlock(ctx.WithBlockHeight(15), req)`

**Expected Result:**
- Validator A: Does NOT panic (skip configured), clears upgrade plan, continues
- Validator B: Panics (no skip, no handler), halts
- State verification shows Validator A has no upgrade plan in state, while Validator B retains it
- This demonstrates consensus failure: validators cannot agree on block validity at height 15

The existing tests in the file (TestSkipUpgradeSkippingAll, TestUpgradeWithoutSkip) test only single validators with given configurations, not the multi-validator consensus failure scenario.

## Notes

This vulnerability is particularly insidious because:

1. **Emergency Context**: The flag is designed for emergencies when coordination is hardest
2. **No Safeguards**: No code-level validation prevents mismatched configurations
3. **Silent Failure**: Validators don't know about others' configurations until the upgrade height is reached
4. **Irreversible**: Once triggered, requires social consensus and hard fork to resolve
5. **Documentation Insufficiency**: While docs mention coordination is needed, the code doesn't enforce it

The root cause is allowing non-deterministic behavior (local configuration affecting consensus-critical state transitions) without any validation or enforcement mechanism. This violates the fundamental principle that all validators must execute identical state machines.

### Citations

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

**File:** x/upgrade/abci.go (L120-125)
```go
// skipUpgrade logs a message that the upgrade has been skipped and clears the upgrade plan.
func skipUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	skipUpgradeMsg := fmt.Sprintf("UPGRADE \"%s\" SKIPPED at %d: %s", plan.Name, plan.Height, plan.Info)
	ctx.Logger().Info(skipUpgradeMsg)
	k.ClearUpgradePlan(ctx)
}
```

**File:** x/upgrade/keeper/keeper.go (L37-45)
```go
type Keeper struct {
	homePath           string                          // root directory of app config
	skipUpgradeHeights map[int64]bool                  // map of heights to skip for an upgrade
	storeKey           sdk.StoreKey                    // key to access x/upgrade store
	cdc                codec.BinaryCodec               // App-wide binary codec
	upgradeHandlers    map[string]types.UpgradeHandler // map of plan name to upgrade handler
	versionSetter      xp.ProtocolVersionSetter        // implements setting the protocol version field on BaseApp
	downgradeVerified  bool                            // tells if we've already sanity checked that this binary version isn't being used against an old state.
}
```

**File:** x/upgrade/keeper/keeper.go (L320-330)
```go
// ClearUpgradePlan clears any schedule upgrade and associated IBC states.
func (k Keeper) ClearUpgradePlan(ctx sdk.Context) {
	// clear IBC states everytime upgrade plan is removed
	oldPlan, found := k.GetUpgradePlan(ctx)
	if found {
		k.ClearIBCState(ctx, oldPlan.Height)
	}

	store := ctx.KVStore(k.storeKey)
	store.Delete(types.PlanKey())
}
```

**File:** simapp/simd/cmd/root.go (L262-265)
```go
	skipUpgradeHeights := make(map[int64]bool)
	for _, h := range cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades)) {
		skipUpgradeHeights[int64(h)] = true
	}
```

**File:** x/upgrade/doc.go (L128-134)
```go
However, let's assume that we don't realize the upgrade has a bug until shortly before it will occur
(or while we try it out - hitting some panic in the migration). It would seem the blockchain is stuck,
but we need to allow an escape for social consensus to overrule the planned upgrade. To do so, there's
a --unsafe-skip-upgrades flag to the start command, which will cause the node to mark the upgrade
as done upon hitting the planned upgrade height(s), without halting and without actually performing a migration.
If over two-thirds run their nodes with this flag on the old binary, it will allow the chain to continue through
the upgrade with a manual override. (This must be well-documented for anyone syncing from genesis later on).
```
