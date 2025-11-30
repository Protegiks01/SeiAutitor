After thorough investigation of the codebase, I can now provide my validation assessment.

# Audit Report

## Title
Consensus Failure Due to Non-Deterministic skipUpgradeHeights Configuration Causing Permanent Chain Split

## Summary
The upgrade module's `skipUpgradeHeights` mechanism allows validators to bypass scheduled upgrades via the `--unsafe-skip-upgrades` CLI flag. This local per-node configuration creates non-deterministic state transitions: validators with skip configured delete the upgrade plan from consensus state and continue, while validators without skip panic and halt. This causes an unrecoverable consensus failure and permanent network partition requiring a hard fork.

## Impact
High

## Finding Description

**Location:**
- Primary divergence point: [1](#0-0) 
- State modification in skip path: [2](#0-1) 
- State deletion from consensus: [3](#0-2) 
- Local configuration storage: [4](#0-3) 
- CLI flag parsing: [5](#0-4) 

**Intended Logic:**
The upgrade module ensures all validators execute scheduled upgrades at the same block height to maintain consensus determinism. The documentation indicates coordination is required: [6](#0-5) 

**Actual Logic:**
The `skipUpgradeHeights` is a local per-node map with no validation ensuring all validators share the same configuration. During BeginBlock at an upgrade height:
1. Validators WITH skip configured: Call `skipUpgrade()` which executes `ClearUpgradePlan(ctx)`, deleting the upgrade plan from the KV store (modifying consensus state)
2. Validators WITHOUT skip: Skip the skip path, find no handler, panic via `panicUpgradeNeeded()` before committing state

**Exploitation Path:**
1. Governance schedules an upgrade at height H via standard proposal
2. Before height H, due to miscommunication or emergency response, some validators configure `--unsafe-skip-upgrades=H` while others don't
3. At height H during BeginBlock:
   - Validators with skip: Clear upgrade plan from consensus state, continue processing, commit modified state, produce AppHash without plan
   - Validators without skip: Panic before state commit, cannot participate in consensus
4. Network partitions based on voting power distribution:
   - If ≥2/3 voting power has skip: Chain continues on one fork, validators without skip permanently stuck
   - If <2/3 voting power has skip: Chain cannot reach consensus, total network halt
5. No in-protocol recovery mechanism exists; requires coordinated hard fork

**Security Guarantee Broken:**
Consensus determinism - the fundamental invariant that all validators must execute identical state transitions for the same block height. The code allows different validators to execute different state modifications based on local configuration, violating this core consensus property.

## Impact Explanation

**Consequences:**
- **Permanent chain split**: Validators diverge into incompatible state machines at the upgrade height with no recovery path
- **Network partition severity depends on validator configuration**:
  - If ≥2/3 validators skip: Chain continues without non-skipping validators (permanent exclusion)
  - If <2/3 validators skip: Total network shutdown (cannot reach consensus threshold)
- **Requires hard fork**: No in-protocol mechanism exists to reconcile the divergent states; requires social consensus and coordinated emergency hard fork
- **Transaction safety compromised**: All transactions in blocks after the divergence are at risk

This precisely matches the High severity impact category: "Unintended permanent chain split requiring hard fork (network partition requiring hard fork)".

## Likelihood Explanation

**Trigger Conditions:**
1. Scheduled upgrade exists in state (normal governance operation)
2. Validators use `--unsafe-skip-upgrades` flag (designed emergency mechanism)
3. Not all validators coordinate on identical skip configurations
4. Upgrade height is reached

**Probability Assessment:**
Moderate to High during upgrade emergencies. The mechanism is specifically designed for emergencies (flag named "unsafe-skip-upgrades"), precisely when coordination is most difficult. While validators are privileged actors, the consequence (permanent chain split requiring hard fork) exceeds validators' intended authority - they intend to skip a problematic upgrade, not destroy network consensus. This represents inadvertent operational misconfiguration during emergency situations when coordination is inherently most difficult.

## Recommendation

**Primary Fix - Remove State Modification from Skip Path:**
Modify `skipUpgrade()` to NOT delete the upgrade plan from consensus state. The upgrade plan remains in consensus state (maintaining determinism) but is locally ignored by nodes with skip configured. All validators maintain identical state regardless of skip configuration.

**Alternative Fix - Governance-Based Skip:**
Include skip decisions in the upgrade plan itself via governance parameters, ensuring all validators agree on skip decisions before reaching the upgrade height through on-chain consensus.

**Immediate Mitigation:**
- Add prominent documentation warning that ALL validators MUST coordinate identical `--unsafe-skip-upgrades` values
- Add startup validation that logs critical warnings when skip heights are configured
- Consider requiring governance approval for skip decisions to ensure network-wide coordination

## Proof of Concept

**Test Location:** `x/upgrade/abci_test.go`

**Setup:**
Simulate two validators with different skip configurations to demonstrate consensus failure:
- Validator A: Initialize with `setupTest(10, map[int64]bool{15: true})` - has skip configured for height 15
- Validator B: Initialize with `setupTest(10, map[int64]bool{})` - no skip configured
- Both validators schedule the same upgrade at height 15 via governance proposal

**Action:**
Execute BeginBlock at height 15 on both validators

**Expected Result:**
- Validator A: Executes successfully (skip configured), clears upgrade plan from state via `ClearUpgradePlan()`, continues processing
- Validator B: Panics via `panicUpgradeNeeded()` (no skip, no handler), halts before committing
- State divergence: Validator A has no upgrade plan in store, Validator B retains it
- Consensus failure: Validators cannot agree on block validity at height 15, producing different AppHashes

The existing tests [7](#0-6)  and [8](#0-7)  only test single validators in isolation and do not expose the multi-validator consensus failure scenario.

## Notes

This vulnerability is particularly critical because:

1. **Emergency Context**: The flag is explicitly designed for emergencies when coordination is inherently most difficult
2. **No Safeguards**: Zero code-level validation prevents mismatched configurations across validators
3. **Silent Until Failure**: Validators are unaware of others' configurations until the upgrade height triggers consensus failure
4. **Irreversible Damage**: Once triggered, requires social consensus and coordinated hard fork to resolve - no in-protocol recovery
5. **Documentation Gap**: While documentation mentions coordination is needed, the implementation provides no enforcement mechanism

The root cause is allowing consensus-critical state transitions to depend on local per-node configuration without any validation or coordination mechanism, fundamentally violating consensus determinism. While validators are privileged actors, the consequence (permanent chain split requiring hard fork) exceeds their intended authority and control.

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

**File:** x/upgrade/abci_test.go (L288-323)
```go
func TestSkipUpgradeSkippingAll(t *testing.T) {
	var (
		skipOne int64 = 11
		skipTwo int64 = 20
	)
	s := setupTest(10, map[int64]bool{skipOne: true, skipTwo: true})

	newCtx := s.ctx

	req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
	err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{Title: "prop", Plan: types.Plan{Name: "test", Height: skipOne}})
	require.NoError(t, err)

	t.Log("Verify if skip upgrade flag clears upgrade plan in both cases")
	VerifySet(t, map[int64]bool{skipOne: true, skipTwo: true})

	newCtx = newCtx.WithBlockHeight(skipOne)
	require.NotPanics(t, func() {
		s.module.BeginBlock(newCtx, req)
	})

	t.Log("Verify a second proposal also is being cleared")
	err = s.handler(s.ctx, &types.SoftwareUpgradeProposal{Title: "prop2", Plan: types.Plan{Name: "test2", Height: skipTwo}})
	require.NoError(t, err)

	newCtx = newCtx.WithBlockHeight(skipTwo)
	require.NotPanics(t, func() {
		s.module.BeginBlock(newCtx, req)
	})

	// To ensure verification is being done only after both upgrades are cleared
	t.Log("Verify if both proposals are cleared")
	VerifyCleared(t, s.ctx)
	VerifyNotDone(t, s.ctx, "test")
	VerifyNotDone(t, s.ctx, "test2")
}
```

**File:** x/upgrade/abci_test.go (L403-416)
```go
func TestUpgradeWithoutSkip(t *testing.T) {
	s := setupTest(10, map[int64]bool{})
	newCtx := s.ctx.WithBlockHeight(s.ctx.BlockHeight() + 1).WithBlockTime(time.Now())
	req := abci.RequestBeginBlock{Header: newCtx.BlockHeader()}
	err := s.handler(s.ctx, &types.SoftwareUpgradeProposal{Title: "prop", Plan: types.Plan{Name: "test", Height: s.ctx.BlockHeight() + 1}})
	require.NoError(t, err)
	t.Log("Verify if upgrade happens without skip upgrade")
	require.Panics(t, func() {
		s.module.BeginBlock(newCtx, req)
	})

	VerifyDoUpgrade(t)
	VerifyDone(t, s.ctx, "test")
}
```
