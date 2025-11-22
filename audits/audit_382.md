## Title
Unintended Chain Split Due to Inconsistent skipUpgradeHeights Configuration Across Validators

## Summary
The `skipUpgradeHeights` configuration is a per-node setting that allows nodes to bypass scheduled upgrades at specific block heights. When different validators configure different skip heights via the `--unsafe-skip-upgrades` flag, they execute divergent state transitions at upgrade heights, computing different application state hashes (AppHash). This breaks Tendermint consensus and causes a permanent chain split requiring a hard fork to resolve.

## Impact
**High**

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:** 
The `--unsafe-skip-upgrades` flag is documented as an emergency mechanism for social consensus to override a buggy upgrade. According to documentation, "If over two-thirds run their nodes with this flag on the old binary, it will allow the chain to continue through the upgrade with a manual override." [5](#0-4)  The expectation is that all validators coordinate to use the same configuration.

**Actual Logic:** 
The `skipUpgradeHeights` map is configured independently on each node through a command-line flag with no consensus-level validation or coordination mechanism. When an upgrade height is reached:

1. Nodes WITH the height in `skipUpgradeHeights`: Call `skipUpgrade()` which only clears the upgrade plan from state [3](#0-2) , leaving module versions, protocol version, and done markers unchanged.

2. Nodes WITHOUT the height in `skipUpgradeHeights`: Call `ApplyUpgrade()` which executes the upgrade handler, updates module version map in state, increments protocol version in state, and marks the upgrade as done [6](#0-5) .

These operations write to different state keys, causing permanent state divergence between nodes.

**Exploit Scenario:**
1. A blockchain schedules an upgrade at height 1000 via governance
2. Before height 1000, some concern arises about the upgrade
3. Validators A and B (holding 40% voting power) start with `--unsafe-skip-upgrades=1000` using the old binary
4. Validators C and D (holding 60% voting power) start with the new binary containing the upgrade handler, without the skip flag
5. At height 1000:
   - Validators A, B: Execute BeginBlocker → skip the upgrade → state remains unchanged → compute AppHash_old
   - Validators C, D: Execute BeginBlocker → apply the upgrade → state updated with new versions → compute AppHash_new
6. AppHash_old ≠ AppHash_new
7. No supermajority (2/3+) can agree on the next block's AppHash
8. Consensus permanently fails → chain split

**Security Failure:** 
This breaks the **consensus agreement** invariant. Tendermint requires all honest validators to agree on the application state hash for each block. The lack of consensus-level enforcement of skip configurations allows validators to diverge in their state transitions, violating this fundamental requirement.

## Impact Explanation

**Affected Assets/Processes:**
- Entire blockchain consensus mechanism
- Transaction finality across the network
- Network availability and liveness

**Severity of Damage:**
- Permanent chain split into two or more incompatible chains
- Loss of consensus - network cannot produce new blocks
- Requires emergency hard fork coordination to resolve
- All pending transactions stalled indefinitely
- Potential double-spend risks if different parts of the network follow different chains

**Why This Matters:**
Chain splits are one of the most severe failures in blockchain systems. They destroy the single source of truth that blockchains provide, create confusion about which chain is canonical, and can lead to significant economic losses. Recovery requires complex social coordination and emergency protocol changes.

## Likelihood Explanation

**Who Can Trigger:**
Any validator operator can trigger this by misconfiguring their node's `--unsafe-skip-upgrades` flag. This doesn't require malicious intent - simple miscommunication or misunderstanding during emergency upgrade coordination is sufficient.

**Required Conditions:**
1. A scheduled upgrade exists at some height H
2. Different validators configure different `skipUpgradeHeights` values
3. The upgrade height is reached

**Frequency:**
This can occur whenever:
- Emergency upgrade skip coordination happens (by design, during crisis situations)
- Validators make configuration errors
- Communication breakdowns occur during upgrade planning
- Different validator operators interpret upgrade guidance differently

The likelihood is **moderate to high** during actual upgrade events, especially emergency situations where the skip mechanism would be used.

## Recommendation

**Immediate Fix:**
Remove or deprecate the `--unsafe-skip-upgrades` functionality. The current design is fundamentally incompatible with consensus safety.

**Proper Alternative:**
If emergency upgrade override is truly needed, implement it as a **consensus-level mechanism**:
1. Require a governance proposal to schedule a "skip upgrade" that gets recorded in consensus state
2. All validators must read this consensus state decision, not individual node configurations
3. Ensure all nodes execute the same logic based on the same on-chain state

**Additional Safeguards:**
- Add warnings in documentation that mismatched skip configurations will cause chain splits
- Implement state hash validation that detects divergence and halts the node with a clear error message
- Consider adding a consensus parameter that tracks which upgrades should be skipped

## Proof of Concept

**Test File:** `x/upgrade/abci_test.go`

**Test Function:** Add the following test to demonstrate the chain split:

```go
func TestChainSplitDueToMismatchedSkipUpgradeHeights(t *testing.T) {
	upgradeHeight := int64(15)
	upgradeName := "test-upgrade"
	
	// Node A: Configured to SKIP the upgrade at height 15
	nodeA := setupTest(10, map[int64]bool{upgradeHeight: true})
	
	// Node B: NOT configured to skip (will apply upgrade)
	nodeB := setupTest(10, map[int64]bool{})
	
	// Both nodes schedule the same upgrade via governance
	plan := types.Plan{Name: upgradeName, Height: upgradeHeight}
	err := nodeA.handler(nodeA.ctx, &types.SoftwareUpgradeProposal{
		Title: "Test Upgrade",
		Plan:  plan,
	})
	require.NoError(t, err)
	
	err = nodeB.handler(nodeB.ctx, &types.SoftwareUpgradeProposal{
		Title: "Test Upgrade", 
		Plan:  plan,
	})
	require.NoError(t, err)
	
	// Register upgrade handler on Node B (simulating new binary)
	nodeB.keeper.SetUpgradeHandler(upgradeName, func(ctx sdk.Context, plan types.Plan, vm module.VersionMap) (module.VersionMap, error) {
		// Simple migration that modifies version map
		vm["testmodule"] = 2
		return vm, nil
	})
	
	// Both nodes process BeginBlock at upgrade height
	ctxA := nodeA.ctx.WithBlockHeight(upgradeHeight)
	ctxB := nodeB.ctx.WithBlockHeight(upgradeHeight)
	
	req := abci.RequestBeginBlock{Header: tmproto.Header{Height: upgradeHeight}}
	
	// Node A: Skips upgrade (no panic)
	require.NotPanics(t, func() {
		nodeA.module.BeginBlock(ctxA, req)
	})
	
	// Node B: Applies upgrade (no panic)
	require.NotPanics(t, func() {
		nodeB.module.BeginBlock(ctxB, req)
	})
	
	// CRITICAL: Verify state divergence
	
	// Check 1: Protocol version differs
	protocolVersionA := nodeA.keeper.getProtocolVersion(ctxA)
	protocolVersionB := nodeB.keeper.getProtocolVersion(ctxB)
	require.NotEqual(t, protocolVersionA, protocolVersionB, 
		"Protocol versions should differ - Node A skipped, Node B applied upgrade")
	
	// Check 2: Done marker differs
	doneHeightA := nodeA.keeper.GetDoneHeight(ctxA, upgradeName)
	doneHeightB := nodeB.keeper.GetDoneHeight(ctxB, upgradeName)
	require.Zero(t, doneHeightA, "Node A should NOT have done marker")
	require.NotZero(t, doneHeightB, "Node B should have done marker")
	
	// Check 3: Module version map differs
	vmA := nodeA.keeper.GetModuleVersionMap(ctxA)
	vmB := nodeB.keeper.GetModuleVersionMap(ctxB)
	require.NotEqual(t, vmA, vmB, 
		"Module version maps should differ due to upgrade handler execution")
	
	// This state divergence means Node A and Node B will compute different AppHashes
	// In a real network, this prevents consensus and causes a permanent chain split
	t.Log("VULNERABILITY CONFIRMED: Nodes with different skipUpgradeHeights configurations")
	t.Log("have divergent state, leading to different AppHashes and consensus failure")
}
```

**Setup:** Two test nodes are initialized with different `skipUpgradeHeights` configurations - one configured to skip height 15, one not configured to skip.

**Trigger:** Both nodes schedule the same upgrade via governance. Node B registers an upgrade handler (simulating a new binary). Both nodes process BeginBlock at the upgrade height.

**Observation:** The test verifies that after processing the upgrade height:
- Protocol versions differ between the two nodes
- Done markers differ (only Node B has the upgrade marked as done)
- Module version maps differ (only Node B executed the migration handler)

This state divergence proves that nodes with different skip configurations compute different state roots, which breaks Tendermint consensus and causes a permanent chain split in production networks.

### Citations

**File:** x/upgrade/keeper/keeper.go (L53-61)
```go
func NewKeeper(skipUpgradeHeights map[int64]bool, storeKey sdk.StoreKey, cdc codec.BinaryCodec, homePath string, vs xp.ProtocolVersionSetter) Keeper {
	return Keeper{
		homePath:           homePath,
		skipUpgradeHeights: skipUpgradeHeights,
		storeKey:           storeKey,
		cdc:                cdc,
		upgradeHandlers:    map[string]types.UpgradeHandler{},
		versionSetter:      vs,
	}
```

**File:** x/upgrade/keeper/keeper.go (L364-391)
```go
// ApplyUpgrade will execute the handler associated with the Plan and mark the plan as done.
func (k Keeper) ApplyUpgrade(ctx sdk.Context, plan types.Plan) {
	handler := k.upgradeHandlers[plan.Name]
	if handler == nil {
		panic("ApplyUpgrade should never be called without first checking HasHandler")
	}

	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}

	k.SetModuleVersionMap(ctx, updatedVM)

	// incremement the protocol version and set it in state and baseapp
	nextProtocolVersion := k.getProtocolVersion(ctx) + 1
	k.setProtocolVersion(ctx, nextProtocolVersion)
	if k.versionSetter != nil {
		// set protocol version on BaseApp
		k.versionSetter.SetProtocolVersion(nextProtocolVersion)
	}

	// Must clear IBC state after upgrade is applied as it is stored separately from the upgrade plan.
	// This will prevent resubmission of upgrade msg after upgrade is already completed.
	k.ClearIBCState(ctx, plan.Height)
	k.ClearUpgradePlan(ctx)
	k.SetDone(ctx, plan.Name)
}
```

**File:** x/upgrade/abci.go (L61-66)
```go
	if plan.ShouldExecute(ctx) {
		// If skip upgrade has been set for current height, we clear the upgrade plan
		if k.IsSkipHeight(ctx.BlockHeight()) {
			skipUpgrade(k, ctx, plan)
			return
		}
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
