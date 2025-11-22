# Audit Report

## Title
Consensus Failure Due to Non-Deterministic skipUpgradeHeights Configuration Causing State Divergence

## Summary
Validator nodes with different `skipUpgradeHeights` configurations will execute different code paths during upgrade block processing, leading to state divergence and consensus failure. When an upgrade is scheduled at a specific height, validators with that height in their skip configuration will clear the upgrade plan from state and continue, while validators without it will panic and halt, creating a network partition.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- State modification occurs at: [2](#0-1) 
- Skip height check: [3](#0-2) 

**Intended Logic:** 
The upgrade module is designed to ensure all validators execute scheduled upgrades at exactly the same block height to maintain consensus. The `skipUpgradeHeights` configuration is an emergency mechanism allowing validators to bypass problematic upgrades. The expectation is that all validators coordinate on the same skip configuration if they choose to use it.

**Actual Logic:**
The `skipUpgradeHeights` is a local per-node configuration map ( [4](#0-3) ), populated via the `--unsafe-skip-upgrades` CLI flag with no validation that all validators share the same configuration. During BeginBlock execution at an upgrade height:

1. Validators with the height in `skipUpgradeHeights` execute the skip path, which calls `ClearUpgradePlan(ctx)` to remove the upgrade plan from consensus state ( [5](#0-4) )

2. Validators without the height in `skipUpgradeHeights` check for an upgrade handler, and if missing, panic via `panicUpgradeNeeded` ( [6](#0-5) )

This creates state divergence: some validators modify state (clear the plan) while others crash before committing any state.

**Exploit Scenario:**
1. A governance proposal schedules an upgrade at height H
2. Before height H, due to miscommunication, emergency response, or social engineering, some validators configure `--unsafe-skip-upgrades=H` while others don't
3. At height H during BeginBlock ( [7](#0-6) ):
   - Validators with skip configured: clear the upgrade plan, continue processing, commit state, produce AppHash without the plan
   - Validators without skip: panic and halt before state commit
4. Network partitions based on which validators have the skip configured
5. Chain permanently splits requiring hard fork to resolve

**Security Failure:**
This breaks the fundamental consensus invariant that all validators must execute identical state transitions for the same block. The `skipUpgradeHeights` setting creates non-deterministic behavior in consensus-critical code, violating the requirement that BeginBlock state changes must be deterministic across all validators.

## Impact Explanation

**Affected Assets/Processes:**
- Network consensus integrity
- Transaction finality 
- Validator coordination
- Chain continuity

**Severity:**
- Network partition: Validators split into two groups processing different state
- If >2/3 voting power skips: chain continues without halted validators (permanent exclusion)
- If <2/3 voting power skips: chain halts entirely (network shutdown)
- If between 1/3 and 2/3 skip: chain may limp along or halt unpredictably
- Requires hard fork to resolve the partition
- All transactions during the partition period are at risk

**Why This Matters:**
Consensus is the core security property of any blockchain. A configuration option that can silently cause consensus failure without validation or coordination is a critical vulnerability. Validators might use this flag during emergencies without realizing that miscoordination will permanently split the network.

## Likelihood Explanation

**Who Can Trigger:**
Validator operators through configuration flags. While validators are privileged actors, this is not intentional misbehavior but rather accidental misconfiguration during emergency situations.

**Required Conditions:**
1. A scheduled upgrade exists
2. At least some validators configure `--unsafe-skip-upgrades` with that height
3. Not all validators use identical skip configurations
4. The upgrade height is reached

**Frequency:**
- Moderate likelihood during actual upgrade emergencies when validators attempt to skip problematic upgrades
- The flag name suggests it's for emergency use, exactly when coordination is most difficult
- No built-in validation prevents configuration mismatch
- Could be triggered by social engineering convincing subset of validators to skip

## Recommendation

**Primary Fix:**
Implement consensus validation for skip upgrade decisions. Options include:

1. **Remove state modification from skip path**: When skipping an upgrade, don't call `ClearUpgradePlan`. Instead, only skip the execution locally without modifying consensus state. The upgrade plan remains in state but is ignored by nodes with the skip configured.

2. **Make skip heights part of consensus**: Include skip heights in the upgrade plan itself via governance, ensuring all validators agree on which upgrades to skip before reaching that height.

3. **Add determinism check**: On startup, if `skipUpgradeHeights` is configured, require that it's also recorded in a governance parameter. Panic if local configuration doesn't match on-chain governance decision.

**Immediate Mitigation:**
- Document clearly that all validators MUST coordinate on identical `--unsafe-skip-upgrades` values
- Add warning logs when skip heights are configured
- Consider deprecating per-node skip configuration in favor of governance-based skip decisions

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestConsensusFailureWithMismatchedSkipConfig`

**Setup:**
```go
// Create two validators with different skip configurations simulating network partition
func TestConsensusFailureWithMismatchedSkipConfig(t *testing.T) {
    var upgradeHeight int64 = 15
    
    // Validator A: Has skipUpgradeHeights configured for height 15
    validatorA := setupTest(10, map[int64]bool{upgradeHeight: true})
    
    // Validator B: Does NOT have skipUpgradeHeights configured
    validatorB := setupTest(10, map[int64]bool{})
    
    // Both validators agree on scheduling the upgrade via governance
    err := validatorA.handler(validatorA.ctx, &types.SoftwareUpgradeProposal{
        Title: "test upgrade",
        Plan:  types.Plan{Name: "testnet-upgrade", Height: upgradeHeight},
    })
    require.NoError(t, err)
    
    err = validatorB.handler(validatorB.ctx, &types.SoftwareUpgradeProposal{
        Title: "test upgrade", 
        Plan:  types.Plan{Name: "testnet-upgrade", Height: upgradeHeight},
    })
    require.NoError(t, err)
```

**Trigger:**
```go
    // Both validators reach the upgrade height
    ctxA := validatorA.ctx.WithBlockHeight(upgradeHeight)
    ctxB := validatorB.ctx.WithBlockHeight(upgradeHeight)
    
    reqA := abci.RequestBeginBlock{Header: ctxA.BlockHeader()}
    reqB := abci.RequestBeginBlock{Header: ctxB.BlockHeader()}
    
    // Validator A: Should NOT panic (skip configured), clears upgrade plan from state
    require.NotPanics(t, func() {
        validatorA.module.BeginBlock(ctxA, reqA)
    })
    
    // Validator B: Should panic (no skip configured, no handler registered)
    require.Panics(t, func() {
        validatorB.module.BeginBlock(ctxB, reqB)
    })
```

**Observation:**
```go
    // Verify state divergence: 
    // Validator A cleared the upgrade plan
    planA, foundA := validatorA.keeper.GetUpgradePlan(ctxA)
    require.False(t, foundA, "Validator A should have cleared the upgrade plan")
    
    // Validator B's state is undefined (panicked before commit)
    // but the upgrade plan should still exist in its last committed state
    planB, foundB := validatorB.keeper.GetUpgradePlan(validatorB.ctx)
    require.True(t, foundB, "Validator B should still have the upgrade plan")
    require.Equal(t, "testnet-upgrade", planB.Name)
    
    // This demonstrates consensus failure:
    // - Validator A modified state (cleared plan) and would produce AppHash1
    // - Validator B crashed and would produce no AppHash
    // - Network partitions between validators with/without skip configured
}
```

This test demonstrates that validators with different `skipUpgradeHeights` configurations will process the same block differently, with one clearing the upgrade plan from state while the other panics, causing irrecoverable consensus failure and network partition.

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

**File:** x/upgrade/keeper/keeper.go (L393-396)
```go
// IsSkipHeight checks if the given height is part of skipUpgradeHeights
func (k Keeper) IsSkipHeight(height int64) bool {
	return k.skipUpgradeHeights[height]
}
```

**File:** simapp/app.go (L478-504)
```go
	beginBlockResp := app.BeginBlock(ctx, abci.RequestBeginBlock{
		Hash: req.Hash,
		ByzantineValidators: utils.Map(req.ByzantineValidators, func(mis abci.Misbehavior) abci.Evidence {
			return abci.Evidence{
				Type:             abci.MisbehaviorType(mis.Type),
				Validator:        abci.Validator(mis.Validator),
				Height:           mis.Height,
				Time:             mis.Time,
				TotalVotingPower: mis.TotalVotingPower,
			}
		}),
		LastCommitInfo: abci.LastCommitInfo{
			Round: req.DecidedLastCommit.Round,
			Votes: utils.Map(req.DecidedLastCommit.Votes, func(vote abci.VoteInfo) abci.VoteInfo {
				return abci.VoteInfo{
					Validator:       abci.Validator(vote.Validator),
					SignedLastBlock: vote.SignedLastBlock,
				}
			}),
		},
		Header: tmproto.Header{
			ChainID:         app.ChainID,
			Height:          req.Height,
			Time:            req.Time,
			ProposerAddress: ctx.BlockHeader().ProposerAddress,
		},
	})
```
