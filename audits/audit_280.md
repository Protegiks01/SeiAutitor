## Title
Future-Height Evidence Bypasses Validation and Causes Network Halt via Panic in Slash Function

## Summary
The evidence module's `HandleEquivocationEvidence` function fails to validate that evidence is not from a future block height. When evidence with `infractionHeight > currentHeight` is processed during BeginBlock, it bypasses the age validation check due to a logic flaw, then causes the staking module's `Slash` function to panic, resulting in a complete network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `HandleEquivocationEvidence` function should reject evidence that is either too old (beyond `MaxAgeDuration` and `MaxAgeNumBlocks`) or from future block heights. The validation is intended to ensure evidence only describes past misbehavior.

**Actual Logic:** 
At line 46, the code calculates: `ageBlocks := ctx.BlockHeader().Height - infractionHeight`

When `infractionHeight` (from evidence) is greater than the current block height, `ageBlocks` becomes **negative**. The validation at line 53 checks:
```
if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks
```

Since this uses AND logic and `MaxAgeNumBlocks` is always positive, a negative `ageBlocks` will never satisfy `ageBlocks > MaxAgeNumBlocks`, causing the validation to pass and future-height evidence to be accepted.

**Exploit Scenario:**
1. Evidence with `Height` set to a future value (e.g., `currentHeight + 100`) enters the application via `RequestBeginBlock.ByzantineValidators` from Tendermint
2. The evidence conversion occurs in BeginBlocker: [2](#0-1) 
3. `HandleEquivocationEvidence` is called with this future-height evidence
4. The age validation fails to reject it due to the negative `ageBlocks` issue
5. At line 101, `distributionHeight` is calculated as `infractionHeight - sdk.ValidatorUpdateDelay` [3](#0-2) 
6. Since `ValidatorUpdateDelay = 1` [4](#0-3) , if `infractionHeight = currentHeight + N` where `N > 1`, then `distributionHeight > currentHeight`
7. This future `distributionHeight` is passed to the staking module's `Slash` function
8. The `Slash` function explicitly panics when `infractionHeight > ctx.BlockHeight()`: [5](#0-4) 
9. The panic propagates through BeginBlock, crashing the node

**Security Failure:** 
This violates the consensus invariant that evidence must be from past blocks and the staking module's contract requirement stated at lines 22-23 of slash.go: "Infraction was committed at the current height or at a past height, not at a height in the future". The panic during BeginBlock causes complete node failure and network halt.

## Impact Explanation

**Affected Components:**
- All network nodes processing the affected block
- Network consensus and block production
- Transaction finality and chain progression

**Severity of Damage:**
When future-height evidence is injected into BeginBlock (via Tendermint's byzantine validator reporting), all nodes that execute BeginBlock will panic simultaneously. This results in:
- Complete network shutdown - no new blocks can be produced
- All nodes crash and cannot recover without removing the malicious evidence
- Requires emergency intervention (potentially a coordinated restart or hard fork) to restore network operation
- No transactions can be confirmed during the outage

**Why This Matters:**
This is a critical denial-of-service vulnerability that can halt the entire blockchain network. While it requires Tendermint to provide malformed evidence (which shouldn't happen under normal operation), the application layer must validate all inputs defensively. A bug in Tendermint, a modified consensus client, or a sophisticated consensus-level attack could inject such evidence, causing catastrophic network failure.

## Likelihood Explanation

**Who Can Trigger It:**
- Technically requires evidence to enter via Tendermint's consensus layer during BeginBlock
- Could be triggered by:
  - A bug in Tendermint's evidence detection/reporting logic
  - A malicious or compromised Tendermint node with modified code
  - A consensus-level attack where attackers control sufficient validator power to inject fabricated evidence
  - Network message manipulation during evidence propagation

**Conditions Required:**
- Evidence with `Height > currentBlockHeight` must reach the application's BeginBlock
- At least one validator must broadcast this evidence to the network
- The evidence must pass Tendermint's own validation (which may have its own bugs)

**Frequency:**
While Tendermint shouldn't normally generate future-height evidence, this represents a **defense-in-depth failure**. The application should validate all external inputs, even from the consensus layer. If triggered (through any of the scenarios above), the impact is immediate and affects 100% of network nodes.

## Recommendation

Add explicit validation to reject future-height evidence before processing:

```go
// In x/evidence/keeper/infraction.go, after line 44:
if infractionHeight > ctx.BlockHeader().Height {
    logger.Info(
        "ignored equivocation; evidence from future height",
        "validator", consAddr,
        "infraction_height", infractionHeight,
        "current_height", ctx.BlockHeader().Height,
    )
    return
}
```

Additionally, fix the age validation logic to use OR instead of AND, or add a separate check for negative ageBlocks:
```go
// Replace line 53 with:
if (ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks) || ageBlocks < 0 {
```

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestHandleDoubleSign_FutureHeight` (add new test)

**Setup:**
1. Initialize test suite with a validator at block height 1
2. Create validator signing info via slashing BeginBlocker
3. Set consensus parameters with standard evidence age limits

**Trigger:**
```go
func (suite *KeeperTestSuite) TestHandleDoubleSign_FutureHeight() {
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(100)
    suite.populateValidators(ctx)
    params := suite.app.StakingKeeper.GetParams(ctx)
    params.MinCommissionRate = sdk.NewDec(0)
    suite.app.StakingKeeper.SetParams(ctx, params)

    power := int64(100)
    operatorAddr, val := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)

    // Create signing info
    req := abcitypes.RequestBeginBlock{
        LastCommitInfo: abcitypes.LastCommitInfo{
            Votes: []abcitypes.VoteInfo{
                {
                    Validator: abcitypes.Validator{
                        Address: val.Address().Bytes(),
                        Power:   power,
                    },
                    SignedLastBlock: true,
                },
            },
        },
    }
    slashing.BeginBlocker(ctx, req, suite.app.SlashingKeeper)

    // Create evidence with FUTURE height (current height is 100, evidence is at 200)
    evidence := &types.Equivocation{
        Height:           200,  // Future height!
        Time:             ctx.BlockTime().Add(-1 * time.Hour), // Past time to pass ageDuration check
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }

    // This should panic when it reaches the staking module's Slash function
    suite.Panics(func() {
        suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
    })
}
```

**Observation:**
The test demonstrates that when evidence with `Height=200` is processed at `currentHeight=100`:
1. The `ageBlocks` calculation yields `100 - 200 = -100` (negative)
2. The validation check `ageBlocks > MaxAgeNumBlocks` fails (since -100 is not > positive value)
3. Evidence is accepted and proceeds to slashing
4. `distributionHeight = 200 - 1 = 199` (still future)
5. The staking module's `Slash` function panics with message: "impossible attempt to slash future infraction at height 199 but we are at height 100"

This confirms the vulnerability causes a panic and network halt when future-height evidence is processed.

### Citations

**File:** x/evidence/keeper/infraction.go (L43-64)
```go
	infractionHeight := evidence.GetHeight()
	infractionTime := evidence.GetTime()
	ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
	ageBlocks := ctx.BlockHeader().Height - infractionHeight

	// Reject evidence if the double-sign is too old. Evidence is considered stale
	// if the difference in time and number of blocks is greater than the allowed
	// parameters defined.
	cp := ctx.ConsensusParams()
	if cp != nil && cp.Evidence != nil {
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
			logger.Info(
				"ignored equivocation; evidence too old",
				"validator", consAddr,
				"infraction_height", infractionHeight,
				"max_age_num_blocks", cp.Evidence.MaxAgeNumBlocks,
				"infraction_time", infractionTime,
				"max_age_duration", cp.Evidence.MaxAgeDuration,
			)
			return
		}
	}
```

**File:** x/evidence/keeper/infraction.go (L95-112)
```go
	// We need to retrieve the stake distribution which signed the block, so we
	// subtract ValidatorUpdateDelay from the evidence height.
	// Note, that this *can* result in a negative "distributionHeight", up to
	// -ValidatorUpdateDelay, i.e. at the end of the
	// pre-genesis block (none) = at the beginning of the genesis block.
	// That's fine since this is just used to filter unbonding delegations & redelegations.
	distributionHeight := infractionHeight - sdk.ValidatorUpdateDelay

	// Slash validator. The `power` is the int64 power of the validator as provided
	// to/by Tendermint. This value is validator.Tokens as sent to Tendermint via
	// ABCI, and now received as evidence. The fraction is passed in to separately
	// to slash unbonding and rebonding delegations.
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)
```

**File:** x/evidence/abci.go (L16-30)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	for _, tmEvidence := range req.ByzantineValidators {
		switch tmEvidence.Type {
		// It's still ongoing discussion how should we treat and slash attacks with
		// premeditation. So for now we agree to treat them in the same way.
		case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
			evidence := types.FromABCIEvidence(tmEvidence)
			k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))

		default:
			k.Logger(ctx).Error(fmt.Sprintf("ignored unknown evidence type: %s", tmEvidence.Type))
		}
	}
```

**File:** types/staking.go (L17-26)
```go
	// Delay, in blocks, between when validator updates are returned to the
	// consensus-engine and when they are applied. For example, if
	// ValidatorUpdateDelay is set to X, and if a validator set update is
	// returned with new validators at the end of block 10, then the new
	// validators are expected to sign blocks beginning at block 11+X.
	//
	// This value is constant as this should not change without a hard fork.
	// For Tendermint this should be set to 1 block, for more details see:
	// https://tendermint.com/docs/spec/abci/apps.html#endblock
	ValidatorUpdateDelay int64 = 1
```

**File:** x/staking/keeper/slash.go (L67-71)
```go
	case infractionHeight > ctx.BlockHeight():
		// Can't slash infractions in the future
		panic(fmt.Sprintf(
			"impossible attempt to slash future infraction at height %d but we are at height %d",
			infractionHeight, ctx.BlockHeight()))
```
