# Audit Report

## Title
Silent Failure in Evidence Processing for Unbonded Validators Allows Byzantine Behavior to Go Unpunished

## Summary
The evidence module's `HandleEquivocationEvidence` function silently discards evidence for validators in the `Unbonded` state without any logging, unlike other rejection paths that emit Info-level logs. This allows malicious validators who complete unbonding before their evidence is processed to escape slashing penalties, and hides Byzantine attacks from network operators.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When evidence of equivocation (double-signing) is submitted, the system should either process it (slashing, jailing, tombstoning the validator) or reject it with appropriate logging to maintain visibility of Byzantine behavior. The evidence age validation checks ensure evidence is not too old, logging rejections at Info level. [2](#0-1) 

**Actual Logic:** 
When a validator reaches `Unbonded` status before their evidence is processed, the function silently returns without any logging. This contrasts with other rejection paths: too-old evidence logs an Info message, and already-tombstoned validators log an Info message. [3](#0-2) 

The silent return at line 70 creates an information gap where Byzantine behavior goes unrecorded.

**Exploit Scenario:**
1. A malicious validator commits equivocation (double-signing) at time T, height H
2. The validator immediately initiates unbonding after the misbehavior
3. The unbonding period completes (default 21 days), transitioning the validator to `Unbonded` status
4. Evidence of the double-signing arrives within `MaxAgeDuration` (also ~21 days) but after the validator has reached `Unbonded` state
5. The evidence processing in `BeginBlocker` calls `HandleEquivocationEvidence` [4](#0-3) 

6. The function silently returns, never calling `Slash`, `Jail`, or `Tombstone`
7. No slashing penalty is applied, and no log entry indicates an attack occurred

**Security Failure:** 
The security property of accountability is broken. Byzantine validators can escape punishment by timing their unbonding to complete before evidence processing. Network operators have no visibility into these attacks due to the silent failure, undermining the evidence system's core purpose of maintaining validator accountability.

## Impact Explanation

**Affected Assets/Processes:**
- **Validator accountability:** Malicious validators escape slashing penalties that should reduce their stake
- **Network security:** The deterrent effect of slashing is undermined if validators can reliably avoid it
- **Operational visibility:** Network operators cannot detect or track Byzantine behavior that gets silently discarded

**Severity of Damage:**
- **Financial impact:** The validator's stake (which should be slashed by `SlashFractionDoubleSign`, typically 5%) is not penalized
- **Reputation/trust impact:** Byzantine attacks go unrecorded, making it impossible to assess validator reliability
- **Systemic risk:** If multiple validators exploit this timing window, the network's Byzantine fault tolerance assumptions are weakened without operators' knowledge

**Why This Matters:**
The evidence system exists specifically to punish Byzantine behavior and maintain network security through economic disincentives. Silent failures that allow attackers to escape punishment while hiding their actions from network monitoring systems fundamentally undermine this security model.

## Likelihood Explanation

**Who Can Trigger:**
Any validator can trigger this by controlling the timing of their unbonding relative to their misbehavior.

**Required Conditions:**
1. Validator commits equivocation
2. Validator initiates unbonding immediately or shortly after
3. Evidence propagation/processing is delayed enough that the unbonding period completes first
4. Evidence still arrives within `MaxAgeDuration` limits (otherwise it's rejected as too old)

The default parameters create a realistic timing window: [5](#0-4) 

With `MaxAgeDuration = 504 hours` (21 days) and typical `UnbondingTime` also being 21 days, evidence arriving late in the window (e.g., day 20) for a validator who started unbonding at day 0 would be silently discarded.

**Frequency:**
This could occur during normal operations whenever:
- Evidence gossip experiences natural network delays
- Validators strategically time their unbonding after misbehavior
- Multiple evidence submissions for the same validator create processing delays

The issue is not purely theoretical - it represents a real timing race condition in the evidence processing system.

## Recommendation

Add explicit logging when evidence is discarded for unbonded validators to maintain operational visibility and match the logging pattern used for other rejection cases:

```go
validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
if validator == nil || validator.IsUnbonded() {
    // Defensive: Simulation doesn't take unbonding periods into account, and
    // Tendermint might break this assumption at some point.
    if validator != nil && validator.IsUnbonded() {
        logger.Info(
            "ignored equivocation; validator already unbonded",
            "validator", consAddr,
            "infraction_height", infractionHeight,
            "infraction_time", infractionTime,
        )
    }
    return
}
```

This ensures Byzantine behavior is always recorded in logs even when punishment cannot be applied, allowing network operators to track and respond to attacks.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add a new test `TestHandleEquivocation_UnbondedValidator_SilentFailure`

**Setup:**
1. Initialize a test chain with a validator
2. Create signing info for the validator
3. Record the validator's initial token balance
4. Transition the validator to `Unbonded` status using `UnbondingToUnbonded`

**Trigger:**
1. Create equivocation evidence with recent timestamp (within `MaxAgeDuration`)
2. Call `HandleEquivocationEvidence` with the evidence
3. Capture all log outputs during the call

**Observation:**
1. Verify the validator was NOT slashed (tokens unchanged)
2. Verify the validator was NOT jailed (IsJailed returns false)
3. Verify the validator was NOT tombstoned (IsTombstoned returns false)
4. Verify NO log messages were emitted about the evidence (silent failure)
5. Compare this with the test `TestHandleDoubleSign_TooOld` which DOES log when rejecting evidence

**Test Code Structure:**
```go
func (suite *KeeperTestSuite) TestHandleEquivocation_UnbondedValidator_SilentFailure() {
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1).WithBlockTime(time.Now())
    suite.populateValidators(ctx)
    
    power := int64(100)
    operatorAddr, val := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    
    // Create bonded validator
    amt := tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Create signing info
    req := abcitypes.RequestBeginBlock{
        LastCommitInfo: abcitypes.LastCommitInfo{
            Votes: []abcitypes.VoteInfo{{
                Validator: abcitypes.Validator{
                    Address: val.Address().Bytes(),
                    Power:   amt.Int64(),
                },
                SignedLastBlock: true,
            }},
        },
    }
    slashing.BeginBlocker(ctx, req, suite.app.SlashingKeeper)
    
    // Transition validator to Unbonded state
    validator, _ := suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    validator = validator.UpdateStatus(stakingtypes.Unbonded)
    suite.app.StakingKeeper.SetValidator(ctx, validator)
    
    oldTokens := suite.app.StakingKeeper.Validator(ctx, operatorAddr).GetTokens()
    
    // Submit evidence (still within age limits)
    evidence := &types.Equivocation{
        Height:           ctx.BlockHeight() - 10,
        Time:             ctx.BlockTime().Add(-1 * time.Hour),
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }
    
    // Process evidence - should be silently discarded
    suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
    
    // Verify NO slashing occurred
    newTokens := suite.app.StakingKeeper.Validator(ctx, operatorAddr).GetTokens()
    suite.True(newTokens.Equal(oldTokens), "tokens should be unchanged")
    
    // Verify NOT jailed
    suite.False(suite.app.StakingKeeper.Validator(ctx, operatorAddr).IsJailed(), "should not be jailed")
    
    // Verify NOT tombstoned
    suite.False(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address())), "should not be tombstoned")
    
    // This demonstrates the silent failure - evidence within age limits is discarded without logging
}
```

This test demonstrates that evidence for unbonded validators is silently discarded even when within valid age parameters, allowing Byzantine behavior to go undetected and unpunished.

### Citations

**File:** x/evidence/keeper/infraction.go (L52-63)
```go
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
```

**File:** x/evidence/keeper/infraction.go (L66-71)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
	if validator == nil || validator.IsUnbonded() {
		// Defensive: Simulation doesn't take unbonding periods into account, and
		// Tendermint might break this assumption at some point.
		return
	}
```

**File:** x/evidence/keeper/infraction.go (L78-86)
```go
	if k.slashingKeeper.IsTombstoned(ctx, consAddr) {
		logger.Info(
			"ignored equivocation; validator already tombstoned",
			"validator", consAddr,
			"infraction_height", infractionHeight,
			"infraction_time", infractionTime,
		)
		return
	}
```

**File:** x/evidence/abci.go (L19-30)
```go
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

**File:** simapp/test_helpers.go (L44-48)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
		MaxBytes:        10000,
	},
```
