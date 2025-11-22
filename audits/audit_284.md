## Audit Report

### Title
Validators Can Escape Equivocation Punishment by Unbonding Before Evidence Submission When UnbondingTime < MaxAgeDuration

### Summary
The `HandleEquivocationEvidence` function in the evidence module returns early without punishment if a validator has already transitioned to `Unbonded` status. When the staking module's `UnbondingTime` parameter is configured to be shorter than the evidence module's `MaxAgeDuration` parameter, malicious validators can commit equivocation, immediately unbond, complete the unbonding period, and avoid all punishment (slashing, jailing, tombstoning) even when evidence is submitted within the valid evidence age window.

### Impact
**High**

### Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The evidence module should slash, jail, and tombstone validators who commit equivocation (double-signing) as long as evidence is submitted within the `MaxAgeDuration` and `MaxAgeNumBlocks` limits. The security model assumes that evidence parameters are properly configured to prevent validators from escaping punishment through unbonding.

**Actual Logic:** 
The `HandleEquivocationEvidence` function checks if a validator is already `Unbonded` and returns early without any punishment: [1](#0-0) 

The evidence age validation only checks if evidence is too old: [2](#0-1) 

However, there is NO validation ensuring the staking module's `UnbondingTime` parameter is less than or equal to the evidence module's `MaxAgeDuration` parameter. These parameters can be set independently:
- `UnbondingTime` default is 3 weeks: [3](#0-2) 
- `MaxAgeDuration` default is 504 hours (also 3 weeks): [4](#0-3) 

While the simulation code suggests they should match: [5](#0-4) 

There is no enforcement of this relationship in the validation logic: [6](#0-5) 

**Exploit Scenario:**
1. A governance proposal changes `UnbondingTime` to 7 days while `MaxAgeDuration` remains at 21 days (or vice versa)
2. Malicious validator commits equivocation at height H, time T
3. Validator immediately initiates unbonding via normal staking operations
4. After 7 days, `UnbondAllMatureValidators` is called during EndBlock: [7](#0-6) 
5. Validator transitions to `Unbonded` status: [8](#0-7) 
6. Evidence is submitted at T + 14 days (within the 21-day `MaxAgeDuration` window)
7. Evidence passes age validation but `HandleEquivocationEvidence` returns early due to `IsUnbonded()` check
8. Validator avoids all punishment despite valid evidence of misbehavior

**Security Failure:** 
This breaks the consensus security invariant that validators must be punished for equivocation. The slashing mechanism, which is critical for preventing Nothing-At-Stake attacks and maintaining Byzantine fault tolerance, can be completely bypassed through parameter misconfiguration and timing.

### Impact Explanation

**Assets Affected:**
- Validator stake that should be slashed (typically 5% for double-signing)
- Network security and consensus integrity
- Economic incentives for honest validator behavior

**Severity:**
- **Direct loss of funds:** The protocol loses the ability to slash misbehaving validators, resulting in lost slashing penalties (typically 5% of validator stake, which can be millions of dollars for large validators)
- **Consensus security breakdown:** If validators can escape punishment, the economic security model breaks down. Validators have reduced incentive to avoid misbehavior if they know they can escape through unbonding
- **Nothing-At-Stake vulnerability:** The evidence system exists specifically to prevent Nothing-At-Stake attacks. This vulnerability undermines that protection

This is a **High severity** issue because it directly enables validators to avoid financial penalties for consensus violations, which is a fundamental security mechanism in Proof-of-Stake systems.

### Likelihood Explanation

**Who can trigger:**
- Any validator can exploit this vulnerability
- Requires parameter misconfiguration (UnbondingTime < MaxAgeDuration), which can occur through governance proposals

**Conditions required:**
- The two parameters must be misaligned (UnbondingTime < MaxAgeDuration)
- While defaults are equal, governance can change them independently without validation
- No cross-module parameter validation exists to prevent this misconfiguration

**Frequency:**
- Once parameters are misconfigured, ANY validator who commits equivocation can exploit this timing window
- The vulnerability persists until parameters are realigned
- Given that governance proposals to change staking or evidence parameters are relatively common in Cosmos chains, the risk of misconfiguration is real

### Recommendation

Implement cross-module parameter validation to ensure `MaxAgeDuration` (evidence params) is always less than or equal to `UnbondingTime` (staking params):

1. Add validation in `ValidateEvidenceParams` that checks against the current staking parameters
2. Add validation when staking parameters are updated to ensure they don't violate the evidence parameter constraints
3. Consider adding a check in `HandleEquivocationEvidence` before the `IsUnbonded()` check that verifies the validator wasn't unbonded during the evidence validity window (by checking if unbonding started after the infraction)
4. Add a runtime invariant check that panics if these parameters become misaligned

Alternatively, modify the `IsUnbonded()` check to only skip unbonded validators if they were already unbonded at the time of the infraction, not if they unbonded afterward.

### Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestHandleDoubleSign_ValidatorUnbondsBeforeEvidence`

```go
func (suite *KeeperTestSuite) TestHandleDoubleSign_ValidatorUnbondsBeforeEvidence() {
    // Setup: Configure UnbondingTime < MaxAgeDuration to create exploit window
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1).WithBlockTime(time.Now())
    suite.populateValidators(ctx)
    
    // Set staking params with SHORT unbonding time (7 days)
    stakingParams := suite.app.StakingKeeper.GetParams(ctx)
    stakingParams.UnbondingTime = time.Hour * 24 * 7  // 7 days
    stakingParams.MinCommissionRate = sdk.NewDec(0)
    suite.app.StakingKeeper.SetParams(ctx, stakingParams)
    
    // Set consensus params with LONG evidence age (21 days)
    cp := suite.app.BaseApp.GetConsensusParams(ctx)
    cp.Evidence = &tmproto.EvidenceParams{
        MaxAgeNumBlocks: 100000,
        MaxAgeDuration:  time.Hour * 24 * 21,  // 21 days
        MaxBytes:        10000,
    }
    ctx = ctx.WithConsensusParams(cp)
    
    slashingParams := suite.app.SlashingKeeper.GetParams(ctx)
    slashingParams.SlashFractionDoubleSign = sdk.NewDec(1).Quo(sdk.NewDec(20))  // 5%
    suite.app.SlashingKeeper.SetParams(ctx, slashingParams)
    
    power := int64(100)
    operatorAddr, val := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    
    // Create validator with power
    selfDelegation := tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Record tokens before slashing
    oldTokens := suite.app.StakingKeeper.Validator(ctx, operatorAddr).GetTokens()
    
    // Validator commits equivocation at this time
    infractionTime := ctx.BlockTime()
    infractionHeight := ctx.BlockHeight()
    
    // Validator immediately starts unbonding
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    del, _ := suite.app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(operatorAddr), operatorAddr)
    validator, _ := suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    totalBond := validator.TokensFromShares(del.GetShares()).TruncateInt()
    tstaking.Ctx = ctx
    tstaking.Denom = stakingParams.BondDenom
    tstaking.Undelegate(sdk.AccAddress(operatorAddr), operatorAddr, totalBond, true)
    
    // Fast forward to complete unbonding (7 days + 1 second)
    ctx = ctx.WithBlockTime(ctx.BlockTime().Add(stakingParams.UnbondingTime).Add(time.Second))
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 10000)
    
    // Complete unbonding
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Verify validator is now Unbonded
    validator, _ = suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    suite.True(validator.IsUnbonded(), "Validator should be unbonded after unbonding period")
    
    // Evidence is submitted at 14 days after infraction (within 21 day MaxAgeDuration)
    ctx = ctx.WithBlockTime(infractionTime.Add(time.Hour * 24 * 14))
    
    // Create equivocation evidence
    evidence := &types.Equivocation{
        Height:           infractionHeight,
        Time:             infractionTime,
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }
    
    // Handle evidence - this should slash but won't due to IsUnbonded check
    suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
    
    // BUG: Validator escapes punishment despite valid evidence
    validator, _ = suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    suite.False(validator.IsJailed(), "BUG: Validator should be jailed but isn't")
    suite.False(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address())), 
        "BUG: Validator should be tombstoned but isn't")
    
    // Tokens unchanged - no slashing occurred
    newTokens := validator.GetTokens()
    suite.True(newTokens.Equal(oldTokens), "BUG: Validator should be slashed but tokens are unchanged")
}
```

**Setup:** The test configures a parameter mismatch where `UnbondingTime = 7 days` but `MaxAgeDuration = 21 days`, creating a 14-day exploit window.

**Trigger:** A validator commits equivocation, immediately unbonds, waits for unbonding to complete, then evidence is submitted within the valid evidence age window.

**Observation:** The test demonstrates that the validator is NOT jailed, NOT tombstoned, and tokens are NOT slashed, despite valid evidence being submitted within `MaxAgeDuration`. This confirms the vulnerability allows validators to completely escape punishment through timing manipulation.

### Citations

**File:** x/evidence/keeper/infraction.go (L48-64)
```go
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

**File:** x/evidence/keeper/infraction.go (L66-71)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
	if validator == nil || validator.IsUnbonded() {
		// Defensive: Simulation doesn't take unbonding periods into account, and
		// Tendermint might break this assumption at some point.
		return
	}
```

**File:** x/staking/types/params.go (L17-21)
```go
const (
	// DefaultUnbondingTime reflects three weeks in seconds as the default
	// unbonding time.
	// TODO: Justify our choice of default here.
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** simapp/test_helpers.go (L44-47)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
		MaxBytes:        10000,
```

**File:** x/simulation/params.go (L169-172)
```go
		Evidence: &tmproto.EvidenceParams{
			MaxAgeNumBlocks: int64(stakingGenesisState.Params.UnbondingTime / AverageBlockTime),
			MaxAgeDuration:  stakingGenesisState.Params.UnbondingTime,
		},
```

**File:** baseapp/params.go (L62-83)
```go
// ValidateEvidenceParams defines a stateless validation on EvidenceParams. This
// function is called whenever the parameters are updated or stored.
func ValidateEvidenceParams(i interface{}) error {
	v, ok := i.(tmproto.EvidenceParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.MaxAgeNumBlocks <= 0 {
		return fmt.Errorf("evidence maximum age in blocks must be positive: %d", v.MaxAgeNumBlocks)
	}

	if v.MaxAgeDuration <= 0 {
		return fmt.Errorf("evidence maximum age time duration must be positive: %v", v.MaxAgeDuration)
	}

	if v.MaxBytes < 0 {
		return fmt.Errorf("maximum evidence bytes must be non-negative: %v", v.MaxBytes)
	}

	return nil
}
```

**File:** x/staking/keeper/validator.go (L397-450)
```go
// UnbondAllMatureValidators unbonds all the mature unbonding validators that
// have finished their unbonding period.
func (k Keeper) UnbondAllMatureValidators(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)

	blockTime := ctx.BlockTime()
	blockHeight := ctx.BlockHeight()

	// unbondingValIterator will contains all validator addresses indexed under
	// the ValidatorQueueKey prefix. Note, the entire index key is composed as
	// ValidatorQueueKey | timeBzLen (8-byte big endian) | timeBz | heightBz (8-byte big endian),
	// so it may be possible that certain validator addresses that are iterated
	// over are not ready to unbond, so an explicit check is required.
	unbondingValIterator := k.ValidatorQueueIterator(ctx, blockTime, blockHeight)
	defer unbondingValIterator.Close()

	for ; unbondingValIterator.Valid(); unbondingValIterator.Next() {
		key := unbondingValIterator.Key()
		keyTime, keyHeight, err := types.ParseValidatorQueueKey(key)
		if err != nil {
			panic(fmt.Errorf("failed to parse unbonding key: %w", err))
		}

		// All addresses for the given key have the same unbonding height and time.
		// We only unbond if the height and time are less than the current height
		// and time.
		if keyHeight <= blockHeight && (keyTime.Before(blockTime) || keyTime.Equal(blockTime)) {
			addrs := types.ValAddresses{}
			k.cdc.MustUnmarshal(unbondingValIterator.Value(), &addrs)

			for _, valAddr := range addrs.Addresses {
				addr, err := sdk.ValAddressFromBech32(valAddr)
				if err != nil {
					panic(err)
				}
				val, found := k.GetValidator(ctx, addr)
				if !found {
					panic("validator in the unbonding queue was not found")
				}

				if !val.IsUnbonding() {
					panic("unexpected validator in unbonding queue; status was not unbonding")
				}

				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
			}

			store.Delete(key)
		}
	}
}
```

**File:** x/staking/keeper/val_state_change.go (L340-346)
```go
// perform all the store operations for when a validator status becomes unbonded
func (k Keeper) completeUnbondingValidator(ctx sdk.Context, validator types.Validator) types.Validator {
	validator = validator.UpdateStatus(types.Unbonded)
	k.SetValidator(ctx, validator)

	return validator
}
```
