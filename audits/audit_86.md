# Audit Report

## Title
Chain Halt Due to Missing Nil Check When Allocating Rewards to Removed Validators

## Summary
The distribution module's `AllocateTokens` function lacks nil validation for validators in the voting loop, while the same protection exists for the proposer. When a validator participates in consensus but is removed before reward distribution (possible with short unbonding periods), the code panics on `val.GetCommission()`, causing a total network shutdown.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** The `AllocateTokens` function should safely distribute rewards to all validators that participated in the previous block, gracefully handling cases where validators may have been removed from state between block production and reward distribution.

**Actual Logic:** The function retrieves each validator from `bondedVotes` via `ValidatorByConsAddr` but does not verify the returned value is non-nil before usage. When `ValidatorByConsAddr` returns nil (validator was removed), this nil value is passed to `AllocateTokensToValidator`, which immediately panics when calling `val.GetCommission()` on the nil interface.

**Exploitation Path:**
1. Validator V is active at block N and votes
2. At block N EndBlock, V may transition to Unbonding state
3. At a subsequent block EndBlock, V completes unbonding with zero delegations and is removed [3](#0-2) 
4. The removal deletes V from the consensus address index [4](#0-3) 
5. At next block BeginBlock, `AllocateTokens` is called with votes including V [5](#0-4) 
6. `ValidatorByConsAddr` returns nil for V [6](#0-5) 
7. No nil check exists, code calls `AllocateTokensToValidator(ctx, nil, reward)`
8. Panic occurs at `val.GetCommission()`, all nodes crash simultaneously

**Security Guarantee Broken:** Chain liveness guarantee. BeginBlock must never panic as it executes identically on all nodes.

## Impact Explanation

A panic in BeginBlock causes all validator nodes to crash at the same block height deterministically. The entire network halts and cannot confirm new transactions. Recovery requires coordinated manual intervention (hard fork to skip the problematic block or restart from previous state). This matches the "Network not being able to confirm new transactions (total network shutdown)" impact criterion defined as Medium severity.

## Likelihood Explanation

**Triggering Conditions:**
- Short unbonding period (1-2 blocks) - common in test networks, possible in production if governance reduces the parameter [7](#0-6) 
- Any validator fully unbonds during the critical timing window
- Can occur naturally or be deliberately triggered by any validator operator

**Evidence of Awareness:** The code explicitly handles this exact scenario for the proposer validator [8](#0-7) , proving developers were aware of the timing issue but failed to apply the protection consistently to regular voters.

## Recommendation

Add nil check in the `bondedVotes` loop mirroring the proposer protection:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s. "+
            "This can happen if the validator unbonded completely within a short period.",
            vote.Validator.Address))
        continue
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)
    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

## Proof of Concept

**Test Function:** `TestAllocateTokensToRemovedValidator` (to add to `x/distribution/keeper/allocation_test.go`)

**Setup:**
1. Initialize test app with very short unbonding period (e.g., 1 second)
2. Create validator with self-delegation
3. Fund fee collector with distribution tokens

**Action:**
1. Undelegate all tokens from validator
2. Call `BlockValidatorUpdates` to transition to Unbonding [9](#0-8) 
3. Advance time past unbonding period
4. Call `UnbondAllMatureValidators` to remove validator
5. Verify validator removal via `ValidatorByConsAddr` returning nil
6. Create `VoteInfo` including the removed validator's consensus address
7. Call `AllocateTokens` with these votes

**Result:**
Panic at line 113 when calling `val.GetCommission()` on nil interface, demonstrating chain-halting vulnerability. The panic is deterministic and would occur on all nodes simultaneously.

## Notes

**Critical Inconsistency:** The code implements proper nil handling for the proposer case with detailed error logging explaining the timing scenario [10](#0-9) , but completely omits this protection for regular voters [1](#0-0) , indicating an incomplete fix to a known timing issue. This inconsistency strongly suggests the vulnerability is unintentional rather than by design.

### Citations

**File:** x/distribution/keeper/allocation.go (L57-79)
```go
	if proposerValidator != nil {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeProposerReward,
				sdk.NewAttribute(sdk.AttributeKeyAmount, proposerReward.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, proposerValidator.GetOperator().String()),
			),
		)

		k.AllocateTokensToValidator(ctx, proposerValidator, proposerReward)
		remaining = remaining.Sub(proposerReward)
	} else {
		// previous proposer can be unknown if say, the unbonding period is 1 block, so
		// e.g. a validator undelegates at block X, it's removed entirely by
		// block X+1's endblock, then X+2 we need to refer to the previous
		// proposer for X+1, but we've forgotten about them.
		logger.Error(fmt.Sprintf(
			"WARNING: Attempt to allocate proposer rewards to unknown proposer %s. "+
				"This should happen only if the proposer unbonded completely within a single block, "+
				"which generally should not happen except in exceptional circumstances (or fuzz testing). "+
				"We recommend you investigate immediately.",
			previousProposer.String()))
	}
```

**File:** x/distribution/keeper/allocation.go (L91-102)
```go
	for _, vote := range bondedVotes {
		validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)

		// TODO: Consider micro-slashing for missing votes.
		//
		// Ref: https://github.com/cosmos/cosmos-sdk/issues/2525#issuecomment-430838701
		powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
		reward := feeMultiplier.MulDecTruncate(powerFraction)

		k.AllocateTokensToValidator(ctx, validator, reward)
		remaining = remaining.Sub(reward)
	}
```

**File:** x/distribution/keeper/allocation.go (L111-114)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** x/staking/keeper/validator.go (L168-177)
```go
	valConsAddr, err := validator.GetConsAddr()
	if err != nil {
		panic(err)
	}

	// delete the old validator record
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetValidatorKey(address))
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
	store.Delete(types.GetValidatorsByPowerIndexKey(validator, k.PowerReduction(ctx)))
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/distribution/abci.go (L29-32)
```go
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
	}
```

**File:** x/staking/keeper/alias_functions.go (L88-96)
```go
// ValidatorByConsAddr gets the validator interface for a particular pubkey
func (k Keeper) ValidatorByConsAddr(ctx sdk.Context, addr sdk.ConsAddress) types.ValidatorI {
	val, found := k.GetValidatorByConsAddr(ctx, addr)
	if !found {
		return nil
	}

	return val
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

**File:** x/staking/keeper/val_state_change.go (L27-33)
```go
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)
```
