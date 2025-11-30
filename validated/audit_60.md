# Audit Report

## Title
Chain Halt Due to Missing Nil Check When Allocating Rewards to Removed Validators

## Summary
The distribution module's `AllocateTokens` function lacks nil validation for validators in the voting loop, while the same protection exists for the proposer. When a validator participates in consensus but is removed before reward distribution, the code panics on `val.GetCommission()`, causing a deterministic chain halt across all nodes.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `AllocateTokens` function should safely distribute rewards to all validators that participated in the previous block, gracefully handling cases where validators may have been removed from state between block production and reward distribution.

**Actual Logic:** The function retrieves each validator from `bondedVotes` via `ValidatorByConsAddr` without verifying the returned value is non-nil before usage. [2](#0-1)  When `ValidatorByConsAddr` returns nil (validator was removed), this nil value is passed to `AllocateTokensToValidator`, which immediately panics when calling `val.GetCommission()` on the nil interface. [3](#0-2) 

**Exploitation Path:**
1. Validator V is active at block N and votes in consensus
2. At block N EndBlock, validator transitions through unbonding states per staking module logic
3. At a subsequent block's EndBlock, `UnbondAllMatureValidators` is called [4](#0-3) 
4. V completes unbonding with zero delegations and `RemoveValidator` is executed [5](#0-4) 
5. The removal deletes V from the consensus address index [6](#0-5) 
6. At next block BeginBlock, `AllocateTokens` is called with `LastCommitInfo.GetVotes()` including V [7](#0-6) 
7. `ValidatorByConsAddr` returns nil for V (no longer in index)
8. No nil check exists; code calls `AllocateTokensToValidator(ctx, nil, reward)`
9. Panic occurs at line 113 when calling `val.GetCommission()` on nil interface
10. All nodes crash simultaneously at the same block height

**Security Guarantee Broken:** Chain liveness guarantee. BeginBlock executes deterministically on all nodes and must never panic, as this causes total network shutdown.

## Impact Explanation

A panic in BeginBlock causes all validator nodes to crash at the same block height deterministically since BeginBlock execution is part of the ABCI state machine that runs identically across all nodes. The entire network halts and cannot confirm new transactions. Recovery requires coordinated manual intervention such as a hard fork to skip the problematic block or consensus to restart from previous state. This directly matches the "Network not being able to confirm new transactions (total network shutdown)" impact criterion defined as Medium severity.

## Likelihood Explanation

**Triggering Conditions:**
- Any validator that fully unbonds (all delegations removed) can trigger this vulnerability
- Timing window: validator removed in block N's EndBlock, rewards allocated in block N+1's BeginBlock
- More likely with short unbonding periods (configurable via governance) [8](#0-7) 
- Can occur naturally through normal validator operations or be deliberately triggered by any validator operator

**Evidence of Developer Awareness:** The code explicitly handles this exact scenario for the proposer validator with detailed error logging [9](#0-8) , proving developers were aware of this timing issue. The comment at lines 69-77 explicitly describes: "validator undelegates at block X, it's removed entirely by block X+1's endblock, then X+2 we need to refer to the previous proposer for X+1, but we've forgotten about them." This same protection was not applied to the voters loop, indicating an incomplete fix.

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
1. Initialize test app with short unbonding period (e.g., 1-2 seconds)
2. Create validator with self-delegation
3. Fund fee collector with distribution tokens

**Action:**
1. Undelegate all tokens from validator
2. Call `BlockValidatorUpdates` to transition validator to Unbonding state
3. Advance block time past unbonding period
4. Call `UnbondAllMatureValidators` to complete unbonding and remove validator from state
5. Verify validator removal via `ValidatorByConsAddr` returning nil
6. Create `VoteInfo` slice including the removed validator's consensus address with voting power
7. Call `AllocateTokens` with these votes and appropriate parameters

**Result:**
Panic at line 113 of `allocation.go` when calling `val.GetCommission()` on nil interface, demonstrating the chain-halting vulnerability. The panic is deterministic and would occur on all nodes simultaneously, halting the entire network.

## Notes

**Critical Inconsistency:** The codebase implements proper nil handling for the proposer case with detailed error logging explaining the timing scenario, but completely omits this protection for regular voters. This inconsistency strongly indicates the vulnerability is unintentional rather than by design. The existence of the proposer check with its explicit comment describing the exact timing scenario proves this is a known edge case that was incompletely addressed.

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

**File:** x/staking/keeper/val_state_change.go (L27-33)
```go
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)
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

**File:** x/staking/types/params.go (L167-178)
```go
func validateUnbondingTime(i interface{}) error {
	v, ok := i.(time.Duration)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v <= 0 {
		return fmt.Errorf("unbonding time must be positive: %d", v)
	}

	return nil
}
```
