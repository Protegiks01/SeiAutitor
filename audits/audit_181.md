# Audit Report

## Title
Chain Halt Due to Missing Nil Check When Allocating Rewards to Removed Validators

## Summary
The distribution module's `AllocateTokens` function fails to validate that validators exist before allocating rewards. When a validator participates in consensus but is subsequently removed from state before rewards are distributed, the code passes a nil validator reference to `AllocateTokensToValidator`, causing a panic that halts all nodes and prevents the chain from producing new blocks.

## Impact
High

## Finding Description

**Location:** `x/distribution/keeper/allocation.go` lines 91-102 and line 113

**Intended Logic:**
The `AllocateTokens` function should safely distribute block rewards to all validators that participated in creating the previous block. When looking up validators by consensus address, the function should handle cases where validators may have been removed from state between block production and reward distribution.

**Actual Logic:**
The function retrieves each validator from the `bondedVotes` list by calling `ValidatorByConsAddr` but does not verify the returned value is non-nil before usage. [1](#0-0) 

When `ValidatorByConsAddr` returns nil (because the validator was removed), this nil value is passed directly to `AllocateTokensToValidator`, which immediately panics when attempting to call `val.GetCommission()` on the nil interface. [2](#0-1) 

Notably, the code already implements proper nil checking for the proposer validator with graceful error handling and logging, but this protection was not applied to regular voters. [3](#0-2) 

**Exploitation Path:**
1. A validator V is active in the bonded set at block N and participates in consensus (votes are recorded)
2. At block N EndBlock, validator V is removed from the active set and transitions to Unbonding state [4](#0-3) 
3. At block N+1 EndBlock (or later), V completes unbonding with zero delegations and is removed via `RemoveValidator` [5](#0-4) 
4. The removal deletes V from the consensus address index, causing `ValidatorByConsAddr` to return nil [6](#0-5) 
5. At block N+2 BeginBlock, `AllocateTokens` is called with votes from block N+1 including validator V
6. The code retrieves nil for validator V but doesn't check before calling `AllocateTokensToValidator(ctx, nil, reward)`
7. Panic occurs at `val.GetCommission()`, causing all nodes to crash simultaneously

**Security Guarantee Broken:**
The chain's liveness guarantee is violated. BeginBlock must never panic as it executes identically on all nodes, meaning a panic causes a total network halt that cannot be recovered without manual intervention.

## Impact Explanation

**Network Availability:** The entire blockchain network becomes unable to confirm new transactions. All validator nodes panic during BeginBlock execution at the same block height and cannot advance to the next block.

**Recovery Requirements:**
- A coordinated hard fork to skip the problematic block, or
- Manual intervention to modify chain parameters and restart from a previous state
- Both options require coordinated off-chain action from validators

**Triggering Conditions:** This vulnerability can occur during normal chain operation when:
- The chain has a short unbonding period (common in test networks or if governance reduces the parameter)
- Any validator unbonds all delegations during the critical timing window
- The code comments explicitly acknowledge this scenario: "if the unbonding period is 1 block" [7](#0-6) 

## Likelihood Explanation

**Who Can Trigger:** 
- Any participant who can create and operate a validator
- Any existing validator that fully unbonds when the unbonding period is short
- The scenario can occur naturally without malicious intent

**Conditions Required:**
- Chain must have a short unbonding period (1-2 blocks), which is common in:
  - Test networks and development environments
  - Chains where governance has reduced the unbonding time
- A validator must be removed from state between participating in consensus and reward allocation

**Frequency:** While requiring specific timing, this scenario:
- Is explicitly documented in the code comments as possible
- Can happen naturally during validator exits with short unbonding periods
- Could be deliberately triggered by a malicious actor who creates a validator and immediately unbonds all delegations

The code's existing protection for the proposer case demonstrates the developers were aware of this timing issue but didn't apply the fix consistently to all validators.

## Recommendation

Add a nil check for validators in the `bondedVotes` loop, mirroring the existing protection for the proposer validator. When a validator is not found, log a warning and skip reward allocation, allowing those rewards to remain in the community pool:

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

**Test Function:** `TestAllocateTokensToRemovedValidator` (to be added to `x/distribution/keeper/allocation_test.go`)

**Setup:**
1. Initialize test application with a very short unbonding time (1 second)
2. Create a validator with self-delegation
3. Fund the fee collector with tokens for distribution

**Trigger:**
1. Undelegate all tokens from the validator
2. Apply validator set updates (EndBlock) to transition validator to Unbonding
3. Advance time past the unbonding period
4. Call `UnbondAllMatureValidators` to complete unbonding and remove the validator from state
5. Verify validator is removed (not found in state)
6. Create a `VoteInfo` list including the now-removed validator
7. Call `AllocateTokens` with these votes

**Result:**
The call to `AllocateTokens` panics at line 113 of `allocation.go` when attempting to call `val.GetCommission()` on a nil validator interface, demonstrating that the vulnerability causes a chain-halting panic.

## Notes

This vulnerability is particularly concerning because:

1. **Inconsistent Protection**: The code already handles this exact scenario for the proposer validator but fails to apply the same protection to regular voters, indicating an incomplete fix.

2. **Documented Scenario**: The code comments explicitly acknowledge this timing issue can occur, yet the protection wasn't applied consistently across all code paths.

3. **High Impact**: A panic in BeginBlock is one of the most severe issues in a blockchain system as it simultaneously crashes all nodes and requires coordinated manual intervention to recover.

4. **Production Risk**: While more likely in test environments with short unbonding periods, production chains could be vulnerable if governance reduces the unbonding time or during specific validator exit patterns.

### Citations

**File:** x/distribution/keeper/allocation.go (L55-79)
```go
	proposerValidator := k.stakingKeeper.ValidatorByConsAddr(ctx, previousProposer)

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

**File:** x/distribution/keeper/allocation.go (L109-114)
```go
// AllocateTokensToValidator allocate tokens to a particular validator,
// splitting according to commission.
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** x/staking/keeper/val_state_change.go (L190-199)
```go
	for _, valAddrBytes := range noLongerBonded {
		validator := k.mustGetValidator(ctx, sdk.ValAddress(valAddrBytes))
		validator, err = k.bondedToUnbonding(ctx, validator)
		if err != nil {
			return
		}
		amtFromBondedToNotBonded = amtFromBondedToNotBonded.Add(validator.GetTokens())
		k.DeleteLastValidatorPower(ctx, validator.GetOperator())
		updates = append(updates, validator.ABCIValidatorUpdateZero())
	}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
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
