# Audit Report

## Title
Network Halt Due to Missing Nil Check in Validator Reward Allocation Loop

## Summary
The `AllocateTokens` function in the distribution module lacks a nil check when allocating rewards to validators who voted in the previous block. When a validator is removed from state between voting and reward distribution, the code attempts to dereference a nil validator interface, causing a deterministic panic that crashes all nodes simultaneously and halts the network.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** The reward allocation loop should safely distribute fees to all validators who participated in consensus, handling edge cases where validators may have been removed from state between the voting phase and reward distribution phase.

**Actual logic:** The code retrieves validators via `ValidatorByConsAddr` without checking for nil before passing them to `AllocateTokensToValidator`. [2](#0-1)  When the validator is nil, the immediate call to `val.GetCommission()` causes a nil pointer dereference panic. [3](#0-2) 

**Exploitation path:**

1. **Block N**: A bonded validator participates in consensus and votes. All delegations are removed via `Undelegate` transactions, causing `DelegatorShares` to reach zero.

2. **Block N EndBlock**: The staking module processes validator state changes via `BlockValidatorUpdates`. [4](#0-3)  The validator transitions from Bonded → Unbonding [5](#0-4) , then Unbonding → Unbonded. Since `DelegatorShares.IsZero()`, `RemoveValidator` deletes the validator including its consensus address mapping. [6](#0-5) [7](#0-6) 

3. **Block N+1 BeginBlock**: Distribution module's `BeginBlocker` calls `AllocateTokens` with votes from block N. [8](#0-7)  `ValidatorByConsAddr` returns nil for the removed validator. The code calls `AllocateTokensToValidator(ctx, nil, reward)` without checking nil, causing immediate panic in BeginBlock.

**Security guarantee broken:** Network liveness and availability. BeginBlock must complete successfully for consensus to proceed. The panic violates the invariant that all state transitions must be handled gracefully without crashing the system.

## Impact Explanation

This vulnerability causes complete network shutdown when triggered. Since BeginBlock execution is deterministic and consensus-critical, all validators process identical state and crash at the same block height. This results in:

1. **Total network halt** - No new blocks can be produced since all nodes panic
2. **Loss of transaction finality** - All pending transactions remain unprocessed  
3. **Requires emergency intervention** - Manual coordination among validators to restart nodes, potentially requiring a coordinated upgrade or hard fork

The severity qualifies as High impact: "Network not being able to confirm new transactions (total network shutdown)."

## Likelihood Explanation

**Who can trigger:** Any network participant with delegations can submit `Undelegate` transactions. No special privileges required.

**Conditions:**
1. Unbonding period configured to a short duration (validation only requires > 0, allowing values as low as 1 nanosecond) [9](#0-8) 
2. A validator must have all delegations removed in a single block
3. The validator must participate in consensus during that block

**Frequency:**
- With short unbonding periods (commonly used in testnets): Moderately likely during normal operations
- With standard periods: Less likely but still possible when unbonding naturally completes

**Critical Evidence:** The code explicitly acknowledges this scenario can occur in the proposer reward allocation, which includes a nil check and detailed warning, while the voter reward path lacks this same protection. [10](#0-9) 

## Recommendation

Add a nil check in the vote allocation loop, mirroring the defensive approach used for proposer rewards:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s. "+
            "This should happen only if the validator unbonded completely within a single block.",
            vote.Validator.Address.String()))
        continue
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)
    
    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

When a validator is removed, their allocated rewards remain in the pool and get added to the community pool at function end, maintaining consistency with proposer reward behavior.

## Proof of Concept

**Test Location:** `x/distribution/keeper/allocation_test.go`

**Setup:**
1. Initialize test app with 1-nanosecond unbonding period via staking params
2. Create a validator with minimal delegation (e.g., 100 tokens)  
3. Fund the fee collector module account with distributable fees
4. Include the validator in the vote list for block N

**Action:**
1. Submit `Undelegate` messages removing all delegations from the validator
2. Call `staking.EndBlocker(ctx)` to process validator state changes:
   - Validator transitions Bonded → Unbonding → Unbonded → Removed
3. Call `distribution.BeginBlocker(ctx, req)` with `req.LastCommitInfo.Votes` containing the removed validator

**Result:**
Panic with nil pointer dereference when `AllocateTokens` attempts to call `val.GetCommission()` on the nil interface at line 113 of allocation.go, causing BeginBlock to fail and halt the network.

## Notes

The vulnerability is confirmed by critical code inconsistency: the proposer reward allocation path includes defensive nil checking with detailed warnings, while the voter reward allocation path lacks this protection despite calling the same underlying function and facing identical risks. This pattern, combined with explicit comments acknowledging the edge case, proves this is an oversight in defensive programming rather than intentional design. The deterministic nature of BeginBlock execution ensures all validators crash simultaneously, making this a network-halting vulnerability.

### Citations

**File:** x/distribution/keeper/allocation.go (L68-79)
```go
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

**File:** x/distribution/keeper/allocation.go (L111-113)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
```

**File:** x/staking/keeper/alias_functions.go (L89-95)
```go
func (k Keeper) ValidatorByConsAddr(ctx sdk.Context, addr sdk.ConsAddress) types.ValidatorI {
	val, found := k.GetValidatorByConsAddr(ctx, addr)
	if !found {
		return nil
	}

	return val
```

**File:** x/staking/keeper/val_state_change.go (L22-26)
```go
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
```

**File:** x/staking/keeper/val_state_change.go (L190-198)
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
```

**File:** x/staking/keeper/validator.go (L176-176)
```go
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/distribution/abci.go (L29-31)
```go
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```

**File:** x/staking/types/params.go (L167-177)
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
```
