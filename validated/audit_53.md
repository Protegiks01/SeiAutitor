# Audit Report

## Title
Division by Zero Panic in Governance Tally Causes Network Halt When Bonded Validator Has Zero Delegator Shares

## Summary
The governance module's `Tally()` function performs unguarded division by a validator's `DelegatorShares` without checking for zero. When a bonded validator with zero shares has voted on a proposal and the voting period ends, the tally function panics during EndBlocker execution, causing complete network shutdown across all validator nodes.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** The tally function should safely compute voting power for all bonded validators who have voted on proposals, handling edge cases where validators may have zero delegator shares gracefully.

**Actual Logic:** The code performs division by `val.DelegatorShares` without checking if it equals zero. The `Dec.Quo()` method panics when the divisor is zero, causing immediate EndBlock failure. [3](#0-2) 

**Exploitation Path:**
1. A validator operates normally with delegations in bonded status
2. The validator casts a vote on an active governance proposal [4](#0-3) 
3. All delegators remove their delegations via standard `Undelegate` transactions
4. After the final undelegation, the validator has both `Tokens = 0` and `DelegatorShares = 0` [5](#0-4) 
5. The validator remains in bonded status because validators with zero shares are only removed if unbonded [6](#0-5) 
6. The proposal's voting period ends, triggering EndBlock processing
7. The governance EndBlocker executes before the staking EndBlocker [7](#0-6) 
8. The governance EndBlocker calls `Tally()` [8](#0-7) 
9. The tally function iterates over bonded validators using `IterateBondedValidatorsByPower()`, which only checks `IsBonded()` status without verifying shares [9](#0-8) 
10. The zero-share validator with a recorded vote triggers the division calculation at line 80
11. Division by zero occurs, causing a panic
12. All validator nodes panic at the same block height, completely halting the chain

**Security Guarantee Broken:** The network's availability and liveness guarantees are violated. The chain cannot progress past the problematic block, and consensus is permanently stalled until coordinated emergency action.

## Impact Explanation

This vulnerability causes complete network shutdown. When the panic occurs during EndBlock execution:
- All validator nodes crash simultaneously at the same block height due to the unhandled panic
- No new blocks can be produced or transactions processed
- The entire network becomes unavailable to users
- Recovery requires emergency coordination among validators to upgrade to a patched version

This represents a critical denial-of-service vulnerability affecting the entire blockchain network, matching the impact category "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Actors:** Any network participants using standard, permissionless operations.

**Required Conditions:**
- An active governance proposal in voting period
- A bonded validator that votes on the proposal
- All delegators of that validator undelegate before voting period ends
- Voting period ends, triggering automatic tally computation

**Likelihood Assessment:** This scenario is realistic and exploitable:
- **Accidental trigger**: Could occur during market stress when mass undelegations happen, or with validators having few delegators who all exit
- **Deliberate attack**: An attacker can trivially trigger this by operating their own validator with minimal self-delegation, voting on any proposal, then self-undelegating before the proposal's voting period ends
- **No privileges required**: Uses only standard, permissionless blockchain operations
- **Low cost**: Attacker only needs enough tokens to run a validator temporarily (tokens can be reclaimed after undelegating)

## Recommendation

Add a zero-check before performing division in the tally computation:

```go
// iterate over the validators again to tally their voting power
for _, val := range currValidators {
    if len(val.Vote) == 0 {
        continue
    }
    
    // Skip validators with zero delegator shares to avoid division by zero
    if val.DelegatorShares.IsZero() {
        continue
    }

    sharesAfterDeductions := val.DelegatorShares.Sub(val.DelegatorDeductions)
    votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)
    
    for _, option := range val.Vote {
        subPower := votingPower.Mul(option.Weight)
        results[option.Option] = results[option.Option].Add(subPower)
    }
    totalVotingPower = totalVotingPower.Add(votingPower)
}
```

Similarly, add a check at line 57 where delegator voting power is calculated.

## Proof of Concept

**Setup:**
- Create a validator with initial delegation
- Create and activate a governance proposal in voting period
- Validator casts a vote on the proposal

**Action:**
- Retrieve the validator's delegation
- Call `Undelegate()` to remove all shares from the validator
- Verify the validator has `DelegatorShares.IsZero() == true` and `IsBonded() == true`
- Wait for the voting period to end or manually call `Tally()` on the proposal

**Result:**
- The function will panic when `Tally()` attempts division by zero at line 80
- The panic demonstrates that this vulnerability would cause chain halt during EndBlock execution in production

## Notes

The staking module's EndBlocker would eventually handle zero-power validators, but the critical issue is that the governance EndBlocker runs **before** the staking EndBlocker. This module ordering means the governance module encounters the zero-share validator before the staking module can transition it to unbonding state, creating the vulnerability window.

### Citations

**File:** x/gov/keeper/tally.go (L57-57)
```go
				votingPower := delegation.GetShares().MulInt(val.BondedTokens).Quo(val.DelegatorShares)
```

**File:** x/gov/keeper/tally.go (L80-80)
```go
		votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)
```

**File:** types/decimal_test.go (L238-239)
```go
		if tc.d2.IsZero() { // panic for divide by zero
			s.Require().Panics(func() { tc.d1.Quo(tc.d2) })
```

**File:** x/gov/keeper/vote.go (L12-42)
```go
func (keeper Keeper) AddVote(ctx sdk.Context, proposalID uint64, voterAddr sdk.AccAddress, options types.WeightedVoteOptions) error {
	proposal, ok := keeper.GetProposal(ctx, proposalID)
	if !ok {
		return sdkerrors.Wrapf(types.ErrUnknownProposal, "%d", proposalID)
	}
	if proposal.Status != types.StatusVotingPeriod {
		return sdkerrors.Wrapf(types.ErrInactiveProposal, "%d", proposalID)
	}

	for _, option := range options {
		if !types.ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(types.ErrInvalidVote, option.String())
		}
	}

	vote := types.NewVote(proposalID, voterAddr, options)
	keeper.SetVote(ctx, vote)

	// called after a vote on a proposal is cast
	keeper.AfterProposalVote(ctx, proposalID, voterAddr)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeProposalVote,
			sdk.NewAttribute(types.AttributeKeyOption, options.String()),
			sdk.NewAttribute(types.AttributeKeyProposalID, fmt.Sprintf("%d", proposalID)),
		),
	)

	return nil
}
```

**File:** x/staking/types/validator.go (L415-418)
```go
	if remainingShares.IsZero() {
		// last delegation share gets any trimmings
		issuedTokens = v.Tokens
		v.Tokens = sdk.ZeroInt()
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** simapp/app.go (L372-373)
```go
	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName, govtypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/gov/abci.go (L48-51)
```go
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/staking/keeper/alias_functions.go (L45-46)
```go
		if validator.IsBonded() {
			stop := fn(i, validator) // XXX is this safe will the validator unexposed fields be able to get written to?
```
