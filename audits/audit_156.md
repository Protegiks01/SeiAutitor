# Audit Report

## Title
Stale Validator Set in Governance Tally Due to Module Execution Order

## Summary
The governance tally computation uses an inconsistent validator set where validators are filtered by stale bonded status from the previous block while their voting power reflects current delegations. This occurs because the governance EndBlocker executes before the staking EndBlocker, creating a temporal mismatch between the power index (updated immediately on delegation) and validator status transitions (updated only in staking EndBlocker).

## Impact
Medium

## Finding Description

**Location:**
- Governance tally: [1](#0-0) 
- Validator iteration: [2](#0-1) 
- Module execution order: [3](#0-2) 

**Intended Logic:** 
The governance tally should compute proposal outcomes using the current active validator set, where validators are selected based on their current power rankings and bonded status reflecting the same state snapshot.

**Actual Logic:**
1. When delegations occur during transaction processing, `AddValidatorTokensAndShares` updates the validator power index immediately [4](#0-3) 
2. However, validator status transitions (bonded ↔ unbonding ↔ unbonded) only occur in `ApplyAndReturnValidatorSetUpdates` during the staking EndBlocker [5](#0-4) 
3. The module execution order specifies governance before staking [3](#0-2) 
4. When `Tally` executes via governance EndBlocker [6](#0-5) , it calls `IterateBondedValidatorsByPower` which iterates by current power but filters by `validator.IsBonded()` at line 45, reflecting the bonded status from the START of the block

**Exploitation Path:**
1. Attacker identifies a proposal reaching voting period end (timestamp-based, predictable)
2. Attacker identifies validators near the maxValidators boundary (e.g., ranks 99-101 when max=100)
3. In the same block as the tally, attacker submits large delegation to an unbonded validator or undelegation from a bonded validator
4. The power index updates immediately, changing validator rankings
5. Governance EndBlocker runs first, computing tally with current token amounts but stale bonded status
6. Newly-powerful validators (still marked unbonded) are excluded from tally
7. Weakened validators (still marked bonded) are included in tally
8. Proposal outcome reflects incorrect validator set

**Security Guarantee Broken:**
The governance integrity invariant is violated: tallies should reflect the actual active validator set's voting power at tally time. Instead, the tally uses a hybrid inconsistent state with current token amounts but previous block's bonded status.

## Impact Explanation

This vulnerability directly affects governance proposal outcomes:
- Proposals that should pass may fail if favorable validators are incorrectly excluded
- Proposals that should fail may pass if unfavorable validators are incorrectly included  
- Quorum calculations use the wrong validator set denominator [7](#0-6) 
- While there is no direct fund loss, governance decisions control protocol parameters, upgrades, and resource allocation
- Undermines the legitimacy and integrity of the governance system

This matches the Medium severity criterion: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Triggering Conditions:**
- Any network participant can submit delegation/undelegation transactions (no special privileges required)
- Attacker needs sufficient stake to move validators across the active set boundary (feasible for high-stake actors)
- Requires timing delegations to coincide with proposal tallies, which are predictable via voting period end times
- More likely when validator power distribution is close to the maxValidators cutoff

**Frequency:**
- Can occur in any block where both a governance tally happens AND delegations change validator set composition
- More impactful for contentious proposals with close vote margins
- Automated monitoring tools could systematically exploit this
- While transaction inclusion timing introduces probabilistic elements, the predictability of proposal end times enables targeted attacks

**Evidence of Known Concern:**
Test files explicitly call `staking.EndBlocker` after delegations before performing tallies [8](#0-7) , [9](#0-8) , suggesting developers understand the need to update validator statuses before tallying. However, the production module execution order does not implement this safeguard.

## Recommendation

Ensure governance tally uses a consistent validator set snapshot by implementing one of these options:

**Option A (Recommended):** Call staking's `ApplyAndReturnValidatorSetUpdates` before computing tallies in the governance EndBlocker. This ensures validator statuses reflect current power rankings with minimal side effects.

**Option B:** Reorder module EndBlockers to execute staking before governance: change to `stakingtypes.ModuleName, govtypes.ModuleName` [3](#0-2) 

**Option C:** Modify `IterateBondedValidatorsByPower` to use power rankings directly for inclusion (top N validators by current power) rather than filtering by bonded status field.

## Proof of Concept

**Conceptual Test:** `TestTallyStaleValidatorSet` (to be added to `x/gov/keeper/tally_test.go`)

**Setup:**
1. Initialize chain with maxValidators=2
2. Create 3 validators: Val1 (100 tokens, bonded, rank 1), Val2 (100 tokens, bonded, rank 2), Val3 (0 tokens, unbonded, rank 3)
3. Create governance proposal with Val1 voting YES, Val2 voting NO, Val3 voting YES
4. Set proposal status to voting period end

**Action:**
1. In the same context (before staking EndBlocker), delegate 150 tokens to Val3
2. Verify Val3's power index now shows 150 tokens (should be rank 1)
3. Verify Val3's status is still Unbonded (not yet updated)
4. Call `keeper.Tally()` directly (simulating governance EndBlocker)

**Expected Result (Correct):**
- Tally should include Val3 (power 150 > Val2's 100), exclude Val2
- Vote count: 2 YES (Val1, Val3), 0 NO

**Actual Result (Bug):**
- Tally includes Val1 and Val2 (both bonded), excludes Val3 (still unbonded status)
- Vote count: 1 YES (Val1), 1 NO (Val2)
- Proposal outcome is incorrect

This demonstrates that `IterateBondedValidatorsByPower` returns an inconsistent validator set that doesn't match current power rankings when delegations occur in the same block as the tally.

### Citations

**File:** x/gov/keeper/tally.go (L13-34)
```go
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal) (passes bool, burnDeposits bool, tallyResults types.TallyResult) {
	results := make(map[types.VoteOption]sdk.Dec)
	results[types.OptionYes] = sdk.ZeroDec()
	results[types.OptionAbstain] = sdk.ZeroDec()
	results[types.OptionNo] = sdk.ZeroDec()
	results[types.OptionNoWithVeto] = sdk.ZeroDec()

	totalVotingPower := sdk.ZeroDec()
	currValidators := make(map[string]types.ValidatorGovInfo)

	// fetch all the bonded validators, insert them into currValidators
	keeper.sk.IterateBondedValidatorsByPower(ctx, func(index int64, validator stakingtypes.ValidatorI) (stop bool) {
		currValidators[validator.GetOperator().String()] = types.NewValidatorGovInfo(
			validator.GetOperator(),
			validator.GetBondedTokens(),
			validator.GetDelegatorShares(),
			sdk.ZeroDec(),
			types.WeightedVoteOptions{},
		)

		return false
	})
```

**File:** x/gov/keeper/tally.go (L99-99)
```go
	percentVoting := totalVotingPower.Quo(keeper.sk.TotalBondedTokens(ctx).ToDec())
```

**File:** x/staking/keeper/alias_functions.go (L33-53)
```go
func (k Keeper) IterateBondedValidatorsByPower(ctx sdk.Context, fn func(index int64, validator types.ValidatorI) (stop bool)) {
	store := ctx.KVStore(k.storeKey)
	maxValidators := k.MaxValidators(ctx)

	iterator := sdk.KVStoreReversePrefixIterator(store, types.ValidatorsByPowerIndexKey)
	defer iterator.Close()

	i := int64(0)
	for ; iterator.Valid() && i < int64(maxValidators); iterator.Next() {
		address := iterator.Value()
		validator := k.mustGetValidator(ctx, address)

		if validator.IsBonded() {
			stop := fn(i, validator) // XXX is this safe will the validator unexposed fields be able to get written to?
			if stop {
				break
			}
			i++
		}
	}
}
```

**File:** simapp/app.go (L372-373)
```go
	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName, govtypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/staking/keeper/validator.go (L98-106)
```go
func (k Keeper) AddValidatorTokensAndShares(ctx sdk.Context, validator types.Validator,
	tokensToAdd sdk.Int) (valOut types.Validator, addedShares sdk.Dec) {
	k.DeleteValidatorByPowerIndex(ctx, validator)
	validator, addedShares = validator.AddTokensFromDel(tokensToAdd)
	k.SetValidator(ctx, validator)
	k.SetValidatorByPowerIndex(ctx, validator)

	return validator, addedShares
}
```

**File:** x/staking/keeper/val_state_change.go (L143-161)
```go
		// apply the appropriate state change if necessary
		switch {
		case validator.IsUnbonded():
			validator, err = k.unbondedToBonded(ctx, validator)
			if err != nil {
				return
			}
			amtFromNotBondedToBonded = amtFromNotBondedToBonded.Add(validator.GetTokens())
		case validator.IsUnbonding():
			validator, err = k.unbondingToBonded(ctx, validator)
			if err != nil {
				return
			}
			amtFromNotBondedToBonded = amtFromNotBondedToBonded.Add(validator.GetTokens())
		case validator.IsBonded():
			// no state change
		default:
			panic("unexpected validator status")
		}
```

**File:** x/gov/abci.go (L51-51)
```go
		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/gov/keeper/tally_test.go (L281-281)
```go
	_ = staking.EndBlocker(ctx, app.StakingKeeper)
```

**File:** x/gov/keeper/tally_test.go (L317-317)
```go
	_ = staking.EndBlocker(ctx, app.StakingKeeper)
```
