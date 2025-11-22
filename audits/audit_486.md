## Audit Report

## Title
Stale Validator Set in Governance Tally Due to Module Execution Order

## Summary
The governance tally computation uses a stale validator set because `IterateBondedValidatorsByPower` filters validators by bonded status before the staking module's `EndBlocker` updates validator state transitions. This occurs at [1](#0-0)  where the governance module queries the validator set before staking processes delegation-induced state changes.

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in the interaction between:
- Governance tally computation: [2](#0-1) 
- Staking validator iteration: [3](#0-2) 
- Module execution order: [4](#0-3) 

**Intended Logic:** The tally should compute vote results using the current active validator set based on their current power rankings and bonded status.

**Actual Logic:** The module execution order has governance EndBlocker running before staking EndBlocker (gov → staking). During a block:
1. Delegation/undelegation messages update validator power in the power index immediately via [5](#0-4) 
2. However, validator status transitions (bonded ↔ unbonding ↔ unbonded) only occur in [6](#0-5)  during staking EndBlocker
3. When governance tally runs, `IterateBondedValidatorsByPower` filters by `validator.IsBonded()` at line 45, which reflects bonded status from the START of the block, not current power rankings
4. The tally thus uses validators with stale bonded status while reading their current token amounts

**Exploit Scenario:** An attacker can manipulate governance outcomes by timing strategic delegations:
1. Identify a proposal reaching its voting period end
2. Identify validators near the active set boundary (e.g., ranks 99-101 when maxValidators=100)
3. In the same block as the tally, perform large delegations to unbonded validators or undelegations from bonded validators
4. The power index updates immediately, but bonded status remains stale
5. The tally excludes newly-powerful validators (still marked unbonded) or includes weakened validators (still marked bonded)
6. Proposal outcome reflects the wrong validator set

**Security Failure:** This breaks the governance integrity invariant that tallies should reflect the current validator set. The tally uses an inconsistent state: current token amounts but stale bonded status, causing incorrect vote counts and proposal outcomes.

## Impact Explanation

This vulnerability affects governance proposal outcomes:
- Proposals that should pass may fail (if favorable validators are incorrectly excluded)
- Proposals that should fail may pass (if unfavorable validators are incorrectly included)
- Quorum calculations use [7](#0-6)  but with an incorrect validator set denominator
- No direct fund loss, but governance decisions affect protocol parameters, upgrades, and resource allocation
- Undermines the legitimacy of governance decisions and validator representation

## Likelihood Explanation

**Triggering conditions:**
- Any network participant can submit delegation/undelegation transactions
- Attacker needs sufficient stake to move validators across the active set boundary
- Requires timing to coincide delegations with proposal tallies (predictable via voting period end times)
- More likely when validator power distribution is close to the maxValidators cutoff

**Frequency:** 
- Can occur in any block where both a governance tally happens AND delegations change the validator set composition
- More impactful for contentious proposals with close vote margins
- Automated tools could monitor and exploit this systematically

## Recommendation

Ensure governance tally uses a consistent validator set snapshot by either:

1. **Option A (Recommended):** Call staking's `ApplyAndReturnValidatorSetUpdates` before computing tallies in the governance EndBlocker to ensure validator statuses reflect current power rankings
   
2. **Option B:** Reorder module EndBlockers to execute staking before governance, updating [4](#0-3)  to `stakingtypes.ModuleName, govtypes.ModuleName`

3. **Option C:** Have `IterateBondedValidatorsByPower` use power rankings to determine inclusion (top N validators by current power) rather than filtering by stale bonded status

Option A provides the most localized fix with minimal side effects on other module interactions.

## Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test Function:** `TestTallyStaleValidatorSet`

**Setup:**
1. Initialize chain with maxValidators=2
2. Create 3 validators: Val1 (power 100, bonded), Val2 (power 100, bonded), Val3 (power 0, unbonded)
3. Create governance proposal P
4. Val1 votes YES, Val2 votes NO, Val3 votes YES
5. Set proposal status to voting period

**Trigger:**
1. In the same context (before staking EndBlocker), delegate 150 tokens to Val3
2. Verify Val3's power index shows 150 but status is still Unbonded
3. Call `Tally()` to compute results

**Observation:**
- Expected: Tally should include Val3 (power 150 > Val2's 100), exclude Val2
- Actual: Tally includes Val1 and Val2, excludes Val3 (still unbonded)
- Vote count: 1 YES (Val1), 1 NO (Val2) - incorrect
- Should be: 2 YES (Val1, Val3), 0 NO - if Val3's bonded status was current

The test demonstrates that `IterateBondedValidatorsByPower` returns an inconsistent validator set that doesn't match current power rankings, affecting the tally outcome.

**Notes**
The vulnerability manifests as a temporal inconsistency where the tally uses a hybrid state: validators filtered by stale bonded status but with current token amounts. This violates the governance invariant that tallies should represent the actual validator set's voting power at tally time.

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

**File:** x/staking/keeper/val_state_change.go (L108-222)
```go
func (k Keeper) ApplyAndReturnValidatorSetUpdates(ctx sdk.Context) (updates []abci.ValidatorUpdate, err error) {
	params := k.GetParams(ctx)
	maxValidators := params.MaxValidators
	powerReduction := k.PowerReduction(ctx)
	totalPower := sdk.ZeroInt()
	amtFromBondedToNotBonded, amtFromNotBondedToBonded := sdk.ZeroInt(), sdk.ZeroInt()

	// Retrieve the last validator set.
	// The persistent set is updated later in this function.
	// (see LastValidatorPowerKey).
	last, err := k.getLastValidatorsByAddr(ctx)
	if err != nil {
		return nil, err
	}

	// Iterate over validators, highest power to lowest.
	iterator := k.ValidatorsPowerStoreIterator(ctx)
	defer iterator.Close()

	for count := 0; iterator.Valid() && count < int(maxValidators); iterator.Next() {
		// everything that is iterated in this loop is becoming or already a
		// part of the bonded validator set
		valAddr := sdk.ValAddress(iterator.Value())
		validator := k.mustGetValidator(ctx, valAddr)

		if validator.Jailed {
			panic("should never retrieve a jailed validator from the power store")
		}

		// if we get to a zero-power validator (which we don't bond),
		// there are no more possible bonded validators
		if validator.PotentialConsensusPower(k.PowerReduction(ctx)) == 0 {
			break
		}

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

		// fetch the old power bytes
		valAddrStr, err := sdk.Bech32ifyAddressBytes(sdk.GetConfig().GetBech32ValidatorAddrPrefix(), valAddr)
		if err != nil {
			return nil, err
		}
		oldPowerBytes, found := last[valAddrStr]
		newPower := validator.ConsensusPower(powerReduction)
		newPowerBytes := k.cdc.MustMarshal(&gogotypes.Int64Value{Value: newPower})

		// update the validator set if power has changed
		if !found || !bytes.Equal(oldPowerBytes, newPowerBytes) {
			updates = append(updates, validator.ABCIValidatorUpdate(powerReduction))

			k.SetLastValidatorPower(ctx, valAddr, newPower)
		}

		delete(last, valAddrStr)
		count++

		totalPower = totalPower.Add(sdk.NewInt(newPower))
	}

	noLongerBonded, err := sortNoLongerBonded(last)
	if err != nil {
		return nil, err
	}

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

	// Update the pools based on the recent updates in the validator set:
	// - The tokens from the non-bonded candidates that enter the new validator set need to be transferred
	// to the Bonded pool.
	// - The tokens from the bonded validators that are being kicked out from the validator set
	// need to be transferred to the NotBonded pool.
	switch {
	// Compare and subtract the respective amounts to only perform one transfer.
	// This is done in order to avoid doing multiple updates inside each iterator/loop.
	case amtFromNotBondedToBonded.GT(amtFromBondedToNotBonded):
		k.notBondedTokensToBonded(ctx, amtFromNotBondedToBonded.Sub(amtFromBondedToNotBonded))
	case amtFromNotBondedToBonded.LT(amtFromBondedToNotBonded):
		k.bondedTokensToNotBonded(ctx, amtFromBondedToNotBonded.Sub(amtFromNotBondedToBonded))
	default: // equal amounts of tokens; no update required
	}

	// set total power on lookup index if there are any updates
	if len(updates) > 0 {
		k.SetLastTotalPower(ctx, totalPower)
	}

	return updates, err
}
```
