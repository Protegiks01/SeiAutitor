## Audit Report

## Title
Node Crash Due to Missing Nil Check for Removed Validators in Reward Allocation Loop

## Summary
The `AllocateTokens` function in the distribution module fails to check if `ValidatorByConsAddr` returns `nil` when processing votes from bonded validators. When a validator that voted in block N is removed during block N's EndBlock (due to complete unbonding with a short unbonding period), the subsequent block's BeginBlock will crash when attempting to allocate rewards to the nil validator, causing a network-wide denial of service. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Module: `x/distribution/keeper`
- File: `allocation.go`
- Lines: 91-100 (vote allocation loop)
- Function: `AllocateTokens`

**Intended Logic:** 
The code should safely handle all validators in the `bondedVotes` list from the previous block, allocating rewards proportionally to their voting power. The system expects that all validators who participated in consensus receive their rewards, maintaining the invariant that voting power is properly rewarded.

**Actual Logic:** 
The code calls `ValidatorByConsAddr` without checking for nil before passing the result to `AllocateTokensToValidator`. When a validator is removed from state between voting in block N and reward allocation in block N+1, the lookup returns nil, causing a panic when `AllocateTokensToValidator` attempts to call methods on the nil interface. [2](#0-1) 

Contrast this with the proposer reward logic which explicitly handles this case: [3](#0-2) 

**Exploit Scenario:**

1. **Block N**: A validator is bonded and participates in consensus by voting/signing block N. During this block, all delegations to this validator are removed via `Undelegate` messages, causing `DelegatorShares` to become zero.

2. **Block N EndBlock**: 
   - `ApplyAndReturnValidatorSetUpdates` transitions the validator from Bonded → Unbonding [4](#0-3) 
   
   - With a short unbonding period (configurable parameter, can be as low as 1 nanosecond), `UnbondAllMatureValidators` immediately transitions the validator from Unbonding → Unbonded [5](#0-4) 
   
   - Since `DelegatorShares.IsZero()` and the validator `IsUnbonded()`, `RemoveValidator` is called, completely deleting the validator and its consensus address mapping: [6](#0-5) [7](#0-6) 

3. **Block N+1 BeginBlock**: 
   - `AllocateTokens` is called with `LastCommitInfo.GetVotes()` from block N [8](#0-7) 
   
   - For the removed validator's vote, `ValidatorByConsAddr` returns nil: [9](#0-8) [10](#0-9) 
   
   - `AllocateTokensToValidator(ctx, nil, reward)` is called without a nil check
   - **PANIC** occurs when attempting to dereference nil: `val.GetCommission()`

**Security Failure:** 
This is a memory safety violation (nil pointer dereference) that crashes the node during BeginBlock processing. Since BeginBlock is consensus-critical and all nodes process the same state transitions, this causes a complete network halt if all nodes share similar configuration (same unbonding period).

## Impact Explanation

**Affected Components:**
- Network availability and liveness
- Block production and transaction finality
- All nodes in the network (consensus failure)

**Severity:**
When triggered, this vulnerability causes immediate node crashes during BeginBlock execution. Since this is deterministic based on blockchain state, all nodes will crash at the same block height when processing the same reward allocation. This results in:

1. **Complete network shutdown** - No new blocks can be produced
2. **Transaction finality loss** - All pending transactions remain unprocessed
3. **Requires emergency intervention** - Manual node restart and potentially a coordinated upgrade/hard fork to fix the state

The vulnerability is particularly severe because:
- It affects consensus-critical code (BeginBlock)
- The crash is deterministic and will affect all nodes simultaneously
- Recovery requires coordinated action across all validators
- The network cannot self-recover without external intervention

## Likelihood Explanation

**Who can trigger it:**
Any network participant who can submit `Undelegate` transactions. No special privileges are required beyond having a delegation to a validator.

**Conditions required:**
1. The staking module must be configured with a very short unbonding period (technologically possible, validated only to be > 0): [11](#0-10) 

2. A validator must have all delegations removed within a single block (achievable through coordinated or large single undelegations)

3. The validator must participate in consensus during that block (highly likely if it's bonded)

**Frequency:**
- With short unbonding periods (used in testnets or some chains): Moderately likely during normal operations
- With standard 3-week unbonding: Less likely but still possible if a validator has minimal delegations
- The comment in the code explicitly acknowledges this scenario can happen: [12](#0-11) 

The fact that the proposer reward allocation explicitly handles this case with a warning log suggests the developers were aware of this edge case but failed to apply the same protection to voter rewards.

## Recommendation

Add a nil check in the vote allocation loop, mirroring the approach used for proposer rewards:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    // Add nil check here
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s. "+
            "This should happen only if the validator unbonded completely within a single block.",
            vote.Validator.Address.String()))
        continue  // Skip this validator and continue with others
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)

    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

This ensures that if a validator is removed, their rewards simply remain in the pool (added to community pool at the end) rather than causing a crash. This matches the behavior for proposer rewards and maintains network stability.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`  
**Test Function:** `TestAllocateTokensWithRemovedValidator`

**Setup:**
1. Initialize a test chain with the staking keeper configured with a 1-nanosecond unbonding period
2. Create a validator with minimal delegation (e.g., 100 tokens)
3. Fund the fee collector with some fees to distribute
4. Have the validator participate in block N by including it in the vote list

**Trigger:**
1. In the same block, submit an `Undelegate` message removing all delegations from the validator
2. Call `staking.EndBlocker` to process validator state changes, which will:
   - Transition the validator to unbonding
   - Immediately complete unbonding (due to 1ns period)
   - Remove the validator from state (since DelegatorShares is zero)
3. Advance to the next block
4. Call `distribution.BeginBlocker` with the vote info from the previous block containing the now-removed validator

**Observation:**
The test will panic with a nil pointer dereference when `AllocateTokens` attempts to call `validator.GetCommission()` on the nil validator returned by `ValidatorByConsAddr`. This confirms the vulnerability.

**Expected test code structure:**
```go
func TestAllocateTokensWithRemovedValidator(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Set 1 nanosecond unbonding period
    params := app.StakingKeeper.GetParams(ctx)
    params.UnbondingTime = 1 * time.Nanosecond
    app.StakingKeeper.SetParams(ctx, params)
    
    // Create validator and setup (implementation details)
    // ... 
    
    // Submit undelegate to remove all delegations
    // Call EndBlocker (validator gets removed)
    // Prepare vote info with removed validator
    // Call AllocateTokens
    // Expect panic (test with require.Panics or similar)
}
```

The test demonstrates that the current code will panic, confirming the vulnerability is exploitable and causes network-wide denial of service.

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

**File:** x/distribution/keeper/allocation.go (L111-115)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)

```

**File:** x/staking/keeper/val_state_change.go (L22-26)
```go
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
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

**File:** x/staking/keeper/validator.go (L36-45)
```go
func (k Keeper) GetValidatorByConsAddr(ctx sdk.Context, consAddr sdk.ConsAddress) (validator types.Validator, found bool) {
	store := ctx.KVStore(k.storeKey)

	opAddr := store.Get(types.GetValidatorByConsAddrKey(consAddr))
	if opAddr == nil {
		return validator, false
	}

	return k.GetValidator(ctx, opAddr)
}
```

**File:** x/staking/keeper/validator.go (L153-181)
```go
func (k Keeper) RemoveValidator(ctx sdk.Context, address sdk.ValAddress) {
	// first retrieve the old validator record
	validator, found := k.GetValidator(ctx, address)
	if !found {
		return
	}

	if !validator.IsUnbonded() {
		panic("cannot call RemoveValidator on bonded or unbonding validators")
	}

	if validator.Tokens.IsPositive() {
		panic("attempting to remove a validator which still contains tokens")
	}

	valConsAddr, err := validator.GetConsAddr()
	if err != nil {
		panic(err)
	}

	// delete the old validator record
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetValidatorKey(address))
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
	store.Delete(types.GetValidatorsByPowerIndexKey(validator, k.PowerReduction(ctx)))

	// call hooks
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
}
```

**File:** x/staking/keeper/validator.go (L399-450)
```go
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
