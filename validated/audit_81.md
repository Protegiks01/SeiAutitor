# Audit Report

## Title
Lack of Zero Voting Power Validation in Validator Set Updates Allows Complete Network Halt

## Summary
The `ApplyAndReturnValidatorSetUpdates` function in the staking module fails to validate that total voting power remains above zero before setting it. When all validators are simultaneously jailed due to mass downtime, the function sets total power to zero without validation, resulting in complete network shutdown as Tendermint/CometBFT cannot reach consensus with zero voting power. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/val_state_change.go`, lines 217-219 where total power is set without validation

**Intended Logic:** The validator set update mechanism should maintain at least one validator with positive voting power to ensure the network can continue producing blocks and reaching consensus. The system should prevent scenarios where the entire validator set becomes powerless.

**Actual Logic:** The function initializes `totalPower` to zero and only accumulates power from validators found in the power store iterator. When validators are jailed, they are removed from the power store via `DeleteValidatorByPowerIndex`. [2](#0-1)  If all validators are jailed simultaneously, the power store becomes empty, the iterator yields no validators, and `totalPower` remains at zero. The function then sets `totalPower` to zero without any validation check.

**Exploitation Path:**
1. Network-wide outage or mass validator downtime occurs (e.g., cloud provider failure, software bug, network partition)
2. All validators miss blocks beyond the `maxMissed` threshold [3](#0-2) 
3. All validators are jailed via `k.sk.Jail(ctx, consAddr)` [4](#0-3) 
4. Each jailed validator is removed from the power store
5. In the next EndBlock, `ApplyAndReturnValidatorSetUpdates` is called
6. The power store iterator finds no validators (all removed when jailed)
7. The loop doesn't accumulate any power, leaving `totalPower` at zero
8. Previously bonded validators receive zero-power updates
9. The function sets `totalPower` to zero and returns zero-power validator set to Tendermint
10. Tendermint cannot reach consensus with zero total voting power (requires >2/3)
11. Network halts completely - no new blocks can be produced

**Security Guarantee Broken:** The fundamental consensus availability invariant is violated. A Proof-of-Stake blockchain must maintain at least one active validator with positive voting power to function.

## Impact Explanation

This vulnerability results in complete network shutdown with the following consequences:

1. **No Block Production**: With zero total voting power, Tendermint/CometBFT cannot select a proposer or reach consensus on new blocks
2. **Transaction Halt**: All pending and new transactions cannot be confirmed or executed  
3. **State Freeze**: The blockchain state becomes permanently frozen at the last successfully committed block
4. **Unrecoverable Without Hard Fork**: Since no transactions can execute (including unjail transactions), validators cannot recover themselves. Recovery requires coordinated manual intervention such as a hard fork with validator set restoration
5. **Economic Damage**: Extended downtime causes loss of user confidence, potential loss of network value, and damage to ecosystem projects

The impact matches the accepted category: "Network not being able to confirm new transactions (total network shutdown)" - Medium severity.

## Likelihood Explanation

**Who Can Trigger:** This is triggered by operational conditions affecting all validators simultaneously:
- Infrastructure failures: Cloud provider outages, ISP failures
- Software issues: Bugs in validator software affecting all nodes running the same version
- Network conditions: Widespread DDoS attacks, network partitions
- Operational errors: Misconfigured chain upgrades

**Conditions Required:**
- All validators must simultaneously exceed the downtime slashing threshold
- Can realistically occur during network-wide infrastructure failures or software bugs
- No privileged access or malicious intent required

**Frequency:**
- Low probability under normal operations with geographically distributed, diverse validator infrastructure
- Higher probability during major cloud provider outages, chain upgrades with bugs, or network-level attacks

While the likelihood is low, the catastrophic impact (complete network halt requiring hard fork) makes this a critical vulnerability. Defense-in-depth principles dictate that the application layer should validate its own invariants rather than relying solely on operational best practices.

## Recommendation

Add validation in `ApplyAndReturnValidatorSetUpdates` to prevent zero total voting power:

```go
// set total power on lookup index if there are any updates
if len(updates) > 0 {
    if totalPower.IsZero() {
        return nil, fmt.Errorf("total voting power cannot be zero: this would halt the network")
    }
    k.SetLastTotalPower(ctx, totalPower)
}
```

Additional recommendations:
1. **Genesis Validation**: Add checks during chain initialization to ensure at least one validator with positive power exists
2. **Minimum Validator Check**: Consider adding a configurable minimum number of active validators required
3. **Emergency Recovery Mechanism**: Document and implement emergency validator set recovery procedures
4. **Monitoring and Alerting**: Implement alerts when total voting power drops below critical thresholds

## Proof of Concept

**Setup:**
1. Initialize test application with multiple validators having bonded status and positive voting power
2. Apply initial validator set updates to establish the bonded validator set
3. Verify the network has positive total voting power

**Action:**
1. Simulate mass jailing by setting all validators' `Jailed` flag to true
2. Remove all validators from the power index via `DeleteValidatorByPowerIndex`
3. Call `ApplyAndReturnValidatorSetUpdates` to process validator set changes

**Result:**
1. The function returns successfully without error
2. All validator updates have zero power
3. `GetLastTotalPower` returns zero
4. This zero-power validator set would be sent to Tendermint, causing network halt

The test would follow patterns in `x/staking/keeper/validator_test.go` using the `applyValidatorSetUpdates` helper function. [5](#0-4) 

## Notes

This vulnerability has been validated through code analysis:
- No validation exists in `SetLastTotalPower` [6](#0-5) 
- No minimum validator checks in genesis validation [7](#0-6) 
- The panic at line 133 ("should never retrieve a jailed validator from the power store") confirms jailed validators are removed from power store, but there's no safeguard for when ALL validators are jailed simultaneously

### Citations

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

**File:** x/staking/keeper/val_state_change.go (L260-268)
```go
func (k Keeper) jailValidator(ctx sdk.Context, validator types.Validator) {
	if validator.Jailed {
		panic(fmt.Sprintf("cannot jail already jailed validator, validator: %v\n", validator))
	}

	validator.Jailed = true
	k.SetValidator(ctx, validator)
	k.DeleteValidatorByPowerIndex(ctx, validator)
}
```

**File:** x/slashing/keeper/infractions.go (L96-122)
```go
	if height > minHeight && signInfo.MissedBlocksCounter > maxMissed {
		validator := k.sk.ValidatorByConsAddr(ctx, consAddr)
		if validator != nil && !validator.IsJailed() {
			// Downtime confirmed: slash and jail the validator
			// We need to retrieve the stake distribution which signed the block, so we subtract ValidatorUpdateDelay from the evidence height,
			// and subtract an additional 1 since this is the LastCommit.
			// Note that this *can* result in a negative "distributionHeight" up to -ValidatorUpdateDelay-1,
			// i.e. at the end of the pre-genesis block (none) = at the beginning of the genesis block.
			// That's fine since this is just used to filter unbonding delegations & redelegations.
			shouldSlash = true
			distributionHeight := height - sdk.ValidatorUpdateDelay - 1
			slashInfo = SlashInfo{
				height:             height,
				power:              power,
				distributionHeight: distributionHeight,
				minHeight:          minHeight,
				minSignedPerWindow: minSignedPerWindow,
			}
			// This value is passed back and the validator is slashed and jailed appropriately
		} else {
			// validator was (a) not found or (b) already jailed so we do not slash
			logger.Info(
				"validator would have been slashed for downtime, but was either not found in store or already jailed",
				"validator", consAddr.String(),
			)
		}
	}
```

**File:** x/staking/keeper/slash.go (L145-151)
```go
// jail a validator
func (k Keeper) Jail(ctx sdk.Context, consAddr sdk.ConsAddress) {
	validator := k.mustGetValidatorByConsAddr(ctx, consAddr)
	k.jailValidator(ctx, validator)
	logger := k.Logger(ctx)
	logger.Info("validator jailed", "validator", consAddr)
}
```

**File:** x/staking/keeper/validator_test.go (L1108-1120)
```go
func applyValidatorSetUpdates(t *testing.T, ctx sdk.Context, k keeper.Keeper, expectedUpdatesLen int) []abci.ValidatorUpdate {
	updates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	require.NoError(t, err)
	if expectedUpdatesLen >= 0 {
		require.Equal(t, expectedUpdatesLen, len(updates), "%v", updates)
	}
	return utils.Map(updates, func(v abci.ValidatorUpdate) abci.ValidatorUpdate {
		return abci.ValidatorUpdate{
			PubKey: v.PubKey,
			Power:  v.Power,
		}
	})
}
```

**File:** x/staking/keeper/keeper.go (L95-98)
```go
func (k Keeper) SetLastTotalPower(ctx sdk.Context, power sdk.Int) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&sdk.IntProto{Int: power})
	store.Set(types.LastTotalPowerKey, bz)
```

**File:** x/staking/genesis.go (L230-235)
```go
func ValidateGenesis(data *types.GenesisState) error {
	if err := validateGenesisStateValidators(data.Validators); err != nil {
		return err
	}

	return data.Params.Validate()
```
