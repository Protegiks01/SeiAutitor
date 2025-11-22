## Title
Lack of Zero Voting Power Validation in Validator Set Updates Allows Complete Network Halt

## Summary
The `ApplyAndReturnValidatorSetUpdates` function in the staking module fails to validate that the total voting power remains above zero when returning validator set updates to the consensus engine. This allows scenarios where all validators lose voting power simultaneously, resulting in an empty validator set being sent to Tendermint/CometBFT and causing a complete network shutdown. [1](#0-0) 

## Impact
**High** - This vulnerability can cause a total network shutdown, preventing the network from confirming any new transactions.

## Finding Description

**Location:** The vulnerability exists in `x/staking/keeper/val_state_change.go`, specifically in the `ApplyAndReturnValidatorSetUpdates` function at lines 217-219 where the total power is set without validation.

**Intended Logic:** The validator set update mechanism should ensure that the network always maintains at least some voting power to continue producing blocks and reaching consensus. The system should prevent scenarios where the entire validator set becomes powerless.

**Actual Logic:** The function accumulates `totalPower` starting from zero and only sets it if there are validator updates, but never validates that `totalPower` is greater than zero before returning. [2](#0-1) 

The iteration logic breaks when encountering zero-power validators: [3](#0-2) 

Validators that are no longer bonded receive zero-power ABCI updates: [4](#0-3) 

The total power is set without any validation: [5](#0-4) 

**Exploit Scenario:** 

1. All validators on the network go offline simultaneously or miss a critical number of blocks (e.g., due to a network partition, coordinated downtime, or software bug)
2. The slashing module's `BeginBlocker` processes validator signatures and detects downtime for all validators
3. All validators exceed the `maxMissed` threshold and get jailed via `SlashJailAndUpdateSigningInfo` [6](#0-5) 

4. Jailed validators are removed from the power store and have zero consensus power: [7](#0-6) 

5. In the next `EndBlock`, `ApplyAndReturnValidatorSetUpdates` iterates through validators but finds none with positive power
6. All previously bonded validators receive zero-power updates and `totalPower` remains zero
7. The empty/zero-power validator set is returned to Tendermint via `ResponseEndBlock.ValidatorUpdates` [8](#0-7) 

**Security Failure:** This breaks the consensus availability property. With zero voting power across all validators, Tendermint/CometBFT cannot form a quorum to propose or vote on new blocks, causing permanent consensus halt until manual intervention (hard fork).

## Impact Explanation

**Affected Processes:** 
- Network consensus and block production
- Transaction finality and confirmation
- All on-chain operations dependent on block progression

**Severity of Damage:**
- Complete network shutdown - no new blocks can be produced
- All transactions halt - users cannot send transactions or interact with smart contracts
- Permanent state freeze - requires coordinated hard fork to recover
- Economic damage from network downtime and loss of confidence

**Why This Matters:**
This is a critical failure mode for any Proof-of-Stake blockchain. The network's ability to function depends on having at least one validator with positive voting power. Without this check, edge cases in slashing, jailing, or token distribution can accidentally create a scenario where the network becomes permanently inoperable.

## Likelihood Explanation

**Who Can Trigger:** This is not directly triggered by an attacker, but rather by a confluence of conditions that could occur during normal operation or edge cases:
- Mass validator downtime (network issues, software bugs)
- Slashing logic bugs that jail all validators
- Extreme delegation/undelegation patterns
- Chain upgrade issues

**Conditions Required:**
- All validators must simultaneously lose their bonded status (become jailed, unbonded, or have zero tokens)
- This can happen if all validators miss blocks beyond the slashing threshold
- Or if a bug in slashing/staking logic incorrectly processes validator states

**Frequency:**
- Low probability under normal operation
- Higher probability during:
  - Network-wide outages or attacks
  - Chain upgrades with bugs
  - Configuration errors in genesis or governance changes
  - Edge cases in slashing parameter updates

While the probability may be low, the impact is catastrophic (complete network halt), making this a critical vulnerability that should be addressed.

## Recommendation

Add validation in `ApplyAndReturnValidatorSetUpdates` to ensure total voting power never reaches zero:

```go
// set total power on lookup index if there are any updates
if len(updates) > 0 {
    if totalPower.IsZero() {
        return nil, fmt.Errorf("total voting power cannot be zero: this would halt the network")
    }
    k.SetLastTotalPower(ctx, totalPower)
}
```

Additionally, consider:
1. Adding a check at genesis initialization to ensure at least one validator with positive power exists
2. Implementing emergency validator set recovery procedures
3. Adding monitoring and alerts when total voting power approaches dangerous thresholds
4. Documenting this failure mode and recovery procedures for node operators

## Proof of Concept

**File:** `x/staking/keeper/val_state_change_test.go` (new test file)

**Test Function:** `TestApplyAndReturnValidatorSetUpdates_ZeroTotalPower`

**Setup:**
1. Initialize a test application with 3 validators with bonded status and positive voting power
2. Apply initial validator set updates to establish the bonded set
3. Verify the network has positive total voting power

**Trigger:**
1. Jail all validators by setting their `Jailed` flag to true
2. Remove all validators from the power index (simulating what happens when validators are jailed)
3. Call `ApplyAndReturnValidatorSetUpdates` to process the validator set changes

**Observation:**
The function returns successfully with `totalPower` set to zero (or all validators with zero power in updates), which would cause Tendermint to have no active validators. The test demonstrates that there's no validation preventing this catastrophic scenario.

**Test Code Structure:**
```go
func TestApplyAndReturnValidatorSetUpdates_ZeroTotalPower(t *testing.T) {
    // Setup: Create app with bonded validators
    app, ctx, addrs, valAddrs := bootstrapValidatorTest(t, 1000, 3)
    
    // Create and bond 3 validators with power
    validators := make([]types.Validator, 3)
    for i := 0; i < 3; i++ {
        validators[i] = teststaking.NewValidator(t, valAddrs[i], PKs[i])
        tokens := app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
        validators[i], _ = validators[i].AddTokensFromDel(tokens)
        validators[i] = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validators[i], true)
    }
    
    // Apply updates - establishes bonded set
    updates := applyValidatorSetUpdates(t, ctx, app.StakingKeeper, 3)
    require.Equal(t, 3, len(updates))
    
    // Verify positive total power
    totalPower := app.StakingKeeper.GetLastTotalPower(ctx)
    require.True(t, totalPower.GT(sdk.ZeroInt()))
    
    // Trigger: Jail all validators (simulating mass downtime slashing)
    for i := 0; i < 3; i++ {
        validator, found := app.StakingKeeper.GetValidator(ctx, valAddrs[i])
        require.True(t, found)
        
        // Simulate jailing (what slashing module does)
        app.StakingKeeper.DeleteValidatorByPowerIndex(ctx, validator)
        validator.Jailed = true
        validator.Status = types.Unbonding
        app.StakingKeeper.SetValidator(ctx, validator)
    }
    
    // Apply updates - all validators should be removed
    updates, err := app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
    require.NoError(t, err)
    
    // Observation: All validators have zero power
    for _, update := range updates {
        require.Equal(t, int64(0), update.Power, "All validators should have zero power")
    }
    
    // Total power is now zero - network would halt!
    totalPower = app.StakingKeeper.GetLastTotalPower(ctx)
    require.True(t, totalPower.IsZero(), "BUG: Total power is zero - network cannot produce blocks!")
}
```

This test demonstrates that the function allows total voting power to reach zero, which would cause complete network shutdown.

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

**File:** x/slashing/keeper/infractions.go (L96-114)
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
```

**File:** x/staking/types/validator.go (L350-356)
```go
func (v Validator) ConsensusPower(r sdk.Int) int64 {
	if v.IsBonded() {
		return v.PotentialConsensusPower(r)
	}

	return 0
}
```

**File:** types/module/module.go (L642-669)
```go
func (m *Manager) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) abci.ResponseEndBlock {
	ctx = ctx.WithEventManager(sdk.NewEventManager())
	validatorUpdates := []abci.ValidatorUpdate{}
	defer telemetry.MeasureSince(time.Now(), "module", "total_end_block")
	for _, moduleName := range m.OrderEndBlockers {
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
		}
		moduleStartTime := time.Now()
		moduleValUpdates := module.EndBlock(ctx, req)
		telemetry.ModuleMeasureSince(moduleName, moduleStartTime, "module", "end_block")
		// use these validator updates if provided, the module manager assumes
		// only one module will update the validator set
		if len(moduleValUpdates) > 0 {
			if len(validatorUpdates) > 0 {
				panic("validator EndBlock updates already set by a previous module")
			}

			validatorUpdates = moduleValUpdates
		}

	}

	return abci.ResponseEndBlock{
		ValidatorUpdates: validatorUpdates,
		Events:           ctx.EventManager().ABCIEvents(),
	}
```
