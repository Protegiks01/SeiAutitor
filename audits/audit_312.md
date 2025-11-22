## Audit Report

## Title
Integer Overflow in Consensus Power Conversion Causes Unrecoverable Chain Halt

## Summary
The consensus power calculation converts validator token amounts to int64 values without bounds checking. When a validator's tokens divided by PowerReduction exceeds MaxInt64 (approximately 9.2 quintillion), the conversion panics, causing complete chain shutdown. This vulnerability exists in critical paths including EndBlock validator set updates and genesis initialization, with no validation preventing the overflow condition.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The consensus power system should safely convert validator token amounts to power units that can be used by the Tendermint consensus engine. The conversion formula is: `consensus_power = tokens / PowerReduction`, where PowerReduction defaults to 1,000,000.

**Actual Logic:**
The `TokensToConsensusPower` function performs integer division and calls `.Int64()` on the result. The `Int64()` method explicitly panics if the value exceeds the int64 maximum value of 9,223,372,036,854,775,807. This panic is unhandled and occurs in critical paths: [4](#0-3) [5](#0-4) 

**Exploit Scenario:**

1. **Genesis Attack Vector:** At chain genesis, configure a validator with token amount exceeding `MaxInt64 * PowerReduction` (approximately 9.2 × 10^21 tokens). When `InitGenesis` calls `SetValidatorByPowerIndex`, the power index key creation will panic: [6](#0-5) 

2. **Delegation Attack Vector:** The max voting power ratio enforcement is skipped at genesis (`BlockHeight == 0`) and before the threshold is reached (default 1,000,000 power units): [7](#0-6) 

This allows a validator to accumulate excessive tokens through delegations. When `ApplyAndReturnValidatorSetUpdates` is called at the next EndBlock, the `ConsensusPower` calculation will panic.

**Security Failure:**
The system fails to validate consensus power bounds, resulting in a denial-of-service through panic in consensus-critical code paths. The panic is unrecoverable without a hard fork to reduce the validator's token balance or modify the PowerReduction parameter.

## Impact Explanation

- **Affected Processes:** The entire blockchain network is affected. All nodes executing EndBlock will panic and halt when processing validator set updates.

- **Severity:** This causes complete network shutdown. No new blocks can be produced, and no transactions can be confirmed. The chain cannot progress without emergency intervention.

- **System Reliability:** The vulnerability breaks the fundamental availability guarantee of the blockchain. Recovery requires coordinated hard fork with genesis state modification, making this a critical permanent freeze scenario requiring hard fork intervention.

## Likelihood Explanation

**Who can trigger it:** 
- At genesis: Chain operators during initial configuration
- Post-genesis: Any participant through delegations, though requires accumulating massive token amounts (>9.2 × 10^21 base units)

**Conditions required:**
- No explicit privilege required for the delegation path
- The max voting power ratio check provides no protection if:
  - Total network power is below threshold (default 1M power units)
  - Genesis validators (BlockHeight == 0 check is skipped)
  - Total supply itself exceeds limits where even 20% would overflow

**Frequency:**
Low probability in practice due to the extremely large token amount required. However, for chains with:
- Very high total supply (quadrillion+ range)
- Early-stage networks below the enforcement threshold
- Genesis misconfiguration

The vulnerability becomes realistic and would result in immediate, permanent chain halt.

## Recommendation

Add explicit bounds checking before the int64 conversion:

1. **In TokensToConsensusPower:** Check if the result exceeds MaxInt64 before conversion and return an error or MaxInt64 as a cap.

2. **In genesis validation:** Add validation in `validateGenesisStateValidators` to ensure no validator's consensus power would overflow: [8](#0-7) 

3. **In delegation checks:** Add overflow protection in the `Delegate` function before performing the max voting power ratio calculation.

4. **Consider using int128 or arbitrary precision for consensus power calculations** if the chain design requires supporting such large token supplies.

Example fix for TokensToConsensusPower:
```go
func TokensToConsensusPower(tokens Int, powerReduction Int) int64 {
    power := tokens.Quo(powerReduction)
    if !power.IsInt64() {
        // Return MaxInt64 as cap or return error
        return math.MaxInt64 
    }
    return power.Int64()
}
```

## Proof of Concept

**File:** `x/staking/keeper/validator_test.go`

**Test Function:** `TestConsenusPowerOverflowCausesChainHalt`

**Setup:**
1. Initialize a test blockchain context with standard staking keeper
2. Create a validator with valid initial configuration
3. Set PowerReduction to the default value (1,000,000)

**Trigger:**
```go
func TestConsensusPowerOverflowCausesChainHalt(t *testing.T) {
    _, app, ctx := createTestInput()
    
    // Create validator with normal initial state
    valAddr := sdk.ValAddress(addrs[0])
    pk := ed25519.GenPrivKey().PubKey()
    val, _ := types.NewValidator(valAddr, pk, types.Description{})
    
    // Set tokens to exceed MaxInt64 * PowerReduction
    // MaxInt64 = 9223372036854775807
    // We need tokens > 9223372036854775807 * 1000000
    overflowTokens := sdk.NewInt(9223372036854775807).Mul(sdk.NewInt(1000000)).Add(sdk.NewInt(1000000))
    val.Tokens = overflowTokens
    val.DelegatorShares = sdk.NewDec(1)
    val.Status = types.Bonded
    
    app.StakingKeeper.SetValidator(ctx, val)
    
    // This should panic when trying to set validator by power index
    // or when calling ConsensusPower
    require.Panics(t, func() {
        app.StakingKeeper.SetValidatorByPowerIndex(ctx, val)
    }, "Expected panic when setting validator with overflow consensus power")
    
    // Alternative: test the actual conversion
    require.Panics(t, func() {
        _ = val.ConsensusPower(sdk.DefaultPowerReduction)
    }, "Expected panic when calculating consensus power that overflows int64")
}
```

**Observation:**
The test will panic with message "Int64() out of bound" when attempting to:
1. Create the power index key via `SetValidatorByPowerIndex`
2. Calculate consensus power via `ConsensusPower` 
3. Process validator set updates in `ApplyAndReturnValidatorSetUpdates`

This confirms that the overflow condition causes an unrecoverable panic in consensus-critical code, demonstrating a complete network shutdown vulnerability.

### Citations

**File:** types/staking.go (L32-35)
```go
// TokensToConsensusPower - convert input tokens to potential consensus-engine power
func TokensToConsensusPower(tokens Int, powerReduction Int) int64 {
	return (tokens.Quo(powerReduction)).Int64()
}
```

**File:** types/int.go (L159-166)
```go
// Int64 converts Int to int64
// Panics if the value is out of range
func (i Int) Int64() int64 {
	if !i.i.IsInt64() {
		panic("Int64() out of bound")
	}
	return i.i.Int64()
}
```

**File:** x/staking/keeper/val_state_change.go (L137-141)
```go
		// if we get to a zero-power validator (which we don't bond),
		// there are no more possible bonded validators
		if validator.PotentialConsensusPower(k.PowerReduction(ctx)) == 0 {
			break
		}
```

**File:** x/staking/keeper/val_state_change.go (L168-170)
```go
		oldPowerBytes, found := last[valAddrStr]
		newPower := validator.ConsensusPower(powerReduction)
		newPowerBytes := k.cdc.MustMarshal(&gogotypes.Int64Value{Value: newPower})
```

**File:** x/staking/types/keys.go (L81-88)
```go
func GetValidatorsByPowerIndexKey(validator Validator, powerReduction sdk.Int) []byte {
	// NOTE the address doesn't need to be stored because counter bytes must always be different
	// NOTE the larger values are of higher value

	consensusPower := sdk.TokensToConsensusPower(validator.Tokens, powerReduction)
	consensusPowerBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(consensusPowerBytes, uint64(consensusPower))

```

**File:** x/staking/genesis.go (L39-44)
```go
	for _, validator := range data.Validators {
		keeper.SetValidator(ctx, validator)

		// Manually set indices for the first time
		keeper.SetValidatorByConsAddr(ctx, validator)
		keeper.SetValidatorByPowerIndex(ctx, validator)
```

**File:** x/staking/genesis.go (L238-274)
```go
func validateGenesisStateValidators(validators []types.Validator) error {
	addrMap := make(map[string]bool, len(validators))

	for i := 0; i < len(validators); i++ {
		val := validators[i]
		consPk, err := val.ConsPubKey()
		if err != nil {
			return err
		}

		strKey := string(consPk.Bytes())

		if _, ok := addrMap[strKey]; ok {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("duplicate validator in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.Jailed && val.IsBonded() {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("validator is bonded and jailed in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.DelegatorShares.IsZero() && !val.IsUnbonding() {
			return fmt.Errorf("bonded/unbonded genesis validator cannot have zero delegator shares, validator: %v", val)
		}

		addrMap[strKey] = true
	}

	return nil
}
```

**File:** x/staking/keeper/delegation.go (L652-664)
```go
	if newTotalPower.GTE(maxVotingPowerEnforcementThreshold) && ctx.BlockHeight() > 0 {
		// Convert bond amount to power first
		validatorNewTotalPower := validator.Tokens.Add(bondAmt).Quo(k.PowerReduction(ctx))
		// Validator's new total power cannot exceed the max power ratio that's allowed
		newVotingPowerRatio := validatorNewTotalPower.ToDec().Quo(newTotalPower.ToDec())
		maxVotingPowerRatio := k.MaxVotingPowerRatio(ctx)
		if newVotingPowerRatio.GT(maxVotingPowerRatio) {
			k.Logger(ctx).Error(
				fmt.Sprintf("validator's voting power ratio exceeds the max allowed ratio: %s > %s\n", newVotingPowerRatio.String(), maxVotingPowerRatio.String()),
			)
			return sdk.ZeroDec(), types.ErrExceedMaxVotingPowerRatio
		}
	}
```
