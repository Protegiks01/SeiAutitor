## Audit Report

## Title
Integer Overflow in ConsensusPower Calculation Causes Network Shutdown

## Summary
The `TokensToConsensusPower` function directly converts a potentially unbounded `sdk.Int` value to `int64` without checking if it exceeds the maximum value, causing a panic that crashes all nodes and halts the network when a validator's consensus power calculation exceeds int64 maximum (9,223,372,036,854,775,807).

## Impact
High

## Finding Description

**Location:** 
- Primary: `types/staking.go` [1](#0-0) 
- Called from: `x/staking/types/validator.go` [2](#0-1) 
- Critical usage: `x/staking/keeper/val_state_change.go` [3](#0-2) 
- Genesis: `x/staking/genesis.go` [4](#0-3) 

**Intended Logic:** 
The consensus power calculation should convert validator tokens to consensus power by dividing by `powerReduction` (default 1,000,000). The result should be safely converted to int64 for ABCI validator updates to Tendermint consensus engine.

**Actual Logic:** 
The `TokensToConsensusPower` function directly calls `.Int64()` on the division result without checking if it fits within int64 range [5](#0-4) . The `Int64()` method panics with "Int64() out of bound" when the value exceeds int64 maximum [6](#0-5) .

**Exploit Scenario:**
1. A validator accumulates tokens >= 9,223,372,036,854,775,807 × 1,000,000 = 9.22 × 10^24 through:
   - Genesis misconfiguration with extremely high initial supply
   - Long-term inflation accumulation (no hard supply cap exists [7](#0-6) )
   - Token minting bugs allowing excessive creation
2. During `EndBlock`, `BlockValidatorUpdates` calls `ApplyAndReturnValidatorSetUpdates` [8](#0-7) 
3. The code calculates `validator.ConsensusPower(powerReduction)` [9](#0-8) 
4. This triggers the panic in `TokensToConsensusPower`
5. All nodes crash simultaneously when processing this block
6. Network halts completely as no node can advance past this block

**Security Failure:** 
Denial of service through unhandled integer overflow. The system panics instead of gracefully handling or validating the edge case, causing complete network shutdown. Unlike safe implementations that check bounds before conversion [10](#0-9) , this critical consensus path lacks proper validation.

## Impact Explanation
This vulnerability causes complete network shutdown when triggered:
- **Network Availability**: All validator nodes crash simultaneously during block processing, preventing any new transactions from being confirmed
- **Consensus Breakdown**: The network cannot reach consensus on any subsequent blocks as all nodes panic at the same block height
- **Service Interruption**: The blockchain becomes completely unavailable until a hard fork is implemented to fix the issue and restart the network
- **Economic Impact**: Users cannot access funds, execute transactions, or interact with the network during the outage

The severity is High because it matches the in-scope impact: "High: Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Conditions:**
- Requires validator tokens >= 9.22 × 10^24 (with default powerReduction)
- Can occur through genesis misconfiguration, long-term inflation accumulation, or minting bugs
- No hard supply cap exists in the codebase to prevent reaching this threshold

**Likelihood Assessment:**
- **Short-term**: Low probability under normal operation
- **Long-term**: Deterministic time-bomb as inflation continuously increases supply without bounds
- **Genesis scenario**: Medium probability due to human error in configuration
- **With other bugs**: High probability if minting vulnerabilities exist

The lack of bounds checking represents a critical defensive programming failure in consensus-critical code, regardless of immediate exploitability.

## Recommendation

Add bounds checking before int64 conversion in `TokensToConsensusPower`:

```go
func TokensToConsensusPower(tokens Int, powerReduction Int) int64 {
    power := tokens.Quo(powerReduction)
    if !power.IsInt64() {
        // Return maximum safe value or zero, or handle via error return
        return math.MaxInt64 
    }
    return power.Int64()
}
```

Alternatively, implement overflow-safe validation at critical call sites before calculating consensus power, especially in `ApplyAndReturnValidatorSetUpdates` and `ABCIValidatorUpdate`.

## Proof of Concept

**File**: `x/staking/types/validator_test.go`

**Test Function**: Add this test to demonstrate the panic:

```go
func TestConsensusPowerOverflow(t *testing.T) {
    // Create a validator with tokens that will overflow int64 after power reduction
    // int64 max = 9,223,372,036,854,775,807
    // With powerReduction = 1,000,000, we need tokens >= 9.22 * 10^24
    
    validator := newValidator(t, valAddr1, pk1)
    
    // Set tokens to a value that exceeds int64 max after division by powerReduction
    // 10^25 tokens / 10^6 = 10^19 which exceeds int64 max (9.22 * 10^18)
    overflowTokens := sdk.NewIntFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(25), nil))
    validator.Tokens = overflowTokens
    validator.Status = types.Bonded
    
    // This should panic with "Int64() out of bound"
    require.Panics(t, func() {
        validator.ConsensusPower(sdk.DefaultPowerReduction)
    }, "Expected panic when consensus power exceeds int64 max")
    
    // Similarly, ABCIValidatorUpdate should panic
    require.Panics(t, func() {
        validator.ABCIValidatorUpdate(sdk.DefaultPowerReduction)
    }, "Expected panic in ABCIValidatorUpdate when power exceeds int64 max")
}
```

**Setup**: The test uses the existing test framework and validator creation helpers.

**Trigger**: Creates a validator with 10^25 tokens, which after dividing by powerReduction (10^6) yields 10^19, exceeding int64 max (9.22 × 10^18).

**Observation**: Both `ConsensusPower` and `ABCIValidatorUpdate` calls panic with "Int64() out of bound", confirming the vulnerability. In production, this would crash all nodes during EndBlock processing.

### Citations

**File:** types/staking.go (L32-35)
```go
// TokensToConsensusPower - convert input tokens to potential consensus-engine power
func TokensToConsensusPower(tokens Int, powerReduction Int) int64 {
	return (tokens.Quo(powerReduction)).Int64()
}
```

**File:** x/staking/types/validator.go (L348-361)
```go
// ConsensusPower gets the consensus-engine power. Aa reduction of 10^6 from
// validator tokens is applied
func (v Validator) ConsensusPower(r sdk.Int) int64 {
	if v.IsBonded() {
		return v.PotentialConsensusPower(r)
	}

	return 0
}

// PotentialConsensusPower returns the potential consensus-engine power.
func (v Validator) PotentialConsensusPower(r sdk.Int) int64 {
	return sdk.TokensToConsensusPower(v.Tokens, r)
}
```

**File:** x/staking/keeper/val_state_change.go (L27-27)
```go
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
```

**File:** x/staking/keeper/val_state_change.go (L139-169)
```go
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
```

**File:** x/staking/genesis.go (L142-151)
```go
			update := validator.ABCIValidatorUpdate(keeper.PowerReduction(ctx))
			update.Power = lv.Power // keep the next-val-set offset, use the last power for the first block
			res = append(res, abci.ValidatorUpdate{
				PubKey: update.PubKey,
				Power:  update.Power,
			})
		}
	} else {
		var err error
		legacyUpdates, err := keeper.ApplyAndReturnValidatorSetUpdates(ctx)
```

**File:** types/int.go (L161-165)
```go
func (i Int) Int64() int64 {
	if !i.i.IsInt64() {
		panic("Int64() out of bound")
	}
	return i.i.Int64()
```

**File:** x/staking/keeper/params.go (L58-60)
```go
func (k Keeper) PowerReduction(ctx sdk.Context) sdk.Int {
	return sdk.DefaultPowerReduction
}
```

**File:** x/auth/ante/validator_tx_fee.go (L78-80)
```go
		if gasPrice.IsInt64() {
			p = gasPrice.Int64()
		}
```
