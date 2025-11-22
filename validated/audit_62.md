# Audit Report

## Title
Missing Commission Rate Validation in Genesis State Causing Deterministic Network Shutdown

## Summary
The `validateGenesisStateValidators` function in the staking module fails to validate validator commission rates during genesis state loading. This allows genesis files to contain validators with commission rates exceeding 100%, which causes all nodes to panic deterministically during reward distribution via `AllocateTokensToValidator`, resulting in total network shutdown requiring a hard fork to recover. [1](#0-0) 

## Impact
High

## Finding Description

- **location**: `x/staking/genesis.go` (validateGenesisStateValidators function, lines 238-273) and `x/distribution/keeper/allocation.go` (AllocateTokensToValidator function, lines 111-114)

- **intended logic**: The staking system enforces that validator commission rates never exceed 100% (1.0 decimal) to maintain proper reward accounting. The commission validation logic exists and is enforced during normal validator creation through transactions. [2](#0-1) [3](#0-2) 

- **actual logic**: The genesis validation function `validateGenesisStateValidators` only validates duplicate validators, jailed+bonded conflicts, and zero delegator shares, but completely omits commission rate validation. During `InitGenesis`, validators are loaded directly into state without any commission validation: [4](#0-3) [5](#0-4) 

When `AllocateTokensToValidator` attempts to distribute rewards to a validator with commission rate > 1.0, it calculates commission amount that exceeds the total tokens being distributed. The subsequent subtraction operation in `DecCoins.Sub` panics: [6](#0-5) [7](#0-6) 

- **exploitation path**: 
  1. Genesis file is created with validator containing `Commission.Rate > 1.0` (e.g., 1.5 = 150%)
  2. `ValidateGenesis` passes because commission rates are not checked
  3. `InitGenesis` loads the validator into state without validation
  4. During first block with reward distribution, `AllocateTokens` is called
  5. `AllocateTokensToValidator` calculates: `commission = tokens × 1.5`, which exceeds `tokens`
  6. `shared = tokens.Sub(commission)` attempts to compute a negative value
  7. `DecCoins.Sub` panics with "negative coin amount"
  8. All nodes crash at the same deterministic point in consensus

- **security guarantee broken**: The invariant that validator commission rates must be ≤ 100% is violated. The system's genesis validation, which validates other validator properties, fails to validate this critical invariant, allowing invalid state to be loaded.

## Impact Explanation

This vulnerability causes **total network shutdown**. All nodes processing blocks will panic at exactly the same block height when reward distribution occurs for the validator with invalid commission rate. The panic is deterministic and occurs in the consensus path, making it impossible for any node to progress past that block. 

The network cannot produce new blocks, all transactions halt, and the chain is completely frozen. Recovery requires a coordinated hard fork to create corrected genesis state, as the invalid validator state cannot be fixed through normal chain operations.

This matches the High severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering conditions**: Requires a genesis file with a validator having commission rate > 100% to be used during:
- New chain initialization
- Network upgrade/hard fork with state migration
- Testnet deployments with less rigorous review

**Who can introduce**: Genesis files are created by chain operators, validators, and core team during chain launches or upgrades. While this requires privileged access, the vulnerability is in the **missing validation** that should prevent such errors.

**Realistic scenarios**:
- Programmatic genesis file generation with bugs
- Data migration errors from other chains
- Human error during manual genesis preparation
- Compromised or malicious genesis preparation tools

**Critical factors**:
1. The system validates OTHER genesis invariants (duplicates, jailed+bonded status, shares), showing intent to prevent invalid genesis states
2. Normal runtime operations properly validate commission rates, but genesis bypasses this
3. Once introduced, the failure is automatic and deterministic
4. The inconsistency between runtime and genesis validation suggests this is an oversight, not intentional design

## Recommendation

Add commission rate validation to `validateGenesisStateValidators` in `x/staking/genesis.go`. Within the validator iteration loop, add:

```go
if err := val.Commission.Validate(); err != nil {
    return fmt.Errorf("invalid commission for validator %s: %w", val.OperatorAddress, err)
}
```

This ensures genesis validators undergo the same commission validation (`MaxRate ≤ 1.0`, `Rate ≤ MaxRate`, `MaxChangeRate ≤ MaxRate`) as validators created through `MsgCreateValidator` transactions, maintaining consistency across all validator creation paths. [8](#0-7) 

## Proof of Concept

**File**: `x/distribution/keeper/allocation_test.go`

**Test Function**: `TestAllocateTokensToValidatorWithCommissionGreaterThan100Percent`

**Setup**:
1. Initialize test application: `app := simapp.Setup(false)`
2. Create context: `ctx := app.BaseApp.NewContext(false, tmproto.Header{})`
3. Create validator with invalid commission by directly constructing the struct:
   ```go
   validator, _ := types.NewValidator(valAddr, consPk, types.Description{})
   validator.Commission = types.NewCommission(sdk.NewDec(2), sdk.NewDec(2), sdk.ZeroDec()) // 200% rate
   validator.Tokens = sdk.NewInt(100)
   validator.DelegatorShares = sdk.NewDec(100)
   validator.Status = types.Bonded
   ```
4. Bypass normal validation: `app.StakingKeeper.SetValidator(ctx, validator)`
5. Initialize distribution: `app.DistrKeeper.AllocateTokensToValidator(ctx, validator, sdk.DecCoins{{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(100)}})`

**Trigger**:
- Call `AllocateTokensToValidator` with 100 tokens
- Commission calculation: `100 × 2.0 = 200 tokens`
- Subtraction attempt: `100 - 200 = -100` (negative)

**Result**:
The test must wrap the call in `require.Panics(t, func() { ... })` to catch the panic with message "negative coin amount". This demonstrates that validators with commission > 100% loaded from genesis (bypassing validation) cause deterministic panic during reward allocation.

## Notes

This vulnerability exists because genesis validation is inconsistent with runtime validation. While the system properly validates commission rates during normal validator creation [3](#0-2) , it omits this check during genesis state loading. The presence of other genesis validations [1](#0-0)  indicates the system intends to validate genesis data, making this omission a security gap rather than intentional design.

The vulnerability qualifies under the exception clause for privileged operations because it causes an unrecoverable security failure (total network shutdown requiring hard fork) beyond what genesis file creators should be able to cause inadvertently. Genesis validation serves as a critical safety mechanism to prevent catastrophic misconfigurations.

### Citations

**File:** x/staking/genesis.go (L39-40)
```go
	for _, validator := range data.Validators {
		keeper.SetValidator(ctx, validator)
```

**File:** x/staking/genesis.go (L238-273)
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
```

**File:** x/staking/types/commission.go (L51-79)
```go
func (cr CommissionRates) Validate() error {
	switch {
	case cr.MaxRate.IsNegative():
		// max rate cannot be negative
		return ErrCommissionNegative

	case cr.MaxRate.GT(sdk.OneDec()):
		// max rate cannot be greater than 1
		return ErrCommissionHuge

	case cr.Rate.IsNegative():
		// rate cannot be negative
		return ErrCommissionNegative

	case cr.Rate.GT(cr.MaxRate):
		// rate cannot be greater than the max rate
		return ErrCommissionGTMaxRate

	case cr.MaxChangeRate.IsNegative():
		// change rate cannot be negative
		return ErrCommissionChangeRateNegative

	case cr.MaxChangeRate.GT(cr.MaxRate):
		// change rate cannot be greater than the max rate
		return ErrCommissionChangeRateGTMaxRate
	}

	return nil
}
```

**File:** x/staking/types/msg.go (L128-130)
```go
	if err := msg.Commission.Validate(); err != nil {
		return err
	}
```

**File:** x/staking/keeper/validator.go (L56-61)
```go
// set the main record holding validator details
func (k Keeper) SetValidator(ctx sdk.Context, validator types.Validator) {
	store := ctx.KVStore(k.storeKey)
	bz := types.MustMarshalValidator(k.cdc, &validator)
	store.Set(types.GetValidatorKey(validator.GetOperator()), bz)
}
```

**File:** x/distribution/keeper/allocation.go (L111-114)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** types/dec_coin.go (L303-310)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}
```

**File:** x/staking/types/validator.go (L284-294)
```go
// SetInitialCommission attempts to set a validator's initial commission. An
// error is returned if the commission is invalid.
func (v Validator) SetInitialCommission(commission Commission) (Validator, error) {
	if err := commission.Validate(); err != nil {
		return v, err
	}

	v.Commission = commission

	return v, nil
}
```
