# Audit Report

## Title
Genesis State Commission Rate Bypass Causing Network Halt via AllocateTokensToValidator Panic

## Summary
The `validateGenesisStateValidators` function does not validate validator commission rates during genesis state loading. This allows a malicious or corrupted genesis file to contain validators with commission rates exceeding 100%, which causes all nodes to panic and crash when `AllocateTokensToValidator` is called during block processing, resulting in total network shutdown.

## Impact
High

## Finding Description

**Location:** 
- Missing validation in `validateGenesisStateValidators` function [1](#0-0) 
- Panic occurs in `AllocateTokensToValidator` function at the subtraction operation [2](#0-1) 
- Underlying panic mechanism in `DecCoins.Sub` method [3](#0-2) 

**Intended Logic:** 
The system enforces that validator commission rates never exceed 100% (1.0) to maintain proper reward accounting. Normal validator creation validates this constraint: [4](#0-3) [5](#0-4) [6](#0-5) 

**Actual Logic:** 
The genesis validator validation function only checks for duplicate validators, jailed+bonded conflicts, and zero delegator shares—but NOT commission rates. This allows validators with commission > 1.0 to be loaded via `InitGenesis`: [7](#0-6) 

When `AllocateTokensToValidator` calculates commission with a rate > 1.0, the commission amount exceeds the tokens being distributed. The `DecCoins.Sub` method explicitly panics on negative results, crashing the node.

**Exploit Scenario:**
1. Genesis file contains validator with `Commission.Rate = 1.5` (150%)
2. `ValidateGenesis` passes since commission rates aren't checked
3. `InitGenesis` loads validator into state without validation
4. During first block processing, `AllocateTokens` calls `AllocateTokensToValidator`
5. `commission = tokens.MulDec(1.5)` produces commission > tokens
6. `shared = tokens.Sub(commission)` panics with "negative coin amount"
7. All nodes crash, causing total network shutdown

**Security Failure:** 
Denial-of-service breaking network availability. The panic occurs deterministically in the consensus path, causing all honest nodes to crash at the same block height. The network cannot recover without a hard fork.

## Impact Explanation

**Affected:** All network nodes and the blockchain's ability to process transactions.

**Severity:** Total network shutdown. Every node attempting to process blocks panics at the same deterministic point. The network cannot produce new blocks, all transactions halt, and the chain is frozen until a coordinated hard fork creates corrected genesis state.

**Systemic Risk:** Unlike bugs requiring specific transaction sequences, this affects fundamental block processing logic. All nodes crash at the exact same block height when allocating rewards to the malicious validator, making recovery impossible without manual intervention.

## Likelihood Explanation

**Who can trigger:** Requires malicious or corrupted genesis file during chain initialization or network upgrade.

**Conditions required:** 
- Introduced at genesis or during coordinated network upgrade
- Normal runtime operations are protected by validation
- Once introduced, trigger is automatic during first reward distribution

**Frequency:** While introducing malicious genesis requires coordination, impact is catastrophic. Vulnerable scenarios include:
- New chain launches with corrupted genesis preparation
- Hard fork upgrades that don't validate migrated validator state  
- Less carefully reviewed testnet environments

Vulnerability manifests immediately upon first block reward distribution.

## Recommendation

Add commission rate validation to `validateGenesisStateValidators` in `x/staking/genesis.go`. After iterating through validators, validate each validator's commission:

```go
if err := val.Commission.Validate(); err != nil {
    return fmt.Errorf("invalid commission for validator %s: %w", val.OperatorAddress, err)
}
```

This ensures genesis validators have the same commission constraints (MaxRate ≤ 1.0, Rate ≤ MaxRate) as validators created through transactions.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensToValidatorWithCommissionGreaterThan100Percent`

**Setup:**
1. Initialize test application with `simapp.Setup(false)`
2. Create context with `app.BaseApp.NewContext(false, tmproto.Header{})`
3. Create validator struct with commission rate > 1.0 (e.g., `sdk.NewDec(2)` = 200%) by directly constructing the Commission struct, bypassing normal validation
4. Use `app.StakingKeeper.SetValidator(ctx, validator)` to directly set validator in state
5. Initialize distribution state for the validator

**Trigger:**
1. Create tokens to allocate: `tokens := sdk.DecCoins{{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(100)}}`
2. Call `app.DistrKeeper.AllocateTokensToValidator(ctx, validator, tokens)`
3. This calculates `commission = tokens.MulDec(2.0)` = 200 tokens
4. Then attempts `shared = tokens.Sub(commission)` = 100 - 200

**Observation:**
The test must use `require.Panics()` to catch the panic with message "negative coin amount" when `DecCoins.Sub` is called. This demonstrates that validators with commission > 100% loaded from genesis (bypassing validation) cause deterministic panic during reward allocation, halting all nodes.

The test proves that the missing genesis validation creates a critical vulnerability allowing network-wide denial of service through malicious genesis state.

### Citations

**File:** x/staking/genesis.go (L40-40)
```go
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

**File:** x/staking/types/commission.go (L57-59)
```go
	case cr.MaxRate.GT(sdk.OneDec()):
		// max rate cannot be greater than 1
		return ErrCommissionHuge
```

**File:** x/staking/types/msg.go (L128-130)
```go
	if err := msg.Commission.Validate(); err != nil {
		return err
	}
```

**File:** x/staking/types/msg.go (L202-204)
```go
		if msg.CommissionRate.GT(sdk.OneDec()) || msg.CommissionRate.IsNegative() {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "commission rate must be between 0 and 1 (inclusive)")
		}
```
