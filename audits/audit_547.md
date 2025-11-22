# Audit Report

## Title
Integer Overflow in BlocksPerYear Parameter Causes Chain Halt via Negative Coin Minting

## Summary
The `BlockProvision` function in `x/mint/types/minter.go:78` performs an unsafe conversion of the `BlocksPerYear` parameter from `uint64` to `int64` without overflow checking. When `BlocksPerYear` exceeds `math.MaxInt64` (9,223,372,036,854,775,807), the conversion wraps to a negative value, causing division by a negative number that produces negative provision amounts. This leads to a panic when attempting to create coins with negative amounts, resulting in complete chain halt. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary: `x/mint/types/minter.go`, line 78 in `BlockProvision` function
- Secondary: `x/mint/types/minter.go`, line 55 in `NextInflationRate` function  
- Validation: `x/mint/types/params.go`, lines 184-195 in `validateBlocksPerYear` function [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
The `BlockProvision` function should safely divide annual provisions by the number of blocks per year to calculate per-block minting provisions. The `BlocksPerYear` parameter should be validated to ensure only safe, positive values are used.

**Actual Logic:**
The code performs `int64(params.BlocksPerYear)` where `BlocksPerYear` is a `uint64`. When `BlocksPerYear > 9,223,372,036,854,775,807` (MaxInt64), Go's type conversion wraps the value to a negative `int64`. The validation function only checks for zero, not for values exceeding MaxInt64: [4](#0-3) 

This negative value is then passed to `sdk.NewInt()` creating a negative `Int`, which when used in `QuoInt` division produces negative provision amounts. When `sdk.NewCoin()` is called with this negative amount in the `BeginBlocker`, it panics: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. Attacker (or well-meaning governance participant) submits a governance proposal to modify the mint module's `BlocksPerYear` parameter
2. The proposal sets `BlocksPerYear` to a value greater than MaxInt64 (e.g., `9223372036854775808`)
3. The parameter validation passes because it only checks for zero, not upper bounds
4. The governance proposal is approved and executed via `SetParams`
5. On the next block, `BeginBlocker` is called which invokes `BlockProvision`
6. The `int64()` conversion wraps to `-9223372036854775808`
7. Division produces a negative provision amount
8. `sdk.NewCoin()` panics with "negative coin amount" error
9. All nodes panic in `BeginBlocker`, unable to process any blocks
10. The entire network halts permanently until a hard fork is deployed [7](#0-6) [8](#0-7) 

**Security Failure:**
This breaks the availability property of the blockchain. The panic in `BeginBlocker` prevents any blocks from being produced, causing total network shutdown. This is a denial-of-service vulnerability that requires a hard fork to remediate.

## Impact Explanation

**Affected Assets and Processes:**
- **Network Availability:** The entire blockchain network becomes unable to produce blocks
- **Transaction Processing:** All pending transactions become stuck indefinitely
- **Economic Activity:** All DeFi protocols, transfers, and smart contract interactions halt
- **Validator Operations:** All validators panic and cannot proceed with consensus

**Severity of Damage:**
- **Complete Network Shutdown:** Once triggered, every single node panics on every block attempt
- **Requires Hard Fork:** The only recovery is a coordinated hard fork to reset the parameter or patch the validation logic
- **Irreversible Without Intervention:** The condition persists until manual chain upgrade
- **Universal Impact:** Affects 100% of network nodes simultaneously

**Why This Matters:**
This vulnerability can completely disable a production blockchain network through a governance parameter that appears legitimate on its face (a large but technically valid uint64 value). The recovery requires emergency coordination among validators for a hard fork, causing extended downtime and potential loss of user confidence.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who can submit and get approval for a governance proposal. While governance requires validator/token holder approval, the parameter change appears innocuous - validators might approve without recognizing the overflow risk.

**Required Conditions:**
1. A governance proposal to change `BlocksPerYear` to a value > MaxInt64
2. The proposal passes governance voting
3. The next block after parameter update triggers the panic

**Frequency:**
- **Single Trigger:** One successful governance proposal permanently breaks the chain
- **Easy to Trigger Accidentally:** A well-intentioned proposal to set an extremely large `BlocksPerYear` (perhaps due to misunderstanding units or attempting to test edge cases) would trigger this
- **No Recovery Without Hard Fork:** Once triggered, every subsequent block attempt fails

The likelihood is **MEDIUM-to-HIGH** because:
- Governance proposals are a normal network operation
- The validation logic appears secure but has a hidden flaw
- Large uint64 values are not obviously problematic to proposal reviewers
- No runtime warnings or checks alert to the danger before deployment

## Recommendation

Add an upper bound validation check in `validateBlocksPerYear` to ensure `BlocksPerYear` does not exceed `math.MaxInt64`:

```go
func validateBlocksPerYear(i interface{}) error {
    v, ok := i.(uint64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v == 0 {
        return fmt.Errorf("blocks per year must be positive: %d", v)
    }

    // Add overflow protection
    if v > math.MaxInt64 {
        return fmt.Errorf("blocks per year exceeds maximum safe value (max: %d, got: %d)", 
            math.MaxInt64, v)
    }

    return nil
}
```

Additionally, consider using `sdk.NewIntFromUint64()` instead of `sdk.NewInt(int64(...))` throughout the codebase to properly handle uint64 values without unsafe conversions: [9](#0-8) 

## Proof of Concept

**File:** `x/mint/types/minter_test.go`

**Test Function:** `TestBlockProvisionOverflow` (add this new test)

**Setup:**
1. Create a `Minter` with positive `AnnualProvisions`
2. Create `Params` with `BlocksPerYear` set to `math.MaxInt64 + 1` (9223372036854775808)
3. The params validation will pass because it only checks for zero

**Trigger:**
Call `minter.BlockProvision(params)` which will:
1. Convert the large uint64 to int64, causing overflow to negative value
2. Perform division by negative number, producing negative provision amount  
3. Attempt to create a coin with negative amount via `sdk.NewCoin()`
4. This will panic with "negative coin amount" error

**Observation:**
The test uses `require.Panics()` to verify that `BlockProvision` panics when given params with oversized `BlocksPerYear`. This confirms the vulnerability.

**Test Code:**
```go
func TestBlockProvisionOverflow(t *testing.T) {
    // Setup: Create minter with positive annual provisions
    minter := InitialMinter(sdk.NewDecWithPrec(1, 1))
    minter.AnnualProvisions = sdk.NewDec(1000000000) // 1 billion
    
    // Create params with BlocksPerYear > MaxInt64
    // This value passes validation but causes int64 overflow
    params := DefaultParams()
    params.BlocksPerYear = uint64(9223372036854775808) // MaxInt64 + 1
    
    // Verify validation passes (demonstrating the vulnerability)
    err := params.Validate()
    require.NoError(t, err, "Params validation should pass but contains unsafe value")
    
    // Trigger: Call BlockProvision which performs unsafe int64 conversion
    // This should panic when trying to create coin with negative amount
    require.Panics(t, func() {
        minter.BlockProvision(params)
    }, "BlockProvision should panic due to int64 overflow creating negative coin amount")
}
```

**Expected Result:**
The test passes, confirming that:
1. Parameter validation incorrectly allows `BlocksPerYear > MaxInt64`
2. `BlockProvision` panics when processing such parameters
3. This panic would occur in `BeginBlocker`, halting the entire network

### Citations

**File:** x/mint/types/minter.go (L55-55)
```go
	inflationRateChange := inflationRateChangePerYear.Quo(sdk.NewDec(int64(params.BlocksPerYear)))
```

**File:** x/mint/types/minter.go (L77-79)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
```

**File:** x/mint/types/params.go (L184-195)
```go
func validateBlocksPerYear(i interface{}) error {
	v, ok := i.(uint64)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v == 0 {
		return fmt.Errorf("blocks per year must be positive: %d", v)
	}

	return nil
}
```

**File:** types/coin.go (L16-27)
```go
func NewCoin(denom string, amount Int) Coin {
	coin := Coin{
		Denom:  denom,
		Amount: amount,
	}

	if err := coin.Validate(); err != nil {
		panic(err)
	}

	return coin
}
```

**File:** types/coin.go (L47-49)
```go
	if coin.Amount.IsNegative() {
		return fmt.Errorf("negative coin amount: %v", coin.Amount)
	}
```

**File:** x/mint/abci.go (L28-29)
```go
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)
```

**File:** x/params/types/subspace.go (L241-255)
```go
func (s Subspace) SetParamSet(ctx sdk.Context, ps ParamSet) {
	for _, pair := range ps.ParamSetPairs() {
		// pair.Field is a pointer to the field, so indirecting the ptr.
		// go-amino automatically handles it but just for sure,
		// since SetStruct is meant to be used in InitGenesis
		// so this method will not be called frequently
		v := reflect.Indirect(reflect.ValueOf(pair.Value)).Interface()

		if err := pair.ValidatorFn(v); err != nil {
			panic(fmt.Sprintf("value from ParamSetPair is invalid: %s", err))
		}

		s.Set(ctx, pair.Key, v)
	}
}
```

**File:** types/int.go (L97-102)
```go
// NewIntFromUint64 constructs an Int from a uint64.
func NewIntFromUint64(n uint64) Int {
	b := big.NewInt(0)
	b.SetUint64(n)
	return Int{b}
}
```
