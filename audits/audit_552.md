## Audit Report

## Title
Integer Overflow in BlocksPerYear Parameter Causes Permanent Chain Halt

## Summary
The `BlockProvision` function in the mint module casts the `BlocksPerYear` parameter from `uint64` to `int64` without validating that the value is within the safe range. If `BlocksPerYear` exceeds `math.MaxInt64`, the cast produces a negative value, leading to a panic when attempting to create a coin with a negative amount, causing permanent chain halt. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Vulnerable code: `x/mint/types/minter.go`, lines 77-80 (BlockProvision function)
- Missing validation: `x/mint/types/params.go`, lines 184-195 (validateBlocksPerYear function)
- Panic site: `x/mint/abci.go`, line 28 (BeginBlocker execution)

**Intended Logic:** 
The mint module is supposed to calculate per-block token provisions by dividing annual provisions by the number of blocks per year. The `BlocksPerYear` parameter validation should ensure all values are safe for arithmetic operations. [2](#0-1) 

**Actual Logic:** 
At line 78 of `minter.go`, `params.BlocksPerYear` (type `uint64`) is cast to `int64` when creating an `Int`: `sdk.NewInt(int64(params.BlocksPerYear))`. If `BlocksPerYear` exceeds `math.MaxInt64` (9,223,372,036,854,775,807), the cast overflows and produces a negative value due to two's complement representation. The validation function only checks that the value is non-zero, not that it's within the valid int64 range. [3](#0-2) 

When the negative `Int` is used as a divisor, `m.AnnualProvisions.QuoInt(negative_int)` produces a negative result. Subsequently, `sdk.NewCoin` is called with this negative amount and panics because coin validation rejects negative amounts. [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. An attacker submits a governance parameter change proposal to set `BlocksPerYear` to `math.MaxUint64` (18,446,744,073,709,551,615)
2. Through social engineering or compromised validators, the proposal passes
3. The parameter change is executed via the governance proposal handler
4. At the next block, `BeginBlocker` calls `minter.BlockProvision(params)`
5. The cast `int64(params.BlocksPerYear)` overflows to -1
6. Division by -1 produces a negative provision amount
7. `sdk.NewCoin` panics with "negative coin amount" error
8. The panic is not caught, halting the chain permanently [6](#0-5) 

**Security Failure:** 
This breaks chain liveness (denial-of-service). The uncaught panic in `BeginBlocker` prevents any blocks from being produced, causing total network shutdown. Recovery requires a hard fork to correct the parameter value or fix the validation logic.

## Impact Explanation

**Affected Components:**
- All validator nodes attempting to produce blocks
- Network consensus and transaction processing
- The entire blockchain's availability

**Severity:**
Once triggered, the chain cannot produce new blocks. All nodes panic when attempting to execute `BeginBlocker`. The only recovery path is a coordinated hard fork to either:
- Roll back to a state before the malicious parameter change, or
- Implement proper validation and upgrade all nodes

This represents a complete network shutdown affecting all users, applications, and economic activity on the chain. No transactions can be processed, no funds can be moved, and the network is effectively frozen until manual intervention via hard fork.

## Likelihood Explanation

**Who Can Trigger:**
An attacker who can influence governance to pass a malicious parameter change proposal. This requires either:
- Sufficient voting power (tokens or validator support) to pass the proposal legitimately
- Social engineering to convince token holders/validators that the change is legitimate
- Compromising validator keys with sufficient voting power

**Conditions Required:**
- A governance proposal to change the `BlocksPerYear` parameter must pass
- The parameter must be set to a value > `math.MaxInt64` (specifically between 9,223,372,036,854,775,808 and 18,446,744,073,709,551,615)
- The malicious value passes current validation (which only checks non-zero)

**Frequency:**
This is a one-time attack that causes permanent damage. Once triggered, the chain halts until a hard fork is deployed. While it requires governance participation, the missing validation makes it trivially exploitable once the parameter change executes.

## Recommendation

Add validation to ensure `BlocksPerYear` does not exceed `math.MaxInt64`:

```go
func validateBlocksPerYear(i interface{}) error {
    v, ok := i.(uint64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }
    
    if v == 0 {
        return fmt.Errorf("blocks per year must be positive: %d", v)
    }
    
    // Add this check to prevent integer overflow when casting to int64
    if v > math.MaxInt64 {
        return fmt.Errorf("blocks per year exceeds maximum safe value: %d", v)
    }
    
    return nil
}
```

Additionally, consider using `sdk.NewIntFromUint64` instead of casting to avoid the overflow entirely, or add defensive checks in `BlockProvision` to validate the parameter before use.

## Proof of Concept

**File:** `x/mint/types/minter_test.go`

**Test Function:** Add this test to demonstrate the vulnerability:

```go
func TestBlockProvisionPanicOnLargeBlocksPerYear(t *testing.T) {
    // Setup: Create a minter with positive annual provisions
    minter := InitialMinter(sdk.NewDecWithPrec(1, 1))
    minter.AnnualProvisions = sdk.NewDec(1000000000)
    
    // Create params with BlocksPerYear > math.MaxInt64
    // This will cause integer overflow when cast to int64
    params := DefaultParams()
    params.BlocksPerYear = uint64(math.MaxInt64) + 1 // 9223372036854775808
    
    // Trigger: Calling BlockProvision should panic
    // because the int64 cast overflows to negative, 
    // causing division to produce negative amount,
    // which makes sdk.NewCoin panic
    require.Panics(t, func() {
        minter.BlockProvision(params)
    }, "BlockProvision should panic when BlocksPerYear > math.MaxInt64")
    
    // Test with math.MaxUint64 to show extreme case
    params.BlocksPerYear = math.MaxUint64 // 18446744073709551615
    require.Panics(t, func() {
        minter.BlockProvision(params)
    }, "BlockProvision should panic when BlocksPerYear = math.MaxUint64")
}
```

**Setup:** The test creates a minter with positive `AnnualProvisions` and sets `BlocksPerYear` to values exceeding `math.MaxInt64`.

**Trigger:** Calling `BlockProvision(params)` triggers the vulnerability. The cast `int64(params.BlocksPerYear)` overflows to a negative value, making the division produce a negative result, which causes `sdk.NewCoin` to panic.

**Observation:** The test uses `require.Panics()` to verify that `BlockProvision` panics with the malicious parameter values. This confirms that the vulnerability exists and would halt the chain in production when `BeginBlocker` executes this code path.

To demonstrate the full chain halt scenario, a more complete integration test would:
1. Initialize a test chain with default mint parameters
2. Submit and execute a governance proposal to change `BlocksPerYear` to `math.MaxUint64`
3. Advance to the next block, which should panic in `BeginBlocker`
4. Verify that block production halts and cannot resume

### Citations

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
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

**File:** types/coin.go (L14-27)
```go
// NewCoin returns a new coin with a denomination and amount. It will panic if
// the amount is negative or if the denomination is invalid.
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

**File:** types/coin.go (L42-52)
```go
func (coin Coin) Validate() error {
	if err := ValidateDenom(coin.Denom); err != nil {
		return err
	}

	if coin.Amount.IsNegative() {
		return fmt.Errorf("negative coin amount: %v", coin.Amount)
	}

	return nil
}
```

**File:** x/mint/abci.go (L27-29)
```go
	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)
```
