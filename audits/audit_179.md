# Audit Report

## Title
Integer Overflow in BlocksPerYear Parameter Causes Permanent Chain Halt

## Summary
The `BlockProvision` function in the mint module performs an unsafe cast of `BlocksPerYear` from `uint64` to `int64` without validation, allowing values exceeding `math.MaxInt64` to overflow into negative numbers. This causes a panic in `sdk.NewCoin` when creating tokens with negative amounts, resulting in permanent chain halt during BeginBlocker execution.

## Impact
High

## Finding Description

**Location:** 
- Vulnerable cast: [1](#0-0) 
- Insufficient validation: [2](#0-1) 
- Panic trigger: [3](#0-2) 
- Panic source: [4](#0-3) 
- Negative amount check: [5](#0-4) 

**Intended Logic:**
The mint module should safely calculate per-block token provisions by dividing annual provisions by blocks per year. The `validateBlocksPerYear` function should ensure all parameter values are safe for arithmetic operations and type conversions.

**Actual Logic:**
The validation function only checks if `BlocksPerYear` is non-zero, but does not verify it's within the safe range for int64 conversion. When `BlockProvision` executes `sdk.NewInt(int64(params.BlocksPerYear))`, any value exceeding `math.MaxInt64` (9,223,372,036,854,775,807) undergoes integer overflow due to Go's two's complement representation, producing a negative value. This negative divisor causes `AnnualProvisions.QuoInt()` to return a negative result, which then triggers a panic in `sdk.NewCoin` since coin validation explicitly rejects negative amounts.

**Exploitation Path:**
1. Attacker influences governance (through social engineering, compromised validators, or voting power) to submit a parameter change proposal setting `BlocksPerYear` to a value > `math.MaxInt64`
2. Proposal passes governance vote (validators/token holders may not recognize the technical danger)
3. Parameter change executes successfully (validation only checks non-zero)
4. At next block, BeginBlocker calls `minter.BlockProvision(params)` [3](#0-2) 
5. Integer overflow occurs: `int64(params.BlocksPerYear)` becomes negative
6. Division produces negative provision amount
7. `sdk.NewCoin` panics when validating the negative amount [6](#0-5) 
8. Panic is uncaught in BeginBlock [7](#0-6)  - no defer/recover mechanism exists
9. All validators experience identical panic, halting the entire chain

**Security Guarantee Broken:**
Chain liveness guarantee is violated. The blockchain becomes unable to produce new blocks, requiring coordinated hard fork intervention for recovery.

## Impact Explanation

This vulnerability causes complete network shutdown affecting all network participants:

- **Validator Impact**: All validator nodes panic when attempting to execute BeginBlocker, preventing block production
- **Network Impact**: Consensus halts permanently - no new blocks can be produced or finalized
- **User Impact**: All transactions become impossible to submit or process; all economic activity freezes
- **Recovery Complexity**: Only solution is coordinated hard fork to either rollback state or fix the validation logic and upgrade all nodes

The impact is catastrophic and unrecoverable through normal chain operations. Unlike a temporary issue or individual node crash, this affects the entire network simultaneously and permanently until manual intervention via hard fork.

## Likelihood Explanation

**Trigger Requirements:**
- Governance proposal to change `BlocksPerYear` parameter must be submitted and approved
- Parameter must be set between 9,223,372,036,854,775,808 and 18,446,744,073,709,551,615
- Current validation allows these values (only checks non-zero)

**Attacker Profile:**
While this requires governance participation, it can be triggered through:
- Social engineering: Convincing validators/token holders that an extremely high `BlocksPerYear` is economically beneficial
- Compromised validators: Gaining control of sufficient voting power
- Inadvertent mistake: Well-meaning governance participant not understanding technical implications

**Likelihood Assessment:**
The missing validation creates a footgun - the system should protect against values causing technical failures, regardless of governance intent. A governance participant might reasonably think setting a very high `BlocksPerYear` is just an unusual economic choice without realizing it causes integer overflow. The validation passing makes the value appear "safe" from the system's perspective.

## Recommendation

Add upper bound validation to prevent integer overflow:

```go
func validateBlocksPerYear(i interface{}) error {
    v, ok := i.(uint64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }
    
    if v == 0 {
        return fmt.Errorf("blocks per year must be positive: %d", v)
    }
    
    // Prevent integer overflow when casting to int64
    if v > math.MaxInt64 {
        return fmt.Errorf("blocks per year exceeds maximum safe value (math.MaxInt64): %d", v)
    }
    
    return nil
}
```

Alternatively, use the safe conversion function that already exists [8](#0-7) :

```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
    provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewIntFromUint64(params.BlocksPerYear))
    return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```

The `NewIntFromUint64` function properly handles the full uint64 range without overflow by using `big.Int.SetUint64()`.

## Proof of Concept

**File:** `x/mint/types/minter_test.go`

**Test Function:**
```go
func TestBlockProvisionPanicOnOverflow(t *testing.T) {
    // Setup: Create minter with positive annual provisions
    minter := InitialMinter(sdk.NewDecWithPrec(1, 1))
    minter.AnnualProvisions = sdk.NewDec(1000000000)
    
    // Create params with BlocksPerYear exceeding math.MaxInt64
    params := DefaultParams()
    params.BlocksPerYear = uint64(math.MaxInt64) + 1
    
    // Trigger: BlockProvision panics due to integer overflow
    // The cast int64(params.BlocksPerYear) overflows to negative
    // Division produces negative result
    // sdk.NewCoin panics on negative amount validation
    require.Panics(t, func() {
        minter.BlockProvision(params)
    })
}
```

**Setup:** Minter configured with positive annual provisions; parameters set with `BlocksPerYear` exceeding safe int64 range.

**Action:** Call `BlockProvision(params)` which performs unsafe cast and arithmetic operations.

**Result:** Function panics when `sdk.NewCoin` validates the negative amount produced by division with overflowed negative divisor. This confirms the vulnerability would halt the chain when executed in BeginBlocker.

## Notes

This vulnerability satisfies the exception to the privileged action rule because:

1. The validation function exists but is incomplete - this is a genuine system bug, not intended behavior
2. Governance participants might inadvertently approve such a value without understanding the technical implications (validation passing suggests it's "safe")  
3. The consequence (permanent chain halt requiring hard fork) is far beyond the intended authority of parameter governance
4. The system should protect against technically dangerous values through proper validation, even if they're approved by governance

The vulnerability is in the **missing validation**, not in governance being malicious. Proper input validation is a security fundamental that should apply even to privileged operations.

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

**File:** x/mint/abci.go (L27-29)
```go
	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)
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

**File:** baseapp/abci.go (L133-156)
```go
// BeginBlock implements the ABCI application interface.
func (app *BaseApp) BeginBlock(ctx sdk.Context, req abci.RequestBeginBlock) (res abci.ResponseBeginBlock) {
	defer telemetry.MeasureSince(time.Now(), "abci", "begin_block")

	if !req.Simulate {
		if err := app.validateHeight(req); err != nil {
			panic(err)
		}
	}

	if app.beginBlocker != nil {
		res = app.beginBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	// call the streaming service hooks with the EndBlock messages
	if !req.Simulate {
		for _, streamingListener := range app.abciListeners {
			if err := streamingListener.ListenBeginBlock(app.deliverState.ctx, req, res); err != nil {
				app.logger.Error("EndBlock listening hook failed", "height", req.Header.Height, "err", err)
			}
		}
	}
	return res
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
