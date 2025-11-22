# Audit Report

## Title
Integer Overflow in Gas Meter Multiplier Calculation Bypasses Overflow Protection

## Summary
The `adjustGas()` function in `multiplierGasMeter` and `infiniteMultiplierGasMeter` performs multiplication without overflow checking, allowing integer overflow to wrap to small values instead of panicking with `ErrorGasOverflow`. This breaks the gas accounting system's overflow protection invariant.

## Impact
**Medium**

## Finding Description

**Location:** 
- `store/types/gas.go`, lines 181-183 (`multiplierGasMeter.adjustGas()`)
- `store/types/gas.go`, lines 288-290 (`infiniteMultiplierGasMeter.adjustGas()`) [1](#0-0) [2](#0-1) 

**Intended Logic:**
The gas meter system is designed to detect integer overflow and panic with `ErrorGasOverflow` when gas calculations exceed `math.MaxUint64`. This is evidenced by:
1. The `ErrorGasOverflow` error type definition [3](#0-2) 
2. The `addUint64Overflow()` helper function for safe addition [4](#0-3) 
3. Overflow protection in `basicGasMeter.ConsumeGas()` [5](#0-4) 
4. Overflow protection even in `infiniteGasMeter.ConsumeGas()` [6](#0-5) 

**Actual Logic:**
The `adjustGas()` function performs `original * g.multiplierNumerator / g.multiplierDenominator` using native Go arithmetic. When `original * g.multiplierNumerator` exceeds `math.MaxUint64`, Go's uint64 multiplication wraps around modulo 2^64, producing a small value instead of detecting overflow. This wrapped value is then passed to `ConsumeGas()`, bypassing the intended overflow protection.

**Exploit Scenario:**
1. Governance sets gas multiplier parameters through the params module (no upper bound validation exists) [7](#0-6) 
2. If `multiplierNumerator` is set to a high value (e.g., 2^63) due to misconfiguration or lack of understanding of overflow risks
3. A user transaction performs operations that consume gas (e.g., KV store reads/writes) [8](#0-7) 
4. When `adjustGas()` calculates `2 * 2^63 = 2^64`, this overflows to 0
5. The transaction consumes 0 gas instead of the intended large amount
6. User bypasses gas accounting and can execute expensive operations for free

**Security Failure:**
This breaks the gas accounting invariant, which is critical for:
- Preventing DoS attacks through resource exhaustion
- Ensuring fair transaction ordering and fee payment
- Maintaining consensus about block gas limits

## Impact Explanation

The vulnerability affects the core gas metering system that governs resource consumption across the entire blockchain:

- **Resource Consumption:** Attackers could execute computationally expensive operations (repeated KV operations, large state updates) while consuming minimal gas, exhausting node resources
- **Economic Model:** Transaction fee calculation becomes incorrect, allowing users to avoid paying for their actual resource consumption
- **Consensus Safety:** Blocks could exceed intended gas limits without triggering protection mechanisms, potentially causing nodes to process transactions beyond safe parameters

While exploitation requires governance to set unsafe multiplier values, the lack of validation and documentation makes this a realistic configuration error. The system provides no warnings or safeguards against values that cause overflow.

## Likelihood Explanation

**Trigger Conditions:**
- Governance must set `CosmosGasMultiplierNumerator` to a value where `amount * numerator > math.MaxUint64` for realistic gas consumption amounts
- Default parameters (1/1) do not trigger the issue [9](#0-8) 
- No validation prevents unsafe values [7](#0-6) 

**Likelihood:**
While requiring governance action, this is not purely theoretical:
- Governance operates on-chain and parameters can be changed through proposals
- No documentation warns about overflow risks for high multiplier values
- The validation only checks for zero, not upper bounds or overflow potential
- Could occur through misconfiguration rather than malicious intent

Once triggered, any user can exploit it repeatedly during the period unsafe parameters are active.

## Recommendation

Add overflow checking to the `adjustGas()` function using the existing `addUint64Overflow()` helper:

```go
func (g *multiplierGasMeter) adjustGas(original Gas) Gas {
    // Check multiplication overflow
    adjusted, overflow := addUint64Overflow(original*g.multiplierNumerator, 0)
    if overflow || adjusted < original*g.multiplierNumerator {
        panic(ErrorGasOverflow{"gas multiplier calculation"})
    }
    return adjusted / g.multiplierDenominator
}
```

Alternatively, perform checked multiplication before division:
```go
func (g *multiplierGasMeter) adjustGas(original Gas) Gas {
    if g.multiplierNumerator > 0 && original > math.MaxUint64/g.multiplierNumerator {
        panic(ErrorGasOverflow{"gas multiplier calculation"})
    }
    return original * g.multiplierNumerator / g.multiplierDenominator
}
```

Additionally, add validation in params to prevent unsafe multiplier values:
```go
func (cg *CosmosGasParams) Validate() error {
    // ... existing checks ...
    if cg.CosmosGasMultiplierNumerator > math.MaxUint64/1000000 {
        return errors.New("cosmos gas multiplier numerator too large, risk of overflow")
    }
    return nil
}
```

## Proof of Concept

**File:** `store/types/gas_test.go`

**Test Function:** `TestMultiplierGasMeterOverflow`

```go
func TestMultiplierGasMeterOverflow(t *testing.T) {
    // Setup: Create a gas meter with a high multiplier that will cause overflow
    // Using 2^63 as numerator - when multiplied by 2, will overflow to 0
    multiplierNumerator := uint64(1 << 63)  // 2^63
    multiplierDenominator := uint64(1)
    
    meter := NewMultiplierGasMeter(10000, multiplierNumerator, multiplierDenominator)
    
    // Trigger: Consume 2 gas units
    // Expected: Should panic with ErrorGasOverflow
    // Actual: Overflows to 0, no panic, gas consumption bypassed
    
    initialConsumed := meter.GasConsumed()
    require.Equal(t, uint64(0), initialConsumed)
    
    // This should cause overflow: 2 * 2^63 = 2^64, which wraps to 0
    // The test demonstrates the vulnerability - no panic occurs
    meter.ConsumeGas(2, "test operation")
    
    // Observation: Gas consumed should have increased significantly,
    // but due to overflow wrapping to 0, it remains at 0
    finalConsumed := meter.GasConsumed()
    
    // This assertion passes, demonstrating the bug:
    // We consumed "2" gas with multiplier 2^63, but recorded consumption is 0
    require.Equal(t, uint64(0), finalConsumed, 
        "Overflow wrapped to 0 instead of panicking - gas accounting bypassed")
}
```

**Setup:** The test creates a `multiplierGasMeter` with `multiplierNumerator = 2^63` and `multiplierDenominator = 1`.

**Trigger:** Calls `ConsumeGas(2, "test operation")`, which should calculate `2 * 2^63 / 1 = 2^64`. Since 2^64 exceeds `math.MaxUint64`, Go's uint64 arithmetic wraps this to 0.

**Observation:** The test verifies that `GasConsumed()` remains 0 despite consuming gas, demonstrating that overflow silently wraps to zero instead of panicking with `ErrorGasOverflow`. This proves the gas accounting bypass.

**Expected behavior:** The function should panic with `ErrorGasOverflow`, similar to how `basicGasMeter.ConsumeGas()` handles overflow at lines 103-106.

### Citations

**File:** store/types/gas.go (L38-42)
```go
// ErrorGasOverflow defines an error thrown when an action results gas consumption
// unsigned integer overflow.
type ErrorGasOverflow struct {
	Descriptor string
}
```

**File:** store/types/gas.go (L87-95)
```go
// addUint64Overflow performs the addition operation on two uint64 integers and
// returns a boolean on whether or not the result overflows.
func addUint64Overflow(a, b uint64) (uint64, bool) {
	if math.MaxUint64-a < b {
		return 0, true
	}

	return a + b, false
}
```

**File:** store/types/gas.go (L101-107)
```go
	var overflow bool
	g.consumed, overflow = addUint64Overflow(g.consumed, amount)
	if overflow {
		g.consumed = math.MaxUint64
		g.incrGasExceededCounter("overflow", descriptor)
		panic(ErrorGasOverflow{descriptor})
	}
```

**File:** store/types/gas.go (L181-183)
```go
func (g *multiplierGasMeter) adjustGas(original Gas) Gas {
	return original * g.multiplierNumerator / g.multiplierDenominator
}
```

**File:** store/types/gas.go (L227-232)
```go
	var overflow bool
	// TODO: Should we set the consumed field after overflow checking?
	g.consumed, overflow = addUint64Overflow(g.consumed, amount)
	if overflow {
		panic(ErrorGasOverflow{descriptor})
	}
```

**File:** store/types/gas.go (L288-290)
```go
func (g *infiniteMultiplierGasMeter) adjustGas(original Gas) Gas {
	return original * g.multiplierNumerator / g.multiplierDenominator
}
```

**File:** x/params/types/params.go (L55-64)
```go
func (cg *CosmosGasParams) Validate() error {
	if cg.CosmosGasMultiplierNumerator == 0 {
		return errors.New("cosmos gas multiplier numerator can not be 0")
	}

	if cg.CosmosGasMultiplierDenominator == 0 {
		return errors.New("cosmos gas multiplier denominator can not be 0")
	}

	return nil
```

**File:** store/gaskv/store.go (L54-66)
```go
func (gs *Store) Get(key []byte) (value []byte) {
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostFlat, types.GasReadCostFlatDesc)
	value = gs.parent.Get(key)

	// TODO overflow-safe math?
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostPerByte*types.Gas(len(key)), types.GasReadPerByteDesc)
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostPerByte*types.Gas(len(value)), types.GasReadPerByteDesc)
	if gs.tracer != nil {
		gs.tracer.Get(key, value, gs.moduleName)
	}

	return value
}
```

**File:** x/params/types/genesis.go (L15-19)
```go
func DefaultCosmosGasParams() *CosmosGasParams {
	return &CosmosGasParams{
		CosmosGasMultiplierNumerator:   1,
		CosmosGasMultiplierDenominator: 1,
	}
```
