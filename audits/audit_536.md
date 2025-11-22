# Audit Report

## Title
Missing Nil Check in Mint Module Parameter Validation Functions Causes Node Crash

## Summary
The mint module's parameter validation functions in `x/mint/types/params.go` fail to check for nil `sdk.Dec` values before invoking methods that dereference internal pointers, causing panics. This differs from the safe pattern implemented in other modules (distribution, staking) and can crash nodes during parameter validation.

## Impact
**Medium** - Can cause node crashes and denial of service during genesis initialization or parameter validation, potentially affecting network availability.

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:** 
Parameter validation functions should safely validate all inputs without causing panics, returning errors for invalid values. The `sdk.Dec` type has an internal `*big.Int` pointer that can be nil, requiring explicit nil checks before operations. [5](#0-4) [6](#0-5) 

**Actual Logic:** 
The mint module's validation functions (`validateInflationRateChange`, `validateInflationMax`, `validateInflationMin`, `validateGoalBonded`) call methods like `IsNegative()`, `IsZero()`, `GT()` directly on `sdk.Dec` values without first checking `IsNil()`. These methods internally dereference the `*big.Int` pointer, causing nil pointer dereference panics when the Dec has an uninitialized internal state.

The `Params.Validate()` method also unsafely calls `LT()` on Dec fields: [7](#0-6) 

**Exploit Scenario:** 
1. A malformed genesis state or parameter update contains `Params` with uninitialized `sdk.Dec` fields (zero value has `i == nil`)
2. During validation, `ValidateGenesis` or `SetParamSet` calls the validation functions
3. The validation functions invoke methods on the nil Dec values
4. Methods like `IsNegative()` call `d.i.Sign()`, dereferencing the nil pointer
5. Node crashes with nil pointer panic

**Security Failure:**
Memory safety violation leading to denial of service. The validation functions, which should safely reject invalid inputs, instead panic and crash the node.

## Impact Explanation

**Affected Components:**
- Node availability during genesis initialization
- Parameter validation during runtime updates
- Chain bootstrap process

**Severity:**
- If a malformed genesis state is distributed, all nodes attempting to start with it will crash
- Affects network availability and node operator experience
- Can delay chain launches or cause widespread node failures
- While not directly exploitable by external attackers during normal operation, it represents a critical defensive programming failure that violates safety guarantees

**Why It Matters:**
Parameter validation is a critical safety mechanism. When validation functions themselves can crash nodes, it undermines the entire safety model. This is particularly dangerous during genesis initialization when all nodes must validate the same state.

## Likelihood Explanation

**Who Can Trigger:**
- Primarily affects node operators using malformed genesis files or configuration
- Could occur accidentally through bugs in genesis generation tools
- Could be triggered by internal code paths that construct Params structs directly

**Conditions Required:**
- Genesis state or parameter update with uninitialized Dec fields
- The zero value of `sdk.Dec` has nil internal pointer
- While JSON/protobuf unmarshaling typically initializes Dec fields, direct struct construction or partial initialization can create nil Decs

**Frequency:**
- Uncommon during normal operation with proper JSON/protobuf serialization
- More likely during development, testing, or genesis generation
- Can be triggered by any code path that validates Params with uninitialized Dec fields

## Recommendation

Add nil checks before calling any Dec methods in all mint module validation functions, following the safe pattern used in distribution and staking modules: [8](#0-7) 

For each validation function in `x/mint/types/params.go`, add:
```go
if v.IsNil() {
    return fmt.Errorf("[parameter name] must be not nil")
}
```

before calling `IsNegative()`, `IsZero()`, `GT()`, `LT()`, or other Dec methods. Also add nil checks in `Params.Validate()` before the `LT()` comparison.

## Proof of Concept

**File:** `x/mint/types/params_test.go` (add new test function)

**Test Function:**
```go
func TestValidateInflationRateChangeWithNilDec(t *testing.T) {
    // Create a Dec with nil internal pointer (zero value)
    nilDec := sdk.Dec{}
    
    // This should return an error, but instead panics
    err := validateInflationRateChange(nilDec)
    require.Error(t, err) // Test will panic before reaching this assertion
}
```

**Setup:**
No special setup required. The test creates a zero-value `sdk.Dec` which has `i == nil`.

**Trigger:**
Call `validateInflationRateChange()` with the nil Dec. The function will attempt to call `v.IsNegative()` which internally calls `(d.i).Sign()`, dereferencing the nil pointer.

**Observation:**
The test will panic with "runtime error: invalid memory address or nil pointer dereference" instead of returning an error. This demonstrates that the validation function is not type-safe against nil values and violates the safety contract of validation functions.

**Alternative PoC** (testing Params.Validate):
```go
func TestParamsValidateWithNilDec(t *testing.T) {
    params := types.Params{
        MintDenom:           "uatom",
        InflationRateChange: sdk.Dec{}, // nil internal pointer
        InflationMax:        sdk.NewDecWithPrec(20, 2),
        InflationMin:        sdk.NewDecWithPrec(7, 2),
        GoalBonded:          sdk.NewDecWithPrec(67, 2),
        BlocksPerYear:       6311520,
    }
    
    // This should return an error, but panics at line 75 calling LT()
    err := params.Validate()
    require.Error(t, err) // Test will panic before reaching this
}
```

This demonstrates the vulnerability exists in both the individual validation functions and the `Params.Validate()` method itself.

### Citations

**File:** x/mint/types/params.go (L75-80)
```go
	if p.InflationMax.LT(p.InflationMin) {
		return fmt.Errorf(
			"max inflation (%s) must be greater than or equal to min inflation (%s)",
			p.InflationMax, p.InflationMin,
		)
	}
```

**File:** x/mint/types/params.go (L120-134)
```go
func validateInflationRateChange(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNegative() {
		return fmt.Errorf("inflation rate change cannot be negative: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("inflation rate change too large: %s", v)
	}

	return nil
}
```

**File:** x/mint/types/params.go (L136-150)
```go
func validateInflationMax(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNegative() {
		return fmt.Errorf("max inflation cannot be negative: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("max inflation too large: %s", v)
	}

	return nil
}
```

**File:** x/mint/types/params.go (L152-166)
```go
func validateInflationMin(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNegative() {
		return fmt.Errorf("min inflation cannot be negative: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("min inflation too large: %s", v)
	}

	return nil
}
```

**File:** x/mint/types/params.go (L168-182)
```go
func validateGoalBonded(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNegative() || v.IsZero() {
		return fmt.Errorf("goal bonded must be positive: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("goal bonded too large: %s", v)
	}

	return nil
}
```

**File:** types/decimal.go (L15-19)
```go
// NOTE: never use new(Dec) or else we will panic unmarshalling into the
// nil embedded big.Int
type Dec struct {
	i *big.Int
}
```

**File:** types/decimal.go (L206-209)
```go
func (d Dec) IsNil() bool       { return d.i == nil }                 // is decimal nil
func (d Dec) IsZero() bool      { return (d.i).Sign() == 0 }          // is equal to zero
func (d Dec) IsNegative() bool  { return (d.i).Sign() == -1 }         // is negative
func (d Dec) IsPositive() bool  { return (d.i).Sign() == 1 }          // is positive
```

**File:** x/distribution/types/params.go (L76-93)
```go
func validateCommunityTax(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNil() {
		return fmt.Errorf("community tax must be not nil")
	}
	if v.IsNegative() {
		return fmt.Errorf("community tax must be positive: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("community tax too large: %s", v)
	}

	return nil
}
```
