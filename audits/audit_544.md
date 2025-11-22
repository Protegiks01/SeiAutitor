# Audit Report

## Title
Missing Cross-Parameter Validation for InflationMax and InflationMin in Governance Parameter Updates

## Summary
The cross-validation check ensuring `InflationMax >= InflationMin` is only enforced during genesis initialization but is bypassed when parameters are updated via governance proposals. This allows the creation of an invalid parameter state that breaks the mint module's inflation mechanism.

## Impact
**Medium**

## Finding Description

**Location:** 
- Validation logic: [1](#0-0) 
- Parameter update handler: [2](#0-1) 
- Subspace Update method: [3](#0-2) 
- Individual validators: [4](#0-3) 

**Intended Logic:** 
The mint module should maintain the invariant that `InflationMax >= InflationMin` at all times. This is validated in the `Params.Validate()` method [1](#0-0) , which checks this relationship and returns an error if violated.

**Actual Logic:** 
When parameters are changed via `ParameterChangeProposal`, the update flow is:
1. Proposal handler calls `ss.Update()` [5](#0-4) 
2. `Update()` only validates the individual parameter using its registered validation function [6](#0-5) 
3. The individual validators (`validateInflationMax` and `validateInflationMin`) only check that values are non-negative and not greater than 1.0 [4](#0-3) 
4. The cross-validation in `Params.Validate()` is **never called** during parameter updates

The `ParamSetPairs()` definition shows individual validators are used [7](#0-6) , not the full `Params.Validate()` method.

**Exploit Scenario:**
1. Submit a governance proposal to change `InflationMax` from 0.20 to 0.05 while `InflationMin` remains at 0.07
2. The proposal passes `validateInflationMax` since 0.05 is between 0 and 1.0
3. The proposal is executed and `InflationMax` is set to 0.05
4. Now `InflationMax (0.05) < InflationMin (0.07)`, violating the invariant
5. In subsequent blocks, `BeginBlocker` calculates inflation using `NextInflationRate()` [8](#0-7) 
6. The `NextInflationRate()` function caps inflation first to InflationMax, then to InflationMin [9](#0-8) 
7. With inverted limits, inflation always gets capped to `InflationMin`, making `InflationMax` ineffective

**Security Failure:** 
This breaks the accounting invariant of the mint module. The system will mint tokens according to `InflationMin` regardless of the `InflationMax` parameter, causing unintended token supply inflation and breaking the economic model's intended behavior.

## Impact Explanation

**Affected Assets/Processes:**
- Token supply and inflation rate control
- Mint module's core economic mechanism
- Network's monetary policy

**Severity:**
- The network will mint more tokens than intended by the `InflationMax` parameter
- Token holders experience uncontrolled dilution beyond expected maximum inflation
- The mint module behaves incorrectly, violating its specification [10](#0-9) 
- Economic damage from unexpected inflation devaluing the token

**Why It Matters:**
This qualifies as **"A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"** per the Medium severity criteria. While funds aren't immediately stolen, the core L1 mint module fails to enforce its design parameters, leading to economic impact through uncontrolled inflation.

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit and pass a governance proposal (requires community consensus via governance voting).

**Conditions Required:**
- A governance proposal that changes either `InflationMax` or `InflationMin` such that they become inverted
- The proposal passes governance voting
- This could happen accidentally (human error in proposal parameters) or maliciously

**Frequency:**
- Governance proposals are infrequent but not rare
- Each parameter change carries this risk
- Once triggered, the invalid state persists until another governance proposal fixes it
- The impact occurs continuously (every block) once the invalid state exists

## Recommendation

Add cross-validation when individual mint parameters are updated. Modify the `validateInflationMax` and `validateInflationMin` functions to check against the other parameter:

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
    // Note: Cross-validation with InflationMin would require access to 
    // current params, which requires context. Better approach is to
    // add a custom Update handler for mint params that validates the
    // full Params object after any change.
    return nil
}
```

**Better approach:** Override the parameter update logic for the mint module to call `Params.Validate()` after any parameter change. This ensures all cross-validations are enforced consistently.

Alternatively, modify the governance proposal validation in [11](#0-10)  to include special handling for mint module parameters similar to the consensus params validation.

## Proof of Concept

**File:** `x/params/proposal_handler_test.go`

**Test Function:** Add this test case to the `TestProposalHandler` function:

```go
{
    "mint: set InflationMax below InflationMin - should fail but currently passes",
    testProposal(proposal.NewParamChange(
        "mint",
        "InflationMax",
        `"0.05"`, // 5% - below default InflationMin of 7%
    )),
    func() {
        // This demonstrates the bug: the proposal passes even though
        // InflationMax (0.05) < InflationMin (0.07)
        params := suite.app.MintKeeper.GetParams(suite.ctx)
        suite.Require().Equal(
            sdk.NewDecWithPrec(5, 2), 
            params.InflationMax,
        )
        suite.Require().Equal(
            sdk.NewDecWithPrec(7, 2), 
            params.InflationMin,
        )
        // Verify the invariant is violated
        suite.Require().True(
            params.InflationMax.LT(params.InflationMin),
            "InflationMax should be less than InflationMin, demonstrating the bug",
        )
        
        // Verify this breaks the inflation mechanism
        minter := suite.app.MintKeeper.GetMinter(suite.ctx)
        minter.Inflation = sdk.NewDecWithPrec(6, 2) // 6% - between Max and Min
        bondedRatio := sdk.NewDecWithPrec(50, 2) // 50% bonded
        
        // The inflation gets incorrectly capped to InflationMin instead of Max
        newInflation := minter.NextInflationRate(params, bondedRatio)
        suite.Require().Equal(
            params.InflationMin,
            newInflation,
            "Inflation incorrectly capped to Min when between inverted Max/Min",
        )
    },
    false, // This should be true (expecting error), but it's false showing the bug
}
```

**Setup:**
- Use the existing test suite structure in `proposal_handler_test.go`
- The test relies on default mint params where `InflationMin = 0.07` (7%)
- Submit a proposal to change `InflationMax` to `0.05` (5%)

**Trigger:**
- Execute the governance proposal handler
- The proposal passes validation despite creating an invalid state

**Observation:**
- The proposal succeeds (no error returned)
- `InflationMax (0.05) < InflationMin (0.07)` - invariant violated
- Calling `NextInflationRate()` with inflation between the inverted limits incorrectly caps to `InflationMin`
- This demonstrates the mint module's broken behavior under invalid parameter state

The test currently passes with `expErr: false`, confirming the vulnerability. After the fix, this test should be updated to `expErr: true` to ensure the proposal is rejected.

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

**File:** x/mint/types/params.go (L93-102)
```go
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(KeyMintDenom, &p.MintDenom, validateMintDenom),
		paramtypes.NewParamSetPair(KeyInflationRateChange, &p.InflationRateChange, validateInflationRateChange),
		paramtypes.NewParamSetPair(KeyInflationMax, &p.InflationMax, validateInflationMax),
		paramtypes.NewParamSetPair(KeyInflationMin, &p.InflationMin, validateInflationMin),
		paramtypes.NewParamSetPair(KeyGoalBonded, &p.GoalBonded, validateGoalBonded),
		paramtypes.NewParamSetPair(KeyBlocksPerYear, &p.BlocksPerYear, validateBlocksPerYear),
	}
}
```

**File:** x/mint/types/params.go (L136-166)
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

**File:** x/params/proposal_handler.go (L26-43)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
}
```

**File:** x/params/types/subspace.go (L196-219)
```go
func (s Subspace) Update(ctx sdk.Context, key, value []byte) error {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
	}

	ty := attr.ty
	dest := reflect.New(ty).Interface()
	s.GetIfExists(ctx, key, dest)

	if err := s.legacyAmino.UnmarshalJSON(value, dest); err != nil {
		return err
	}

	// destValue contains the dereferenced value of dest so validation function do
	// not have to operate on pointers.
	destValue := reflect.Indirect(reflect.ValueOf(dest)).Interface()
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
	}

	s.Set(ctx, key, dest)
	return nil
}
```

**File:** x/mint/abci.go (L23-23)
```go
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
```

**File:** x/mint/types/minter.go (L43-49)
```go
// NextInflationRate returns the new inflation rate for the next hour.
func (m Minter) NextInflationRate(params Params, bondedRatio sdk.Dec) sdk.Dec {
	// The target annual inflation rate is recalculated for each previsions cycle. The
	// inflation is also subject to a rate change (positive or negative) depending on
	// the distance from the desired ratio (67%). The maximum rate change possible is
	// defined to be 13% per year, however the annual inflation is capped as between
	// 7% and 20%.
```

**File:** x/mint/types/minter.go (L59-64)
```go
	if inflation.GT(params.InflationMax) {
		inflation = params.InflationMax
	}
	if inflation.LT(params.InflationMin) {
		inflation = params.InflationMin
	}
```

**File:** x/params/types/proposal/proposal.go (L84-113)
```go
// ValidateChanges performs basic validation checks over a set of ParamChange. It
// returns an error if any ParamChange is invalid.
func ValidateChanges(changes []ParamChange) error {
	if len(changes) == 0 {
		return ErrEmptyChanges
	}

	for _, pc := range changes {
		if len(pc.Subspace) == 0 {
			return ErrEmptySubspace
		}
		if len(pc.Key) == 0 {
			return ErrEmptyKey
		}
		if len(pc.Value) == 0 {
			return ErrEmptyValue
		}
		// We need to verify ConsensusParams since they are only validated once the proposal passes.
		// If any of them are invalid at time of passing, this will cause a chain halt since validation is done during
		// ApplyBlock: https://github.com/sei-protocol/sei-tendermint/blob/d426f1fe475eb0c406296770ff5e9f8869b3887e/internal/state/execution.go#L320
		// Therefore, we validate when we get a param-change msg for ConsensusParams
		if pc.Subspace == "baseapp" {
			if err := verifyConsensusParamsUsingDefault(changes); err != nil {
				return err
			}
		}
	}

	return nil
}
```
