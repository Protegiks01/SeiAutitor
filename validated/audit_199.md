Audit Report

## Title
Governance Parameter Changes Can Bypass Cross-Parameter Validation Leading to Network Shutdown via Negative Reward Calculation

## Summary
The distribution module's governance parameter update mechanism fails to enforce the critical invariant that `CommunityTax + BaseProposerReward + BonusProposerReward ≤ 1.0`. Individual parameter validators only check that each value is between 0 and 1, allowing their sum to exceed 1.0. This causes negative validator rewards during fee allocation, violating the `NonNegativeOutstandingInvariant` and triggering a chain halt.

## Impact
High

## Finding Description

- **location**: 
  - Validation gap: [1](#0-0) 
  - Individual validators: [2](#0-1) 
  - Negative reward calculation: [3](#0-2) 
  - Invariant check: [4](#0-3) 
  - Chain halt: [5](#0-4) 

- **intended logic**: The distribution module enforces that the sum of `CommunityTax`, `BaseProposerReward`, and `BonusProposerReward` cannot exceed 1.0 to ensure proper fee allocation. This cross-parameter constraint is checked by `ValidateBasic()`. [6](#0-5) 

- **actual logic**: During governance parameter updates via `Subspace.Update()`, only individual parameter validators are invoked. These validators check that each parameter is between 0 and 1 independently, but never validate the cross-parameter sum constraint. [1](#0-0) 

- **exploitation path**: 
  1. Submit governance proposals to set: CommunityTax=0.5, BaseProposerReward=0.4, BonusProposerReward=0.4
  2. Each proposal passes individual validation (all values are ≤ 1.0)
  3. During next block's `AllocateTokens`, the calculation `voteMultiplier = 1.0 - proposerMultiplier - communityTax` produces a negative value when proposerMultiplier + communityTax > 1.0
  4. Negative rewards are allocated to validators, making outstanding rewards negative
  5. The `NonNegativeOutstandingInvariant` detects this violation
  6. The crisis module's `AssertInvariants` panics on the broken invariant, halting the chain

- **security guarantee broken**: The accounting invariant that validator outstanding rewards must always be non-negative is violated, and the system's ability to continue processing blocks is compromised.

## Impact Explanation
When the parameter sum exceeds 1.0, the reward allocation formula at [7](#0-6)  produces negative values. These negative rewards corrupt the validator outstanding rewards state at [8](#0-7) . The `NonNegativeOutstandingInvariant` detects this corruption, and if invariant checking is enabled (standard for production chains), the crisis module triggers a panic that halts the entire network. The chain cannot produce new blocks until the issue is resolved through emergency intervention or a hard fork.

## Likelihood Explanation
This vulnerability has medium to high likelihood because:
- Any participant can submit governance proposals
- Requires standard governance approval (typically 50%+ voting power)
- Can occur unintentionally during routine parameter adjustments without malicious intent
- Governance participants may not manually verify cross-parameter constraints
- Once triggered, every subsequent block is affected until parameters are corrected
- Requires 3 separate parameter changes (can be in a single proposal or separate proposals)

## Recommendation
Add cross-parameter validation during governance parameter updates. Modify the parameter update handler to validate all distribution parameters together after any individual parameter change:

```go
// In x/params/proposal_handler.go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
    for _, c := range p.Changes {
        ss, ok := k.GetSubspace(c.Subspace)
        if !ok {
            return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
        }
        
        if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
            return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
        }
        
        // Add cross-parameter validation for distribution module
        if c.Subspace == "distribution" {
            var params distributiontypes.Params
            ss.GetParamSet(ctx, &params)
            if err := params.ValidateBasic(); err != nil {
                return err
            }
        }
    }
    return nil
}
```

## Proof of Concept
**File**: `x/distribution/keeper/allocation_test.go`

**Test Function**: `TestAllocateTokensInvariantViolation`

**Setup**:
1. Initialize test application with default state
2. Create two validators with equal voting power (100 each)
3. Fund the fee collector module with test tokens (1000 tokens)

**Action**:
1. Call `SetParams` with invalid parameter combination where sum > 1.0:
   - CommunityTax = 0.5
   - BaseProposerReward = 0.4
   - BonusProposerReward = 0.4
2. Execute `AllocateTokens` with both validators voting (full participation)
3. Check validator outstanding rewards and invariant status

**Result**:
- The `voteMultiplier` calculation produces -0.3 (negative value)
- Validator outstanding rewards become negative
- `NonNegativeOutstandingInvariant` returns `broken = true`
- In production, this would trigger a chain halt via panic in [9](#0-8) 

## Notes

The vulnerability is confirmed through code analysis:
1. Cross-parameter validation exists in `ValidateBasic()` but is only called at genesis [10](#0-9) 
2. Governance updates bypass this validation [11](#0-10) 
3. The test suite confirms expected behavior for valid parameters [12](#0-11)  but lacks tests for the invalid parameter sum scenario
4. This matches the impact specification: "Network not being able to confirm new transactions (total network shutdown)"

### Citations

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

**File:** x/distribution/types/params.go (L51-74)
```go
func (p Params) ValidateBasic() error {
	if p.CommunityTax.IsNegative() || p.CommunityTax.GT(sdk.OneDec()) {
		return fmt.Errorf(
			"community tax should be non-negative and less than one: %s", p.CommunityTax,
		)
	}
	if p.BaseProposerReward.IsNegative() {
		return fmt.Errorf(
			"base proposer reward should be positive: %s", p.BaseProposerReward,
		)
	}
	if p.BonusProposerReward.IsNegative() {
		return fmt.Errorf(
			"bonus proposer reward should be positive: %s", p.BonusProposerReward,
		)
	}
	if v := p.BaseProposerReward.Add(p.BonusProposerReward).Add(p.CommunityTax); v.GT(sdk.OneDec()) {
		return fmt.Errorf(
			"sum of base, bonus proposer rewards, and community tax cannot be greater than one: %s", v,
		)
	}

	return nil
}
```

**File:** x/distribution/types/params.go (L76-131)
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

func validateBaseProposerReward(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNil() {
		return fmt.Errorf("base proposer reward must be not nil")
	}
	if v.IsNegative() {
		return fmt.Errorf("base proposer reward must be positive: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("base proposer reward too large: %s", v)
	}

	return nil
}

func validateBonusProposerReward(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNil() {
		return fmt.Errorf("bonus proposer reward must be not nil")
	}
	if v.IsNegative() {
		return fmt.Errorf("bonus proposer reward must be positive: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("bonus proposer reward too large: %s", v)
	}

	return nil
}
```

**File:** x/distribution/keeper/allocation.go (L82-84)
```go
	communityTax := k.GetCommunityTax(ctx)
	voteMultiplier := sdk.OneDec().Sub(proposerMultiplier).Sub(communityTax)
	feeMultiplier := feesCollected.MulDecTruncate(voteMultiplier)
```

**File:** x/distribution/keeper/allocation.go (L143-145)
```go
	outstanding := k.GetValidatorOutstandingRewards(ctx, val.GetOperator())
	outstanding.Rewards = outstanding.Rewards.Add(tokens...)
	k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), outstanding)
```

**File:** x/distribution/keeper/invariants.go (L43-62)
```go
func NonNegativeOutstandingInvariant(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		var msg string
		var count int
		var outstanding sdk.DecCoins

		k.IterateValidatorOutstandingRewards(ctx, func(addr sdk.ValAddress, rewards types.ValidatorOutstandingRewards) (stop bool) {
			outstanding = rewards.GetRewards()
			if outstanding.IsAnyNegative() {
				count++
				msg += fmt.Sprintf("\t%v has negative outstanding coins: %v\n", addr, outstanding)
			}
			return false
		})
		broken := count != 0

		return sdk.FormatInvariant(types.ModuleName, "nonnegative outstanding",
			fmt.Sprintf("found %d validators with negative outstanding rewards\n%s", count, msg)), broken
	}
}
```

**File:** x/crisis/keeper/keeper.go (L72-91)
```go
func (k Keeper) AssertInvariants(ctx sdk.Context) {
	logger := k.Logger(ctx)

	start := time.Now()
	invarRoutes := k.Routes()
	n := len(invarRoutes)
	for i, ir := range invarRoutes {
		logger.Info("asserting crisis invariants", "inv", fmt.Sprint(i+1, "/", n), "name", ir.FullRoute())
		if res, stop := ir.Invar(ctx); stop {
			// TODO: Include app name as part of context to allow for this to be
			// variable.
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
		}
	}

	diff := time.Since(start)
	logger.Info("asserted all invariants", "duration", diff, "height", ctx.BlockHeight())
}
```

**File:** x/distribution/types/genesis.go (L45-48)
```go
func ValidateGenesis(gs *GenesisState) error {
	if err := gs.Params.ValidateBasic(); err != nil {
		return err
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

**File:** x/distribution/keeper/allocation_test.go (L54-63)
```go
	testDistrParms := disttypes.Params{
		CommunityTax:        sdk.NewDecWithPrec(2, 2), // 2%
		BaseProposerReward:  sdk.NewDecWithPrec(1, 2), // 1%
		BonusProposerReward: sdk.NewDecWithPrec(4, 2), // 4%
		WithdrawAddrEnabled: true,
	}
	app.DistrKeeper.SetParams(
		ctx,
		testDistrParms,
	)
```
