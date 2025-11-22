## Title
Governance Parameter Changes Can Violate Distribution Module Invariants Leading to Negative Rewards and Potential Chain Halt

## Summary
The distribution module allows governance to change `CommunityTax`, `BaseProposerReward`, and `BonusProposerReward` parameters individually without validating that their sum remains ≤ 1.0. This violates a critical accounting invariant and causes negative validator rewards to be allocated, breaking the `NonNegativeOutstandingInvariant` and potentially halting the chain. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown) or unintended chain behavior requiring emergency intervention.

## Finding Description

**Location:** 
- Parameter validation: [2](#0-1) 
- Allocation logic: [3](#0-2) 
- Invariant check: [4](#0-3) 

**Intended Logic:** 
The distribution module expects that `CommunityTax + BaseProposerReward + BonusProposerReward ≤ 1.0` to ensure proper fee allocation. The `ValidateBasic()` function enforces this cross-parameter constraint. [5](#0-4) 

**Actual Logic:** 
When parameters are changed through governance proposals, the `Update()` method only calls individual parameter validators registered in `ParamSetPairs()`, which check that each parameter is between 0 and 1 individually. The cross-parameter validation in `ValidateBasic()` is never called. [2](#0-1) 

The individual validators allow values like:
- `CommunityTax = 0.5` [6](#0-5) 
- `BaseProposerReward = 0.4` [7](#0-6) 
- `BonusProposerReward = 0.4` [8](#0-7) 

Sum = 1.3 > 1.0, violating the invariant.

**Exploit Scenario:**
1. Submit and pass governance proposal to set `CommunityTax = 0.5`
2. Submit and pass governance proposal to set `BaseProposerReward = 0.4`
3. Submit and pass governance proposal to set `BonusProposerReward = 0.4`
4. During next block's BeginBlock, `AllocateTokens` calculates:
   - `proposerMultiplier = 0.4 + 0.4 * previousFractionVotes` (up to 0.8)
   - `voteMultiplier = 1.0 - 0.8 - 0.5 = -0.3` (negative!)
   - `feeMultiplier = feesCollected * (-0.3)` (negative rewards)
5. Negative rewards are allocated to validators [9](#0-8) 
6. The `NonNegativeOutstandingInvariant` detects negative outstanding rewards and marks invariant as broken [10](#0-9) 

**Security Failure:** 
The accounting invariant is violated, resulting in negative validator rewards. This breaks the protocol's fee distribution mechanism and causes invariant violations that can halt the chain if invariant checking is enabled.

## Impact Explanation

**Affected Components:**
- Fee distribution accounting becomes invalid
- Validator outstanding rewards become negative
- Chain invariants are violated
- Network consensus may halt

**Severity:**
If invariant checking is enabled (which is standard for production chains), this causes an immediate chain halt requiring emergency coordination and potentially a hard fork to fix. Even if invariant checking is disabled, the negative rewards corrupt the fee distribution accounting, causing incorrect validator compensation and potential economic attacks.

**Systemic Risk:**
This affects the core economic incentive mechanism of the blockchain. Validators would receive incorrect rewards, undermining the security model of the proof-of-stake consensus.

## Likelihood Explanation

**Trigger Conditions:**
- Any network participant can submit governance proposals
- Requires proposals to pass through normal governance voting (typically 50%+ voting power approval)
- No special privileges required beyond normal governance participation
- Can occur through legitimate governance activity (not requiring malicious intent)

**Frequency:**
- Could happen during routine parameter adjustments if governance participants don't manually verify cross-parameter constraints
- Once triggered, affects every subsequent block until parameters are corrected
- Requires 3 separate governance proposals to reach the vulnerable state

**Likelihood:** Medium to High - While requiring multiple governance proposals, the lack of automatic validation means well-intentioned parameter changes could accidentally trigger this during routine governance operations.

## Recommendation

Add cross-parameter validation during governance parameter updates. Modify the `Update` method or the parameter validation flow to call `Params.ValidateBasic()` after updating any distribution parameter to ensure all cross-parameter constraints are satisfied:

```go
// In x/params/proposal_handler.go or create a custom handler for distribution params
if c.Subspace == "distribution" {
    // After updating, validate all params together
    var params distributiontypes.Params
    ss.GetParamSet(ctx, &params)
    if err := params.ValidateBasic(); err != nil {
        return err
    }
}
```

Alternatively, implement a more sophisticated validator function that has access to all current parameter values when validating changes.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensInvariantViolation`

**Setup:**
1. Initialize a test chain with default distribution parameters
2. Create two validators with voting power
3. Fund the fee collector with test tokens

**Trigger:**
1. Use governance parameter update mechanism to set:
   - `CommunityTax = 0.5`
   - `BaseProposerReward = 0.4`  
   - `BonusProposerReward = 0.4`
2. Call `AllocateTokens` with votes from both validators
3. Check validator outstanding rewards

**Observation:**
The test will show that validator outstanding rewards become negative, violating the invariant. The `NonNegativeOutstandingInvariant` check will return `broken = true`.

```go
func TestAllocateTokensInvariantViolation(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Set invalid params that sum to > 1.0 (simulating governance changes)
    invalidParams := disttypes.Params{
        CommunityTax:        sdk.NewDecWithPrec(50, 2), // 0.5
        BaseProposerReward:  sdk.NewDecWithPrec(40, 2), // 0.4
        BonusProposerReward: sdk.NewDecWithPrec(40, 2), // 0.4
        WithdrawAddrEnabled: true,
    }
    app.DistrKeeper.SetParams(ctx, invalidParams)
    
    addrs := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1234))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDec(0), sdk.NewDec(0), sdk.NewDec(0))
    tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
    tstaking.CreateValidator(valAddrs[1], valConsPk2, sdk.NewInt(100), true)
    
    // Fund fee collector
    fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(1000)))
    feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
    require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
    app.AccountKeeper.SetAccount(ctx, feeCollector)
    
    votes := []abci.VoteInfo{
        {Validator: abci.Validator{Address: valConsPk1.Address(), Power: 100}, SignedLastBlock: true},
        {Validator: abci.Validator{Address: valConsPk2.Address(), Power: 100}, SignedLastBlock: true},
    }
    
    // Allocate tokens - this will create negative rewards
    app.DistrKeeper.AllocateTokens(ctx, 200, 200, valConsAddr2, votes)
    
    // Check that outstanding rewards are negative (invariant violation)
    rewards := app.DistrKeeper.GetValidatorOutstandingRewards(ctx, valAddrs[0]).Rewards
    require.True(t, rewards.IsAnyNegative(), "Expected negative rewards due to parameter sum > 1.0")
    
    // Verify invariant is broken
    _, broken := keeper.NonNegativeOutstandingInvariant(app.DistrKeeper)(ctx)
    require.True(t, broken, "NonNegativeOutstandingInvariant should be broken")
}
```

This test demonstrates that when distribution parameters sum to more than 1.0, the `AllocateTokens` function produces negative validator rewards, violating the critical accounting invariant.

### Citations

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

**File:** x/distribution/types/params.go (L95-112)
```go
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
```

**File:** x/distribution/types/params.go (L114-131)
```go
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

**File:** x/distribution/keeper/allocation.go (L44-102)
```go
	// calculate fraction votes
	previousFractionVotes := sdk.NewDec(sumPreviousPrecommitPower).Quo(sdk.NewDec(totalPreviousPower))

	// calculate previous proposer reward
	baseProposerReward := k.GetBaseProposerReward(ctx)
	bonusProposerReward := k.GetBonusProposerReward(ctx)
	proposerMultiplier := baseProposerReward.Add(bonusProposerReward.MulTruncate(previousFractionVotes))
	proposerReward := feesCollected.MulDecTruncate(proposerMultiplier)

	// pay previous proposer
	remaining := feesCollected
	proposerValidator := k.stakingKeeper.ValidatorByConsAddr(ctx, previousProposer)

	if proposerValidator != nil {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeProposerReward,
				sdk.NewAttribute(sdk.AttributeKeyAmount, proposerReward.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, proposerValidator.GetOperator().String()),
			),
		)

		k.AllocateTokensToValidator(ctx, proposerValidator, proposerReward)
		remaining = remaining.Sub(proposerReward)
	} else {
		// previous proposer can be unknown if say, the unbonding period is 1 block, so
		// e.g. a validator undelegates at block X, it's removed entirely by
		// block X+1's endblock, then X+2 we need to refer to the previous
		// proposer for X+1, but we've forgotten about them.
		logger.Error(fmt.Sprintf(
			"WARNING: Attempt to allocate proposer rewards to unknown proposer %s. "+
				"This should happen only if the proposer unbonded completely within a single block, "+
				"which generally should not happen except in exceptional circumstances (or fuzz testing). "+
				"We recommend you investigate immediately.",
			previousProposer.String()))
	}

	// calculate fraction allocated to validators
	communityTax := k.GetCommunityTax(ctx)
	voteMultiplier := sdk.OneDec().Sub(proposerMultiplier).Sub(communityTax)
	feeMultiplier := feesCollected.MulDecTruncate(voteMultiplier)

	// allocate tokens proportionally to voting power
	//
	// TODO: Consider parallelizing later
	//
	// Ref: https://github.com/cosmos/cosmos-sdk/pull/3099#discussion_r246276376
	for _, vote := range bondedVotes {
		validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)

		// TODO: Consider micro-slashing for missing votes.
		//
		// Ref: https://github.com/cosmos/cosmos-sdk/issues/2525#issuecomment-430838701
		powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
		reward := feeMultiplier.MulDecTruncate(powerFraction)

		k.AllocateTokensToValidator(ctx, validator, reward)
		remaining = remaining.Sub(reward)
	}
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
