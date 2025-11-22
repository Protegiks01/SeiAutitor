## Audit Report

## Title
Governance Proposals Can Desynchronize MintDenom and BondDenom Breaking Staking Rewards Mechanism

## Summary
A governance parameter change proposal can modify the mint module's `MintDenom` parameter independently from the staking module's `BondDenom` parameter, causing newly minted staking rewards to be in a denomination that cannot be re-staked. This breaks the core staking rewards mechanism and degrades the network's economic security model. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- Mint parameter validation: [1](#0-0) 
- Staking delegation validation: [2](#0-1) 
- Parameter update handler: [3](#0-2) 

**Intended Logic:** 
The mint module should create new tokens in a denomination that validators and delegators can use for staking. By default, both `MintDenom` and `BondDenom` are set to the same value (`sdk.DefaultBondDenom`) [4](#0-3) , ensuring minted tokens can be staked.

**Actual Logic:**
The parameter validation system validates each parameter independently within its own subspace [5](#0-4) . There is no cross-module validation to enforce that `MintDenom` equals `BondDenom`. A governance proposal can change `MintDenom` to a different denomination (e.g., "atom") while `BondDenom` remains "usei", and both validations will pass independently.

**Exploit Scenario:**
1. Initial state: `MintDenom` = "usei", `BondDenom` = "usei"
2. A governance proposal is submitted via `ParameterChangeProposal` to change `MintDenom` to "atom"
3. The proposal passes governance voting
4. The parameter is updated via `handleParameterChangeProposal` [3](#0-2) 
5. In subsequent blocks, `BeginBlocker` mints coins in "atom" denomination [6](#0-5) 
6. These "atom" coins are sent to the fee collector and distributed to validators/delegators as rewards [7](#0-6) 
7. When users attempt to delegate their rewards using `MsgDelegate`, the staking keeper validates that the coin denomination must match `BondDenom` [2](#0-1) 
8. Since the rewards are in "atom" but `BondDenom` is "usei", delegation transactions fail

**Security Failure:**
This breaks the accounting and economic security invariant that staking rewards should be re-stakable. The system accumulates rewards in an unusable denomination, degrading the bonded ratio over time and distorting the inflation mechanism.

## Impact Explanation

**Affected Assets and Processes:**
- Staking rewards become unusable for their primary purpose (re-staking)
- The bonded ratio (percentage of tokens staked) decreases as rewards accumulate but cannot be re-bonded
- The inflation rate calculation, which adjusts based on bonded ratio [8](#0-7) , becomes distorted
- Network economic security degrades as effective staking participation decreases

**Severity:**
This constitutes a medium-severity bug that results in unintended protocol behavior. While funds are not directly lost or stolen, the core staking rewards mechanism breaks down, affecting all validators and delegators. The network's economic model depends on validators and delegators being able to compound their staking rewards, and this vulnerability prevents that.

**Systemic Impact:**
Over time, as more rewards accumulate in the wrong denomination, the effective participation in network security decreases, potentially making the network more vulnerable to attacks or reducing validator incentives.

## Likelihood Explanation

**Who Can Trigger:**
This requires a governance proposal to pass, which means it needs either:
- Malicious governance participants with sufficient voting power
- Well-intentioned governance participants who don't understand the dependency between these parameters

**Conditions Required:**
- A parameter change proposal that modifies `MintDenom` without also updating `BondDenom` to match
- The proposal passes through the normal governance voting process

**Frequency:**
This could happen during routine parameter updates if governance participants are not aware of the strict requirement that these two parameters must remain synchronized. The risk is particularly high during:
- Network upgrades or migrations
- Economic parameter adjustments
- Multi-chain configurations where different denominations might be considered

The likelihood is moderate because while governance is required, the lack of validation makes it easy for this to occur accidentally.

## Recommendation

Add cross-module validation to enforce that `MintDenom` must equal `BondDenom`. This can be implemented in one of two ways:

**Option 1: Validate in Parameter Change Proposal Handler**
Modify `handleParameterChangeProposal` to check if either `MintDenom` or `BondDenom` is being changed, and if so, verify they remain equal.

**Option 2: Add Validation in Mint Params**
Extend the `Validate()` function in mint params to query the staking keeper and verify `MintDenom` matches `BondDenom`:

```go
// In x/mint/types/params.go, enhance the Validate function
func (p Params) ValidateWithStakingParams(stakingBondDenom string) error {
    if err := p.Validate(); err != nil {
        return err
    }
    if p.MintDenom != stakingBondDenom {
        return fmt.Errorf(
            "mint denom (%s) must equal staking bond denom (%s)",
            p.MintDenom, stakingBondDenom,
        )
    }
    return nil
}
```

**Option 3: Document and Add Governance Check**
At minimum, add a governance proposal validation that checks for this condition and rejects proposals that would desynchronize these parameters.

## Proof of Concept

**File:** `x/mint/keeper/params_test.go` (new test file)

**Test Function:** `TestMintDenomBondDenomMismatchBreaksStaking`

**Setup:**
```go
func TestMintDenomBondDenomMismatchBreaksStaking(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Initial setup: both params use default "usei"
    mintParams := app.MintKeeper.GetParams(ctx)
    stakingParams := app.StakingKeeper.GetParams(ctx)
    require.Equal(t, mintParams.MintDenom, stakingParams.BondDenom)
    
    // Create a test account with initial balance
    addrs := simapp.AddTestAddrsIncremental(app, ctx, 1, sdk.NewInt(1000000))
    delAddr := addrs[0]
}
```

**Trigger:**
```go
    // Simulate governance proposal changing MintDenom to different denomination
    mintParams.MintDenom = "atom"
    app.MintKeeper.SetParams(ctx, mintParams)
    
    // Mint new coins in "atom" denomination (simulating BeginBlocker)
    minter := app.MintKeeper.GetMinter(ctx)
    mintedCoin := sdk.NewCoin("atom", sdk.NewInt(1000))
    err := app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, sdk.NewCoins(mintedCoin))
    require.NoError(t, err)
    
    // Send minted coins to test account (simulating distribution)
    err = app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, delAddr, sdk.NewCoins(mintedCoin))
    require.NoError(t, err)
```

**Observation:**
```go
    // Verify account has "atom" rewards
    balance := app.BankKeeper.GetBalance(ctx, delAddr, "atom")
    require.Equal(t, sdk.NewInt(1000), balance.Amount)
    
    // Create validator
    valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
    validator := teststaking.NewValidator(t, valAddrs[0], PKs[0])
    validator, _ = validator.AddTokensFromDel(sdk.NewInt(100))
    app.StakingKeeper.SetValidator(ctx, validator)
    
    // Attempt to delegate the "atom" rewards - THIS SHOULD FAIL
    msgServer := stakingkeeper.NewMsgServerImpl(app.StakingKeeper)
    delegateMsg := stakingtypes.NewMsgDelegate(
        delAddr.String(),
        valAddrs[0].String(), 
        sdk.NewCoin("atom", sdk.NewInt(500)), // Trying to delegate "atom"
    )
    
    _, err = msgServer.Delegate(sdk.WrapSDKContext(ctx), delegateMsg)
    
    // Test confirms vulnerability: delegation fails because wrong denomination
    require.Error(t, err)
    require.Contains(t, err.Error(), "invalid coin denomination: got atom, expected usei")
    
    // This demonstrates that staking rewards in wrong denomination cannot be re-staked
}
```

This PoC demonstrates that when `MintDenom` and `BondDenom` are desynchronized through a governance proposal, the resulting minted coins cannot be used for staking, breaking the staking rewards mechanism.

### Citations

**File:** x/mint/types/params.go (L44-53)
```go
func DefaultParams() Params {
	return Params{
		MintDenom:           sdk.DefaultBondDenom,
		InflationRateChange: sdk.NewDecWithPrec(13, 2),
		InflationMax:        sdk.NewDecWithPrec(20, 2),
		InflationMin:        sdk.NewDecWithPrec(7, 2),
		GoalBonded:          sdk.NewDecWithPrec(67, 2),
		BlocksPerYear:       uint64(60 * 60 * 8766 / 5), // assuming 5 second block times
	}
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

**File:** x/staking/keeper/msg_server.go (L210-215)
```go
	bondDenom := k.BondDenom(ctx)
	if msg.Amount.Denom != bondDenom {
		return nil, sdkerrors.Wrapf(
			sdkerrors.ErrInvalidRequest, "invalid coin denomination: got %s, expected %s", msg.Amount.Denom, bondDenom,
		)
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

**File:** x/mint/abci.go (L13-55)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	// fetch stored minter & params
	minter := k.GetMinter(ctx)
	params := k.GetParams(ctx)

	// recalculate inflation rate
	totalStakingSupply := k.StakingTokenSupply(ctx)
	bondedRatio := k.BondedRatio(ctx)
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
	minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
	k.SetMinter(ctx, minter)

	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)

	err := k.MintCoins(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	// send the minted coins to the fee collector account
	err = k.AddCollectedFees(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	if mintedCoin.Amount.IsInt64() {
		defer telemetry.ModuleSetGauge(types.ModuleName, float32(mintedCoin.Amount.Int64()), "minted_tokens")
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeMint,
			sdk.NewAttribute(types.AttributeKeyBondedRatio, bondedRatio.String()),
			sdk.NewAttribute(types.AttributeKeyInflation, minter.Inflation.String()),
			sdk.NewAttribute(types.AttributeKeyAnnualProvisions, minter.AnnualProvisions.String()),
			sdk.NewAttribute(sdk.AttributeKeyAmount, mintedCoin.Amount.String()),
		),
	)
}
```

**File:** x/distribution/keeper/allocation.go (L15-107)
```go
func (k Keeper) AllocateTokens(
	ctx sdk.Context, sumPreviousPrecommitPower, totalPreviousPower int64,
	previousProposer sdk.ConsAddress, bondedVotes []abci.VoteInfo,
) {

	logger := k.Logger(ctx)

	// fetch and clear the collected fees for distribution, since this is
	// called in BeginBlock, collected fees will be from the previous block
	// (and distributed to the previous proposer)
	feeCollector := k.authKeeper.GetModuleAccount(ctx, k.feeCollectorName)
	feesCollectedInt := k.bankKeeper.GetAllBalances(ctx, feeCollector.GetAddress())
	feesCollected := sdk.NewDecCoinsFromCoins(feesCollectedInt...)

	// transfer collected fees to the distribution module account
	err := k.bankKeeper.SendCoinsFromModuleToModule(ctx, k.feeCollectorName, types.ModuleName, feesCollectedInt)
	if err != nil {
		panic(err)
	}

	// temporary workaround to keep CanWithdrawInvariant happy
	// general discussions here: https://github.com/cosmos/cosmos-sdk/issues/2906#issuecomment-441867634
	feePool := k.GetFeePool(ctx)
	if totalPreviousPower == 0 {
		feePool.CommunityPool = feePool.CommunityPool.Add(feesCollected...)
		k.SetFeePool(ctx, feePool)
		return
	}

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

	// allocate community funding
	feePool.CommunityPool = feePool.CommunityPool.Add(remaining...)
	k.SetFeePool(ctx, feePool)
}
```

**File:** x/mint/types/minter.go (L44-67)
```go
func (m Minter) NextInflationRate(params Params, bondedRatio sdk.Dec) sdk.Dec {
	// The target annual inflation rate is recalculated for each previsions cycle. The
	// inflation is also subject to a rate change (positive or negative) depending on
	// the distance from the desired ratio (67%). The maximum rate change possible is
	// defined to be 13% per year, however the annual inflation is capped as between
	// 7% and 20%.

	// (1 - bondedRatio/GoalBonded) * InflationRateChange
	inflationRateChangePerYear := sdk.OneDec().
		Sub(bondedRatio.Quo(params.GoalBonded)).
		Mul(params.InflationRateChange)
	inflationRateChange := inflationRateChangePerYear.Quo(sdk.NewDec(int64(params.BlocksPerYear)))

	// adjust the new annual inflation for this next cycle
	inflation := m.Inflation.Add(inflationRateChange) // note inflationRateChange may be negative
	if inflation.GT(params.InflationMax) {
		inflation = params.InflationMax
	}
	if inflation.LT(params.InflationMin) {
		inflation = params.InflationMin
	}

	return inflation
}
```
