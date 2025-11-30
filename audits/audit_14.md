# Audit Report

## Title
Network Halt Due to Negative Vote Multiplier from Unbounded Parameter Sum in Fee Allocation

## Summary
The distribution module allows governance to set parameters where `baseProposerReward + bonusProposerReward + communityTax` exceeds 1.0 through individual parameter updates. This causes `voteMultiplier` to become negative in `AllocateTokens`, triggering a panic that halts the entire network during block processing.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended logic:**
Distribution parameters must satisfy the invariant `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0` to ensure `voteMultiplier` remains non-negative. This invariant is explicitly validated in ValidateBasic(): [3](#0-2) 

**Actual logic:**
When parameters are updated through governance proposals, the system only validates individual parameters (checking each is between 0 and 1.0) via individual validator functions: [4](#0-3) 

The governance handler calls Subspace.Update() which only invokes individual validators: [5](#0-4) [6](#0-5) 

ValidateBasic() that checks the combined sum constraint is only called during genesis validation: [7](#0-6) 

**Exploitation path:**
1. Three governance proposals pass independently (each appears valid with 0 ≤ value ≤ 1.0): baseProposerReward=0.5, bonusProposerReward=0.5, communityTax=0.1 (sum=1.1)
2. During BeginBlock, AllocateTokens is called: [8](#0-7) 
3. With high validator participation, proposerMultiplier approaches 1.0, making voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1 (negative)
4. Negative DecCoins flow to AllocateTokensToValidator, where tokens.Sub(commission) triggers panic: [9](#0-8) 

**Security guarantee broken:**
The system fails to enforce its explicitly documented invariant that distribution parameters must sum to ≤ 1.0 during governance parameter updates.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes panic simultaneously when processing blocks after misconfigured parameters take effect
- **Cannot process transactions**: Network consensus completely halts
- **Unrecoverable without hard fork**: Emergency governance cannot fix parameters because the network is halted
- **Requires coordinated manual intervention**: Validators must coordinate off-chain to reset parameters and restart

**Developer precedent:**
The developers explicitly recognized and fixed this exact pattern for ConsensusParams, acknowledging that parameter validation gaps "will cause a chain halt": [10](#0-9) 

This confirms the severity of such validation gaps. Distribution parameters have the same risk but lack the same protection.

## Likelihood Explanation

**Who Can Trigger:** Governance (requires proposals to pass democratic voting)

**Realistic Scenario (Non-Malicious):**
- Month 1: Proposal to increase proposer rewards (baseProposerReward = 0.5)
- Month 2: Proposal to add voting bonuses (bonusProposerReward = 0.5)
- Month 3: Proposal to fund community pool (communityTax = 0.1)
- Each proposal reviewed individually, all appear valid (0 ≤ value ≤ 1.0)
- No reviewer checks combined constraint across all parameters
- Network halts inadvertently

**Likelihood:** Moderate - Parameter adjustments are routine governance activities. Multiple parameters adjusted independently over time could inadvertently violate the combined constraint. The fact that each individual change appears valid makes this particularly dangerous.

While this requires governance action, it meets the "trusted role exception" because: (1) it can happen inadvertently without malicious intent, (2) it causes unrecoverable network failure beyond governance's intended authority, and (3) the system should enforce its own documented invariants.

## Recommendation

1. **Immediate Fix**: Add special validation for distribution parameters in the governance proposal validation (similar to ConsensusParams). When any distribution parameter is proposed for update, retrieve all current distribution parameters, apply the change, and validate the complete Params struct using ValidateBasic().

2. **Alternative Approach**: Modify the individual validator functions to query current values of other distribution parameters and validate that the combined sum will not exceed 1.0 after the update.

3. **Defensive Programming**: Add a safety check in AllocateTokens to detect negative voteMultiplier and handle gracefully (clamp to zero, emit error event) rather than allowing the panic to propagate.

4. **Follow Existing Pattern**: Apply the same validation pattern used for ConsensusParams to distribution parameters in ValidateChanges().

## Proof of Concept

**Test Structure** (following existing pattern at): [11](#0-10) 

**Setup:**
- Initialize test application using `simapp.Setup(false)`
- Create two validators with equal voting power
- Set misconfigured parameters via `app.DistrKeeper.SetParams()` bypassing validation:
  - CommunityTax: 0.1 (10%)
  - BaseProposerReward: 0.5 (50%)
  - BonusProposerReward: 0.5 (50%)
  - Combined sum: 1.1 > 1.0
- Fund fee collector module with tokens

**Action:**
- Call `app.DistrKeeper.AllocateTokens(ctx, 200, 200, proposerConsAddr, votes)` with 100% validator participation
- This results in voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1

**Result:**
- Panic with message "negative coin amount" when AllocateTokensToValidator attempts tokens.Sub(commission) operation on negative token amounts
- This panic would halt all nodes processing blocks with these parameters in production
- BeginBlock has no panic recovery mechanism: [12](#0-11) 

## Notes

This vulnerability matches the impact category "Network not being able to confirm new transactions (total network shutdown)" classified as Medium severity. The system has an explicit invariant that can be bypassed during governance updates, leading to total network halt. Developer precedent with ConsensusParams confirms this pattern requires explicit protection.

### Citations

**File:** x/distribution/keeper/allocation.go (L82-84)
```go
	communityTax := k.GetCommunityTax(ctx)
	voteMultiplier := sdk.OneDec().Sub(proposerMultiplier).Sub(communityTax)
	feeMultiplier := feesCollected.MulDecTruncate(voteMultiplier)
```

**File:** x/distribution/keeper/allocation.go (L111-114)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** x/distribution/types/params.go (L67-71)
```go
	if v := p.BaseProposerReward.Add(p.BonusProposerReward).Add(p.CommunityTax); v.GT(sdk.OneDec()) {
		return fmt.Errorf(
			"sum of base, bonus proposer rewards, and community tax cannot be greater than one: %s", v,
		)
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

**File:** x/distribution/types/genesis.go (L44-50)
```go
// ValidateGenesis validates the genesis state of distribution genesis input
func ValidateGenesis(gs *GenesisState) error {
	if err := gs.Params.ValidateBasic(); err != nil {
		return err
	}
	return gs.FeePool.ValidateGenesis()
}
```

**File:** x/distribution/abci.go (L29-31)
```go
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```

**File:** types/dec_coin.go (L303-309)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
```

**File:** x/params/types/proposal/proposal.go (L101-109)
```go
		// We need to verify ConsensusParams since they are only validated once the proposal passes.
		// If any of them are invalid at time of passing, this will cause a chain halt since validation is done during
		// ApplyBlock: https://github.com/sei-protocol/sei-tendermint/blob/d426f1fe475eb0c406296770ff5e9f8869b3887e/internal/state/execution.go#L320
		// Therefore, we validate when we get a param-change msg for ConsensusParams
		if pc.Subspace == "baseapp" {
			if err := verifyConsensusParamsUsingDefault(changes); err != nil {
				return err
			}
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

**File:** baseapp/abci.go (L133-157)
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
}
```
