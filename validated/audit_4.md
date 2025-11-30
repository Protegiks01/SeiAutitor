# Audit Report

## Title
Network Halt Due to Negative Vote Multiplier from Unbounded Parameter Sum in Fee Allocation

## Summary
A critical validation gap in the distribution module allows governance to set parameters where `baseProposerReward + bonusProposerReward + communityTax > 1.0` through individual parameter updates, causing `voteMultiplier` to become negative and triggering a network-halting panic during block processing.

## Impact
High

## Finding Description

**Location:** 
- x/distribution/keeper/allocation.go (lines 82-84, 111-114)
- x/params/proposal_handler.go (lines 26-43)
- x/params/types/subspace.go (lines 196-219)
- x/distribution/types/params.go (lines 41-47, 67-71, 76-131) [1](#0-0) [2](#0-1) 

**Intended Logic:**
Distribution parameters must satisfy the invariant `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0` to ensure `voteMultiplier` remains non-negative. This invariant is explicitly enforced in `ValidateBasic()`: [3](#0-2) 

**Actual Logic:**
When parameters are updated through governance proposals, the system calls `handleParameterChangeProposal()` which iterates through changes and calls `Subspace.Update()`: [4](#0-3) 

The `Update()` method only validates individual parameters using their registered validator functions: [5](#0-4) 

These individual validator functions only check that each parameter is between 0 and 1.0: [6](#0-5) 

The `ValidateBasic()` function that checks the combined constraint is only called during genesis validation: [7](#0-6) 

**Exploitation Path:**
1. Three governance proposals pass independently (each appears valid: 0 ≤ value ≤ 1.0):
   - `baseProposerReward = 0.5`
   - `bonusProposerReward = 0.5`
   - `communityTax = 0.1`
   - Combined sum: 1.1 > 1.0 (violates invariant)

2. During BeginBlock, `AllocateTokens` is called automatically: [8](#0-7) 

3. With 100% validator participation, `proposerMultiplier = 0.5 + (0.5 × 1.0) = 1.0`, resulting in `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` (negative)

4. This produces negative `DecCoins` via `MulDecTruncate(-0.1)`

5. `AllocateTokensToValidator` is called with negative tokens

6. When computing `shared = tokens.Sub(commission)`, the `Sub` method panics: [9](#0-8) 

**Security Guarantee Broken:**
The system fails to enforce the critical invariant that distribution parameters must sum to ≤ 1.0 during governance parameter updates, allowing inadvertent configuration that causes catastrophic network failure.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes panic simultaneously when processing BeginBlock after the misconfigured parameters take effect
- **Cannot process transactions**: Network consensus completely breaks down as all nodes crash in BeginBlock
- **Unrecoverable without hard fork**: Emergency governance cannot fix parameters because the network is halted and no blocks can be processed
- **Requires coordinated manual intervention**: Validators must coordinate off-chain to reset parameters and restart the network with corrected state

**Precedent in Codebase:**
The developers explicitly recognized and fixed a similar issue for ConsensusParams: [10](#0-9) 

The comment acknowledges that parameter validation gaps "will cause a chain halt since validation is done during ApplyBlock". This confirms the severity of such validation gaps and demonstrates that distribution parameters lack the same protection.

## Likelihood Explanation

**Who Can Trigger:**
Any token holder can submit governance proposals. This requires three separate proposals to pass through normal democratic voting.

**Realistic Scenario (Non-Malicious):**
- Month 1: Proposal to increase proposer rewards (`baseProposerReward = 0.5`)
- Month 2: Proposal to add voting bonuses (`bonusProposerReward = 0.5`)
- Month 3: Proposal to fund community pool (`communityTax = 0.1`)
- Each proposal reviewed individually, all appear valid (0 ≤ value ≤ 1.0)
- No reviewer checks combined constraint across all parameters
- Network halts inadvertently on next block

**Likelihood:** Moderate - Parameter adjustments are routine governance activities. Multiple parameters adjusted independently over time could inadvertently violate the combined constraint without malicious intent.

**Platform Rule Exception:**
While this requires governance approval (privileged role), the platform acceptance rule explicitly allows this because "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority." This is a validation bug in the code that allows governance to accidentally exceed its intended authority through seemingly valid individual parameter changes.

## Recommendation

1. **Immediate Fix**: Add cross-parameter validation to governance parameter updates. Modify `handleParameterChangeProposal()` to call `Params.ValidateBasic()` on the complete parameter set after applying changes to distribution parameters, similar to the ConsensusParams validation pattern: [11](#0-10) 

2. **Alternative Approach**: Enhance individual validator functions to query current values of other parameters and validate the combined sum will not exceed 1.0 after the update.

3. **Defensive Programming**: Add a safety check in `AllocateTokens` to detect negative `voteMultiplier` and handle gracefully (log error, clamp to zero) rather than allowing panic to propagate.

4. **Follow Existing Pattern**: Apply the same validation pattern used for ConsensusParams to distribution parameters to prevent inadvertent chain halts from parameter misconfiguration.

## Proof of Concept

**Test File:** `x/distribution/keeper/allocation_test.go`

**Setup:**
- Initialize test application using `simapp.Setup(false)` following existing test pattern: [12](#0-11) 

- Create two validators with equal voting power
- Set misconfigured parameters simulating post-governance state:
  - `CommunityTax: sdk.NewDecWithPrec(1, 1)` (0.1)
  - `BaseProposerReward: sdk.NewDecWithPrec(5, 1)` (0.5)
  - `BonusProposerReward: sdk.NewDecWithPrec(5, 1)` (0.5)
  - Combined sum: 1.1 > 1.0

- Fund fee collector with tokens: [13](#0-12) 

**Action:**
- Create vote info with both validators at 100% participation (`SignedLastBlock: true`): [14](#0-13) 

- Call `app.DistrKeeper.AllocateTokens(ctx, totalPower, totalPower, proposerConsAddr, votes)`
- This maximizes `proposerMultiplier = 1.0`, resulting in `voteMultiplier = -0.1`

**Result:**
- Panic with message "negative coin amount" when `AllocateTokensToValidator` attempts `tokens.Sub(commission)` on negative amounts
- This panic would halt all nodes processing blocks with these parameters, requiring coordinated off-chain intervention to recover

## Notes

This vulnerability represents a validation gap in the code rather than a governance system issue. The codebase precedent of fixing similar issues for ConsensusParams confirms this is a recognized vulnerability pattern. The privilege exception applies because governance can inadvertently trigger an unrecoverable network halt beyond its intended authority through seemingly valid individual parameter changes that each pass validation independently but collectively violate critical system invariants.

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

**File:** x/distribution/types/genesis.go (L45-46)
```go
func ValidateGenesis(gs *GenesisState) error {
	if err := gs.Params.ValidateBasic(); err != nil {
```

**File:** x/distribution/abci.go (L29-31)
```go
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```

**File:** types/dec_coin.go (L302-309)
```go
// Sub subtracts a set of DecCoins from another (adds the inverse).
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

**File:** x/params/types/proposal/proposal.go (L115-134)
```go
func verifyConsensusParamsUsingDefault(changes []ParamChange) error {
	// Start with a default (valid) set of parameters, and update based on proposal then check
	defaultCP := types.DefaultConsensusParams()
	for _, change := range changes {
		// Note: BlockParams seems to be the only support ConsensusParams available for modifying with proposal
		switch change.Key {
		case "BlockParams":
			blockParams := types.DefaultBlockParams()
			err := json.Unmarshal([]byte(change.Value), &blockParams)
			if err != nil {
				return err
			}
			defaultCP.Block = blockParams
		}
	}
	if err := defaultCP.ValidateConsensusParams(); err != nil {
		return err
	}
	return nil
}
```

**File:** x/distribution/keeper/allocation_test.go (L47-63)
```go
func TestAllocateTokensToManyValidators(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})
	params := app.StakingKeeper.GetParams(ctx)
	params.MinCommissionRate = sdk.NewDec(0)
	app.StakingKeeper.SetParams(ctx, params)

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

**File:** x/distribution/keeper/allocation_test.go (L96-101)
```go
	fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100)))
	feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
	require.NotNil(t, feeCollector)

	// fund fee collector
	require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
```

**File:** x/distribution/keeper/allocation_test.go (L105-114)
```go
	votes := []abci.VoteInfo{
		{
			Validator:       abciValA,
			SignedLastBlock: true,
		},
		{
			Validator:       abciValB,
			SignedLastBlock: true,
		},
	}
```
