# Audit Report

## Title
Network Halt Due to Unbounded Distribution Parameter Sum Bypassing Validation in Governance Updates

## Summary
The distribution module contains a critical validation gap where governance parameter updates bypass the `ValidateBasic()` check that enforces the invariant `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0`. When this sum exceeds 1.0 through independent parameter updates, the `voteMultiplier` in `AllocateTokens()` becomes negative, causing a panic in `DecCoins.Sub()` that halts the entire network during block processing.

## Impact
Medium

## Finding Description

**Location:** 
- Vulnerability trigger: [1](#0-0) 
- Panic location: [2](#0-1) 
- Panic implementation: [3](#0-2) 

**Intended logic:**
Distribution parameters must satisfy the invariant documented in `ValidateBasic()` that the sum of all three distribution parameters cannot exceed 1.0: [4](#0-3) 

This invariant is critical because the `voteMultiplier` calculation `1.0 - proposerMultiplier - communityTax` must remain non-negative to prevent negative token amounts.

**Actual logic:**
When parameters are updated through governance proposals, only individual parameter validators are invoked: [5](#0-4) 

These individual validators only check that each parameter is between 0 and 1.0, but do not validate the combined sum constraint.

The governance parameter change handler calls `Subspace.Update()`: [6](#0-5) 

Which only invokes the individual validation function registered for that specific parameter: [7](#0-6) 

The `ValidateBasic()` method that checks the combined sum is only called during genesis validation: [8](#0-7) 

**Exploitation path:**
1. Three independent governance proposals pass over time, each appearing valid individually:
   - Set `baseProposerReward = 0.5` (passes: 0.5 ≤ 1.0)
   - Set `bonusProposerReward = 0.5` (passes: 0.5 ≤ 1.0)
   - Set `communityTax = 0.1` (passes: 0.1 ≤ 1.0)
   - Combined sum: 1.1 > 1.0 (violates invariant, but not checked)

2. During the next block processing, `AllocateTokens` is called in BeginBlock: [9](#0-8) 

3. With high validator participation (normal operation), `proposerMultiplier` approaches `baseProposerReward + bonusProposerReward = 1.0`

4. The calculation `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` yields a negative value

5. This produces negative `DecCoins` that flow to `AllocateTokensToValidator()`

6. When `tokens.Sub(commission)` is called on negative tokens, `DecCoins.Sub()` detects the negative result and panics with "negative coin amount"

7. This panic occurs in BeginBlock which has no recovery mechanism, causing all nodes to crash simultaneously and halting the network

**Security guarantee broken:**
The system fails to enforce its explicitly documented invariant that distribution parameters must sum to ≤ 1.0 during governance parameter updates, despite having `ValidateBasic()` that defines this invariant.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes panic simultaneously when processing blocks after misconfigured parameters take effect
- **Cannot process new transactions**: Network consensus completely halts
- **Unrecoverable through governance**: Emergency parameter fixes cannot be applied because the network is down
- **Requires manual intervention**: Validators must coordinate off-chain to manually reset parameters and restart their nodes

This matches the impact category "Network not being able to confirm new transactions (total network shutdown)" classified as Medium severity in the provided impact list.

**Developer precedent confirms severity:**
The developers explicitly recognized and protected against this exact pattern for ConsensusParams: [10](#0-9) 

The comment states: "We need to verify ConsensusParams since they are only validated once the proposal passes. If any of them are invalid at time of passing, this will cause a chain halt..."

This confirms that parameter validation gaps causing chain halts are recognized as serious issues requiring explicit protection. Distribution parameters have the same risk but lack the same protection.

## Likelihood Explanation

**Who can trigger:** Governance (requires proposals to pass democratic voting)

**Realistic scenario (non-malicious):**
Multiple governance proposals pass independently over time:
- Month 1: Increase proposer base rewards to incentivize block production
- Month 2: Add bonus rewards for high participation  
- Month 3: Increase community tax to fund development
- Each proposal appears valid individually (0 ≤ value ≤ 1.0)
- No reviewer checks the combined constraint across all parameters
- Network halts inadvertently on the next block with transaction fees

**Likelihood:** Moderate

While this requires governance action, it meets the "trusted role exception" criteria because:
1. It can happen inadvertently without malicious intent through routine parameter adjustments
2. It causes unrecoverable network failure (total halt) beyond governance's intended authority
3. The system has an explicit invariant in `ValidateBasic()` that should be enforced automatically
4. Developer precedent with ConsensusParams shows this pattern requires protection

Parameter adjustments are routine governance activities, and the fact that each individual change appears valid makes this particularly dangerous.

## Recommendation

**Immediate fix:** Add special validation for distribution parameters in `ValidateChanges()` similar to ConsensusParams. When any distribution parameter is proposed for update:
1. Retrieve all current distribution parameter values
2. Apply the proposed change
3. Create a complete `Params` struct with all values
4. Call `ValidateBasic()` on the complete struct to validate the combined sum

This follows the exact pattern already implemented for ConsensusParams protection.

**Implementation pattern:**
```go
// In ValidateChanges() function
if pc.Subspace == "distribution" {
    if err := verifyDistributionParamsUsingCurrent(changes, keeper); err != nil {
        return err
    }
}
```

**Alternative defensive measure:** Add a safety check in `AllocateTokens()` to detect negative `voteMultiplier` and handle gracefully (clamp to zero, log error event) rather than allowing the panic to propagate.

## Proof of Concept

**Test structure** (following existing test pattern): [11](#0-10) 

**Setup:**
- Initialize test application using `simapp.Setup(false)`
- Create two validators with equal voting power (100 each)
- Set misconfigured parameters via `app.DistrKeeper.SetParams()` bypassing validation:
  - `CommunityTax: 0.1` (10%)
  - `BaseProposerReward: 0.5` (50%)
  - `BonusProposerReward: 0.5` (50%)
  - Combined sum: 1.1 > 1.0
- Fund fee collector module with 100 tokens

**Action:**
- Call `app.DistrKeeper.AllocateTokens(ctx, 200, 200, proposerConsAddr, votes)` with 100% validator participation
- This results in: `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1`

**Expected result:**
- Panic with message "negative coin amount" when `AllocateTokensToValidator()` attempts `tokens.Sub(commission)` with negative tokens
- In production, this panic would occur during BeginBlock processing, halting all nodes simultaneously with no recovery mechanism

## Notes

This vulnerability represents a validation gap where governance parameter updates bypass a critical system invariant check that exists in `ValidateBasic()`. The developers' explicit protection of ConsensusParams from this exact pattern confirms that parameter validation gaps causing chain halts are serious issues requiring explicit safeguards. The distribution module lacks this protection, creating an unrecoverable network halt scenario that can occur inadvertently through routine governance activities.

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

**File:** types/dec_coin.go (L303-309)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
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
