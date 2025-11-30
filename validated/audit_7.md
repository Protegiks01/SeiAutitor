# Audit Report

## Title
Network Halt Due to Unchecked Parameter Sum Constraint in Distribution Module Governance Updates

## Summary
The distribution module fails to validate the invariant `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0` during governance parameter updates. This allows individually valid parameter changes to collectively violate the constraint, causing negative `voteMultiplier` calculations in `AllocateTokens` that trigger a panic and halt all network nodes. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:**
- Vulnerable calculation: [2](#0-1) 
- Panic trigger: [3](#0-2) 
- Validation gap: [4](#0-3) 
- Governance handler: [5](#0-4) 

**Intended logic:**
The distribution module should enforce that `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0` to ensure `voteMultiplier` remains non-negative. The `ValidateBasic()` method at [1](#0-0)  explicitly checks this constraint.

**Actual logic:**
Genesis validation correctly applies the constraint via [6](#0-5) . However, governance parameter updates bypass this by calling `Subspace.Update()` [7](#0-6)  which only invokes individual parameter validators that check `0 ≤ value ≤ 1.0` but not the combined sum.

**Exploitation path:**
1. Three separate governance proposals pass over time, each individually valid:
   - `baseProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1.0)
   - `bonusProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1.0)
   - `communityTax = 0.1` (valid: 0 ≤ 0.1 ≤ 1.0)
   - Combined sum: 1.1 > 1.0 (violates invariant)

2. On the next block, BeginBlock calls `AllocateTokens()` [8](#0-7) 

3. With high validator participation (e.g., 100%):
   - `proposerMultiplier = 0.5 + 0.5 × 1.0 = 1.0`
   - `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` (negative)
   - `feeMultiplier` becomes negative DecCoins
   - Validators receive negative reward tokens

4. When `AllocateTokensToValidator` calls `tokens.Sub(commission)` [9](#0-8)  with negative tokens, the `Sub()` operation panics with "negative coin amount", halting all nodes simultaneously.

**Security guarantee broken:**
The system fails to enforce its explicitly documented invariant during governance parameter updates, despite having the validation logic present in `ValidateBasic()`.

## Impact Explanation

The vulnerability causes total network shutdown with the following consequences:

- **Complete consensus halt**: All validator nodes panic simultaneously when processing any block after misconfigured parameters take effect
- **Transaction processing stops**: No new transactions can be confirmed
- **Governance cannot self-repair**: Emergency governance proposals cannot pass because the network is halted
- **Requires coordinated manual intervention**: Validators must coordinate off-chain to manually reset parameters or restart with corrected genesis

The developers explicitly recognized this pattern for ConsensusParams [10](#0-9) , implementing special validation to prevent chain halts from invalid parameters, but did not extend this protection to distribution parameters despite the identical risk.

## Likelihood Explanation

**Who can trigger:** Governance via democratic proposal voting

**Realistic scenario (non-malicious):**
- Multiple proposals to adjust rewards/taxes pass over several months
- Each proposal appears valid individually (0 ≤ value ≤ 1.0)
- No reviewer checks the combined constraint across all parameters
- Network inadvertently halts when sum exceeds 1.0

**Likelihood:** Moderate - Parameter adjustments are routine governance activities. The fact that each individual change appears valid makes this particularly dangerous, as reviewers would need to manually check all three parameters together to catch the violation.

While governance-controlled, this meets the trusted role exception because: (1) it can occur inadvertently without malicious intent, (2) it causes unrecoverable network failure beyond governance's intended authority, and (3) the system has an explicit invariant that should be automatically enforced.

Existing tests confirm the invariant exists [11](#0-10)  and that valid configurations sum to much less than 1.0 [12](#0-11) .

## Recommendation

1. **Immediate Fix**: Add special validation for distribution parameters in the governance proposal validation, similar to the ConsensusParams pattern. When any distribution parameter is updated via governance, retrieve all current distribution parameters, apply the proposed change, and validate the complete `Params` struct using `ValidateBasic()`.

2. **Implementation Pattern**: Extend the existing pattern at [13](#0-12)  to check `if pc.Subspace == "distribution"` and perform combined validation.

3. **Defensive Programming**: Add a safety check in `AllocateTokens` to detect negative `voteMultiplier` and handle gracefully (e.g., clamp to zero with error event) rather than allowing the panic to propagate.

## Proof of Concept

**Test Location:** `x/distribution/keeper/allocation_test.go`

**Setup:**
- Initialize test application with two validators
- Set misconfigured parameters that violate the invariant:
```go
params := disttypes.Params{
    CommunityTax:        sdk.NewDecWithPrec(10, 2),  // 0.1
    BaseProposerReward:  sdk.NewDecWithPrec(50, 2),  // 0.5
    BonusProposerReward: sdk.NewDecWithPrec(50, 2),  // 0.5
    WithdrawAddrEnabled: true,
}
// Sum: 1.1 > 1.0 (violates invariant)
app.DistrKeeper.SetParams(ctx, params)
```
- Fund fee collector module with tokens

**Action:**
- Call `app.DistrKeeper.AllocateTokens(ctx, totalPower, totalPower, proposerAddr, votes)` with 100% validator participation
- This results in `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1`

**Result:**
- Panic with message "negative coin amount" when `AllocateTokensToValidator` attempts `tokens.Sub(commission)` on negative token amounts
- This panic would halt all nodes processing blocks with these parameters in production

## Notes

This vulnerability represents a validation gap where the protection applied to ConsensusParams was not extended to distribution parameters despite the same risk. The system has an explicit invariant documented in code and tests, but the governance update path bypasses this validation. Recovery requires coordinated off-chain intervention by validators, making this a significant availability issue that qualifies for the Medium severity classification under "Network not being able to confirm new transactions (total network shutdown)".

### Citations

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

**File:** x/distribution/types/genesis.go (L45-49)
```go
func ValidateGenesis(gs *GenesisState) error {
	if err := gs.Params.ValidateBasic(); err != nil {
		return err
	}
	return gs.FeePool.ValidateGenesis()
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

**File:** x/distribution/types/params_test.go (L30-30)
```go
		{"total sum greater than 1", fields{toDec("0.2"), toDec("0.5"), toDec("0.4"), false}, true},
```

**File:** x/distribution/keeper/allocation_test.go (L54-59)
```go
	testDistrParms := disttypes.Params{
		CommunityTax:        sdk.NewDecWithPrec(2, 2), // 2%
		BaseProposerReward:  sdk.NewDecWithPrec(1, 2), // 1%
		BonusProposerReward: sdk.NewDecWithPrec(4, 2), // 4%
		WithdrawAddrEnabled: true,
	}
```
