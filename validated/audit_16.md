# Audit Report

## Title
Network Halt Due to Negative Vote Multiplier from Unbounded Parameter Sum in Fee Allocation

## Summary
The distribution module's governance parameter update mechanism fails to validate that `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0`, allowing individual parameter changes to collectively violate this invariant. When the sum exceeds 1.0, the `AllocateTokens` function in BeginBlock calculates a negative `voteMultiplier`, resulting in negative token amounts that trigger a panic, halting the entire network. [1](#0-0) [2](#0-1) 

## Impact
Medium

## Finding Description

**Location:**
- Vulnerable calculation: `x/distribution/keeper/allocation.go` lines 82-84
- Panic trigger: `types/dec_coin.go` lines 303-309  
- Validation gap: `x/distribution/types/params.go` lines 76-131
- Governance handler: `x/params/proposal_handler.go` lines 26-43

**Intended logic:**
The distribution module should enforce the invariant that `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0` to ensure `voteMultiplier` remains non-negative. The `ValidateBasic()` method explicitly checks this constraint. [3](#0-2) 

**Actual logic:**
When parameters are updated through governance proposals, the system validates each parameter individually (checking 0 ≤ value ≤ 1.0) but does not verify the combined sum constraint. The `ValidateBasic()` method that checks the sum is only called during genesis initialization, not during governance parameter updates. [4](#0-3) [5](#0-4) [6](#0-5) 

Genesis validation correctly applies the constraint: [7](#0-6) 

However, governance updates bypass this validation by calling `Subspace.Update()` which only invokes individual parameter validators.

**Exploitation path:**
1. Governance passes three separate proposals that individually appear valid:
   - `baseProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1.0)
   - `bonusProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1.0)  
   - `communityTax = 0.1` (valid: 0 ≤ 0.1 ≤ 1.0)
   - Combined sum: 1.1 > 1.0 (violates invariant)

2. On the next block, BeginBlock calls `AllocateTokens()`: [8](#0-7) 

3. With high validator participation (e.g., 100%):
   - `proposerMultiplier = 0.5 + 0.5 × 1.0 = 1.0`
   - `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` (negative)
   - `feeMultiplier` becomes negative DecCoins
   - Validators receive negative reward tokens

4. When `AllocateTokensToValidator` calls `tokens.Sub(commission)` with negative tokens: [9](#0-8) 

The `Sub()` operation panics with "negative coin amount", halting all nodes simultaneously.

**Security guarantee broken:**
The system fails to enforce its explicitly documented invariant that distribution parameters must sum to ≤ 1.0 during governance parameter updates.

## Impact Explanation

The vulnerability causes total network shutdown with the following consequences:

- **Complete consensus halt**: All validator nodes panic simultaneously when processing any block after the misconfigured parameters take effect
- **Transaction processing stops**: No new transactions can be confirmed
- **Governance cannot self-repair**: Emergency governance proposals cannot pass because the network is halted
- **Requires coordinated manual intervention**: Validators must coordinate off-chain to manually reset parameters in state or restart with corrected genesis, similar to a hard fork recovery process

The developers explicitly recognized this pattern for ConsensusParams and implemented special validation, confirming the severity: [10](#0-9) 

## Likelihood Explanation

**Who can trigger:** Governance (requires democratic proposal voting to pass)

**Realistic scenario (non-malicious):**
- Month 1: Proposal to increase proposer rewards passes (`baseProposerReward = 0.5`)
- Month 2: Proposal to add voting bonuses passes (`bonusProposerReward = 0.5`)  
- Month 3: Proposal to fund community pool passes (`communityTax = 0.1`)
- Each proposal appears valid when reviewed individually (0 ≤ value ≤ 1.0)
- No reviewer checks the combined constraint across all three parameters
- Network inadvertently halts

**Likelihood:** Moderate - Parameter adjustments are routine governance activities. Multiple parameters adjusted independently over time could inadvertently violate the combined constraint without malicious intent. The fact that each individual change appears valid makes this particularly dangerous.

While governance-controlled, this meets the trusted role exception because: (1) it can occur inadvertently without malicious intent, (2) it causes unrecoverable network failure beyond governance's intended authority, and (3) the system has an explicit invariant that should be automatically enforced.

## Recommendation

1. **Immediate Fix**: Add special validation for distribution parameters in the governance proposal handler, similar to the ConsensusParams pattern. When any distribution parameter is updated via governance, retrieve all current distribution parameters, apply the proposed change, and validate the complete `Params` struct using `ValidateBasic()`.

2. **Alternative Approach**: Modify individual validator functions to query current values of other distribution parameters and validate that the combined sum will not exceed 1.0 after the update is applied.

3. **Defensive Programming**: Add a safety check in `AllocateTokens` to detect negative `voteMultiplier` and handle gracefully (e.g., clamp to zero with error event) rather than allowing the panic to propagate and halt the network.

4. **Apply Existing Pattern**: Extend the ConsensusParams validation pattern to distribution parameters, as both can cause chain halts if misconfigured.

## Proof of Concept

**Test File:** `x/distribution/keeper/allocation_test.go`

**Setup:**
- Initialize test application: `app := simapp.Setup(false)`
- Create two validators with equal voting power
- Set misconfigured parameters directly (to simulate post-governance state):
  ```go
  params := disttypes.Params{
      CommunityTax:        sdk.NewDecWithPrec(10, 2),  // 0.1 (10%)
      BaseProposerReward:  sdk.NewDecWithPrec(50, 2),  // 0.5 (50%)
      BonusProposerReward: sdk.NewDecWithPrec(50, 2),  // 0.5 (50%)
      WithdrawAddrEnabled: true,
  }
  // Sum: 1.1 > 1.0 (violates invariant)
  app.DistrKeeper.SetParams(ctx, params)
  ```
- Fund fee collector module with tokens

**Action:**
- Call `app.DistrKeeper.AllocateTokens(ctx, 200, 200, proposerConsAddr, votes)` with 100% validator participation
- This results in `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1`

**Result:**
- Panic with message "negative coin amount" when `AllocateTokensToValidator` attempts `tokens.Sub(commission)` on negative token amounts
- This panic would halt all nodes processing blocks with these parameters in production

**Note:**
Existing allocation tests use valid parameters with sum = 0.07: [11](#0-10) 

Test validation confirms the invariant exists: [12](#0-11) 

## Notes

This vulnerability represents a gap in the parameter validation system where the protection applied to ConsensusParams (to prevent chain halts) was not extended to distribution parameters despite the same risk. The system has an explicit invariant documented in code and tests, but the governance update path bypasses this validation, allowing incremental changes to collectively violate the constraint. Recovery requires coordinated off-chain intervention by validators, making this a significant availability issue despite being governance-controlled.

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

**File:** x/distribution/types/params_test.go (L12-45)
```go
func TestParams_ValidateBasic(t *testing.T) {
	toDec := sdk.MustNewDecFromStr

	type fields struct {
		CommunityTax        sdk.Dec
		BaseProposerReward  sdk.Dec
		BonusProposerReward sdk.Dec
		WithdrawAddrEnabled bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"success", fields{toDec("0.1"), toDec("0.5"), toDec("0.4"), false}, false},
		{"negative community tax", fields{toDec("-0.1"), toDec("0.5"), toDec("0.4"), false}, true},
		{"negative base proposer reward", fields{toDec("0.1"), toDec("-0.5"), toDec("0.4"), false}, true},
		{"negative bonus proposer reward", fields{toDec("0.1"), toDec("0.5"), toDec("-0.4"), false}, true},
		{"total sum greater than 1", fields{toDec("0.2"), toDec("0.5"), toDec("0.4"), false}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := types.Params{
				CommunityTax:        tt.fields.CommunityTax,
				BaseProposerReward:  tt.fields.BaseProposerReward,
				BonusProposerReward: tt.fields.BonusProposerReward,
				WithdrawAddrEnabled: tt.fields.WithdrawAddrEnabled,
			}
			if err := p.ValidateBasic(); (err != nil) != tt.wantErr {
				t.Errorf("ValidateBasic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
```
