# Audit Report

## Title
Network Halt Due to Negative Vote Multiplier from Unbounded Distribution Parameter Sum

## Summary
A validation gap in the distribution module allows governance to set distribution parameters (`baseProposerReward`, `bonusProposerReward`, and `communityTax`) that individually pass validation but collectively violate the invariant that their sum must not exceed 1.0. This causes `voteMultiplier` to become negative during fee allocation, triggering a panic that halts the entire network during `BeginBlock`.

## Impact
Medium

## Finding Description

**Location:** 
- `x/distribution/types/params.go` (individual validator functions)
- `x/params/types/subspace.go` (Update function)
- `x/distribution/keeper/allocation.go` (AllocateTokens and AllocateTokensToValidator)

**Intended Logic:**
Distribution parameters must satisfy the invariant: `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0`. This invariant is enforced by `ValidateBasic()`: [1](#0-0) 

**Actual Logic:**
When parameters are updated through governance proposals, the system calls `handleParameterChangeProposal()`: [2](#0-1) 

This triggers `Subspace.Update()` which validates using individual validator functions: [3](#0-2) 

These individual validators (e.g., `validateCommunityTax`) only check if each parameter is between 0 and 1.0, NOT the combined sum constraint: [4](#0-3) 

`ValidateBasic()` is only called during genesis validation and never during governance parameter updates: [5](#0-4) 

**Exploitation Path:**
1. Three governance proposals pass independently over time:
   - Set `baseProposerReward = 0.5` (passes: 0 ≤ 0.5 ≤ 1.0)
   - Set `bonusProposerReward = 0.5` (passes: 0 ≤ 0.5 ≤ 1.0)
   - Set `communityTax = 0.1` (passes: 0 ≤ 0.1 ≤ 1.0)
   - Combined sum: 1.1 > 1.0 (violates invariant but never checked)

2. During the next block's `BeginBlock`, `AllocateTokens` is automatically called: [6](#0-5) 

3. With high validator participation (e.g., 100%), `proposerMultiplier = 0.5 + (0.5 × 1.0) = 1.0`, resulting in `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` (negative): [7](#0-6) 

4. This produces negative `DecCoins` which are passed to `AllocateTokensToValidator`: [8](#0-7) 

5. The `tokens.Sub(commission)` operation detects negative amounts and panics: [9](#0-8) 

**Security Guarantee Broken:**
The critical invariant that distribution parameters must sum to ≤ 1.0 is not enforced during governance parameter updates, allowing configurations that cause catastrophic network failure.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes panic simultaneously during `BeginBlock` processing
- **Transaction processing halts**: Network consensus completely fails; no new blocks can be produced  
- **Unrecoverable through governance**: Emergency governance proposals cannot execute because the network is halted
- **Requires coordinated manual intervention**: Validators must coordinate off-chain to manually reset parameters and restart nodes

**Precedent:**
The developers explicitly recognized this pattern for ConsensusParams and implemented special validation to prevent chain halts: [10](#0-9) 

The comment acknowledges that parameter validation gaps "will cause a chain halt." However, distribution parameters lack the same protection.

## Likelihood Explanation

**Who Can Trigger:**
Any token holder can submit governance proposals. This requires three separate proposals to pass through normal democratic voting processes.

**Realistic Non-Malicious Scenario:**
- Month 1: Community votes to increase proposer incentives (`baseProposerReward = 0.5`)
- Month 2: Community votes to add bonus rewards (`bonusProposerReward = 0.5`)
- Month 3: Community votes to fund development pool (`communityTax = 0.1`)
- Each proposal is reviewed individually and appears valid (0 ≤ value ≤ 1.0)
- No reviewer checks the combined constraint across all parameters
- Network halts inadvertently

**Likelihood:** Moderate - Parameter adjustments are routine governance activities. Multiple parameters adjusted independently over time through legitimate governance could inadvertently violate the combined constraint without any malicious intent.

**Platform Rule Exception:**
While this requires governance approval (privileged role), the exception applies: "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority." Governance's intended authority is to adjust economic parameters, NOT to halt the network. This is a validation bug that allows governance to accidentally exceed its intended authority.

## Recommendation

1. **Immediate Fix**: Add a validation hook in `handleParameterChangeProposal()` specifically for distribution parameters (checking `if pc.Subspace == "distribution"`) that reconstructs the complete parameter set after applying changes and calls `Params.ValidateBasic()`.

2. **Alternative Approach**: Modify individual validator functions to query current values of other distribution parameters and verify the combined sum will not exceed 1.0 after the update.

3. **Defensive Programming**: Add a safety check in `AllocateTokens` to detect negative `voteMultiplier` and handle gracefully (e.g., clamp to zero with error event) rather than allowing panic.

4. **Follow ConsensusParams Pattern**: Apply the same validation pattern used for ConsensusParams to distribution parameters.

## Proof of Concept

**Test File:** `x/distribution/keeper/allocation_test.go`

**Setup:**
- Initialize test application: `app := simapp.Setup(false)`
- Create two validators with equal voting power using `teststaking.NewHelper`
- Set misconfigured parameters via `app.DistrKeeper.SetParams()` simulating post-governance state:
  - `CommunityTax: sdk.NewDecWithPrec(1, 1)` (0.1)
  - `BaseProposerReward: sdk.NewDecWithPrec(5, 1)` (0.5)
  - `BonusProposerReward: sdk.NewDecWithPrec(5, 1)` (0.5)
  - Combined sum: 1.1 > 1.0
- Fund fee collector module with tokens using `simapp.FundModuleAccount`

**Action:**
- Create `VoteInfo` array with both validators having `SignedLastBlock: true` (100% participation)
- Call `app.DistrKeeper.AllocateTokens(ctx, totalPower, totalPower, proposerConsAddr, votes)`
- With 100% participation, this maximizes `proposerMultiplier = 1.0`, resulting in `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1`

**Result:**
- Panic occurs with message "negative coin amount"
- The panic happens when `AllocateTokensToValidator` attempts `shared := tokens.Sub(commission)` with negative token amounts
- This demonstrates that misconfigured parameters cause network-halting panics during normal block processing

## Notes

This vulnerability represents a validation gap in the code's parameter update mechanism. The ConsensusParams precedent confirms this is a recognized vulnerability pattern that developers have addressed elsewhere but not for distribution parameters. The privileged misconfiguration exception applies because governance can inadvertently trigger an unrecoverable network halt beyond its intended authority through seemingly valid individual parameter changes that appear correct when evaluated in isolation.

### Citations

**File:** x/distribution/types/params.go (L67-71)
```go
	if v := p.BaseProposerReward.Add(p.BonusProposerReward).Add(p.CommunityTax); v.GT(sdk.OneDec()) {
		return fmt.Errorf(
			"sum of base, bonus proposer rewards, and community tax cannot be greater than one: %s", v,
		)
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

**File:** types/dec_coin.go (L302-310)
```go
// Sub subtracts a set of DecCoins from another (adds the inverse).
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}
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
