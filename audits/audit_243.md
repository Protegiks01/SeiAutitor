# Audit Report

## Title
Network Halt Due to Negative Vote Multiplier from Unbounded Parameter Sum in Fee Allocation

## Summary
A critical validation gap in the distribution module allows the sum of `baseProposerReward + bonusProposerReward + communityTax` to exceed 1.0 when parameters are updated individually through governance proposals. This causes `voteMultiplier` to become negative in `AllocateTokens`, leading to a panic and complete network shutdown during block processing. [1](#0-0) 

## Impact
**High** - Total network shutdown (all nodes panic, network cannot confirm new transactions)

## Finding Description

**Location:** 
- Primary: `x/distribution/keeper/allocation.go`, lines 82-84 (voteMultiplier calculation)
- Secondary: `x/distribution/keeper/allocation.go`, line 114 (panic trigger in AllocateTokensToValidator)
- Validation gap: `x/distribution/types/params.go`, lines 41-48 (ParamSetPairs) and `x/params/types/subspace.go`, lines 196-219 (Update method) [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The distribution parameters should satisfy the invariant: `baseProposerReward + bonusProposerReward + communityTax ≤ 1.0`. This ensures that `voteMultiplier = 1.0 - proposerMultiplier - communityTax` remains non-negative, preventing negative reward allocations. [3](#0-2) 

**Actual Logic:** 
The combined sum validation exists in `ValidateBasic()` but is only enforced during genesis validation. When parameters are updated through governance proposals, only individual parameter validation functions are called via `Subspace.Update()`. These individual validators check each parameter is `≥ 0` and `≤ 1.0`, but do NOT verify the combined sum constraint. [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. Three governance proposals are submitted and approved independently:
   - Proposal 1: Set `baseProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1)
   - Proposal 2: Set `bonusProposerReward = 0.5` (valid: 0 ≤ 0.5 ≤ 1)
   - Proposal 3: Set `communityTax = 0.1` (valid: 0 ≤ 0.1 ≤ 1)

2. Combined sum: `0.5 + 0.5 + 0.1 = 1.1 > 1.0` (violates invariant)

3. During the next block's `BeginBlock`, `AllocateTokens` is called:
   - When `previousFractionVotes = 1.0`: `proposerMultiplier = 0.5 + 0.5×1.0 = 1.0`
   - `voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1` (negative!)
   - `feeMultiplier = feesCollected × (-0.1)` produces negative DecCoins
   - `reward = feeMultiplier × powerFraction` produces negative rewards
   - `AllocateTokensToValidator` is called with negative tokens
   - At line 114: `shared := tokens.Sub(commission)` attempts to subtract, resulting in a negative amount
   - `DecCoins.Sub()` panics with "negative coin amount" [6](#0-5) 

**Security Failure:** 
Denial of service - complete network halt. All validator nodes crash simultaneously when processing any block after the misconfigured parameters are in effect, preventing transaction confirmation and breaking consensus.

## Impact Explanation

**Assets/Processes Affected:**
- Entire network availability and transaction processing
- All validator nodes crash and cannot produce/validate blocks
- Network consensus completely breaks down

**Severity:**
The network experiences total shutdown. Once the panic occurs during `AllocateTokens` (called in every block's `BeginBlock`), all nodes crash. The network cannot recover without:
1. Emergency governance action to fix parameters (impossible if network is halted)
2. Hard fork or coordinated manual intervention to reset parameters

**System Security/Reliability:**
This represents a catastrophic failure mode where a seemingly benign sequence of parameter updates (each individually valid) creates an unrecoverable network halt. The issue is particularly severe because:
- The panic occurs in core block processing logic
- All nodes are affected simultaneously
- No automatic recovery mechanism exists
- The condition persists across all subsequent blocks until parameters are manually corrected

## Likelihood Explanation

**Who Can Trigger:**
Any token holder can submit governance proposals. The vulnerability requires three proposals to pass through normal democratic governance voting.

**Conditions Required:**
- Three separate governance proposals updating distribution parameters individually
- Each proposal must achieve majority approval
- Proposals are reviewed in isolation without considering combined effects
- High validator participation (previousFractionVotes approaching 1.0) increases the likelihood of the panic

**Frequency/Likelihood:**
**Moderate to High** likelihood over time:
- Parameter adjustments are routine governance activities in Cosmos chains
- Multiple parameters may be adjusted independently over weeks/months
- Reviewers examining individual proposals may not check combined constraints
- No automated validation prevents this during the proposal process
- Could occur accidentally through well-intentioned governance actions
- Could also be deliberately orchestrated by an attacker controlling sufficient voting power

The vulnerability is particularly insidious because each individual change appears safe in isolation.

## Recommendation

Implement combined sum validation in the individual parameter validation functions to enforce the invariant at every parameter update:

1. **Immediate Fix**: Modify `validateCommunityTax`, `validateBaseProposerReward`, and `validateBonusProposerReward` to accept a context parameter and query current values of the other parameters, then validate the combined sum will not exceed 1.0.

2. **Alternative Approach**: Add a custom validation hook in `Subspace.Update()` specifically for distribution parameters that calls `ValidateBasic()` on the complete parameter set after any individual parameter change.

3. **Additional Safety**: Add a defensive check in `AllocateTokens` to detect negative `voteMultiplier` and handle gracefully (e.g., clamp to zero, emit warning event) rather than allowing the panic to propagate.

4. **Long-term**: Consider implementing parameter change proposals that require atomic updates of all interdependent parameters together, preventing piecemeal changes that violate invariants.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensWithNegativeVoteMultiplier`

**Setup:**
```
- Initialize test application with simapp.Setup(false)
- Create context and test accounts
- Create two validators with equal voting power (100 each)
- Set misconfigured parameters through SetParams (simulating post-governance state):
  * CommunityTax: 0.1 (10%)
  * BaseProposerReward: 0.5 (50%)
  * BonusProposerReward: 0.5 (50%)
  * Combined sum: 1.1 > 1.0
- Fund the fee collector with 100 tokens
```

**Trigger:**
```
- Call AllocateTokens with:
  * sumPreviousPrecommitPower = 200 (both validators voted)
  * totalPreviousPower = 200 (100% participation)
  * previousFractionVotes = 1.0 (maximum bonus)
  * This maximizes proposerMultiplier = 0.5 + 0.5×1.0 = 1.0
  * Therefore voteMultiplier = 1.0 - 1.0 - 0.1 = -0.1
```

**Observation:**
```
- The test should catch a panic with message "negative coin amount"
- This occurs when AllocateTokensToValidator tries to compute:
  shared := tokens.Sub(commission)
  where both tokens and commission are negative
- Use require.Panics() to assert the panic occurs
- This confirms that misconfigured parameters cause network-halting panics
```

**Complete Test Code:**
Add this test to `x/distribution/keeper/allocation_test.go`:

```go
func TestAllocateTokensWithNegativeVoteMultiplier(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})
	
	// Setup: misconfigure parameters to violate sum constraint
	// baseProposerReward + bonusProposerReward + communityTax = 1.1 > 1.0
	misconfiguredParams := disttypes.Params{
		CommunityTax:        sdk.NewDecWithPrec(1, 1), // 0.1 (10%)
		BaseProposerReward:  sdk.NewDecWithPrec(5, 1), // 0.5 (50%)
		BonusProposerReward: sdk.NewDecWithPrec(5, 1), // 0.5 (50%)
		WithdrawAddrEnabled: true,
	}
	app.DistrKeeper.SetParams(ctx, misconfiguredParams)
	
	// Create validators
	addrs := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1234))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
	tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
	
	tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDec(0), sdk.NewDec(0), sdk.NewDec(0))
	tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
	tstaking.CreateValidator(valAddrs[1], valConsPk2, sdk.NewInt(100), true)
	
	// Fund fee collector
	fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100)))
	feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
	require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
	app.AccountKeeper.SetAccount(ctx, feeCollector)
	
	// Setup votes with 100% participation (previousFractionVotes = 1.0)
	votes := []abci.VoteInfo{
		{
			Validator: abci.Validator{
				Address: valConsPk1.Address(),
				Power:   100,
			},
			SignedLastBlock: true,
		},
		{
			Validator: abci.Validator{
				Address: valConsPk2.Address(),
				Power:   100,
			},
			SignedLastBlock: true,
		},
	}
	
	// Trigger: This should panic due to negative voteMultiplier
	// voteMultiplier = 1.0 - (0.5 + 0.5*1.0) - 0.1 = -0.1
	require.Panics(t, func() {
		app.DistrKeeper.AllocateTokens(ctx, 200, 200, valConsAddr1, votes)
	}, "Expected panic due to negative voteMultiplier causing negative coin amount")
}
```

This test demonstrates that when parameters violate the sum constraint, `AllocateTokens` panics with "negative coin amount", causing a network halt. The panic is deterministic and will affect all nodes processing blocks with these parameters.

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

**File:** types/dec_coin.go (L303-310)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}
```
