# Audit Report

## Title
Division by Zero Panic in Governance Tally Causes Network Halt When Bonded Validator Has Zero Delegator Shares

## Summary
The governance module's tally computation performs unguarded division by a validator's `DelegatorShares` without checking for zero. When a bonded validator with zero shares has voted on a proposal, the tally function panics during governance EndBlocker execution, causing complete network shutdown across all validator nodes.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The tally function should safely compute voting power for all bonded validators who have voted on a proposal, handling edge cases where validators may have zero delegator shares gracefully.

**Actual Logic:** The code performs division by `val.DelegatorShares` without checking if it equals zero. The `Dec.Quo()` method panics when the divisor is zero [2](#0-1) , causing immediate EndBlock failure.

**Exploitation Path:**
1. A validator operates normally with delegations and is in bonded status
2. The validator casts a vote on an active governance proposal
3. All delegators remove their delegations via standard `Undelegate` transactions
4. After the final undelegation, the validator has both `Tokens = 0` and `DelegatorShares = 0` [3](#0-2) 
5. The validator remains in bonded status because validators with zero shares are only removed if unbonded [4](#0-3)  and status changes only occur in the staking EndBlocker
6. The proposal's voting period ends
7. The governance EndBlocker executes before the staking EndBlocker [5](#0-4) 
8. The governance EndBlocker calls `Tally()` [6](#0-5) 
9. The tally function iterates over bonded validators using `IterateBondedValidatorsByPower()` [7](#0-6) , which only checks `IsBonded()` status [8](#0-7)  without verifying voting power
10. The zero-share validator with a recorded vote triggers the division calculation
11. Division by zero occurs, causing panic
12. All validator nodes panic at the same block height, completely halting the chain

**Security Guarantee Broken:** The network's availability and liveness guarantees are violated. The chain cannot progress past the problematic block, and consensus is permanently stalled until a coordinated emergency upgrade is deployed.

## Impact Explanation

This vulnerability causes complete network shutdown. When the panic occurs during EndBlock execution:
- All validator nodes crash simultaneously at the same block height
- No new blocks can be produced or transactions processed  
- The entire network becomes unavailable to users
- Recovery requires emergency coordination among validators to upgrade to a patched version
- This represents a critical denial-of-service vulnerability affecting the entire blockchain

The severity qualifies as HIGH impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Actors:** Any network participants using standard operations - validators can vote on proposals and delegators can undelegate through normal transactions.

**Required Conditions:**
- An active governance proposal in voting period (common occurrence)
- A bonded validator that votes on the proposal (expected behavior)
- All delegators of that validator undelegate before voting period ends (feasible through normal operations)
- Voting period ends, triggering automatic tally computation

**Likelihood Assessment:** While requiring specific timing, this scenario is realistic and can occur through:
- Normal market dynamics (mass undelegations during market stress)
- Validators with few delegators voting then losing all delegations
- Deliberate triggering by an attacker controlling delegations to a validator or operating their own validator with minimal self-delegation

The vulnerability requires no special privileges and can be triggered through standard, permissionless transactions. An attacker could deliberately create this condition by setting up a validator, self-delegating minimal tokens, voting on a proposal, then self-undelegating before the proposal ends.

## Recommendation

Add a zero-check before performing the division in the tally computation:

```go
// In x/gov/keeper/tally.go at line 74-80:
for _, val := range currValidators {
    if len(val.Vote) == 0 {
        continue
    }
    
    // Skip validators with zero delegator shares to avoid division by zero
    if val.DelegatorShares.IsZero() {
        continue
    }

    sharesAfterDeductions := val.DelegatorShares.Sub(val.DelegatorDeductions)
    votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)
    // ... rest of logic
}
```

Similarly, add a check at line 57 [9](#0-8)  where delegator voting power is calculated, though this path is less likely to be reached as zero-share validators should have no remaining delegations.

## Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test Function:** `TestTallyPanicWithZeroShareValidator`

**Setup:**
- Create a validator with initial delegation using the existing `createValidators()` helper [10](#0-9) 
- Create and activate a governance proposal in voting period
- Validator casts a vote on the proposal using `AddVote()`

**Action:**
- Retrieve the validator's delegation
- Call `Undelegate()` to remove all shares from the validator
- Verify validator has zero shares (`DelegatorShares.IsZero()`) but remains bonded (`IsBonded()`)
- Call `Tally()` on the proposal

**Result:**
- The test will panic from `Tally()` when it attempts division by zero
- This panic demonstrates that the vulnerability causes chain halt during EndBlock execution
- In production, this would crash all validator nodes at the same block height, halting the network

The PoC confirms that the scenario is reproducible and would cause the described network shutdown in a live environment.

### Citations

**File:** x/gov/keeper/tally.go (L24-34)
```go
	keeper.sk.IterateBondedValidatorsByPower(ctx, func(index int64, validator stakingtypes.ValidatorI) (stop bool) {
		currValidators[validator.GetOperator().String()] = types.NewValidatorGovInfo(
			validator.GetOperator(),
			validator.GetBondedTokens(),
			validator.GetDelegatorShares(),
			sdk.ZeroDec(),
			types.WeightedVoteOptions{},
		)

		return false
	})
```

**File:** x/gov/keeper/tally.go (L56-57)
```go
				// delegation shares * bonded / total shares
				votingPower := delegation.GetShares().MulInt(val.BondedTokens).Quo(val.DelegatorShares)
```

**File:** x/gov/keeper/tally.go (L79-80)
```go
		sharesAfterDeductions := val.DelegatorShares.Sub(val.DelegatorDeductions)
		votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)
```

**File:** types/decimal_test.go (L238-239)
```go
		if tc.d2.IsZero() { // panic for divide by zero
			s.Require().Panics(func() { tc.d1.Quo(tc.d2) })
```

**File:** x/staking/types/validator.go (L415-418)
```go
	if remainingShares.IsZero() {
		// last delegation share gets any trimmings
		issuedTokens = v.Tokens
		v.Tokens = sdk.ZeroInt()
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** simapp/app.go (L372-373)
```go
	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName, govtypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/gov/abci.go (L48-51)
```go
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/staking/keeper/alias_functions.go (L45-46)
```go
		if validator.IsBonded() {
			stop := fn(i, validator) // XXX is this safe will the validator unexposed fields be able to get written to?
```

**File:** x/gov/keeper/common_test.go (L21-58)
```go
func createValidators(t *testing.T, ctx sdk.Context, app *simapp.SimApp, powers []int64) ([]sdk.AccAddress, []sdk.ValAddress) {
	addrs := simapp.AddTestAddrsIncremental(app, ctx, 5, sdk.NewInt(30000000))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
	pks := simapp.CreateTestPubKeys(5)
	cdc := simapp.MakeTestEncodingConfig().Marshaler

	app.StakingKeeper = stakingkeeper.NewKeeper(
		cdc,
		app.GetKey(stakingtypes.StoreKey),
		app.AccountKeeper,
		app.BankKeeper,
		app.GetSubspace(stakingtypes.ModuleName),
	)

	val1, err := stakingtypes.NewValidator(valAddrs[0], pks[0], stakingtypes.Description{})
	require.NoError(t, err)
	val2, err := stakingtypes.NewValidator(valAddrs[1], pks[1], stakingtypes.Description{})
	require.NoError(t, err)
	val3, err := stakingtypes.NewValidator(valAddrs[2], pks[2], stakingtypes.Description{})
	require.NoError(t, err)

	app.StakingKeeper.SetValidator(ctx, val1)
	app.StakingKeeper.SetValidator(ctx, val2)
	app.StakingKeeper.SetValidator(ctx, val3)
	app.StakingKeeper.SetValidatorByConsAddr(ctx, val1)
	app.StakingKeeper.SetValidatorByConsAddr(ctx, val2)
	app.StakingKeeper.SetValidatorByConsAddr(ctx, val3)
	app.StakingKeeper.SetNewValidatorByPowerIndex(ctx, val1)
	app.StakingKeeper.SetNewValidatorByPowerIndex(ctx, val2)
	app.StakingKeeper.SetNewValidatorByPowerIndex(ctx, val3)

	_, _ = app.StakingKeeper.Delegate(ctx, addrs[0], app.StakingKeeper.TokensFromConsensusPower(ctx, powers[0]), stakingtypes.Unbonded, val1, true)
	_, _ = app.StakingKeeper.Delegate(ctx, addrs[1], app.StakingKeeper.TokensFromConsensusPower(ctx, powers[1]), stakingtypes.Unbonded, val2, true)
	_, _ = app.StakingKeeper.Delegate(ctx, addrs[2], app.StakingKeeper.TokensFromConsensusPower(ctx, powers[2]), stakingtypes.Unbonded, val3, true)

	_ = staking.EndBlocker(ctx, app.StakingKeeper)

	return addrs, valAddrs
```
