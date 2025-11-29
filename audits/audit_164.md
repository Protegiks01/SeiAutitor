# Audit Report

## Title
Division by Zero Panic in Governance Tally Causes Network Halt When Bonded Validator Has Zero Delegator Shares

## Summary
The governance module's tally computation performs unguarded division by a validator's `DelegatorShares` at critical points. When a bonded validator has voted on a proposal but subsequently has all delegations removed, the validator temporarily retains bonded status with zero shares. During the governance EndBlocker execution (which runs before the staking EndBlocker), the tally function attempts to divide by zero, causing a panic that halts the entire network.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The tally function should safely compute voting power for all bonded validators who have voted on a proposal. The calculation `votingPower = sharesAfterDeductions * BondedTokens / DelegatorShares` should account for edge cases where validators may have zero delegator shares.

**Actual Logic:** The code performs division by `val.DelegatorShares` without checking if it equals zero. The `Dec.Quo()` method panics when the divisor is zero, as confirmed by the decimal implementation: [2](#0-1) 

**Exploitation Path:**
1. A validator operates normally with delegations and is in bonded status
2. The validator casts a vote on an active governance proposal (vote is stored)
3. All delegators remove their delegations via standard `Undelegate` transactions
4. After the final undelegation, the validator has both `Tokens = 0` and `DelegatorShares = 0`: [3](#0-2) 
5. The validator remains in bonded status because status changes only occur in the staking EndBlocker: [4](#0-3) 
6. The proposal's voting period ends
7. The governance EndBlocker executes (before staking EndBlocker) as defined by module ordering: [5](#0-4) 
8. The governance EndBlocker calls `Tally()`: [6](#0-5) 
9. The tally function iterates over bonded validators (including the zero-share validator) and attempts to calculate voting power
10. At line 79-80 of tally.go, the division by zero occurs: `votingPower = sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)`
11. The `Quo` method panics, crashing EndBlock execution
12. All validator nodes panic at the same block height, completely halting the chain

**Security Guarantee Broken:** The network's availability and liveness guarantees are violated. The chain cannot progress past the problematic block, and consensus is permanently stalled until a coordinated emergency upgrade is deployed.

## Impact Explanation

This vulnerability causes complete network shutdown. When the panic occurs during EndBlock execution:
- All validator nodes crash simultaneously at the same block height
- No new blocks can be produced or transactions processed
- The entire network becomes unavailable to users
- Recovery requires emergency coordination among validators to upgrade to a patched version
- This represents a critical denial-of-service vulnerability affecting the entire blockchain

The severity meets the HIGH impact threshold of "Network not being able to confirm new transactions (total network shutdown)" as specified in the impact categories.

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
- Deliberate triggering by an attacker controlling delegations to a validator or operating their own validator with minimal delegation

The vulnerability requires no special privileges and can be triggered through standard, permissionless transactions. An attacker could deliberately create this condition by setting up a validator, self-delegating, voting on a proposal, then self-undelegating before the proposal ends.

## Recommendation

Add a zero-check before performing the division in the tally computation. In `x/gov/keeper/tally.go`:

```go
// At line 74-80, add zero-check:
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

Similarly, add a check at line 57 where delegator voting power is calculated, though this path is less likely to be reached (as zero-share validators should have no remaining delegations).

## Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test Function:** `TestTallyPanicWithZeroShareValidator`

**Setup:**
- Create a validator with initial delegation using `createValidators()`
- Create and activate a governance proposal in voting period
- Validator casts a vote on the proposal using `AddVote()`

**Action:**
- Retrieve the validator's delegation
- Call `Undelegate()` to remove all shares from the validator
- Verify validator has zero shares (`DelegatorShares.IsZero()`) but remains bonded (`IsBonded()`)
- Call `Tally()` on the proposal

**Result:**
- The test expects a panic from `Tally()` when it attempts division by zero
- This panic demonstrates that the vulnerability causes chain halt during EndBlock execution
- In production, this would crash all validator nodes at the same block height, halting the network

The PoC confirms that the scenario is reproducible and would cause the described network shutdown in a live environment.

### Citations

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
