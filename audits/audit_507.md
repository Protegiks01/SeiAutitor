## Audit Report

## Title
Division by Zero Panic in Governance Tally Causes Network Halt When Bonded Validator Has Zero Delegator Shares

## Summary
The governance tally computation performs division by a validator's `DelegatorShares` without checking if it's zero. A bonded validator with all delegations removed but that has voted on a proposal will cause a panic during the tally computation in EndBlock, halting the entire network. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** The vulnerability exists in the governance module's tally computation at `x/gov/keeper/tally.go` lines 79-80, where voting power is calculated for validators who have voted.

**Intended Logic:** The tally function should safely compute the voting power of all bonded validators who have voted on a proposal, using the formula: `votingPower = sharesAfterDeductions * BondedTokens / DelegatorShares`. This calculates the validator's self-delegated voting power after deducting delegator shares that voted separately.

**Actual Logic:** The code performs the division without checking if `DelegatorShares` is zero. When a validator has zero delegator shares, the `Dec.Quo()` method panics with a division by zero error. [2](#0-1) 

**Exploit Scenario:**
1. A validator becomes bonded with delegations
2. The validator votes on an active governance proposal
3. All delegators undelegate from the validator through normal `Undelegate` transactions
4. After the last undelegation, the validator has both `Tokens = 0` and `DelegatorShares = 0` [3](#0-2) 
5. The validator remains in bonded status because the status change only happens in staking's EndBlocker [4](#0-3) 
6. When the proposal's voting period ends, the governance EndBlocker runs and calls `Tally()` [5](#0-4) 
7. The governance EndBlocker executes BEFORE the staking EndBlocker [6](#0-5) 
8. The tally function iterates over bonded validators and attempts to calculate voting power for the zero-share validator
9. Division by zero panic occurs, crashing the EndBlock execution and halting the chain

**Security Failure:** This breaks the availability property of the network. The chain cannot process new blocks because EndBlock execution panics, resulting in a complete network shutdown. All validators would crash at the same block height when trying to execute the problematic tally.

## Impact Explanation

- **Affected Process:** The entire blockchain network's ability to produce new blocks
- **Severity:** When this panic occurs during EndBlock, the chain completely halts. No new transactions can be processed, and the network cannot continue until nodes are upgraded with a patched version
- **System Impact:** This represents a critical denial-of-service vulnerability that can freeze all chain operations. The chain would be unable to progress past the block where the tally computation fails, requiring an emergency hard fork or coordinated upgrade to resume operations

## Likelihood Explanation

**Triggering Actors:** Any combination of normal network participants - validators can vote on proposals and delegators can undelegate, both through standard operations.

**Required Conditions:**
- An active governance proposal in voting period
- A bonded validator that votes on the proposal  
- All delegators of that validator undelegate before the proposal's voting period ends
- The tally computation occurs (automatically at voting period end)

**Frequency:** While requiring specific timing, this can occur during normal operations and doesn't require malicious intent. It becomes more likely when:
- Validators with small delegation counts vote on proposals
- Market conditions cause mass undelegations
- A validator with a single self-delegation votes and then self-undelegates

This could also be deliberately triggered by an attacker who controls enough delegations to a validator (or runs their own validator with minimal delegation).

## Recommendation

Add a check before the division to handle the zero-shares case. In `x/gov/keeper/tally.go`, before computing voting power:

```go
// Skip validators with zero delegator shares to avoid division by zero
if val.DelegatorShares.IsZero() {
    continue
}

sharesAfterDeductions := val.DelegatorShares.Sub(val.DelegatorDeductions)
votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)
```

Additionally, add the same check at line 57 where delegator voting power is calculated: [7](#0-6) 

## Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test Function:** Add this new test to the existing test file:

```go
func TestTallyPanicWithZeroShareValidator(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})

    // Create a single validator with delegation
    addrs, valAddrs := createValidators(t, ctx, app, []int64{10})
    
    // Create and activate a governance proposal
    tp := TestProposal
    proposal, err := app.GovKeeper.SubmitProposal(ctx, tp)
    require.NoError(t, err)
    proposalID := proposal.ProposalId
    proposal.Status = types.StatusVotingPeriod
    app.GovKeeper.SetProposal(ctx, proposal)
    
    // Validator votes on the proposal
    require.NoError(t, app.GovKeeper.AddVote(ctx, proposalID, addrs[0], types.NewNonSplitVoteOption(types.OptionYes)))
    
    // Verify validator is bonded and has shares
    val, found := app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    require.True(t, found)
    require.True(t, val.IsBonded())
    require.False(t, val.DelegatorShares.IsZero())
    
    // Get the delegation and undelegate all tokens
    delegation, found := app.StakingKeeper.GetDelegation(ctx, addrs[0], valAddrs[0])
    require.True(t, found)
    
    // Undelegate all shares from the validator
    _, err = app.StakingKeeper.Undelegate(ctx, addrs[0], valAddrs[0], delegation.Shares)
    require.NoError(t, err)
    
    // Verify validator now has zero shares but is still bonded
    // (will be unbonded in next staking EndBlocker)
    val, found = app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    require.True(t, found)
    require.True(t, val.IsBonded(), "Validator should still be bonded until EndBlocker")
    require.True(t, val.DelegatorShares.IsZero(), "Validator should have zero delegator shares")
    require.True(t, val.Tokens.IsZero(), "Validator should have zero tokens")
    
    // Get the proposal
    proposal, ok := app.GovKeeper.GetProposal(ctx, proposalID)
    require.True(t, ok)
    
    // This should panic with division by zero when computing the validator's voting power
    require.Panics(t, func() {
        app.GovKeeper.Tally(ctx, proposal)
    }, "Tally should panic when validator has zero DelegatorShares")
}
```

**Setup:** The test creates a validator with a single delegation and an active governance proposal.

**Trigger:** The validator votes on the proposal, then all delegations are removed via `Undelegate()`. The validator remains bonded (status only changes during staking EndBlocker). The tally function is then called.

**Observation:** The test asserts that `Tally()` panics when attempting to divide by the validator's zero `DelegatorShares`. The panic confirms the vulnerability - in a real chain, this would halt all nodes at EndBlock execution.

### Citations

**File:** x/gov/keeper/tally.go (L57-57)
```go
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

**File:** x/staking/keeper/val_state_change.go (L139-141)
```go
		if validator.PotentialConsensusPower(k.PowerReduction(ctx)) == 0 {
			break
		}
```

**File:** x/gov/abci.go (L48-51)
```go
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** simapp/app.go (L372-373)
```go
	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName, govtypes.ModuleName, stakingtypes.ModuleName,
```
