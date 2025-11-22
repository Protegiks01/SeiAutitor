## Audit Report

### Title
Genesis Import Allows Invalid Weighted Votes Bypassing Sum-to-1 Validation, Corrupting Tally Computation

### Summary
The governance module's genesis import process bypasses weighted vote validation, allowing votes with weights that don't sum to 1 (including zero-weight options) to be imported into state. This creates an accounting mismatch during tally computation where full voting power is counted but only partial power is allocated to vote options, affecting quorum, veto, and pass/fail threshold calculations.

### Impact
Medium

### Finding Description

**Location:** 
- Validation bypass: [1](#0-0) 
- Missing genesis validation: [2](#0-1) 
- Incomplete keeper validation: [3](#0-2) 
- Tally accounting mismatch: [4](#0-3) 

**Intended Logic:** 
Weighted votes should have all option weights sum to exactly 1.0, with each individual weight being positive (>0) and ≤1. This ensures that when tally computation multiplies `votingPower * weight` for each option, the sum of allocated power equals the voter's full voting power. The validation exists in [5](#0-4)  and [6](#0-5) .

**Actual Logic:** 
During genesis import, votes are set directly via `SetVote` without any validation. The `ValidateGenesis` function does not validate votes. The keeper's `AddVote` validation only checks individual options via `ValidWeightedVoteOption` (which rejects zero weights per [7](#0-6) ) but does NOT verify weights sum to 1. This allows malformed votes into state.

During tally at [4](#0-3) , for each vote option: `subPower = votingPower.Mul(option.Weight)` is added to results, but `totalVotingPower` adds the full `votingPower`. If weights sum to less than 1 (e.g., 0.8), only 80% of voting power is allocated to options while 100% is counted in the denominator for threshold calculations.

**Exploit Scenario:** 
1. Attacker prepares a genesis file for chain initialization/upgrade containing a vote with options: `{Yes: 0.5, No: 0.3}` (sum = 0.8, or includes zero-weight options)
2. Genesis import executes `InitGenesis` which calls `SetVote` directly, bypassing validation
3. When tally is computed for that proposal, the vote contributes its full voting power (e.g., 100 tokens) to `totalVotingPower`, but only allocates 80 tokens to Yes/No results
4. This inflates the denominator in percentage calculations:
   - Line 99: `percentVoting = totalVotingPower / totalBondedTokens` artificially inflated, making quorum easier to reach
   - Line 112: `results[NoWithVeto] / totalVotingPower` denominator inflated, making veto harder to trigger
   - Line 119: Pass threshold calculation affected

**Security Failure:** 
Accounting invariant violation - the fundamental assumption that allocated voting power equals total voting power is broken, causing incorrect governance outcomes.

### Impact Explanation

This vulnerability affects governance proposal outcomes:

- **Quorum manipulation:** Inflated `totalVotingPower` makes proposals appear to have more participation than actual, potentially allowing proposals to pass quorum when they shouldn't
- **Veto threshold manipulation:** Makes it harder to reach the 1/3 veto threshold by inflating the denominator
- **Pass/fail manipulation:** Affects the Yes threshold calculation, potentially changing proposal outcomes

The severity is Medium because it results in unintended governance behavior that could lead to incorrect protocol decisions, but requires a malicious genesis file (possible during chain upgrades/forks). While it doesn't directly cause fund loss, corrupted governance could indirectly lead to harmful protocol changes.

### Likelihood Explanation

**Who can trigger:** Any party involved in chain initialization or genesis file preparation (validators/chain operators during network launch or upgrade).

**Conditions required:** Requires importing a malicious genesis file with invalid weighted votes. This is realistic during:
- Initial chain launch
- Chain upgrades requiring genesis export/import
- Fork scenarios

**Frequency:** Low frequency but high impact when triggered. Once imported, the corrupted votes persist and affect all tally computations for affected proposals.

### Recommendation

Add vote validation to `ValidateGenesis`:

```go
func ValidateGenesis(data *GenesisState) error {
    // ... existing validation ...
    
    // Validate votes
    for _, vote := range data.Votes {
        // Validate each option
        for _, option := range vote.Options {
            if !ValidWeightedVoteOption(option) {
                return fmt.Errorf("invalid vote option: %s", option.String())
            }
        }
        
        // Validate weights sum to 1
        totalWeight := sdk.ZeroDec()
        usedOptions := make(map[VoteOption]bool)
        for _, option := range vote.Options {
            if usedOptions[option.Option] {
                return fmt.Errorf("duplicate vote option in vote for proposal %d", vote.ProposalId)
            }
            usedOptions[option.Option] = true
            totalWeight = totalWeight.Add(option.Weight)
        }
        if !totalWeight.Equal(sdk.OneDec()) {
            return fmt.Errorf("vote weights must sum to 1.0, got %s for proposal %d", totalWeight.String(), vote.ProposalId)
        }
    }
    
    return nil
}
```

Additionally, add the sum-to-1 check in `keeper.AddVote` as defense-in-depth.

### Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test function:** Add this test to demonstrate the vulnerability:

```go
func TestTallyGenesisInvalidWeightSum(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create 3 validators with equal power (10 tokens each)
    addrs, _ := createValidators(t, ctx, app, []int64{10, 10, 10})
    
    // Create proposal
    tp := TestProposal
    proposal, err := app.GovKeeper.SubmitProposal(ctx, tp)
    require.NoError(t, err)
    proposalID := proposal.ProposalId
    proposal.Status = types.StatusVotingPeriod
    app.GovKeeper.SetProposal(ctx, proposal)
    
    // Normal votes from validators 0 and 1
    require.NoError(t, app.GovKeeper.AddVote(ctx, proposalID, addrs[0], 
        types.NewNonSplitVoteOption(types.OptionYes)))
    require.NoError(t, app.GovKeeper.AddVote(ctx, proposalID, addrs[1], 
        types.NewNonSplitVoteOption(types.OptionNo)))
    
    // Malicious vote via SetVote (simulating genesis import)
    // Weights sum to 0.8 instead of 1.0
    maliciousVote := types.Vote{
        ProposalId: proposalID,
        Voter:      addrs[2].String(),
        Options: types.WeightedVoteOptions{
            {Option: types.OptionYes, Weight: sdk.NewDecWithPrec(5, 1)}, // 0.5
            {Option: types.OptionNo, Weight: sdk.NewDecWithPrec(3, 1)},  // 0.3
            // Total = 0.8, not 1.0!
        },
    }
    app.GovKeeper.SetVote(ctx, maliciousVote)
    
    // Tally the proposal
    proposal, ok := app.GovKeeper.GetProposal(ctx, proposalID)
    require.True(t, ok)
    _, _, tallyResults := app.GovKeeper.Tally(ctx, proposal)
    
    // Accounting mismatch demonstrated:
    // Expected: Validator 0: 10 Yes, Validator 1: 10 No, Validator 2: 5 Yes + 3 No
    // Actual allocated: 15 Yes, 13 No (total 28 tokens)
    // But totalVotingPower in tally = 30 tokens (includes full power of malicious vote)
    // The 2-token discrepancy corrupts all percentage-based threshold checks
    
    expectedYes := app.StakingKeeper.TokensFromConsensusPower(ctx, 15)
    expectedNo := app.StakingKeeper.TokensFromConsensusPower(ctx, 13)
    
    // This proves only 28 of 30 tokens were allocated
    require.Equal(t, expectedYes, tallyResults.Yes)
    require.Equal(t, expectedNo, tallyResults.No)
    
    // The vulnerability: 2 tokens are counted in totalVotingPower 
    // but not allocated to any option, skewing all percentage calculations
}
```

**Setup:** Test creates validators with voting power and a proposal in voting period.

**Trigger:** Uses `SetVote` directly to bypass validation (simulating genesis import) with a vote having weights summing to 0.8.

**Observation:** Tally results show only 28 tokens allocated to options (15 Yes + 13 No) from a total of 30 tokens voting power. This proves the accounting mismatch where full voting power is counted in denominators but only partial power allocated to numerators, corrupting threshold calculations in lines 99, 112, and 119 of `tally.go`.

### Citations

**File:** x/gov/genesis.go (L30-32)
```go
	for _, vote := range data.Votes {
		k.SetVote(ctx, vote)
	}
```

**File:** x/gov/types/genesis.go (L45-73)
```go
func ValidateGenesis(data *GenesisState) error {
	if data == nil {
		return fmt.Errorf("governance genesis state cannot be nil")
	}

	if data.Empty() {
		return fmt.Errorf("governance genesis state cannot be nil")
	}

	validateTallyParams(data.TallyParams)

	if !data.DepositParams.MinDeposit.IsValid() {
		return fmt.Errorf("governance deposit amount must be a valid sdk.Coins amount, is %s",
			data.DepositParams.MinDeposit.String())
	}

	if !data.DepositParams.MinExpeditedDeposit.IsValid() {
		return fmt.Errorf("governance min expedited deposit amount must be a valid sdk.Coins amount, is %s",
			data.DepositParams.MinExpeditedDeposit.String())
	}

	if data.DepositParams.MinExpeditedDeposit.IsAllLTE(data.DepositParams.MinDeposit) {
		return fmt.Errorf("governance min expedited deposit amount %s must be greater than regular min deposit %s",
			data.DepositParams.MinExpeditedDeposit.String(),
			data.DepositParams.MinDeposit.String())
	}

	return nil
}
```

**File:** x/gov/keeper/vote.go (L21-25)
```go
	for _, option := range options {
		if !types.ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(types.ErrInvalidVote, option.String())
		}
	}
```

**File:** x/gov/keeper/tally.go (L59-63)
```go
				for _, option := range vote.Options {
					subPower := votingPower.Mul(option.Weight)
					results[option.Option] = results[option.Option].Add(subPower)
				}
				totalVotingPower = totalVotingPower.Add(votingPower)
```

**File:** x/gov/types/msgs.go (L252-271)
```go
	totalWeight := sdk.NewDec(0)
	usedOptions := make(map[VoteOption]bool)
	for _, option := range msg.Options {
		if !ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(ErrInvalidVote, option.String())
		}
		totalWeight = totalWeight.Add(option.Weight)
		if usedOptions[option.Option] {
			return sdkerrors.Wrap(ErrInvalidVote, "Duplicated vote option")
		}
		usedOptions[option.Option] = true
	}

	if totalWeight.GT(sdk.NewDec(1)) {
		return sdkerrors.Wrap(ErrInvalidVote, "Total weight overflow 1.00")
	}

	if totalWeight.LT(sdk.NewDec(1)) {
		return sdkerrors.Wrap(ErrInvalidVote, "Total weight lower than 1.00")
	}
```

**File:** x/gov/types/vote.go (L80-85)
```go
func ValidWeightedVoteOption(option WeightedVoteOption) bool {
	if !option.Weight.IsPositive() || option.Weight.GT(sdk.NewDec(1)) {
		return false
	}
	return ValidVoteOption(option.Option)
}
```

**File:** types/decimal.go (L209-209)
```go
func (d Dec) IsPositive() bool  { return (d.i).Sign() == 1 }          // is positive
```
