## Title
Genesis Import Bypasses Weighted Vote Validation Allowing Vote Inflation in Governance Tallies

## Summary
The governance module's `InitGenesis` function imports votes without validating that weighted vote options sum to exactly 1.0. This allows maliciously crafted genesis states to include votes with weights summing to greater than 1.0, causing the `Tally` function to inflate vote counts beyond voters' actual voting power and potentially alter proposal outcomes. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Vulnerable code: [1](#0-0) 
- Missing validation: [2](#0-1) 
- Tally calculation: [3](#0-2) 

**Intended Logic:** 
Weighted vote options must sum to exactly 1.0 to ensure that each voter's voting power is counted exactly once. The normal transaction path enforces this through `MsgVoteWeighted.ValidateBasic()`: [4](#0-3) 

**Actual Logic:** 
When votes are imported via genesis state, they bypass all validation. The `InitGenesis` function directly stores votes using `k.SetVote(ctx, vote)` without checking weight sums. The `ValidateGenesis` function only validates deposit parameters and tally parameters, completely ignoring vote validation.

During tally calculation, the code multiplies each option's weight by the voter's voting power and accumulates results. If weights sum to more than 1.0, a single voter's power is effectively counted multiple times across different options.

**Exploit Scenario:**
1. During a chain launch, upgrade, or migration, the genesis state includes a vote with weighted options that sum to more than 1.0 (e.g., `{Yes: 0.6, No: 0.6}` totaling 1.2)
2. The `InitGenesis` function imports this vote without validation
3. When `Tally` is called for the proposal, the malformed vote inflates the vote count by 20% for this voter
4. This can change proposal outcomes, especially in close votes

**Security Failure:** 
This breaks the fundamental accounting invariant that total votes should never exceed total voting power. The governance module's integrity is compromised as proposal outcomes can be manipulated through genesis state manipulation.

## Impact Explanation

**Affected Assets/Processes:**
- Governance proposal outcomes are directly affected
- Protocol parameters and upgrades controlled by governance are at risk
- Chain integrity during genesis import, migrations, and chain forks

**Severity:**
- Malicious votes in genesis state can inflate voting power by arbitrary amounts (e.g., 20%, 50%, or more)
- Can cause proposals to pass that should fail, or vice versa
- Governance controls critical protocol functions including parameter changes and upgrades
- This is a protocol-level bug that affects the layer 1 governance mechanism

**Why This Matters:**
Governance is the highest authority in a blockchain protocol. If governance can be manipulated through genesis state, it undermines the entire security model of the chain. While genesis files are typically reviewed, this is a subtle mathematical issue that could easily be missed, especially during complex chain migrations or community-proposed genesis states.

## Likelihood Explanation

**Who Can Trigger:**
- Anyone who can influence genesis state content (chain launchers, migration coordinators, fork creators)
- Does not require privileged on-chain access once the chain is running

**Conditions Required:**
- Occurs during chain initialization or state import from genesis
- Requires malformed votes to be present in genesis state
- No special timing or consensus conditions needed

**Frequency:**
- Rare but high-impact: occurs during chain launches, major upgrades, or migrations
- Once imported, the malformed votes persist in state and affect tally results
- More likely during emergency chain recoveries or contentious forks where genesis review may be rushed

## Recommendation

Add vote validation to the genesis import process:

1. **In `ValidateGenesis` function:** Add validation loop to check all votes in genesis state:
   - Verify each vote's weighted options sum to exactly 1.0
   - Verify no duplicate options exist
   - Verify all weights are positive and ≤ 1.0

2. **In `InitGenesis` function:** Consider adding defensive validation before `k.SetVote()` calls as an additional safety layer.

Example validation to add in `ValidateGenesis`:
```go
// Validate votes
for _, vote := range data.Votes {
    totalWeight := sdk.ZeroDec()
    usedOptions := make(map[VoteOption]bool)
    for _, option := range vote.Options {
        if !ValidWeightedVoteOption(option) {
            return fmt.Errorf("invalid weighted vote option in genesis: %v", option)
        }
        if usedOptions[option.Option] {
            return fmt.Errorf("duplicate vote option in genesis vote: %v", option.Option)
        }
        usedOptions[option.Option] = true
        totalWeight = totalWeight.Add(option.Weight)
    }
    if !totalWeight.Equal(sdk.NewDec(1)) {
        return fmt.Errorf("vote weights must sum to 1.0, got %v for voter %s", totalWeight, vote.Voter)
    }
}
```

## Proof of Concept

**File:** `x/gov/keeper/tally_test.go`

**Test Function:** Add this test function to demonstrate the vulnerability:

```go
func TestTallyWithInflatedGenesisVotes(t *testing.T) {
    // Setup: Create app and context
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create validator with 100 tokens of voting power
    addrs, _ := createValidators(t, ctx, app, []int64{100})
    
    // Create a proposal
    tp := TestProposal
    proposal, err := app.GovKeeper.SubmitProposal(ctx, tp)
    require.NoError(t, err)
    proposalID := proposal.ProposalId
    proposal.Status = types.StatusVotingPeriod
    app.GovKeeper.SetProposal(ctx, proposal)
    
    // Trigger: Craft a malicious vote with weights summing to 1.2 (20% inflation)
    // This simulates a vote imported from genesis that bypassed validation
    maliciousVote := types.Vote{
        ProposalId: proposalID,
        Voter:      addrs[0].String(),
        Options: types.WeightedVoteOptions{
            {Option: types.OptionYes, Weight: sdk.NewDecWithPrec(6, 1)},    // 0.6
            {Option: types.OptionNo, Weight: sdk.NewDecWithPrec(6, 1)},     // 0.6
        },
    }
    
    // Directly set the vote bypassing normal validation (as genesis import does)
    app.GovKeeper.SetVote(ctx, maliciousVote)
    
    // Observation: Run tally and check for vote inflation
    proposal, ok := app.GovKeeper.GetProposal(ctx, proposalID)
    require.True(t, ok)
    _, _, tallyResults := app.GovKeeper.Tally(ctx, proposal)
    
    // With 100 tokens of voting power and weights of 0.6 + 0.6 = 1.2:
    // Yes votes should be inflated to 60 (0.6 * 100)
    // No votes should be inflated to 60 (0.6 * 100)
    // Total counted power = 120 from a 100-token validator (20% inflation)
    
    expectedYes := app.StakingKeeper.TokensFromConsensusPower(ctx, 60)
    expectedNo := app.StakingKeeper.TokensFromConsensusPower(ctx, 60)
    
    // This demonstrates the vulnerability: votes are inflated beyond actual voting power
    require.Equal(t, expectedYes, tallyResults.Yes, "Yes votes should be inflated to 60")
    require.Equal(t, expectedNo, tallyResults.No, "No votes should be inflated to 60")
    
    // The total effective voting power counted (120) exceeds the validator's actual power (100)
    totalCounted := tallyResults.Yes.Add(tallyResults.No).Add(tallyResults.Abstain).Add(tallyResults.NoWithVeto)
    actualPower := app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
    require.True(t, totalCounted.GT(actualPower), 
        "Total counted votes (%v) should exceed actual voting power (%v), demonstrating vote inflation", 
        totalCounted, actualPower)
}
```

**Setup:** The test creates a validator with 100 tokens of voting power and a proposal in voting period.

**Trigger:** A malicious vote is crafted with weights `{Yes: 0.6, No: 0.6}` summing to 1.2, then directly stored via `SetVote()` to simulate genesis import that bypasses validation.

**Observation:** The tally shows 60 tokens for Yes and 60 tokens for No (total 120 tokens counted) from a validator with only 100 tokens, demonstrating 20% vote inflation. This confirms the invariant violation where total votes exceed actual voting power.

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

**File:** x/gov/keeper/tally.go (L59-62)
```go
				for _, option := range vote.Options {
					subPower := votingPower.Mul(option.Weight)
					results[option.Option] = results[option.Option].Add(subPower)
				}
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
