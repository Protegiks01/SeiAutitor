## Audit Report

## Title
Mid-Proposal Parameter Change Allows Retroactive Rule Modification During Active Votes

## Summary
Governance tally parameters (quorum, threshold, veto threshold) are fetched at tally-time rather than locked when voting begins. This allows a parameter change proposal to modify the rules for another proposal that is still being voted on, causing it to be evaluated under different criteria than when voting started.

## Impact
Medium

## Finding Description

- **Location:** 
  - `x/gov/keeper/tally.go` (Tally function, line 89) [1](#0-0) 
  - `x/gov/abci.go` (EndBlocker, line 51) [2](#0-1) 
  - `x/params/proposal_handler.go` (handleParameterChangeProposal, lines 26-42) [3](#0-2) 

- **Intended Logic:** Governance proposals should be evaluated under consistent rules throughout their voting period. When a proposal enters the voting period, the governance parameters (quorum, threshold, veto threshold) that will determine its outcome should be fixed for the duration of that vote.

- **Actual Logic:** When a proposal's voting period ends, the `Tally` function retrieves the current tally parameters from storage at that moment via `keeper.GetTallyParams(ctx)`. [1](#0-0)  These parameters are used to determine if the proposal passes (checking quorum at line 101-103, veto at line 112, and threshold at line 119). [4](#0-3)  If a `ParameterChangeProposal` executes during another proposal's voting period and modifies these tally parameters, the second proposal will be evaluated under the new rules.

- **Exploit Scenario:**
  1. Proposal A is submitted and enters voting period with current tally params (e.g., 50% threshold for passage)
  2. Validators/delegators vote on Proposal A, accumulating 60% YES votes (sufficient under current 50% threshold)
  3. Proposal B (a `ParameterChangeProposal`) is submitted to increase the vote threshold to 80%
  4. Proposal B passes and executes via `handleParameterChangeProposal`, which calls `ss.Update()` to immediately modify the tally parameters in storage [5](#0-4) 
  5. When Proposal A's voting period ends, `EndBlocker` calls `Tally` which fetches the NEW 80% threshold [2](#0-1) 
  6. Proposal A fails with 60% YES votes under the new 80% threshold, even though it would have passed under the original rules

- **Security Failure:** This violates the governance invariant that voting rules should remain stable during an active vote. It breaks the fairness and predictability of the governance system, allowing retroactive rule changes that can manipulate proposal outcomes.

## Impact Explanation

This vulnerability affects the governance process of the blockchain:

- **Affected Process:** Any governance proposal being voted on can have its success criteria changed mid-vote by a parameter change proposal
- **Severity:** The governance router includes handlers for fund-related proposals like `CommunityPoolSpendProposal` [6](#0-5) , meaning proposals involving treasury funds could be affected
- **Concrete Damage:** 
  - Proposals that should pass under original rules can be made to fail
  - Proposals that should fail can be made to pass
  - Loss of governance integrity and predictability
  - Potential financial impact if proposals involve fund transfers
  - Undermines voter trust in the governance system
- **System Impact:** This matches the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - though funds could be at risk if combined with treasury proposals.

## Likelihood Explanation

- **Who can trigger:** Any participant who can submit and pass governance proposals. While this requires governance participation, it doesn't require privileged access.
- **Conditions required:** 
  - Two or more proposals must have overlapping voting periods
  - One must be a parameter change proposal modifying tally params
  - The parameter change proposal must pass before other proposals finish voting
- **Frequency:** This can occur whenever proposals overlap, which is realistic in active governance systems. The longer voting periods are, the more likely overlaps become. With default 2-day voting periods, multiple concurrent proposals are common.
- **Realistic scenario:** This is not a contrived edge case - governance systems regularly have multiple active proposals, and parameter changes are a normal governance function.

## Recommendation

Store a snapshot of tally parameters when a proposal enters the voting period, and use those snapshotted parameters when tallying, rather than fetching current parameters:

1. Modify the `Proposal` type to include `TallyParamsSnapshot` field
2. In `ActivateVotingPeriod` function [7](#0-6) , capture tally params at that moment and store them in the proposal
3. Modify `Tally` function to use `proposal.TallyParamsSnapshot` instead of calling `keeper.GetTallyParams(ctx)`
4. This ensures each proposal is evaluated under the rules that were active when voting began

## Proof of Concept

Add this test to `x/gov/keeper/tally_test.go`:

```go
func TestTallyParamsChangedMidVoting(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	// Create validators with voting power: 40%, 30%, 30%
	addrs, _ := createValidators(t, ctx, app, []int64{40, 30, 30})

	// Submit Proposal A (a text proposal)
	proposalA, err := app.GovKeeper.SubmitProposal(ctx, TestProposal)
	require.NoError(t, err)
	proposalAID := proposalA.ProposalId
	proposalA.Status = types.StatusVotingPeriod
	app.GovKeeper.SetProposal(ctx, proposalA)

	// Get initial tally params (default threshold is 0.5 = 50%)
	initialTallyParams := app.GovKeeper.GetTallyParams(ctx)
	require.Equal(t, sdk.NewDecWithPrec(5, 1), initialTallyParams.Threshold)

	// Validators vote on Proposal A: 70% YES (40% + 30%), 30% NO
	require.NoError(t, app.GovKeeper.AddVote(ctx, proposalAID, addrs[0], types.NewNonSplitVoteOption(types.OptionYes)))
	require.NoError(t, app.GovKeeper.AddVote(ctx, proposalAID, addrs[1], types.NewNonSplitVoteOption(types.OptionYes)))
	require.NoError(t, app.GovKeeper.AddVote(ctx, proposalAID, addrs[2], types.NewNonSplitVoteOption(types.OptionNo)))

	// Verify Proposal A would pass with current params (70% > 50% threshold)
	proposalA, _ = app.GovKeeper.GetProposal(ctx, proposalAID)
	passes, _, _ := app.GovKeeper.Tally(ctx, proposalA)
	require.True(t, passes, "Proposal A should pass with 70%% YES under 50%% threshold")

	// Submit and execute Proposal B to change tally threshold to 80%
	newTallyParamsJSON := `{"quorum":"0.334","expedited_quorum":"0.667","threshold":"0.8","expedited_threshold":"0.667","veto_threshold":"0.334"}`
	paramChangeProposal := &proposal.ParameterChangeProposal{
		Title:       "Increase Vote Threshold",
		Description: "Change threshold to 80%",
		Changes: []proposal.ParamChange{
			{
				Subspace: "gov",
				Key:      "tallyparams",
				Value:    newTallyParamsJSON,
			},
		},
	}

	// Execute the parameter change (simulating it passed)
	handler := app.GovKeeper.Router().GetRoute(paramChangeProposal.ProposalRoute())
	err = handler(ctx, paramChangeProposal)
	require.NoError(t, err)

	// Verify tally params changed to 80%
	newTallyParams := app.GovKeeper.GetTallyParams(ctx)
	require.Equal(t, sdk.NewDecWithPrec(8, 1), newTallyParams.Threshold)

	// Tally Proposal A again with the NEW params
	// The same 70% YES votes should now FAIL under 80% threshold
	proposalA, _ = app.GovKeeper.GetProposal(ctx, proposalAID)
	passes, _, _ = app.GovKeeper.Tally(ctx, proposalA)
	
	// VULNERABILITY: Proposal A now fails even though votes haven't changed
	// Rules changed mid-vote: 70% was sufficient under 50% threshold,
	// but insufficient under new 80% threshold
	require.False(t, passes, "VULNERABILITY DEMONSTRATED: Proposal A fails with same votes after mid-vote parameter change")
}
```

**Setup:** Creates validators with 40%, 30%, 30% voting power and initializes Proposal A in voting status.

**Trigger:** Casts votes (70% YES) that would pass under original 50% threshold, then executes a parameter change proposal that increases threshold to 80%.

**Observation:** The same Proposal A with unchanged votes now fails when tallied, demonstrating that the rules changed mid-vote. The test shows `passes` transitions from `true` to `false` without any vote changes, proving the vulnerability.

### Citations

**File:** x/gov/keeper/tally.go (L89-89)
```go
	tallyParams := keeper.GetTallyParams(ctx)
```

**File:** x/gov/keeper/tally.go (L101-119)
```go
	quorumThreshold := tallyParams.GetQuorum(proposal.IsExpedited)
	if percentVoting.LT(quorumThreshold) {
		return false, true, tallyResults
	}

	// If no one votes (everyone abstains), proposal fails
	if totalVotingPower.Sub(results[types.OptionAbstain]).Equal(sdk.ZeroDec()) {
		return false, false, tallyResults
	}

	// If more than 1/3 of voters veto, proposal fails
	if results[types.OptionNoWithVeto].Quo(totalVotingPower).GT(tallyParams.VetoThreshold) {
		return false, true, tallyResults
	}

	// If more than threshold of non-abstaining voters vote Yes, proposal passes
	// default value for regular proposals is 1/2. For expedited 2/3
	voteYesThreshold := tallyParams.GetThreshold(proposal.IsExpedited)
	if results[types.OptionYes].Quo(totalVotingPower.Sub(results[types.OptionAbstain])).GT(voteYesThreshold) {
```

**File:** x/gov/abci.go (L51-51)
```go
		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/params/proposal_handler.go (L26-42)
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
```

**File:** simapp/app.go (L306-309)
```go
	govRouter.AddRoute(govtypes.RouterKey, govtypes.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper)).
		AddRoute(distrtypes.RouterKey, distr.NewCommunityPoolSpendProposalHandler(app.DistrKeeper)).
		AddRoute(upgradetypes.RouterKey, upgrade.NewSoftwareUpgradeProposalHandler(app.UpgradeKeeper))
```

**File:** x/gov/keeper/proposal.go (L201-210)
```go
func (keeper Keeper) ActivateVotingPeriod(ctx sdk.Context, proposal types.Proposal) {
	proposal.VotingStartTime = ctx.BlockHeader().Time
	votingPeriod := keeper.GetVotingParams(ctx).GetVotingPeriod(proposal.IsExpedited)
	proposal.VotingEndTime = proposal.VotingStartTime.Add(votingPeriod)
	proposal.Status = types.StatusVotingPeriod
	keeper.SetProposal(ctx, proposal)

	keeper.RemoveFromInactiveProposalQueue(ctx, proposal.ProposalId, proposal.DepositEndTime)
	keeper.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
}
```
