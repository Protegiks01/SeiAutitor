# Audit Report

## Title
Vote Deletion Causes Vote Loss When Expedited Proposals Convert to Regular Proposals

## Summary
The `Tally` function deletes all votes immediately after processing them, but when an expedited proposal fails and is converted to a regular proposal with an extended voting period, all votes cast during the expedited period are permanently lost because they were already deleted during the first tally. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Vote deletion: [2](#0-1) 
- Expedited proposal conversion logic: [3](#0-2) 
- Initial tally call: [4](#0-3) 

**Intended Logic:** 
When an expedited proposal fails to meet the higher voting threshold, it should be converted to a regular proposal with an extended voting period. The code comments explicitly state "Once the regular voting period expires again, the tally is repeated according to the regular proposal rules" [5](#0-4) , implying that votes from the expedited period should be counted in the final tally.

**Actual Logic:** 
The `Tally` function deletes each vote immediately after processing it [6](#0-5) . When an expedited proposal's voting period ends, `Tally` is called and deletes all votes. If the proposal fails to pass the expedited threshold, it gets converted to a regular proposal [7](#0-6) , but all votes have already been deleted. When the extended voting period ends and `Tally` is called again, there are no votes to count, causing the proposal to fail due to lack of quorum.

**Exploit Scenario:**
1. User submits an expedited proposal and deposits the required amount
2. Multiple validators/users vote on the proposal during the expedited voting period
3. The expedited voting period ends with insufficient votes to meet the expedited threshold (e.g., needs 67% but only has 55%)
4. EndBlocker calls `Tally`, which processes and deletes all votes
5. The proposal is converted to a regular proposal with extended voting period
6. Users assume their votes still count and wait for the extended period to end
7. When the regular voting period ends, `Tally` is called again but finds zero votes
8. The proposal fails due to lack of quorum, despite having received valid votes

**Security Failure:** 
This breaks the governance protocol's integrity by disenfranchising voters. Votes that were legitimately cast are lost and not counted in the final tally, violating the intended behavior described in the code comments and the governance design.

## Impact Explanation

This vulnerability affects the governance mechanism of the L1 blockchain protocol:

- **Affected Process:** The governance voting system, specifically for expedited proposals that convert to regular proposals
- **Severity:** All votes cast during the expedited voting period are permanently lost when the proposal converts to regular, effectively nullifying voter participation
- **Protocol Impact:** Proposals that should pass (when considering all votes from both expedited and regular periods) will instead fail, or vice versa, leading to incorrect governance outcomes that could affect protocol parameters, upgrades, or other governance-controlled features

The comment on deposit handling explicitly preserves deposits when expedited proposals convert to regular [8](#0-7) , showing the intent to preserve state for the second tally. However, votes are not similarly preserved, creating an inconsistency in the implementation.

## Likelihood Explanation

**Who can trigger:** Any user can submit an expedited proposal and vote on it. This is normal governance participation requiring no special privileges.

**Conditions required:** 
- An expedited proposal must be submitted and reach the voting period
- The proposal must receive votes during the expedited period
- The proposal must fail to meet the expedited threshold but still be valid
- This converts it to a regular proposal

**Frequency:** This will occur every time an expedited proposal fails to meet its threshold and converts to regular, which is an expected and documented feature of the governance system. The existing test suite even demonstrates this scenario [9](#0-8) , but works around the issue by adding new votes after conversion rather than relying on votes from the expedited period.

## Recommendation

Modify the `Tally` function to accept a boolean parameter indicating whether this is a final tally or an intermediate tally. For intermediate tallies (expedited proposals that may convert to regular), skip the vote deletion step:

```
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal, deletevotes bool) (...)
```

Then in `EndBlocker`, call:
- `Tally(ctx, proposal, false)` for expedited proposals (don't delete votes)
- Only delete votes if the proposal is not being converted to regular, or after the final tally of the regular proposal

Alternatively, only call `deleteVote` when the proposal reaches a terminal state (passed, rejected, or failed), not during intermediate tallies for proposals that will continue voting.

## Proof of Concept

**Test File:** `x/gov/abci_test.go`

**Test Function:** Add this new test function:

```go
func TestExpeditedProposalVotesLostOnConversion(t *testing.T) {
    // Setup: Create app, context, and validator
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    addrs := simapp.AddTestAddrs(app, ctx, 10, valTokens)
    params := app.StakingKeeper.GetParams(ctx)
    params.MinCommissionRate = sdk.NewDec(0)
    app.StakingKeeper.SetParams(ctx, params)
    
    stakingHandler := staking.NewHandler(app.StakingKeeper)
    govHandler := gov.NewHandler(app.GovKeeper)
    
    // Create validator
    valAddr := sdk.ValAddress(addrs[0])
    createValidators(t, stakingHandler, ctx, []sdk.ValAddress{valAddr}, []int64{10})
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Submit expedited proposal
    testProposal := types.NewTextProposal("Test", "description", true)
    proposalCoins := sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, app.StakingKeeper.TokensFromConsensusPower(ctx, 10))}
    newProposalMsg, err := types.NewMsgSubmitProposalWithExpedite(testProposal, proposalCoins, addrs[0], true)
    require.NoError(t, err)
    
    res, err := govHandler(ctx, newProposalMsg)
    require.NoError(t, err)
    
    var proposalData types.MsgSubmitProposalResponse
    proto.Unmarshal(res.Data, &proposalData)
    proposalID := proposalData.ProposalId
    
    // Deposit to activate proposal
    newDepositMsg := types.NewMsgDeposit(addrs[1], proposalID, proposalCoins)
    govHandler(ctx, newDepositMsg)
    
    // Cast vote during expedited period (will vote YES but not enough to pass expedited threshold)
    err = app.GovKeeper.AddVote(ctx, proposalID, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
    require.NoError(t, err)
    
    // Verify vote exists
    vote, found := app.GovKeeper.GetVote(ctx, proposalID, addrs[0])
    require.True(t, found)
    require.Equal(t, types.OptionYes, vote.Options[0].Option)
    
    // Fast forward to end of expedited voting period (proposal will fail expedited threshold and convert to regular)
    votingParams := app.GovKeeper.GetVotingParams(ctx)
    newHeader := ctx.BlockHeader()
    newHeader.Time = ctx.BlockHeader().Time.Add(app.GovKeeper.GetDepositParams(ctx).MaxDepositPeriod).Add(votingParams.ExpeditedVotingPeriod)
    ctx = ctx.WithBlockHeader(newHeader)
    
    // Trigger: EndBlocker processes expedited proposal, tallies (deletes votes), and converts to regular
    gov.EndBlocker(ctx, app.GovKeeper)
    
    // Observation 1: Proposal should be converted to regular
    proposal, ok := app.GovKeeper.GetProposal(ctx, proposalID)
    require.True(t, ok)
    require.False(t, proposal.IsExpedited, "Proposal should be converted to regular")
    require.Equal(t, types.StatusVotingPeriod, proposal.Status)
    
    // Observation 2: BUG - Vote from expedited period has been deleted!
    vote, found = app.GovKeeper.GetVote(ctx, proposalID, addrs[0])
    require.False(t, found, "BUG: Vote should still exist but was deleted during tally!")
    
    // Fast forward to end of regular voting period
    newHeader.Time = proposal.VotingEndTime
    ctx = ctx.WithBlockHeader(newHeader)
    
    // Trigger second tally
    gov.EndBlocker(ctx, app.GovKeeper)
    
    // Observation 3: Proposal fails due to no votes (quorum not met)
    proposal, ok = app.GovKeeper.GetProposal(ctx, proposalID)
    require.True(t, ok)
    require.Equal(t, types.StatusRejected, proposal.Status, "Proposal failed due to lost votes")
    
    // This demonstrates that the vote from the expedited period was lost,
    // causing the proposal to fail when it should have been counted
}
```

**Setup:** Creates a blockchain context, validators, and an expedited governance proposal.

**Trigger:** 
1. A vote is cast during the expedited voting period
2. EndBlocker is called when the expedited period ends
3. The proposal fails the expedited threshold and converts to regular
4. EndBlocker is called again when the regular period ends

**Observation:** The test demonstrates that:
1. The vote exists after being cast
2. The vote is deleted during the first EndBlocker call (when expedited period ends)
3. The vote does not exist when the regular period ends
4. The proposal fails due to lack of votes, even though a valid vote was cast

This confirms the vulnerability: votes from the expedited period are deleted and not counted in the final tally after conversion to regular.

### Citations

**File:** x/gov/keeper/tally.go (L36-71)
```go
	keeper.IterateVotes(ctx, proposal.ProposalId, func(vote types.Vote) bool {
		// if validator, just record it in the map
		voter := sdk.MustAccAddressFromBech32(vote.Voter)

		valAddrStr := sdk.ValAddress(voter.Bytes()).String()
		if val, ok := currValidators[valAddrStr]; ok {
			val.Vote = vote.Options
			currValidators[valAddrStr] = val
		}

		// iterate over all delegations from voter, deduct from any delegated-to validators
		keeper.sk.IterateDelegations(ctx, voter, func(index int64, delegation stakingtypes.DelegationI) (stop bool) {
			valAddrStr := delegation.GetValidatorAddr().String()

			if val, ok := currValidators[valAddrStr]; ok {
				// There is no need to handle the special case that validator address equal to voter address.
				// Because voter's voting power will tally again even if there will deduct voter's voting power from validator.
				val.DelegatorDeductions = val.DelegatorDeductions.Add(delegation.GetShares())
				currValidators[valAddrStr] = val

				// delegation shares * bonded / total shares
				votingPower := delegation.GetShares().MulInt(val.BondedTokens).Quo(val.DelegatorShares)

				for _, option := range vote.Options {
					subPower := votingPower.Mul(option.Weight)
					results[option.Option] = results[option.Option].Add(subPower)
				}
				totalVotingPower = totalVotingPower.Add(votingPower)
			}

			return false
		})

		keeper.deleteVote(ctx, vote.ProposalId, voter)
		return false
	})
```

**File:** x/gov/keeper/tally.go (L127-130)
```go

```

**File:** x/gov/abci.go (L51-51)
```go
		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/gov/abci.go (L53-56)
```go
		// If an expedited proposal fails, we do not want to update
		// the deposit at this point since the proposal is converted to regular.
		// As a result, the deposits are either deleted or refunded in all casses
		// EXCEPT when an expedited proposal fails.
```

**File:** x/gov/abci.go (L95-106)
```go
			if proposal.IsExpedited {
				// When expedited proposal fails, it is converted to a regular proposal.
				// As a result, the voting period is extended.
				// Once the regular voting period expires again, the tally is repeated
				// according to the regular proposal rules.
				proposal.IsExpedited = false
				votingParams := keeper.GetVotingParams(ctx)
				proposal.VotingEndTime = proposal.VotingStartTime.Add(votingParams.VotingPeriod)

				keeper.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
				tagValue = types.AttributeValueExpeditedConverted
				logMsg = "expedited proposal converted to regular"
```

**File:** x/gov/abci_test.go (L361-369)
```go
			name:                       "expedited fails, converted to regular - regular eventually passes",
			isExpeditedPasses:          false,
			isRegularEventuallyPassing: true,
		},
		{
			name:                       "expedited fails, converted to regular - regular eventually fails",
			isExpeditedPasses:          false,
			isRegularEventuallyPassing: false,
		},
```
