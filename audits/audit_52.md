# Audit Report

## Title
Vote Deletion Causes Vote Loss When Expedited Proposals Convert to Regular Proposals

## Summary
The governance module's `Tally` function unconditionally deletes all votes during processing. When an expedited proposal fails its threshold and converts to a regular proposal with an extended voting period, all votes cast during the expedited period are permanently deleted. The second tally finds no votes, causing the proposal to fail due to lack of quorum despite having received legitimate votes.

## Impact
Medium

## Finding Description

**Location:**
- Vote deletion: `x/gov/keeper/tally.go` line 69
- Expedited-to-regular conversion: `x/gov/abci.go` lines 95-106  
- Tally invocation: `x/gov/abci.go` line 51
- Vote deletion implementation: `x/gov/keeper/vote.go` lines 127-130

**Intended Logic:**
When an expedited proposal fails to meet the higher voting threshold, it should convert to a regular proposal with an extended voting period. The code comment explicitly states "Once the regular voting period expires again, the tally is repeated according to the regular proposal rules" [1](#0-0) , indicating that votes from the expedited period should be counted in the final tally. This interpretation is supported by the fact that deposits are explicitly preserved during conversion [2](#0-1) .

**Actual Logic:**
The `Tally` function iterates over all votes and unconditionally deletes each one via `keeper.deleteVote(ctx, vote.ProposalId, voter)` [3](#0-2) . The `deleteVote` function permanently removes votes from storage [4](#0-3) . When an expedited proposal's voting period ends, `EndBlocker` calls `Tally` [5](#0-4) , which deletes all votes. If the proposal then converts to regular [6](#0-5) , the votes are already gone. When the regular voting period ends and `Tally` is called again, no votes exist to count.

**Exploitation Path:**
1. Any user submits an expedited proposal with required deposit
2. Validators and delegators vote during the expedited voting period
3. Expedited voting period ends with votes insufficient for expedited threshold (e.g., 55% YES vs 67% required)
4. `EndBlocker` invokes `Tally`, which processes and deletes all votes
5. Proposal converts to regular with extended `VotingEndTime`
6. Regular voting period expires
7. `EndBlocker` invokes `Tally` again but finds zero votes
8. Proposal fails quorum check despite having received legitimate votes

**Security Guarantee Broken:**
The governance protocol's integrity is violated. Votes legitimately cast are not counted in the final tally, contradicting the documented behavior that the tally should be "repeated" and creating an inconsistency where deposits are preserved but votes are not.

## Impact Explanation

This vulnerability affects the core governance mechanism of the Cosmos SDK Layer 1 blockchain. All votes cast during the expedited voting period are permanently lost when the proposal converts to regular, effectively nullifying voter participation. Governance proposals that should pass (considering all votes from both periods) will instead fail, or vice versa, leading to incorrect governance outcomes that affect protocol parameters, upgrades, and other governance-controlled features.

The issue fits the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." The governance module is Layer 1 network code exhibiting unintended behavior (vote loss), with no direct fund loss (deposits are preserved).

## Likelihood Explanation

**Who can trigger:** Any participant in governance - this requires no special privileges beyond normal governance participation.

**Conditions required:**
- An expedited proposal must be submitted and reach voting period
- The proposal must receive votes during expedited period  
- The proposal must fail expedited threshold but remain valid for conversion to regular

**Frequency:** This occurs whenever an expedited proposal fails its threshold and converts to regular, which is an expected and documented feature. The existing test suite demonstrates this exact scenario [7](#0-6) , but works around the issue by adding a NEW vote after conversion [8](#0-7)  rather than relying on votes from the expedited period, confirming that votes are not preserved.

## Recommendation

Modify the `Tally` function to accept a boolean parameter indicating whether votes should be deleted:

```go
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal, deleteVotes bool) (passes bool, burnDeposits bool, tallyResults types.TallyResult)
```

In `EndBlocker`, call `Tally(ctx, proposal, false)` for expedited proposals that may convert to regular, and only delete votes after the final tally or when a proposal reaches a terminal state (passed, rejected, failed). Alternatively, refactor to only call `deleteVote` when the proposal is in a terminal state, not during intermediate tallies.

## Proof of Concept

The existing test `TestExpeditedProposalPassAndConvertToRegular` in `x/gov/abci_test.go` demonstrates this behavior. After the proposal converts from expedited to regular at line 461 [9](#0-8) , the test adds a NEW vote at line 521 [8](#0-7)  for the regular proposal to potentially pass. This confirms that votes from the expedited period are not available for the regular tally.

**Test scenario verification:**
1. Vote is cast during expedited period (exists in storage)
2. `EndBlocker` called when expedited period ends, triggering first tally  
3. Proposal converts from expedited to regular with extended voting period
4. Vote from expedited period has been deleted from storage (verifiable via `GetVote`)
5. When regular voting period ends and `EndBlocker` called again, no votes exist
6. Proposal fails due to lack of quorum despite having received legitimate votes

## Notes

The vulnerability is confirmed by multiple evidence points:
- Unconditional vote deletion in `Tally` [3](#0-2) 
- Conversion logic extending voting period [6](#0-5)   
- Code comment stating tally should be "repeated" [1](#0-0) 
- Preservation of deposits but not votes [2](#0-1) 
- Existing test's workaround of adding new votes after conversion [8](#0-7) 

This is a valid Medium severity vulnerability that breaks the governance protocol's integrity through an implementation inconsistency between documented intent and actual behavior.

### Citations

**File:** x/gov/abci.go (L51-51)
```go
		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
```

**File:** x/gov/abci.go (L53-63)
```go
		// If an expedited proposal fails, we do not want to update
		// the deposit at this point since the proposal is converted to regular.
		// As a result, the deposits are either deleted or refunded in all casses
		// EXCEPT when an expedited proposal fails.
		if !(proposal.IsExpedited && !passes) {
			if burnDeposits {
				keeper.DeleteDeposits(ctx, proposal.ProposalId)
			} else {
				keeper.RefundDeposits(ctx, proposal.ProposalId)
			}
		}
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

**File:** x/gov/keeper/tally.go (L69-69)
```go
		keeper.deleteVote(ctx, vote.ProposalId, voter)
```

**File:** x/gov/keeper/vote.go (L127-130)
```go
func (keeper Keeper) deleteVote(ctx sdk.Context, proposalID uint64, voterAddr sdk.AccAddress) {
	store := ctx.KVStore(keeper.storeKey)
	store.Delete(types.VoteKey(proposalID, voterAddr))
}
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

**File:** x/gov/abci_test.go (L461-461)
```go
			gov.EndBlocker(ctx, app.GovKeeper)
```

**File:** x/gov/abci_test.go (L519-523)
```go
			if tc.isRegularEventuallyPassing {
				// Validator votes YES, letting the converted regular proposal pass.
				err = app.GovKeeper.AddVote(ctx, proposal.ProposalId, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
				require.NoError(t, err)
			}
```
