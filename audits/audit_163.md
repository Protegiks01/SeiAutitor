# Audit Report

## Title
Vote Deletion Causes Vote Loss When Expedited Proposals Convert to Regular Proposals

## Summary
The governance module's `Tally` function deletes all votes immediately after processing them. When an expedited proposal fails to meet the higher voting threshold and converts to a regular proposal with an extended voting period, all votes cast during the expedited period are permanently lost. When the regular voting period ends and `Tally` is called again, there are no votes to count, causing the proposal to fail due to lack of quorum despite having received legitimate votes.

## Impact
Medium

## Finding Description

**Location:**
- Vote deletion: `x/gov/keeper/tally.go` line 69 [1](#0-0) 
- Expedited proposal conversion logic: `x/gov/abci.go` lines 95-106 [2](#0-1) 
- Initial tally call: `x/gov/abci.go` line 51 [3](#0-2) 

**Intended Logic:**
When an expedited proposal fails to meet the higher voting threshold, it should be converted to a regular proposal with an extended voting period. The code comment explicitly states "Once the regular voting period expires again, the tally is repeated according to the regular proposal rules" [4](#0-3) , implying that votes from the expedited period should be counted in the final tally.

**Actual Logic:**
The `Tally` function iterates over all votes and deletes each one during processing [5](#0-4) . When an expedited proposal's voting period ends, `EndBlocker` calls `Tally`, which processes and deletes all votes. If the proposal fails to pass the expedited threshold, it gets converted to a regular proposal [2](#0-1) , but all votes have already been deleted. When the extended voting period ends and `Tally` is called again, there are no votes to count, causing the proposal to fail the quorum check.

**Exploitation Path:**
1. Any user submits an expedited proposal with the required deposit
2. Validators and users vote on the proposal during the expedited voting period
3. The expedited voting period ends with insufficient votes to meet the expedited threshold (e.g., 55% YES but needs 67%)
4. `EndBlocker` calls `Tally`, which processes all votes and deletes them via `deleteVote`
5. The proposal is converted to a regular proposal with extended `VotingEndTime`
6. Voters assume their votes still count and wait for the extended period to end
7. When the regular voting period ends, `Tally` is called again but finds zero votes
8. The proposal fails due to lack of quorum (line 102-103 of tally.go), despite having received valid votes

**Security Guarantee Broken:**
The governance protocol's integrity is compromised by disenfranchising voters. Votes that were legitimately cast are lost and not counted in the final tally, violating the documented behavior and governance design.

## Impact Explanation

This vulnerability affects the core governance mechanism of the Cosmos SDK L1 blockchain:

- **Affected Process:** The governance voting system, specifically for expedited proposals that convert to regular proposals
- **Severity:** All votes cast during the expedited voting period are permanently lost when the proposal converts to regular, effectively nullifying voter participation
- **Protocol Impact:** Proposals that should pass (when considering all votes from both periods) will instead fail, or vice versa, leading to incorrect governance outcomes that could affect protocol parameters, upgrades, or other governance-controlled features

The code explicitly preserves deposits when expedited proposals convert to regular [6](#0-5) , showing the intent to preserve state for the second tally. However, votes are not similarly preserved, creating an inconsistency in the implementation.

This matches the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:** Any user can submit an expedited proposal and vote on it. This is normal governance participation requiring no special privileges.

**Conditions required:**
- An expedited proposal must be submitted and reach the voting period
- The proposal must receive votes during the expedited period
- The proposal must fail to meet the expedited threshold but still be valid enough to convert to regular

**Frequency:** This will occur every time an expedited proposal fails to meet its threshold and converts to regular, which is an expected and documented feature of the governance system. The existing test suite demonstrates this scenario [7](#0-6) , but the test works around the issue by adding new votes after conversion (line 521) rather than relying on votes from the expedited period [8](#0-7) .

## Recommendation

Modify the `Tally` function to accept a boolean parameter indicating whether this is a final tally or an intermediate tally:

```go
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal, deleteVotes bool) (passes bool, burnDeposits bool, tallyResults types.TallyResult)
```

For intermediate tallies (expedited proposals that may convert to regular), skip the vote deletion step. In `EndBlocker`:
- Call `Tally(ctx, proposal, false)` for expedited proposals (don't delete votes)
- Only delete votes if the proposal is not being converted to regular, or after the final tally of the regular proposal

Alternatively, refactor the vote deletion logic to only call `deleteVote` when the proposal reaches a terminal state (passed, rejected, or failed), not during intermediate tallies for proposals that will continue voting.

## Proof of Concept

**Test Scenario:**
The provided PoC test would demonstrate that:
1. A vote is cast during the expedited voting period and exists in storage
2. `EndBlocker` is called when the expedited period ends, triggering the first tally
3. The proposal converts from expedited to regular with extended voting period
4. The vote from the expedited period has been deleted from storage (can be verified with `GetVote`)
5. When the regular voting period ends and `EndBlocker` is called again, there are no votes to tally
6. The proposal fails due to lack of quorum, despite having received a legitimate vote

**Evidence from existing test:**
The test `TestExpeditedProposalPassAndConvertToRegular` in `x/gov/abci_test.go` demonstrates this behavior by working around it. After the proposal converts to regular (line 461), the test adds a NEW vote (line 521) for the regular proposal to potentially pass [8](#0-7) . This indicates that votes from the expedited period are not available for the regular tally, confirming the vulnerability.

## Notes

The vulnerability is confirmed by examining:
1. The vote deletion in the `Tally` function [1](#0-0) 
2. The expedited-to-regular conversion logic that extends the voting period [2](#0-1) 
3. The code comment stating the tally should be "repeated" [4](#0-3) 
4. The preservation of deposits but not votes during conversion [6](#0-5) 
5. The existing test's workaround of adding new votes after conversion [8](#0-7) 

This is a valid Medium severity vulnerability that breaks the governance protocol's integrity through an implementation inconsistency.

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

**File:** x/gov/abci_test.go (L519-523)
```go
			if tc.isRegularEventuallyPassing {
				// Validator votes YES, letting the converted regular proposal pass.
				err = app.GovKeeper.AddVote(ctx, proposal.ProposalId, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
				require.NoError(t, err)
			}
```
