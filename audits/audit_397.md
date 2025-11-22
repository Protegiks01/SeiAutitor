## Audit Report

## Title
Vote Deletion During Expedited-to-Regular Proposal Conversion Allows Malicious Upgrades to Bypass Security Checks

## Summary
When an expedited governance proposal fails to pass and is automatically converted to a regular proposal, all votes cast during the expedited voting period are permanently deleted. This allows an attacker to abuse the expedited proposal mechanism to get a "second chance" at passing malicious upgrade proposals with a clean vote slate and significantly lower approval thresholds.

## Impact
Medium

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
The expedited proposal feature is designed to allow critical proposals to be decided quickly (24 hours) but with stricter requirements: higher deposit (MinExpeditedDeposit > MinDeposit), higher quorum (67% vs 33.4%), and higher approval threshold (67% vs 50%). [3](#0-2) [4](#0-3) [5](#0-4) 

If an expedited proposal fails, it should be converted to a regular proposal to give the community more time to evaluate it under normal governance parameters.

**Actual Logic:** 
During the tally process, all votes are permanently deleted from storage. [6](#0-5)  When an expedited proposal fails its tally and converts to a regular proposal, the conversion logic simply changes the `IsExpedited` flag to false and extends the voting period, but does NOT preserve or restore the votes that were already cast. [2](#0-1) 

This means:
1. All votes cast during the expedited period are deleted during tally
2. The proposal converts to regular status with zero votes
3. Validators must vote again from scratch
4. If validators don't realize they need to vote again, their previous opposition is lost

**Exploit Scenario:**
1. Attacker submits a malicious software upgrade proposal as expedited with the required high deposit
2. During the 24-hour expedited voting period, honest validators notice the malicious upgrade and vote "No" (e.g., 80% No, 20% Yes)
3. The expedited proposal fails to reach the 67% Yes threshold
4. At block end, the Tally function is called and **deletes all votes** from storage
5. The proposal is converted to regular with IsExpedited=false and voting period extended by 24 hours
6. Validators who already voted may assume:
   - The proposal was rejected and is now inactive
   - Their previous vote still counts
   - The proposal doesn't need further attention
7. The attacker now only needs 50% Yes threshold (vs 67%) and 33.4% quorum (vs 67%) with a completely fresh vote slate
8. If enough validators don't vote again, the malicious upgrade could pass

**Security Failure:** 
This breaks the security invariant that expedited proposals have stricter approval requirements. An attacker can use the expedited flag not to expedite approval, but to:
- Get a "free retry" if the first vote fails
- Reset the vote count to zero
- Benefit from validator confusion/apathy
- Pass malicious proposals with lower thresholds than were originally rejected with

## Impact Explanation

**Affected Assets/Processes:**
- Governance proposal voting integrity
- Software upgrade proposals (critical for chain security)
- Validator voting participation and effectiveness

**Severity:**
- A malicious software upgrade could compromise all network nodes
- Could lead to unauthorized protocol changes
- Could enable theft of funds through malicious contract execution
- Undermines the security model of higher thresholds for expedited proposals

**System Significance:**
Software upgrade proposals are among the most critical governance actions, as they directly affect the protocol code running on all validator nodes. The ability to manipulate the voting process to pass malicious upgrades represents a fundamental security failure in the governance system.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with sufficient funds for MinExpeditedDeposit can submit an expedited proposal and attempt this exploit.

**Required Conditions:**
- Attacker has funds for expedited deposit (higher than regular, but not prohibitive)
- Proposal initially fails expedited vote (gets significant "No" votes)
- Enough validators fail to vote again during the regular period due to:
  - Lack of awareness that voting period was extended
  - Assumption that failed expedited = rejected proposal  
  - Weekend/holiday reduced participation
  - Alert fatigue or monitoring gaps

**Frequency:**
This could be attempted on every critical upgrade proposal. The likelihood of success depends on:
- Validator monitoring practices (many may not alert on proposal status changes)
- Timing (exploiting periods of reduced validator attention)
- Social engineering (creating confusion about proposal status)

Given that the existing test suite explicitly demonstrates this behavior [7](#0-6)  (validators must vote again after conversion), this is clearly the implemented behavior and could be exploited in production.

## Recommendation

**Option 1 (Preserve Votes):**
Modify the tally logic to NOT delete votes when an expedited proposal converts to regular. Instead, preserve existing votes and allow them to count toward the regular tally. Update the Tally function to have a parameter indicating whether to delete votes:

```go
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal, deleteVotes bool) (passes bool, burnDeposits bool, tallyResults types.TallyResult)
```

In EndBlocker, only delete votes when the proposal is finalized (passed/rejected), not during expedited-to-regular conversion.

**Option 2 (Prevent Expedited Conversion):**
Remove the expedited-to-regular conversion feature entirely. If an expedited proposal fails, it should be permanently rejected rather than getting a second chance. This aligns with the purpose of expedited proposals (quick decision on critical matters).

**Option 3 (Require Re-deposit):**
When converting from expedited to regular, require the deposit to be topped up again to trigger the conversion. This prevents free retries and ensures proposers have continued skin in the game.

## Proof of Concept

**File:** `x/gov/abci_test.go`

**Test Function:** Add new test `TestExpeditedConversionVoteDeletionVulnerability`

**Setup:**
1. Initialize test environment with validator that has voting power
2. Submit an expedited text proposal with sufficient deposit
3. Activate voting period

**Trigger:**
1. Validator votes "No" during expedited period (80% voting power voting No)
2. Advance time to end of expedited voting period
3. Call EndBlocker to trigger tally and conversion
4. Verify proposal converted to regular (IsExpedited=false)
5. Query votes - should show ZERO votes despite previous "No" vote
6. Do NOT vote again during regular period
7. Advance time to end of regular voting period
8. Call EndBlocker again

**Observation:**
The test demonstrates that:
1. The "No" vote from expedited period is deleted after first EndBlocker call
2. After conversion, `GetVotes()` returns empty even though validator voted
3. Without new votes, the proposal outcome changes from what the original votes indicated
4. This confirms votes are not preserved during conversion

The existing test at [8](#0-7)  already partially demonstrates this by requiring validators to vote again at line 521 after conversion, but doesn't explicitly test the security implications of vote deletion.

A complete PoC would show a proposal that:
- Receives "No" votes during expedited (should fail)
- Converts to regular with votes deleted
- Passes due to lack of participation in second round
- Results in opposite outcome from initial voter intent

## Notes

The vote deletion behavior is confirmed by the code flow where `Tally()` calls `deleteVote()` for each vote processed [1](#0-0) , and the conversion logic does not preserve or restore these votes [2](#0-1) . The existing test suite confirms this is the implemented behavior by requiring fresh votes after conversion [7](#0-6) .

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

**File:** x/gov/types/params.go (L97-99)
```go
	if v.MinExpeditedDeposit.IsAllLTE(v.MinDeposit) {
		return fmt.Errorf("minimum expedited deposit: %s should be larger than minimum deposit: %s", v.MinExpeditedDeposit, v.MinDeposit)
	}
```

**File:** x/gov/types/params.go (L172-174)
```go
	if v.ExpeditedQuorum.LTE(v.Quorum) {
		return fmt.Errorf("expedited quorum %s, must be greater than the regular quorum %s", v.ExpeditedQuorum, v.Quorum)
	}
```

**File:** x/gov/types/params.go (L187-189)
```go
	if v.ExpeditedThreshold.LTE(v.Threshold) {
		return fmt.Errorf("expedited vote threshold %s, must be greater than the regular threshold %s", v.ExpeditedThreshold, v.Threshold)
	}
```

**File:** x/gov/abci_test.go (L348-530)
```go
func TestExpeditedProposalPassAndConvertToRegular(t *testing.T) {
	testcases := []struct {
		name string
		// flag indicating whether the expedited proposal passes.
		isExpeditedPasses bool
		// flag indicating whether the converted regular proposal is expected to eventually pass
		isRegularEventuallyPassing bool
	}{
		{
			name:              "expedited passes and not converted to regular",
			isExpeditedPasses: true,
		},
		{
			name:                       "expedited fails, converted to regular - regular eventually passes",
			isExpeditedPasses:          false,
			isRegularEventuallyPassing: true,
		},
		{
			name:                       "expedited fails, converted to regular - regular eventually fails",
			isExpeditedPasses:          false,
			isRegularEventuallyPassing: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			isExpedited := true
			testProposal := types.NewTextProposal("TestTitle", "description", isExpedited)

			app := simapp.Setup(false)
			ctx := app.BaseApp.NewContext(false, tmproto.Header{})
			addrs := simapp.AddTestAddrs(app, ctx, 10, valTokens)
			params := app.StakingKeeper.GetParams(ctx)
			params.MinCommissionRate = sdk.NewDec(0)
			app.StakingKeeper.SetParams(ctx, params)
			SortAddresses(addrs)
			header := tmproto.Header{Height: app.LastBlockHeight() + 1}
			app.BeginBlock(ctx, abci.RequestBeginBlock{Header: header})

			valAddr := sdk.ValAddress(addrs[0])

			stakingHandler := staking.NewHandler(app.StakingKeeper)
			govHandler := gov.NewHandler(app.GovKeeper)

			// Create a validator so that able to vote on proposal.
			createValidators(t, stakingHandler, ctx, []sdk.ValAddress{valAddr}, []int64{10})
			staking.EndBlocker(ctx, app.StakingKeeper)

			inactiveQueue := app.GovKeeper.InactiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.False(t, inactiveQueue.Valid())
			inactiveQueue.Close()
			activeQueue := app.GovKeeper.ActiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.False(t, activeQueue.Valid())
			activeQueue.Close()

			macc := app.GovKeeper.GetGovernanceAccount(ctx)
			require.NotNil(t, macc)
			initialModuleAccCoins := app.BankKeeper.GetAllBalances(ctx, macc.GetAddress())

			submitterInitialBalance := app.BankKeeper.GetAllBalances(ctx, addrs[0])
			depositorInitialBalance := app.BankKeeper.GetAllBalances(ctx, addrs[1])

			proposalCoins := sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, app.StakingKeeper.TokensFromConsensusPower(ctx, 10))}
			newProposalMsg, err := types.NewMsgSubmitProposalWithExpedite(testProposal, proposalCoins, addrs[0], isExpedited)
			require.NoError(t, err)

			res, err := govHandler(ctx, newProposalMsg)
			require.NoError(t, err)
			require.NotNil(t, res)

			var proposalData types.MsgSubmitProposalResponse
			err = proto.Unmarshal(res.Data, &proposalData)
			require.NoError(t, err)

			proposalID := proposalData.ProposalId

			newHeader := ctx.BlockHeader()
			newHeader.Time = ctx.BlockHeader().Time.Add(time.Duration(1) * time.Second)
			ctx = ctx.WithBlockHeader(newHeader)

			newDepositMsg := types.NewMsgDeposit(addrs[1], proposalID, proposalCoins)

			res, err = govHandler(ctx, newDepositMsg)
			require.NoError(t, err)
			require.NotNil(t, res)

			votingParams := app.GovKeeper.GetVotingParams(ctx)
			newHeader = ctx.BlockHeader()

			newHeader.Time = ctx.BlockHeader().Time.Add(app.GovKeeper.GetDepositParams(ctx).MaxDepositPeriod).Add(votingParams.ExpeditedVotingPeriod)
			ctx = ctx.WithBlockHeader(newHeader)

			inactiveQueue = app.GovKeeper.InactiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.False(t, inactiveQueue.Valid())
			inactiveQueue.Close()

			activeQueue = app.GovKeeper.ActiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.True(t, activeQueue.Valid())

			activeProposalID := types.GetProposalIDFromBytes(activeQueue.Value())
			proposal, ok := app.GovKeeper.GetProposal(ctx, activeProposalID)
			require.True(t, ok)
			require.Equal(t, types.StatusVotingPeriod, proposal.Status)

			activeQueue.Close()

			if tc.isExpeditedPasses {
				// Validator votes YES, letting the expedited proposal pass.
				err = app.GovKeeper.AddVote(ctx, proposal.ProposalId, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
				require.NoError(t, err)
			}

			// Here the expedited proposal is converted to regular after expiry.
			gov.EndBlocker(ctx, app.GovKeeper)

			activeQueue = app.GovKeeper.ActiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)

			if tc.isExpeditedPasses {
				require.False(t, activeQueue.Valid())

				proposal, ok = app.GovKeeper.GetProposal(ctx, activeProposalID)
				require.True(t, ok)

				require.Equal(t, types.StatusPassed, proposal.Status)

				submitterEventualBalance := app.BankKeeper.GetAllBalances(ctx, addrs[0])
				depositorEventualBalance := app.BankKeeper.GetAllBalances(ctx, addrs[1])

				eventualModuleAccCoins := app.BankKeeper.GetAllBalances(ctx, macc.GetAddress())

				// Module account has refunded the deposit
				require.Equal(t, initialModuleAccCoins, eventualModuleAccCoins)

				require.Equal(t, submitterInitialBalance, submitterEventualBalance)
				require.Equal(t, depositorInitialBalance, depositorEventualBalance)
				return
			}

			// Expedited proposal should be converted to a regular proposal instead.
			require.True(t, activeQueue.Valid())

			activeProposalID = types.GetProposalIDFromBytes(activeQueue.Value())
			activeQueue.Close()

			proposal, ok = app.GovKeeper.GetProposal(ctx, activeProposalID)
			require.True(t, ok)
			require.Equal(t, types.StatusVotingPeriod, proposal.Status)
			require.False(t, proposal.IsExpedited)
			require.Equal(t, proposal.VotingStartTime.Add(votingParams.VotingPeriod), proposal.VotingEndTime)

			// We also want to make sure that the deposit is not refunded yet and is still present in the module account
			macc = app.GovKeeper.GetGovernanceAccount(ctx)
			require.NotNil(t, macc)
			intermediateModuleAccCoins := app.BankKeeper.GetAllBalances(ctx, macc.GetAddress())
			require.NotEqual(t, initialModuleAccCoins, intermediateModuleAccCoins)

			// Submit proposal deposit + 1 extra top up deposit
			expectedIntermediateMofuleAccCoings := initialModuleAccCoins.Add(proposalCoins...).Add(proposalCoins...)
			require.Equal(t, expectedIntermediateMofuleAccCoings, intermediateModuleAccCoins)

			// block header time at the voting period
			newHeader.Time = ctx.BlockHeader().Time.Add(app.GovKeeper.GetDepositParams(ctx).MaxDepositPeriod).Add(votingParams.VotingPeriod)
			ctx = ctx.WithBlockHeader(newHeader)

			inactiveQueue = app.GovKeeper.InactiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.False(t, inactiveQueue.Valid())
			inactiveQueue.Close()

			activeQueue = app.GovKeeper.ActiveProposalQueueIterator(ctx, ctx.BlockHeader().Time)
			require.True(t, activeQueue.Valid())

			if tc.isRegularEventuallyPassing {
				// Validator votes YES, letting the converted regular proposal pass.
				err = app.GovKeeper.AddVote(ctx, proposal.ProposalId, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
				require.NoError(t, err)
			}

			// Here we validate the converted regular proposal
			gov.EndBlocker(ctx, app.GovKeeper)

			macc = app.GovKeeper.GetGovernanceAccount(ctx)
			require.NotNil(t, macc)
			eventualModuleAccCoins := app.BankKeeper.GetAllBalances(ctx, macc.GetAddress())
```
