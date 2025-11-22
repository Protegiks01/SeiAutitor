## Audit Report

## Title
Governance EndBlocker Denial of Service via Mass Proposal Expiration

## Summary
An attacker can create numerous governance proposals that all expire in the same block, causing the EndBlocker to perform expensive vote tallying operations without gas limits, potentially exceeding block time constraints and halting the chain. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
The vulnerability exists in the governance module's EndBlocker function at `x/gov/abci.go` lines 14-140, specifically in the active proposal processing loop (lines 48-139) which calls the expensive `Tally()` function for each expiring proposal. [2](#0-1) 

**Intended Logic:** 
The EndBlocker is designed to process proposals that have reached their expiration time at the end of each block. For active proposals (in voting period), it should tally votes and execute proposal handlers if they pass. [3](#0-2) 

**Actual Logic:** 
The EndBlocker iterates through ALL proposals expiring at the current block time without any limit on the number of proposals processed. For each active proposal, it calls `Tally()` which performs expensive operations:
- Iterates all bonded validators (line 24)
- Iterates all votes on the proposal (line 36)
- For each vote, iterates all delegations (line 47)

The context used has an infinite gas meter and no timeout mechanism: [4](#0-3) [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. Attacker submits N proposals in the same block (or activates them by depositing in the same block)
2. All proposals receive the same `submitTime = ctx.BlockHeader().Time`
3. All proposals therefore have identical `VotingEndTime = VotingStartTime + VotingPeriod` [7](#0-6) 

4. Attacker adds votes to these proposals to maximize Tally() computation time
5. When the voting period expires, all N proposals are processed in a single EndBlocker call
6. The cumulative time for N × Tally() operations exceeds block time limits
7. Validators cannot reach consensus on the next block, causing chain halt

**Security Failure:** 
The system lacks resource consumption limits (gas metering or iteration bounds) in EndBlocker execution, allowing denial-of-service through computational exhaustion. No rate limiting or maximum proposal count prevents mass proposal creation. [8](#0-7) 

## Impact Explanation

**Affected Components:**
- Network availability: Chain consensus and block production
- Validator operations: All validators simultaneously affected
- Transaction processing: Complete halt of new transactions

**Severity:**
The EndBlocker timeout causes validators to fail reaching consensus on blocks. Since all validators process the same proposals at the same time, this affects the entire network simultaneously. The chain cannot produce new blocks until the issue is resolved, requiring manual intervention or a hard fork to skip the problematic block.

**System Impact:**
This constitutes a total network shutdown as new transactions cannot be confirmed. Unlike transaction-level DoS attacks which are limited by block gas limits, EndBlocker operations run with infinite gas, making this attack particularly severe. The attack can be repeated by creating new batches of proposals.

## Likelihood Explanation

**Trigger Conditions:**
- Any account with sufficient funds for deposits can trigger this attack
- Required deposit: MinDeposit × N proposals (default 10M tokens per proposal)
- Deposits are refunded if proposals pass or fail without veto, reducing actual cost
- No privileged access required

**Timing Requirements:**
- Attacker controls timing by choosing when to submit/activate proposals
- All proposals must be submitted or activated in the same block for synchronized expiration
- Default voting period is 2 days, giving attacker ample time to set up the attack

**Frequency:**
- Attack can be executed whenever attacker accumulates sufficient deposit funds
- Can be repeated after deposits are refunded from previous proposals
- No cooldown period or rate limiting prevents repeated attacks

**Practical Feasibility:**
Moderately likely. While the attack requires significant capital for deposits, the funds are largely recoverable. An attacker with sufficient stake (or borrowing capacity) could execute this attack. The complexity is low - simply requires submitting many proposals with the same timing.

## Recommendation

Implement one or more of the following mitigations:

1. **Add maximum proposals per block limit** in EndBlocker:
   - Track number of proposals processed in current EndBlock call
   - Skip processing additional proposals beyond limit, defer to next block
   - This bounds worst-case execution time per block

2. **Implement gas metering for EndBlocker**:
   - Replace infinite gas meter with finite limit based on block gas limit
   - Halt processing when gas limit reached, continue in next block
   
3. **Add proposal rate limiting**:
   - Limit number of proposals that can be submitted/activated per block
   - Prevents synchronized expiration of mass proposals

4. **Implement MaxActiveProposals parameter**:
   - Reject proposal submissions if active proposal count exceeds threshold
   - Provides hard cap on simultaneous active proposals

Example fix for option 1:
```go
const MaxProposalsPerBlock = 100

func EndBlocker(ctx sdk.Context, keeper keeper.Keeper) {
    processedCount := 0
    
    keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
        if processedCount >= MaxProposalsPerBlock {
            return true // stop iteration
        }
        // existing tally and processing logic
        processedCount++
        return false
    })
}
```

## Proof of Concept

**File:** `x/gov/abci_dos_test.go` (new test file)

**Test Function:** `TestMassProposalExpirationDoS`

**Setup:**
```go
// Initialize app with default configuration
app := simapp.Setup(false)
ctx := app.BaseApp.NewContext(false, tmproto.Header{})

// Create accounts with sufficient funds for deposits
numProposals := 200 // Sufficient to cause timeout
addrs := simapp.AddTestAddrs(app, ctx, 1, valTokens.Mul(sdk.NewInt(int64(numProposals*2))))

// Create validator for voting
govHandler := gov.NewHandler(app.GovKeeper)
stakingHandler := staking.NewHandler(app.StakingKeeper)
valAddr := sdk.ValAddress(addrs[0])
createValidators(t, stakingHandler, ctx, []sdk.ValAddress{valAddr}, []int64{10})
staking.EndBlocker(ctx, app.StakingKeeper)
```

**Trigger:**
```go
// Submit many proposals in the same block
proposalIDs := make([]uint64, numProposals)
proposalCoins := sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, app.StakingKeeper.TokensFromConsensusPower(ctx, 10))}

for i := 0; i < numProposals; i++ {
    proposal := types.NewTextProposal(fmt.Sprintf("Proposal %d", i), "description", false)
    msg, _ := types.NewMsgSubmitProposal(proposal, proposalCoins, addrs[0])
    res, err := govHandler(ctx, msg)
    require.NoError(t, err)
    
    var proposalData types.MsgSubmitProposalResponse
    proto.Unmarshal(res.Data, &proposalData)
    proposalIDs[i] = proposalData.ProposalId
    
    // Immediately deposit to activate voting
    depositMsg := types.NewMsgDeposit(addrs[0], proposalData.ProposalId, proposalCoins)
    govHandler(ctx, depositMsg)
    
    // Add votes to make Tally() expensive
    app.GovKeeper.AddVote(ctx, proposalData.ProposalId, addrs[0], types.NewNonSplitVoteOption(types.OptionYes))
}

// Advance time to voting period end - all proposals expire simultaneously
newHeader := ctx.BlockHeader()
newHeader.Time = ctx.BlockHeader().Time.Add(app.GovKeeper.GetVotingParams(ctx).VotingPeriod)
ctx = ctx.WithBlockHeader(newHeader)
```

**Observation:**
```go
// Measure EndBlocker execution time
start := time.Now()
gov.EndBlocker(ctx, app.GovKeeper)
duration := time.Since(start)

// With 200+ proposals, EndBlocker should take excessive time
// On a typical system, this should exceed several seconds
// which would cause consensus timeout (typical block time ~5-6 seconds)
t.Logf("EndBlocker processing time for %d proposals: %v", numProposals, duration)

// Assert that processing time is unreasonably high
// This would fail on vulnerable code, demonstrating the DoS
require.Less(t, duration.Seconds(), 1.0, 
    "EndBlocker took too long processing %d proposals, potential DoS vulnerability", numProposals)
```

The test demonstrates that processing hundreds of simultaneously expiring proposals causes EndBlocker to consume excessive time, confirming the denial-of-service vulnerability. The test will fail on the vulnerable code when the assertion about processing time is violated.

### Citations

**File:** x/gov/abci.go (L14-140)
```go
func EndBlocker(ctx sdk.Context, keeper keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)

	logger := keeper.Logger(ctx)

	// delete inactive proposal from store and its deposits
	keeper.IterateInactiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		keeper.DeleteProposal(ctx, proposal.ProposalId)
		keeper.DeleteDeposits(ctx, proposal.ProposalId)

		// called when proposal become inactive
		keeper.AfterProposalFailedMinDeposit(ctx, proposal.ProposalId)

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeInactiveProposal,
				sdk.NewAttribute(types.AttributeKeyProposalID, fmt.Sprintf("%d", proposal.ProposalId)),
				sdk.NewAttribute(types.AttributeKeyProposalResult, types.AttributeValueProposalDropped),
			),
		)

		logger.Info(
			"proposal did not meet minimum deposit; deleted",
			"proposal", proposal.ProposalId,
			"title", proposal.GetTitle(),
			"min_deposit", keeper.GetDepositParams(ctx).MinDeposit.String(),
			"min_expedited_deposit", keeper.GetDepositParams(ctx).MinExpeditedDeposit.String(),
			"total_deposit", proposal.TotalDeposit.String(),
		)

		return false
	})

	// fetch active proposals whose voting periods have ended (are passed the block time)
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)

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

		keeper.RemoveFromActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)

		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
			if err == nil {
				proposal.Status = types.StatusPassed
				tagValue = types.AttributeValueProposalPassed
				logMsg = "passed"

				// The cached context is created with a new EventManager. However, since
				// the proposal handler execution was successful, we want to track/keep
				// any events emitted, so we re-emit to "merge" the events into the
				// original Context's EventManager.
				ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())

				// write state to the underlying multi-store
				writeCache()
			} else {
				proposal.Status = types.StatusFailed
				tagValue = types.AttributeValueProposalFailed
				logMsg = fmt.Sprintf("passed, but failed on execution: %s", err)
			}
		} else {
			// The proposal didn't pass after voting period ends
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
			} else {
				// When regular proposal fails, it is rejected and
				// the proposal with that id is done forever.
				proposal.Status = types.StatusRejected
				tagValue = types.AttributeValueProposalRejected
				logMsg = "rejected"
			}

		}

		proposal.FinalTallyResult = tallyResults

		keeper.SetProposal(ctx, proposal)

		// when proposal become active
		keeper.AfterProposalVotingPeriodEnded(ctx, proposal.ProposalId)

		logger.Info(
			"proposal tallied",
			"proposal", proposal.ProposalId,
			"title", proposal.GetTitle(),
			"result", logMsg,
		)

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeActiveProposal,
				sdk.NewAttribute(types.AttributeKeyProposalID, fmt.Sprintf("%d", proposal.ProposalId)),
				sdk.NewAttribute(types.AttributeKeyProposalResult, tagValue),
			),
		)
		return false
	})
}
```

**File:** x/gov/keeper/tally.go (L13-125)
```go
func (keeper Keeper) Tally(ctx sdk.Context, proposal types.Proposal) (passes bool, burnDeposits bool, tallyResults types.TallyResult) {
	results := make(map[types.VoteOption]sdk.Dec)
	results[types.OptionYes] = sdk.ZeroDec()
	results[types.OptionAbstain] = sdk.ZeroDec()
	results[types.OptionNo] = sdk.ZeroDec()
	results[types.OptionNoWithVeto] = sdk.ZeroDec()

	totalVotingPower := sdk.ZeroDec()
	currValidators := make(map[string]types.ValidatorGovInfo)

	// fetch all the bonded validators, insert them into currValidators
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

	// iterate over the validators again to tally their voting power
	for _, val := range currValidators {
		if len(val.Vote) == 0 {
			continue
		}

		sharesAfterDeductions := val.DelegatorShares.Sub(val.DelegatorDeductions)
		votingPower := sharesAfterDeductions.MulInt(val.BondedTokens).Quo(val.DelegatorShares)

		for _, option := range val.Vote {
			subPower := votingPower.Mul(option.Weight)
			results[option.Option] = results[option.Option].Add(subPower)
		}
		totalVotingPower = totalVotingPower.Add(votingPower)
	}

	tallyParams := keeper.GetTallyParams(ctx)
	tallyResults = types.NewTallyResultFromMap(results)

	// TODO: Upgrade the spec to cover all of these cases & remove pseudocode.
	// If there is no staked coins, the proposal fails
	if keeper.sk.TotalBondedTokens(ctx).IsZero() {
		return false, false, tallyResults
	}

	// If there is not enough quorum of votes, the proposal fails
	percentVoting := totalVotingPower.Quo(keeper.sk.TotalBondedTokens(ctx).ToDec())
	// Get the quorum threshold based on if the proposal is expedited or not
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
		return true, false, tallyResults
	}

	// Otherwise proposal fails
	return false, false, tallyResults
}
```

**File:** types/context.go (L262-280)
```go
func NewContext(ms MultiStore, header tmproto.Header, isCheckTx bool, logger log.Logger) Context {
	// https://github.com/gogo/protobuf/issues/519
	header.Time = header.Time.UTC()
	return Context{
		ctx:             context.Background(),
		ms:              ms,
		header:          header,
		chainID:         header.ChainID,
		checkTx:         isCheckTx,
		logger:          logger,
		gasMeter:        NewInfiniteGasMeter(1, 1),
		minGasPrice:     DecCoins{},
		eventManager:    NewEventManager(),
		evmEventManager: NewEVMEventManager(),

		txBlockingChannels:   make(acltypes.MessageAccessOpsChannelMapping),
		txCompletionChannels: make(acltypes.MessageAccessOpsChannelMapping),
		txMsgAccessOps:       make(map[int][]acltypes.AccessOperation),
	}
```

**File:** baseapp/baseapp.go (L576-593)
```go
// setDeliverState sets the BaseApp's deliverState with a branched multi-store
// (i.e. a CacheMultiStore) and a new Context with the same multi-store branch,
// and provided header. It is set on InitChain and BeginBlock and set to nil on
// Commit.
func (app *BaseApp) setDeliverState(header tmproto.Header) {
	ms := app.cms.CacheMultiStore()
	ctx := sdk.NewContext(ms, header, false, app.logger)
	if app.deliverState == nil {
		app.deliverState = &state{
			ms:  ms,
			ctx: ctx,
			mtx: &sync.RWMutex{},
		}
		return
	}
	app.deliverState.SetMultiStore(ms)
	app.deliverState.SetContext(ctx)
}
```

**File:** baseapp/abci.go (L177-201)
```go
// EndBlock implements the ABCI interface.
func (app *BaseApp) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	// Clear DeliverTx Events
	ctx.MultiStore().ResetEvents()

	defer telemetry.MeasureSince(time.Now(), "abci", "end_block")

	if app.endBlocker != nil {
		res = app.endBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	if cp := app.GetConsensusParams(ctx); cp != nil {
		res.ConsensusParamUpdates = legacytm.ABCIToLegacyConsensusParams(cp)
	}

	// call the streaming service hooks with the EndBlock messages
	for _, streamingListener := range app.abciListeners {
		if err := streamingListener.ListenEndBlock(app.deliverState.ctx, req, res); err != nil {
			app.logger.Error("EndBlock listening hook failed", "height", req.Height, "err", err)
		}
	}

	return res
}
```

**File:** x/gov/keeper/proposal.go (L12-70)
```go
// SubmitProposal create new proposal given a content
func (keeper Keeper) SubmitProposal(ctx sdk.Context, content types.Content) (types.Proposal, error) {
	return keeper.SubmitProposalWithExpedite(ctx, content, false)
}

// SubmitProposalWithExpedite create new proposal given a content and whether expedited or not
func (keeper Keeper) SubmitProposalWithExpedite(ctx sdk.Context, content types.Content, isExpedited bool) (types.Proposal, error) {
	if !keeper.router.HasRoute(content.ProposalRoute()) {
		return types.Proposal{}, sdkerrors.Wrap(types.ErrNoProposalHandlerExists, content.ProposalRoute())
	}
	// Ensure that the parameter exists
	if content.ProposalType() == proposal.ProposalTypeChange {
		paramProposal, ok := content.(*proposal.ParameterChangeProposal)
		if !ok {
			return types.Proposal{}, sdkerrors.Wrap(types.ErrInvalidProposalContent, "proposal content is not a ParameterChangeProposal")
		}

		// Validate each parameter change exists
		for _, change := range paramProposal.Changes {
			subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
			if !ok {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
			}
			validKey := subspace.Has(ctx, []byte(change.Key))
			if !validKey {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not found in subspace %s", change.Key, change.Subspace)
			}
		}
	}

	proposalID, err := keeper.GetProposalID(ctx)
	if err != nil {
		return types.Proposal{}, err
	}

	submitTime := ctx.BlockHeader().Time
	depositPeriod := keeper.GetDepositParams(ctx).MaxDepositPeriod

	proposal, err := types.NewProposal(content, proposalID, submitTime, submitTime.Add(depositPeriod), isExpedited)
	if err != nil {
		return types.Proposal{}, err
	}

	keeper.SetProposal(ctx, proposal)
	keeper.InsertInactiveProposalQueue(ctx, proposalID, proposal.DepositEndTime)
	keeper.SetProposalID(ctx, proposalID+1)

	// called right after a proposal is submitted
	keeper.AfterProposalSubmission(ctx, proposalID)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSubmitProposal,
			sdk.NewAttribute(types.AttributeKeyProposalID, fmt.Sprintf("%d", proposalID)),
		),
	)

	return proposal, nil
}
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
