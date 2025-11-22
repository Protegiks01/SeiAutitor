## Title
Missing Validation of Voting Time Ordering in Genesis Import Allows Premature Proposal Execution

## Summary
The governance module's genesis validation does not verify that `VotingEndTime > VotingStartTime` for proposals. This allows a malicious or buggy genesis state to import proposals with inverted voting times, causing proposals to be tallied and potentially executed before their intended voting start time.

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Genesis import: [2](#0-1) 
- EndBlocker processing: [3](#0-2) 

**Intended Logic:** 
Governance proposals should only be tallied and executed after a complete voting period where `VotingStartTime <= CurrentTime <= VotingEndTime`. During normal operation, `ActivateVotingPeriod` ensures this invariant by setting [4](#0-3) , where `VotingEndTime = VotingStartTime + VotingPeriod`, guaranteeing `VotingEndTime > VotingStartTime`.

**Actual Logic:** 
The `ValidateGenesis` function only validates deposit parameters and tally parameters, but does NOT validate individual proposals. [1](#0-0)  shows no checks on proposal voting times. When `InitGenesis` imports proposals [2](#0-1) , it directly inserts them into the active proposal queue without time validation.

The `EndBlocker` processes proposals using [5](#0-4) , which iterates over proposals where `VotingEndTime <= CurrentBlockTime`. It never checks if `CurrentBlockTime >= VotingStartTime` before tallying. Additionally, `AddVote` only checks proposal status [6](#0-5) , not the time window.

**Exploit Scenario:**
1. An operator crafts a genesis file containing a proposal with:
   - `Status = StatusVotingPeriod`
   - `VotingStartTime = T_future` (e.g., 1 year from genesis)
   - `VotingEndTime = T_past` (e.g., 1 second after genesis)
2. The genesis file passes `ValidateGenesis` since proposals aren't validated
3. `InitGenesis` imports the proposal and inserts it into the active queue with key based on `VotingEndTime`
4. At the first `EndBlock` after genesis (time ≈ T_past), the proposal is processed because `VotingEndTime <= CurrentBlockTime`
5. The proposal is tallied and potentially executed, even though `CurrentBlockTime < VotingStartTime`
6. Voting was supposed to start 1 year later, but the proposal was already resolved

**Security Failure:**
This breaks the fundamental governance invariant that proposals must complete their voting period before execution. The voting period ordering constraint is violated, allowing proposals to bypass proper democratic voting processes.

## Impact Explanation

The vulnerability affects the governance system's integrity:
- **Process affected:** Governance proposal execution and voting
- **Severity:** A malicious upgrade proposal could be executed without proper voting, potentially compromising the entire chain
- **Data affected:** Governance state consistency and proposal lifecycle management
- **Why it matters:** Governance is the mechanism for protocol upgrades and parameter changes. Bypassing the voting period undermines the decentralized decision-making process and could enable unauthorized protocol changes

This falls under the in-scope impact: "Medium: A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:** 
- Chain operators/validators who generate or modify genesis files
- Could occur accidentally through bugs in genesis export/import tooling
- Could occur when migrating state between chains with different time references

**Conditions required:**
- Only triggerable during genesis import or chain initialization
- Cannot be exploited during normal chain operation
- Requires genesis file modification before chain start

**Frequency:**
- Low during normal operation since genesis is created by trusted parties
- However, bugs in tooling or state migration could accidentally create invalid proposals
- Once exploited at genesis, the damage is done permanently

## Recommendation

Add comprehensive proposal validation to `ValidateGenesis`:

```go
// In x/gov/types/genesis.go, add to ValidateGenesis function:
for _, proposal := range data.Proposals {
    if proposal.Status == StatusVotingPeriod {
        if proposal.VotingEndTime.Before(proposal.VotingStartTime) ||
           proposal.VotingEndTime.Equal(proposal.VotingStartTime) {
            return fmt.Errorf("proposal %d has voting end time (%s) before or equal to start time (%s)",
                proposal.ProposalId, proposal.VotingEndTime, proposal.VotingStartTime)
        }
        if proposal.VotingStartTime.IsZero() || proposal.VotingEndTime.IsZero() {
            return fmt.Errorf("proposal %d in voting period has zero voting times", proposal.ProposalId)
        }
    }
}
```

Additionally, consider adding a defensive check in `EndBlocker` before tallying to ensure `ctx.BlockTime() >= proposal.VotingStartTime`.

## Proof of Concept

**File:** `x/gov/types/genesis_test.go`
**Function:** Add new test `TestValidateGenesis_InvalidVotingTimes`

**Setup:**
Create a genesis state with a proposal that has `VotingEndTime` before `VotingStartTime`.

**Trigger:**
Call `ValidateGenesis` with the malformed genesis state.

**Observation:**
Currently, `ValidateGenesis` returns `nil` (passes validation) even though the proposal has invalid voting times. The test should fail, demonstrating that the validation is missing.

**Test Code:**
```go
func TestValidateGenesis_InvalidVotingTimes(t *testing.T) {
    // Create a proposal with VotingEndTime before VotingStartTime
    proposal := Proposal{
        ProposalId:       1,
        Status:           StatusVotingPeriod,
        VotingStartTime:  time.Now().Add(24 * time.Hour),  // 1 day in future
        VotingEndTime:    time.Now(),                       // now (before start!)
        DepositEndTime:   time.Now(),
        TotalDeposit:     sdk.NewCoins(),
        FinalTallyResult: EmptyTallyResult(),
    }
    
    genesisState := &GenesisState{
        StartingProposalId: 2,
        Proposals:          []Proposal{proposal},
        DepositParams:      DefaultDepositParams(),
        VotingParams:       DefaultVotingParams(),
        TallyParams:        DefaultTallyParams(),
    }
    
    // This should fail but currently passes
    err := ValidateGenesis(genesisState)
    require.Error(t, err, "should reject proposal with VotingEndTime before VotingStartTime")
    require.Contains(t, err.Error(), "voting end time")
}
```

The test demonstrates that `ValidateGenesis` incorrectly accepts proposals with invalid voting time ordering, confirming the vulnerability.

### Citations

**File:** x/gov/types/genesis.go (L44-73)
```go
// ValidateGenesis checks if parameters are within valid ranges
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

**File:** x/gov/genesis.go (L34-42)
```go
	for _, proposal := range data.Proposals {
		switch proposal.Status {
		case types.StatusDepositPeriod:
			k.InsertInactiveProposalQueue(ctx, proposal.ProposalId, proposal.DepositEndTime)
		case types.StatusVotingPeriod:
			k.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
		}
		k.SetProposal(ctx, proposal)
	}
```

**File:** x/gov/abci.go (L47-51)
```go
	// fetch active proposals whose voting periods have ended (are passed the block time)
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)
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

**File:** x/gov/keeper/keeper.go (L131-148)
```go
// IterateActiveProposalsQueue iterates over the proposals in the active proposal queue
// and performs a callback function
func (keeper Keeper) IterateActiveProposalsQueue(ctx sdk.Context, endTime time.Time, cb func(proposal types.Proposal) (stop bool)) {
	iterator := keeper.ActiveProposalQueueIterator(ctx, endTime)

	defer iterator.Close()
	for ; iterator.Valid(); iterator.Next() {
		proposalID, _ := types.SplitActiveProposalQueueKey(iterator.Key())
		proposal, found := keeper.GetProposal(ctx, proposalID)
		if !found {
			panic(fmt.Sprintf("proposal %d does not exist", proposalID))
		}

		if cb(proposal) {
			break
		}
	}
}
```

**File:** x/gov/keeper/vote.go (L17-19)
```go
	if proposal.Status != types.StatusVotingPeriod {
		return sdkerrors.Wrapf(types.ErrInactiveProposal, "%d", proposalID)
	}
```
