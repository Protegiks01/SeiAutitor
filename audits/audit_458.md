# Audit Report

## Title
EndBlocker Panic Due to Missing Proposal Route Validation in Genesis State

## Summary
Proposals loaded through genesis state bypass the proposal handler route validation that exists in normal proposal submission. If a proposal with an unregistered handler route is included in genesis state, passes voting, and reaches execution, the EndBlocker will panic causing total network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Missing validation: [1](#0-0) 
- Missing validation: [2](#0-1) 
- Panic location: [3](#0-2) 
- Panic trigger: [4](#0-3) 

**Intended Logic:** 
All proposals should have their handler routes validated before being stored in state to ensure they can be executed when passed. This validation exists in the normal submission path: [5](#0-4) 

**Actual Logic:** 
When proposals are loaded from genesis state via `InitGenesis`, they are directly stored without any route validation. The `ValidateGenesis` function only validates deposit parameters and does not check if proposal routes have registered handlers.

**Exploit Scenario:**
1. During chain initialization or upgrade, a genesis file is prepared containing proposals
2. A proposal is included with a route that doesn't have a registered handler (e.g., due to typo, handler name change between versions, or incomplete handler registration)
3. The chain starts successfully and the proposal progresses through voting
4. When the proposal passes and reaches the execution phase in EndBlocker, the code calls `keeper.Router().GetRoute(proposal.ProposalRoute())`
5. The `GetRoute()` method panics because the route doesn't exist
6. The panic crashes all validator nodes, halting the entire network

**Security Failure:**
This breaks network availability through a denial-of-service. The panic in EndBlocker causes all validator nodes to crash simultaneously, making the network unable to confirm new transactions.

## Impact Explanation

**Assets/Processes Affected:**
- Network availability: The entire blockchain network becomes unavailable
- Transaction finality: No new transactions can be confirmed
- All validator nodes crash simultaneously

**Severity of Damage:**
- Complete network shutdown requiring emergency intervention
- All validator nodes must be restarted with a patched binary or corrected genesis state
- Potential for extended downtime during incident response
- May require coordinated hard fork if the issue occurs after network launch

**Why This Matters:**
This directly falls under the High severity scope criterion: "Network not being able to confirm new transactions (total network shutdown)". A single malformed proposal in genesis state can brick the entire network.

## Likelihood Explanation

**Who Can Trigger:**
While genesis state is controlled by chain operators (privileged role), this vulnerability represents a subtle logic error that could be triggered accidentally, not through intentional malicious behavior.

**Conditions Required:**
- A proposal with an unregistered handler route must be included in genesis state
- The proposal must reach voting period and pass
- This commonly occurs during:
  - Chain upgrades where genesis is exported from one version and imported to another
  - Module handler routes being renamed or removed between versions
  - Manual genesis file creation with typographical errors
  - Contentious forks using different handler configurations

**Frequency:**
This could occur during any chain upgrade or initialization that involves exporting/importing genesis state, which happens regularly in Cosmos SDK chains. The inconsistency between validation in `SubmitProposal` and `InitGenesis` makes this an easy mistake to make.

## Recommendation

Add proposal route validation to the genesis initialization path:

1. In `ValidateGenesis` function, add validation to check that all proposals in genesis have valid routes (requires passing the router as parameter or validating routes during `InitGenesis`)

2. In `InitGenesis` function, before setting each proposal, validate that its route exists in the router:
   ```go
   for _, proposal := range data.Proposals {
       // Add validation
       if !k.Router().HasRoute(proposal.ProposalRoute()) {
           panic(fmt.Sprintf("genesis proposal %d has unregistered route: %s", 
               proposal.ProposalId, proposal.ProposalRoute()))
       }
       // existing code...
   }
   ```

3. Alternatively, make `GetRoute()` return an error instead of panicking, and handle the error gracefully in EndBlocker by marking the proposal as failed rather than crashing.

## Proof of Concept

**File:** `x/gov/genesis_test.go`

**Test Function:** `TestGenesisProposalWithUnregisteredRouteCausesPanic`

**Setup:**
1. Create a test proposal type with an unregistered route (similar to the existing `invalidProposalRoute` test type)
2. Construct a genesis state with this proposal in StatusVotingPeriod with sufficient votes to pass
3. Initialize a new chain with this genesis state

**Trigger:**
1. Advance the block time past the proposal's voting end time
2. Call `gov.EndBlocker()` to process the passed proposal

**Observation:**
The test should catch a panic when `GetRoute()` is called with the unregistered route. The panic will occur because:
- [6](#0-5)  panics when the route doesn't exist
- This is called from [7](#0-6)  during proposal execution

**Test Code Outline:**
```go
func TestGenesisProposalWithUnregisteredRouteCausesPanic(t *testing.T) {
    // Create proposal with unregistered route
    invalidProposal := &invalidProposalRoute{...}
    
    // Create genesis state with this proposal in voting period
    genState := &types.GenesisState{
        StartingProposalId: 2,
        Proposals: []types.Proposal{passedProposalWithInvalidRoute},
        ...
    }
    
    // Initialize new chain with genesis
    app := simapp.NewSimApp(...)
    app.InitChain(..., AppStateBytes: genesisStateBytes)
    
    // Advance time past voting period
    ctx = ctx.WithBlockTime(votingEndTime.Add(1))
    
    // This should panic
    require.Panics(t, func() {
        gov.EndBlocker(ctx, app.GovKeeper)
    })
}
```

This demonstrates that proposals with unregistered routes loaded through genesis bypass validation and cause network-halting panics during execution.

### Citations

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

**File:** x/gov/types/router.go (L66-71)
```go
func (rtr *router) GetRoute(path string) Handler {
	if !rtr.HasRoute(path) {
		panic(fmt.Sprintf("route \"%s\" does not exist", path))
	}

	return rtr.routes[path]
```

**File:** x/gov/abci.go (L67-74)
```go
		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
```

**File:** x/gov/keeper/proposal.go (L19-21)
```go
	if !keeper.router.HasRoute(content.ProposalRoute()) {
		return types.Proposal{}, sdkerrors.Wrap(types.ErrNoProposalHandlerExists, content.ProposalRoute())
	}
```
