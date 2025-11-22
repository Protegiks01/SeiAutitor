# Audit Report

## Title
Genesis Import Allows Proposals with Unregistered Routes Causing Network-Wide Panic

## Summary
The governance module's `InitGenesis` function loads proposals from genesis state without validating their routes against the sealed router. When a proposal with an unregistered route passes voting, the `EndBlocker` attempts to retrieve its handler via `keeper.Router().GetRoute()`, which panics if the route doesn't exist, causing all nodes to crash simultaneously and resulting in total network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Vulnerable code: `x/gov/genesis.go` lines 34-42 (InitGenesis function) [1](#0-0) 

- Panic point: `x/gov/abci.go` line 68 (EndBlocker calling GetRoute) [2](#0-1) 

- Panic source: `x/gov/types/router.go` lines 66-71 (GetRoute panics on missing route) [3](#0-2) 

**Intended Logic:** 
The governance router should only process proposals with routes that have been registered and sealed in the keeper. The `SubmitProposal` function validates this by checking `keeper.router.HasRoute(content.ProposalRoute())` before accepting proposals. [4](#0-3) 

**Actual Logic:** 
The `InitGenesis` function loads proposals from genesis state without any route validation. It directly calls `k.SetProposal(ctx, proposal)` after only checking the proposal status for queue insertion, completely bypassing the route validation that exists in `SubmitProposal`. [1](#0-0) 

**Exploit Scenario:**
1. An attacker crafts a malicious genesis file containing a proposal with a route that doesn't exist in the governance router (e.g., "nonexistent_module" or even an empty string "")
2. The proposal is set to `StatusVotingPeriod` status in the genesis with sufficient votes to pass
3. When the chain starts, `InitGenesis` loads this malicious proposal without validation
4. On the first block (or when voting period ends), `EndBlocker` processes proposals in the active queue
5. When the malicious proposal passes tally, `EndBlocker` calls `keeper.Router().GetRoute(proposal.ProposalRoute())`
6. Since the route doesn't exist, `GetRoute()` executes `panic(fmt.Sprintf("route \"%s\" does not exist", path))`
7. All nodes panic at the exact same block height with identical state
8. Complete network shutdown - no nodes can progress past this block

**Security Failure:** 
This breaks consensus availability and network liveness. The panic is deterministic across all nodes, meaning every validator will crash at the same block height. Since the malicious proposal is embedded in the chain state, restarting nodes will not help - they will crash again at the same block. Recovery requires either a hard fork to fix the genesis state or adding a handler for the missing route.

## Impact Explanation

**Affected Assets/Processes:**
- Complete network operation and availability
- All transaction processing capabilities
- Chain progression and consensus finality

**Severity of Damage:**
- **Total network shutdown:** All validator nodes crash simultaneously and deterministically
- **Permanent halt:** Nodes cannot restart and progress past the problematic block without intervention
- **Requires hard fork:** Recovery necessitates either modifying the genesis state to remove/fix the malicious proposal or adding the missing route handler to all nodes
- **No self-recovery:** Unlike transient network issues, this is a state-embedded problem that persists across restarts

**System Security Impact:**
This vulnerability allows an attacker who can influence genesis state (such as during chain initialization, major upgrades, or in testnets/devnets) to embed a time bomb that completely halts the network. Even if detected, fixing requires coordinated hard fork action across all validators, causing significant downtime and potential chain splits if not executed uniformly.

## Likelihood Explanation

**Who Can Trigger:**
- Anyone who can influence genesis file content (chain administrators, governance participants in chain upgrades, or in worst case scenarios, compromised chain initialization processes)
- Most realistic in new chain launches, testnet deployments, or during major network upgrades that export/import state

**Required Conditions:**
- Malicious proposal must be included in genesis state with an unregistered route
- Proposal must either be in `StatusVotingPeriod` with sufficient votes to pass, or transition to voting and pass naturally
- No special timing required - will trigger deterministically when the proposal execution is attempted

**Frequency/Exploitability:**
- **Moderate to High likelihood** during chain initialization or major upgrades where genesis files are created/modified
- **Deterministic exploitation:** Once the malicious genesis is deployed, the network will inevitably crash
- **Single point of failure:** Only one malicious proposal needed to halt the entire network
- Could be accidental during module removals/refactoring where old proposals reference removed modules

## Recommendation

Add route validation to the `InitGenesis` function to reject proposals with unregistered routes. The fix should:

1. **Add validation check in InitGenesis** (in `x/gov/genesis.go`):
```go
for _, proposal := range data.Proposals {
    // Validate that the proposal route exists in the router
    content := proposal.GetContent()
    if content != nil {
        route := content.ProposalRoute()
        if !k.Router().HasRoute(route) {
            panic(fmt.Sprintf("genesis proposal %d has invalid route: %s", proposal.ProposalId, route))
        }
    }
    
    // Existing code for queue insertion and storage
    switch proposal.Status {
    // ... rest of existing code
}
```

2. **Alternative:** Modify `GetRoute()` to return an error instead of panicking, and handle the error gracefully in `EndBlocker` by marking the proposal as failed rather than crashing the node.

## Proof of Concept

**File:** `x/gov/genesis_test.go`

**Test Function:** `TestGenesisImportWithInvalidRoute`

**Setup:**
1. Create a test application using `simapp.Setup(false)`
2. Create a custom proposal content type that implements the `Content` interface with an unregistered route (e.g., "invalid_route_test")
3. Construct a genesis state with this proposal in `StatusVotingPeriod` that would pass tally
4. Initialize the chain with this malicious genesis

**Trigger:**
1. Call `gov.InitGenesis()` with the malicious genesis state - this should succeed without validation
2. Set up the context with voting parameters that would make the proposal pass
3. Call `gov.EndBlocker()` to process the proposal

**Observation:**
The test will panic with message: `panic: route "invalid_route_test" does not exist` when `EndBlocker` calls `keeper.Router().GetRoute()` on line 68 of `abci.go`. This demonstrates that:
- Invalid proposals can be loaded through genesis without validation
- The panic occurs deterministically during block processing
- All nodes would crash at the same block height

**Test Code Structure:**
```go
func TestGenesisImportWithInvalidRoute(t *testing.T) {
    // Setup: Create custom proposal type with invalid route
    type InvalidProposal struct {
        Title       string
        Description string
    }
    
    // Implement Content interface with invalid route
    func (ip *InvalidProposal) ProposalRoute() string { return "invalid_route_test" }
    func (ip *InvalidProposal) ProposalType() string { return "Invalid" }
    // ... other interface methods
    
    // Create genesis state with this proposal
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create malicious proposal with invalid route
    content := &InvalidProposal{Title: "Test", Description: "Test"}
    proposal, _ := types.NewProposal(content, 1, time.Now(), time.Now().Add(time.Hour), false)
    proposal.Status = types.StatusVotingPeriod
    proposal.VotingEndTime = time.Now().Add(-time.Second) // Already ended
    
    genesisState := &types.GenesisState{
        Proposals: []types.Proposal{proposal},
        // ... other required genesis fields
    }
    
    // InitGenesis should accept it without validation (BUG)
    gov.InitGenesis(ctx, app.AccountKeeper, app.BankKeeper, app.GovKeeper, genesisState)
    
    // Trigger: Run EndBlocker - should panic
    require.Panics(t, func() {
        gov.EndBlocker(ctx, app.GovKeeper)
    })
}
```

This test demonstrates that the vulnerability allows network-halting panics through malicious or corrupted genesis state.

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

**File:** x/gov/abci.go (L68-68)
```go
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
```

**File:** x/gov/types/router.go (L66-71)
```go
func (rtr *router) GetRoute(path string) Handler {
	if !rtr.HasRoute(path) {
		panic(fmt.Sprintf("route \"%s\" does not exist", path))
	}

	return rtr.routes[path]
```

**File:** x/gov/keeper/proposal.go (L19-20)
```go
	if !keeper.router.HasRoute(content.ProposalRoute()) {
		return types.Proposal{}, sdkerrors.Wrap(types.ErrNoProposalHandlerExists, content.ProposalRoute())
```
