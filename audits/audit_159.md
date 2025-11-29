# Audit Report

## Title
Unhandled Missing Route in Governance Proposal Execution Causes Network-Wide Node Crash

## Summary
The governance module's `EndBlocker` function in `x/gov/abci.go` calls `GetRoute()` without checking if the route exists when executing passed proposals. Since `GetRoute()` panics on missing routes and `EndBlock` lacks panic recovery, this causes all nodes to crash when processing proposals with routes that were removed during chain upgrades, resulting in total network shutdown.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
When a governance proposal passes and enters execution in EndBlocker, the system should safely retrieve the proposal handler and execute it. If a route becomes unavailable (e.g., after a chain upgrade), the system should handle this gracefully by failing the proposal rather than crashing.

**Actual Logic:**
The code directly calls `GetRoute()` without checking route existence. The router's `GetRoute()` function internally checks `HasRoute()` and panics if the route doesn't exist: [2](#0-1) 

**Exploitation Path:**
1. A user submits a governance proposal when route "X" exists. The submission validates successfully because the route check passes: [3](#0-2) 

2. The proposal enters the voting period (can last weeks)
3. During this period, a chain upgrade occurs where route "X" is removed from the router initialization (e.g., deprecating a module or refactoring route names)
4. The proposal accumulates votes and passes
5. When `EndBlocker` processes the passed proposal, it calls `keeper.Router().GetRoute(proposal.ProposalRoute())`
6. `GetRoute()` panics with "route does not exist"
7. Unlike transaction processing which has panic recovery middleware, `EndBlock` has NO panic recovery: [4](#0-3) 

8. The panic propagates and crashes the node
9. ALL nodes processing this block crash identically at the same height, causing complete network shutdown

**Security Guarantee Broken:**
This violates the blockchain's liveness and availability guarantees. The lack of defensive programming (checking route existence before retrieval) in a critical consensus code path creates a catastrophic failure mode where normal operational activities (chain upgrades) can inadvertently trigger network-wide outages.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator and full nodes crash when processing the block containing the proposal execution
- **Consensus failure**: No new blocks can be produced as all nodes are halted at the same height
- **Requires emergency intervention**: Recovery requires either a coordinated hard fork to remove the problematic proposal from state, or an emergency hotfix release with defensive checks
- **Cannot self-recover**: Unlike typical consensus issues, this cannot be resolved through normal consensus mechanisms since all nodes crash deterministically at the same block

This affects the core availability property of the blockchain and matches the listed impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Conditions:**
- Governance proposals can be submitted by any user (permissionless)
- Proposals have voting periods of weeks, during which chain upgrades commonly occur
- Chain upgrades that modify module routes or deprecate modules are routine maintenance operations
- Routes are hardcoded during application initialization
- Once triggered, network halt is guaranteed (100% deterministic, not probabilistic)

**Frequency Assessment:**
Medium-to-High likelihood during active chain development. The longer a proposal sits in the voting period across upgrade boundaries, the higher the risk. This is not a malicious exploit scenario but rather a defensive programming gap that creates operational risk during normal chain evolution.

**Who Can Trigger:**
While anyone can submit proposals (creating the initial condition), the vulnerability manifests during chain upgrades performed by the development team. However, this is NOT a "privileged misconfiguration" - removing routes during upgrades is legitimate refactoring. The vulnerability is the system's failure to handle this gracefully, causing damage far beyond the intended scope of the upgrade.

## Recommendation

Add a defensive check before calling `GetRoute()` in the EndBlocker execution path:

```go
if passes {
    // Check if route exists before attempting to get it
    if !keeper.Router().HasRoute(proposal.ProposalRoute()) {
        // Log error and mark proposal as failed instead of panicking
        proposal.Status = types.StatusFailed
        tagValue = types.AttributeValueProposalFailed
        logMsg = fmt.Sprintf("failed: handler route %s not registered", proposal.ProposalRoute())
    } else {
        handler := keeper.Router().GetRoute(proposal.ProposalRoute())
        // ... rest of execution logic
    }
}
```

This ensures that routes becoming unavailable after proposal submission (due to upgrades or configuration changes) are handled gracefully. The proposal would fail with a clear error message rather than crashing all nodes, maintaining network availability.

**Alternative approach:** Add panic recovery to the `EndBlock` function similar to how `runTx` handles panics, though the defensive check approach is preferable as it provides clearer error semantics.

## Proof of Concept

**Test Setup:**
1. Initialize test application with `simapp.Setup(false)`
2. Create test accounts and validator
3. Define a custom proposal content type implementing `types.Content` interface that returns a non-registered route (e.g., "nonexistent-route")
4. Submit the proposal using the custom content
5. Deposit sufficient tokens to activate voting
6. Cast YES votes to ensure proposal passes
7. Advance block time past the voting period end

**Trigger:**
Execute `gov.EndBlocker(ctx, app.GovKeeper)` to process the passed proposal

**Expected Result:**
The system panics with: `panic: route "nonexistent-route" does not exist` originating from the router's `GetRoute()` method. This demonstrates:
- The panic occurs in the critical consensus code path (EndBlocker)
- No recovery mechanism exists
- All nodes would crash when processing this block
- The network would halt completely

The panic recovery middleware only applies to transaction processing via `runTx`, not to EndBlock operations, as confirmed by examining the BaseApp architecture.

### Citations

**File:** x/gov/abci.go (L68-68)
```go
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
```

**File:** x/gov/types/router.go (L66-72)
```go
func (rtr *router) GetRoute(path string) Handler {
	if !rtr.HasRoute(path) {
		panic(fmt.Sprintf("route \"%s\" does not exist", path))
	}

	return rtr.routes[path]
}
```

**File:** x/gov/keeper/proposal.go (L19-21)
```go
	if !keeper.router.HasRoute(content.ProposalRoute()) {
		return types.Proposal{}, sdkerrors.Wrap(types.ErrNoProposalHandlerExists, content.ProposalRoute())
	}
```

**File:** baseapp/abci.go (L178-201)
```go
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
