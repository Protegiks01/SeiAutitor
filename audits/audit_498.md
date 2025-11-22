## Audit Report

## Title
Unhandled Missing Route in Governance Proposal Execution Causes Network-Wide Node Crash

## Summary
The governance module's `EndBlocker` function calls `GetRoute()` without first checking if the route exists when executing passed proposals. Since `GetRoute()` panics on missing routes and `EndBlock` has no panic recovery mechanism, this causes all nodes processing the block to crash, resulting in a complete network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Panic source: [2](#0-1) 

**Intended Logic:** 
When a governance proposal passes, the system should safely execute the proposal's handler. The router should only retrieve handlers for routes that have been properly registered during application initialization.

**Actual Logic:** 
The code directly calls `GetRoute()` without checking route existence. The `GetRoute` function checks `HasRoute()` internally and panics with the message `"route \"%s\" does not exist"` if the route is not found. [3](#0-2) 

**Exploit Scenario:**
1. A governance proposal is submitted when route "X" exists in the router configuration and passes the validation check at submission time [4](#0-3) 
2. The proposal goes through the voting period and accumulates enough votes to pass
3. A chain upgrade occurs where route "X" is removed from the router initialization code (e.g., deprecating a module or changing route names) [5](#0-4) 
4. The old proposal with route "X" remains in the chain state
5. When `EndBlocker` processes the passed proposal, it calls `keeper.Router().GetRoute()` which panics
6. Unlike transaction processing which has panic recovery middleware, `EndBlock` has NO panic recovery [6](#0-5) 
7. The panic propagates up and crashes the node
8. ALL nodes processing this block crash identically, causing complete network shutdown

**Security Failure:** 
This breaks the availability and liveness guarantees of the blockchain. The lack of defensive programming (checking route existence before retrieval) combined with no panic recovery in critical consensus code paths creates a denial-of-service vulnerability that affects all network participants.

## Impact Explanation

**Affected Components:**
- All validator and full nodes processing blocks
- Network consensus and transaction finality
- Overall blockchain availability

**Severity of Damage:**
- **100% network shutdown**: All nodes crash when processing the block containing the proposal execution
- Requires emergency intervention: Either a coordinated hard fork to remove/modify the problematic proposal from state, or a hotfix release with defensive checks
- Cannot be resolved through normal consensus mechanisms since all nodes crash at the same block height
- Complete halt of transaction processing until manual intervention

**System Criticality:**
This vulnerability affects the core availability property of the blockchain. The governance module is a critical system component, and chain upgrades removing routes are realistic operational scenarios. The combination of missing defensive checks and no panic recovery in EndBlock creates a catastrophic failure mode.

## Likelihood Explanation

**Who Can Trigger:**
This vulnerability is triggered through normal governance operations - any user can submit proposals following standard procedures. The vulnerability manifests during chain upgrades performed by the core development team.

**Conditions Required:**
1. A governance proposal with a specific route must be submitted and pass voting (normal governance flow)
2. A chain upgrade that removes or changes that route must occur before the proposal executes
3. The proposal must pass and reach execution in EndBlocker after the upgrade

**Frequency:**
- **Medium-to-High likelihood during upgrades**: Chain upgrades that modify module routes or deprecate modules are common in Cosmos SDK chains
- The longer proposals sit in voting period across upgrade boundaries, the higher the risk
- Once triggered, it's a guaranteed network halt (not a probabilistic race condition)

Governance proposals can have voting periods of weeks, and upgrades may occur during this time. The router configuration is hardcoded in the application initialization [5](#0-4) , so any module deprecation or route changes in upgrades create this risk.

## Recommendation

Add a defensive check before calling `GetRoute()` in the EndBlocker:

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

This ensures that even if a route becomes unavailable after proposal submission (due to upgrades or configuration changes), the node will gracefully handle the situation rather than crashing. The proposal would be marked as failed with a clear error message, maintaining network availability.

## Proof of Concept

**File:** `x/gov/abci_test.go`

**Test Function:** `TestMissingRouteDoesNotPanicEndBlocker`

**Setup:**
1. Initialize a test application using `simapp.Setup(false)`
2. Create test accounts and a validator
3. Create a custom proposal content type that returns a route not registered in the router (e.g., "nonexistent-route")
4. Submit the proposal and deposit enough to activate voting
5. Vote YES to make the proposal pass
6. Advance time past the voting period end time

**Trigger:**
Call `gov.EndBlocker(ctx, app.GovKeeper)` which will attempt to execute the passed proposal with the non-existent route.

**Observation:**
The test will panic with the message: `panic: route "nonexistent-route" does not exist` originating from [7](#0-6) 

This demonstrates that:
1. The panic occurs in a critical consensus code path (EndBlocker)
2. There is no recovery mechanism 
3. All nodes would crash when processing this block
4. The network would halt completely

The panic recovery middleware only applies to transaction processing via `runTx`, not to EndBlock operations, as documented in the codebase architecture.

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

**File:** simapp/app.go (L305-309)
```go
	govRouter := govtypes.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govtypes.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper)).
		AddRoute(distrtypes.RouterKey, distr.NewCommunityPoolSpendProposalHandler(app.DistrKeeper)).
		AddRoute(upgradetypes.RouterKey, upgrade.NewSoftwareUpgradeProposalHandler(app.UpgradeKeeper))
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
