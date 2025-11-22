# Audit Report

## Title
Time-of-Check Time-of-Use Vulnerability in Governance Proposal Route Validation Leading to Chain Halt

## Summary
The governance module validates proposal handler routes only at submission time but not before execution. When software upgrades remove handlers from the router while proposals with those routes remain in state, the execution in `EndBlocker` triggers an unconditional panic, causing complete blockchain network shutdown.

## Impact
High

## Finding Description

**Location:** 
- Validation check: [1](#0-0) 
- Vulnerable execution: [2](#0-1) 
- Panic point: [3](#0-2) 

**Intended logic:** The route validation at proposal submission [1](#0-0)  is intended to ensure proposals can only be created for handlers that exist in the system, preventing execution failures later.

**Actual logic:** The validation only checks handler existence at submission time. The router is recreated during software upgrades [4](#0-3) , and if a new version doesn't register a previously existing handler, old proposals stored in state will reference non-existent routes. When `GetRoute()` is called during execution [2](#0-1) , it panics unconditionally [3](#0-2) . Since `EndBlocker` has no panic recovery [5](#0-4) , this causes immediate chain halt.

**Exploitation path:**
1. A governance proposal is submitted with a valid handler route at block N
2. The proposal enters deposit period and voting period (potentially weeks or months)
3. A software upgrade passes via governance that upgrades to a new chain version
4. The chain restarts with new code that doesn't register the previously existing handler in the governance router
5. The original proposal passes voting and reaches execution phase
6. In `EndBlocker`, the code calls `keeper.Router().GetRoute(proposal.ProposalRoute())` without checking if the route exists
7. `GetRoute()` panics with "route does not exist" error
8. The panic propagates through `EndBlocker` with no recovery mechanism
9. All validators halt simultaneously, unable to process blocks
10. Chain remains halted until validators coordinate an emergency hard fork

**Security guarantee broken:** This violates the availability guarantee of the blockchain. The system assumes handlers validated at submission time will exist at execution time, but software upgrades can violate this invariant without any defensive checks or panic recovery.

## Impact Explanation

**Affected Process:** Network availability and consensus

**Severity of Damage:** Complete network shutdown. All validators panic in `EndBlocker`, preventing block production. No new transactions can be confirmed. The chain remains halted until validators coordinate an emergency hard fork to either re-register the missing handler or manually remove the problematic proposal from state. This affects the entire blockchain network uniformly - users cannot perform transactions, all services built on the chain become unavailable, and economic activity ceases.

**System Impact:** Since this occurs in consensus-critical code (`EndBlocker`), it affects all nodes identically, preventing any subset from continuing operation. This constitutes a total network shutdown requiring coordinated hard fork recovery.

## Likelihood Explanation

**Who Can Trigger:** This is triggered through normal protocol operations, not by a malicious actor:
- Any user can submit legitimate governance proposals
- Software upgrades occur through governance voting
- Developers may deprecate or rename handlers as part of normal protocol evolution

**Required Conditions:**
- A proposal must be submitted and pass through deposit period
- A software upgrade must occur that doesn't register the same handler route
- The original proposal must pass voting and reach execution after the upgrade

**Frequency:** Medium-to-high likelihood during active protocol development. Software upgrades occur regularly in blockchain protocols, and handler changes are a normal part of protocol evolution. Without explicit safeguards, this scenario will occur whenever handler modifications coincide with active proposals, which becomes increasingly likely as the protocol matures and accrues more active proposals.

## Recommendation

**Primary Fix:** Add defensive route validation before proposal execution in `EndBlocker`:

In `x/gov/abci.go` at line 67-68, modify the execution logic:
```go
if passes {
    if !keeper.Router().HasRoute(proposal.ProposalRoute()) {
        // Log error and mark proposal as failed instead of panicking
        proposal.Status = types.StatusFailed
        tagValue = types.AttributeValueProposalFailed
        logMsg = fmt.Sprintf("handler for route %s no longer exists", proposal.ProposalRoute())
    } else {
        handler := keeper.Router().GetRoute(proposal.ProposalRoute())
        // ... existing execution logic
    }
}
```

**Alternative Mitigations:**
1. Add migration logic in upgrade handlers to validate active proposals and handle those with deprecated routes before they execute
2. Consider adding panic recovery in `BaseApp.EndBlock` to prevent chain halt from proposal execution failures (though this is a more invasive change)
3. Document handler deprecation procedures requiring coordination with active proposals

## Proof of Concept

**Test File:** `x/gov/abci_test.go`

**Test Function:** `TestProposalExecutionWithMissingHandler`

**Setup:**
1. Initialize test application with governance keeper using standard test setup (similar to existing tests in the file)
2. Create and submit a proposal with a valid handler route (e.g., text proposal using `govtypes.RouterKey`)
3. Deposit sufficient tokens to activate the proposal
4. Add validator vote to pass the proposal
5. Advance block time to end of voting period

**Trigger:**
1. Before calling `EndBlocker`, simulate upgrade by creating a new router without the original handler
2. Use reflection or test helper to replace the keeper's router with the new one (simulating what happens during chain restart after upgrade)
3. Call `gov.EndBlocker(ctx, app.GovKeeper)` to process the passed proposal

**Expected Result:**
The test will panic with message "route \"...\" does not exist" when `GetRoute()` is called at [2](#0-1) , demonstrating the chain halt condition. Use `require.Panics()` to verify this behavior.

**Verification:** This panic in `EndBlocker` without recovery [5](#0-4)  confirms that the vulnerability results in consensus failure and chain halt, matching the "Network not being able to confirm new transactions (total network shutdown)" impact category.

## Notes

This vulnerability represents a TOCTOU (Time-of-Check Time-of-Use) race condition between proposal submission and execution, where the state of the router can change during the intervening time period due to software upgrades. While handler removal during upgrades is within developer authority, the catastrophic impact (complete chain halt requiring hard fork) is far beyond the intended consequences and represents an unrecoverable security failure. The lack of defensive programming (no re-validation or panic recovery) transforms a normal operational change into a critical availability failure.

### Citations

**File:** x/gov/keeper/proposal.go (L19-21)
```go
	if !keeper.router.HasRoute(content.ProposalRoute()) {
		return types.Proposal{}, sdkerrors.Wrap(types.ErrNoProposalHandlerExists, content.ProposalRoute())
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

**File:** simapp/app.go (L305-314)
```go
	govRouter := govtypes.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govtypes.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper)).
		AddRoute(distrtypes.RouterKey, distr.NewCommunityPoolSpendProposalHandler(app.DistrKeeper)).
		AddRoute(upgradetypes.RouterKey, upgrade.NewSoftwareUpgradeProposalHandler(app.UpgradeKeeper))
	//TODO: we may need to add acl gov proposal types here
	govKeeper := govkeeper.NewKeeper(
		appCodec, keys[govtypes.StoreKey], app.GetSubspace(govtypes.ModuleName), app.AccountKeeper, app.BankKeeper,
		&stakingKeeper, app.ParamsKeeper, govRouter,
	)
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
