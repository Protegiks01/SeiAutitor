# Audit Report

## Title
Unhandled Missing Route in Governance Proposal Execution Causes Network-Wide Node Crash

## Summary
The governance module's EndBlocker function calls `GetRoute()` without checking if the route exists when executing passed proposals. Since `GetRoute()` panics on missing routes and EndBlock lacks panic recovery, proposals with routes removed during chain upgrades cause all nodes to crash deterministically at the same block height, resulting in total network shutdown.

## Impact
Medium

## Finding Description

**Location:** 
- `x/gov/abci.go` line 68 [1](#0-0) 
- `x/gov/types/router.go` lines 66-72 [2](#0-1) 

**Intended Logic:**
When a governance proposal passes and enters execution in EndBlocker, the system should safely retrieve and execute the proposal handler. If a route becomes unavailable after proposal submission (e.g., due to chain upgrades), the system should handle this gracefully by failing the proposal rather than crashing.

**Actual Logic:**
The EndBlocker directly calls `GetRoute()` without checking route existence [1](#0-0) . The router's `GetRoute()` function panics if the route doesn't exist [2](#0-1) . This creates a time-of-check-time-of-use (TOCTOU) vulnerability where routes are validated during proposal submission [3](#0-2)  but not during execution.

**Exploitation Path:**
1. User submits a governance proposal when route "X" exists - submission succeeds because route validation passes
2. Proposal enters voting period (typically lasting weeks)
3. Chain upgrade occurs where route "X" is removed from router initialization (legitimate refactoring or module deprecation)
4. Proposal accumulates sufficient votes and passes
5. EndBlocker processes the passed proposal and calls `keeper.Router().GetRoute(proposal.ProposalRoute())`
6. `GetRoute()` panics with "route does not exist" message
7. Unlike transaction processing which has panic recovery [4](#0-3) , EndBlock has no panic recovery mechanism [5](#0-4) 
8. Panic propagates and crashes the node
9. All nodes processing this block crash identically at the same height, causing complete network shutdown

**Security Guarantee Broken:**
This violates the blockchain's liveness and availability guarantees. The lack of defensive programming in a critical consensus code path (EndBlocker) creates a catastrophic failure mode where normal operational activities (chain upgrades) inadvertently trigger network-wide outages.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator and full nodes crash when processing the block containing the proposal execution
- **Consensus failure**: No new blocks can be produced as all nodes halt at the same height
- **Requires emergency intervention**: Recovery requires either a coordinated hard fork to remove the problematic proposal from state, or an emergency hotfix release adding defensive checks
- **Cannot self-recover**: This cannot be resolved through normal consensus mechanisms since all nodes crash deterministically at the same block

This directly matches the impact category: "Network not being able to confirm new transactions (total network shutdown)" classified as Medium severity.

## Likelihood Explanation

**Triggering Conditions:**
- Governance proposals are permissionless (any user can submit)
- Proposals have voting periods of weeks during which chain upgrades commonly occur
- Chain upgrades that modify module routes or deprecate modules are routine maintenance operations
- Routes are hardcoded during application initialization [6](#0-5) 
- Once triggered, network halt is guaranteed (100% deterministic)

**Frequency Assessment:**
Medium likelihood during active chain development. The longer a proposal sits in the voting period across upgrade boundaries, the higher the risk. This is not a malicious exploit but a defensive programming gap creating operational risk during normal chain evolution.

**Who Can Trigger:**
Anyone can submit proposals (creating the precondition). The vulnerability manifests during chain upgrades performed by the development team. However, this is NOT a "privileged misconfiguration" - removing routes during upgrades is legitimate refactoring. The vulnerability is the system's failure to handle this gracefully, causing damage far beyond the intended scope of the upgrade.

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

This ensures routes becoming unavailable after proposal submission are handled gracefully. The proposal would fail with a clear error message rather than crashing all nodes, maintaining network availability.

**Alternative approach:** Add panic recovery to the EndBlock function similar to how Query [7](#0-6)  and PrepareProposal [8](#0-7)  handle panics, though the defensive check approach is preferable for clearer error semantics.

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
- No recovery mechanism exists in EndBlock
- All nodes would crash when processing this block
- The network would halt completely

The panic recovery middleware only applies to transaction processing via `runTx`, not to EndBlock operations.

## Notes

This vulnerability represents a time-of-check-time-of-use (TOCTOU) issue where the system validates route existence during proposal submission but not during execution. The gap between these operations (potentially weeks) allows for legitimate state changes (chain upgrades) that the system fails to handle gracefully. While other ABCI methods like Query and PrepareProposal have panic recovery, EndBlock notably lacks this protection, making it vulnerable to panics from any module's EndBlocker logic.

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

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
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

**File:** baseapp/abci.go (L488-493)
```go
	defer func() {
		if r := recover(); r != nil {
			resp := sdkerrors.QueryResultWithDebug(sdkerrors.Wrapf(sdkerrors.ErrPanic, "%v", r), app.trace)
			res = &resp
		}
	}()
```

**File:** baseapp/abci.go (L1037-1052)
```go
	defer func() {
		if err := recover(); err != nil {
			app.logger.Error(
				"panic recovered in PrepareProposal",
				"height", req.Height,
				"time", req.Time,
				"panic", err,
			)

			resp = &abci.ResponsePrepareProposal{
				TxRecords: utils.Map(req.Txs, func(tx []byte) *abci.TxRecord {
					return &abci.TxRecord{Action: abci.TxRecord_UNMODIFIED, Tx: tx}
				}),
			}
		}
	}()
```

**File:** simapp/app.go (L305-309)
```go
	govRouter := govtypes.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govtypes.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper)).
		AddRoute(distrtypes.RouterKey, distr.NewCommunityPoolSpendProposalHandler(app.DistrKeeper)).
		AddRoute(upgradetypes.RouterKey, upgrade.NewSoftwareUpgradeProposalHandler(app.UpgradeKeeper))
```
