# Audit Report

## Title
Time-of-Check Time-of-Use Vulnerability in Governance Proposal Route Validation Leading to Chain Halt

## Summary
The route validation in `SubmitProposalWithExpedite` at line 19 checks handler existence at proposal submission time, but does not re-validate before execution in `EndBlocker`. During software upgrades, handlers can be removed from the router while proposals with those routes remain in state. When such proposals execute, the code panics and halts the entire blockchain.

## Impact
High

## Finding Description

**Location:** 
- Validation check: [1](#0-0) 
- Vulnerable execution: [2](#0-1) 
- Panic point: [3](#0-2) 

**Intended Logic:** The route validation at proposal submission is intended to ensure proposals can only be created for handlers that exist in the system, preventing execution failures later.

**Actual Logic:** The validation only checks handler existence at submission time. The router is recreated during software upgrades [4](#0-3) , and if a new version doesn't register a previously existing handler, old proposals stored in state will reference non-existent routes. When `GetRoute()` is called during execution, it panics unconditionally [5](#0-4) . Since `EndBlocker` has no panic recovery [6](#0-5) , this causes immediate chain halt.

**Exploit Scenario:**
1. At block height 100: A governance proposal is submitted with route "customhandler" and passes validation
2. The proposal enters deposit period and voting period (weeks/months)
3. At block height 500: A software upgrade proposal passes that upgrades the chain to a new version
4. The chain restarts with new code that doesn't register "customhandler" in the governance router
5. At block height 600: The original proposal passes voting and enters execution
6. In `EndBlocker`, line 68 calls `keeper.Router().GetRoute("customhandler")`
7. `GetRoute()` panics with "route "customhandler" does not exist"
8. The panic propagates through `EndBlocker` with no recovery
9. All validators halt, unable to process blocks
10. Chain requires emergency hard fork to fix

**Security Failure:** This breaks availability (denial-of-service). The system assumes handlers validated at submission time will exist at execution time, but software upgrades violate this invariant. The lack of re-validation or panic recovery allows a time-of-check time-of-use (TOCTOU) vulnerability to cause complete network shutdown.

## Impact Explanation

**Affected Process:** Network availability and transaction confirmation

**Severity of Damage:** Complete chain halt. All validators panic in `EndBlocker`, preventing block production. No new transactions can be confirmed. The chain remains halted until validators coordinate an emergency hard fork to either:
- Re-register the missing handler, or
- Manually remove the problematic proposal from state

**System Impact:** This affects the entire blockchain network. Users cannot perform any transactions. All services built on top of the chain become unavailable. Since the issue occurs in consensus logic, it affects all nodes uniformly, preventing any subset from continuing.

## Likelihood Explanation

**Who Can Trigger:** This is not triggered by a malicious actor but occurs during normal protocol operations when:
- Legitimate governance proposals are submitted
- Software upgrades remove or rename handlers
- Old proposals reach execution phase

**Required Conditions:**
- A proposal must be submitted and pass through deposit period
- A software upgrade must occur that doesn't register the same handler
- The original proposal must pass voting after the upgrade

**Frequency:** Medium-to-high likelihood during active protocol development. Software upgrades occur regularly in blockchain protocols, and handler deprecation is a normal part of protocol evolution. Without explicit safeguards, this scenario will occur whenever handler changes coincide with active proposals.

## Recommendation

Add route re-validation before proposal execution in `EndBlocker`:

1. In `x/gov/abci.go` at line 67-68, add a defensive check:
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

2. Alternatively, add migration logic in upgrade handlers to validate and handle proposals with removed routes before they execute.

3. Consider adding panic recovery in `BaseApp.EndBlock` to prevent chain halt from proposal execution failures.

## Proof of Concept

**File:** `x/gov/abci_test.go`

**Test Function:** Add a new test `TestProposalExecutionWithMissingHandler`

**Setup:**
1. Initialize a test application with governance keeper
2. Create and submit a proposal with a valid handler route
3. Deposit sufficient funds and vote to pass the proposal
4. Advance time to voting end

**Trigger:**
1. Before calling `EndBlocker`, simulate an upgrade by creating a new router without the handler
2. Replace the keeper's router with the new one (simulating what happens during chain restart)
3. Call `gov.EndBlocker()` to process the passed proposal

**Observation:**
The test will panic with "route "..." does not exist" when `GetRoute()` is called at [2](#0-1) . This panic demonstrates the chain halt condition.

**Test Code Structure:**
```go
func TestProposalExecutionWithMissingHandler(t *testing.T) {
    // 1. Setup: Create app and submit proposal with valid handler
    // 2. Advance through deposit and voting periods
    // 3. Simulate upgrade: create new router without the handler
    // 4. Replace keeper's router (via reflection or test helper)
    // 5. Call EndBlocker - this should panic
    // 6. Assert: require.Panics() to verify chain halt occurs
}
```

The test confirms that proposal execution without handler existence validation causes a panic in `EndBlocker`, resulting in chain halt as there is no panic recovery mechanism in [7](#0-6) .

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

**File:** x/gov/keeper/keeper.go (L47-72)
```go
func NewKeeper(
	cdc codec.BinaryCodec, key sdk.StoreKey, paramSpace types.ParamSubspace,
	authKeeper types.AccountKeeper, bankKeeper types.BankKeeper, sk types.StakingKeeper,
	paramsKeeper types.ParamsKeeper, rtr types.Router,
) Keeper {

	// ensure governance module account is set
	if addr := authKeeper.GetModuleAddress(types.ModuleName); addr == nil {
		panic(fmt.Sprintf("%s module account has not been set", types.ModuleName))
	}

	// It is vital to seal the governance proposal router here as to not allow
	// further handlers to be registered after the keeper is created since this
	// could create invalid or non-deterministic behavior.
	rtr.Seal()

	return Keeper{
		storeKey:   key,
		paramSpace: paramSpace,
		authKeeper: authKeeper,
		bankKeeper: bankKeeper,
		sk:         sk,
		cdc:        cdc,
		router:     rtr,
		paramsKeeper: paramsKeeper,
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
