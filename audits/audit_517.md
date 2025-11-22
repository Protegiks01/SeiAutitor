## Audit Report

## Title
Unrecovered Panic in Governance Proposal Handler Causes Complete Network Halt

## Summary
The governance module's `EndBlocker` function executes proposal handlers without panic recovery. When a passed governance proposal's handler panics during execution in the cached context, the panic propagates uncaught through the call stack, causing all validator nodes to crash simultaneously at the same block height, resulting in a complete network shutdown that requires a hard fork to resolve. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary: `x/gov/abci.go`, lines 67-92, specifically line 74 where the handler is invoked
- Secondary: `baseapp/abci.go`, lines 178-201 (EndBlock with no panic recovery) [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The governance EndBlocker should execute passed proposal handlers safely. If a handler fails, the proposal should be marked as failed and logged, but the chain should continue processing blocks. The cached context at line 69 is intended to isolate state changes, allowing them to be discarded if the handler returns an error (lines 88-92).

**Actual Logic:** 
The code only handles errors returned by the handler (line 74 checks `if err == nil`), but provides no protection against panics. When a handler panics instead of returning an error, the panic propagates uncaught through:
1. `gov.EndBlocker` (no defer/recover block)
2. `BaseApp.EndBlock` at line 185 (no defer/recover block)
3. The ABCI layer, crashing the validator node [3](#0-2) 

This is in stark contrast to `ProcessProposal` which has explicit panic recovery: [4](#0-3) 

**Exploit Scenario:**
1. A third-party module (or malicious actor who controls a module) registers a governance proposal handler that panics under certain conditions
2. A governance proposal of that type is submitted to the chain
3. Token holders vote and the proposal passes (requires normal governance approval)
4. When the voting period ends, `gov.EndBlocker` is called during block finalization
5. The EndBlocker iterates through active proposals and calls the handler at line 74
6. The malicious/buggy handler panics (e.g., via explicit `panic()`, array index out of bounds, nil pointer dereference, or `MustMarshal` failure)
7. No defer/recover catches the panic in `gov.EndBlocker` or `BaseApp.EndBlock`
8. All validator nodes crash at the exact same block height
9. The network completely halts - no new blocks can be produced
10. Recovery requires coordinated hard fork with patched binary

**Security Failure:** 
Availability failure through denial-of-service. A single panicking proposal handler causes catastrophic network-wide consensus failure where all validators simultaneously crash, violating the fundamental assumption that the chain can continue processing blocks even when individual proposals fail.

## Impact Explanation

**Affected Processes:**
- All block production and transaction processing halts immediately
- All validator nodes crash simultaneously
- Network cannot reach consensus on any new blocks
- Users cannot submit or execute any transactions
- All chain operations cease completely

**Severity of Damage:**
- **Complete network shutdown:** 100% of validators halt at the same block
- **Requires hard fork:** Cannot be resolved through normal chain operations
- **Coordinated recovery needed:** All validators must upgrade to patched binary
- **Potential data loss:** Any unfinalized state is lost
- **Economic impact:** Trading halts, DeFi protocols freeze, user funds inaccessible

**System Reliability:**
This violates the core blockchain assumption that the network should be resilient to individual component failures. A single malformed proposal handler creates a single point of failure that can take down the entire network, fundamentally breaking the chain's availability guarantees.

## Likelihood Explanation

**Trigger Requirements:**
- **Who:** Any party that can get a governance proposal passed (requires token holder votes)
- **Prerequisites:** 
  - A module with a registered proposal handler that contains a panic path (either malicious or buggy)
  - Governance approval (typically requires majority token holder support)
  - Natural completion of voting period

**Likelihood Factors:**
- **Medium-High likelihood** in practice:
  - Third-party modules commonly integrate custom proposal handlers
  - Handler implementations may contain bugs (nil checks, array access, type assertions)
  - Standard library functions like `MustMarshal` panic on error [5](#0-4) [6](#0-5) 

  - Even well-intentioned code can panic unexpectedly under edge cases
  - No code review process can guarantee panic-free handlers across all integrated modules

**Frequency:**
- Could occur on any block where a passed proposal's voting period ends
- Each integrated third-party module is a potential vulnerability source
- Risk increases as ecosystem grows and more modules are added

## Recommendation

Add panic recovery to the governance EndBlocker function, mirroring the protection pattern used in `ProcessProposal`:

**Recommended Fix:**
1. Add a defer/recover block at the beginning of `gov.EndBlocker` function in `x/gov/abci.go`
2. In the recovery handler:
   - Log the panic details (proposal ID, type, stack trace)
   - Mark the proposal as failed (status = `StatusFailed`)
   - Continue processing remaining proposals
   - Return normally to prevent node crash

**Alternative/Additional Fix:**
Add panic recovery wrapper around the specific handler call at lines 68-74:
- Create a deferred recovery that catches panics from the handler invocation
- Convert panics to errors and handle them through the existing error path (lines 88-92)
- Ensure the cached context changes are discarded on panic (do not call `writeCache()`)

This approach provides defense-in-depth: even if a handler panics, the chain continues operating and the proposal is safely marked as failed.

## Proof of Concept

**Test File:** `x/gov/abci_test.go`

**Test Function Name:** `TestProposalHandlerPanicCausesChainHalt`

**Setup:**
1. Initialize a SimApp test application with standard configuration
2. Create test accounts and validators with sufficient tokens
3. Register a custom proposal handler that deliberately panics when executed
4. Submit a governance proposal of the custom type
5. Deposit sufficient tokens to activate the proposal
6. Vote YES on the proposal to ensure it passes
7. Advance blockchain time past the voting period end

**Trigger:**
1. Call `gov.EndBlocker(ctx, app.GovKeeper)` which processes the passed proposal
2. The EndBlocker will invoke the registered handler at line 74
3. The handler panics with a deliberate `panic("malicious handler panic")`

**Observation:**
The test demonstrates that calling `gov.EndBlocker` with a panicking handler causes an unrecovered panic that would crash the validator node. The test should be wrapped in a recover block to catch and verify the panic occurs:

```go
func TestProposalHandlerPanicCausesChainHalt(t *testing.T) {
    // Setup: Create app and register panicking handler
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Register a handler that panics
    govRouter := app.GovKeeper.Router()
    govRouter.AddRoute("panic", func(ctx sdk.Context, content govtypes.Content) error {
        panic("malicious handler deliberately panics")
    })
    
    // Submit, vote, and pass a proposal
    // ... (standard proposal submission code)
    
    // Advance time to end of voting period
    // ... (time advancement code)
    
    // Trigger: This should panic and would crash a real validator
    defer func() {
        if r := recover(); r != nil {
            // Panic occurred - vulnerability confirmed
            t.Logf("VULNERABILITY CONFIRMED: EndBlocker panicked with: %v", r)
            t.Logf("In production, this would crash all validators simultaneously")
        } else {
            t.Fatal("Expected panic from malicious handler, but none occurred")
        }
    }()
    
    gov.EndBlocker(ctx, app.GovKeeper)
}
```

**Expected Result:**
The test catches the panic, confirming that no recovery mechanism exists in the EndBlocker path. In a production environment, this panic would propagate to the consensus layer and crash the validator node, causing network-wide halt when all validators process the same block containing the malicious proposal execution.

### Citations

**File:** x/gov/abci.go (L67-92)
```go
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

**File:** baseapp/abci.go (L1106-1118)
```go
	defer func() {
		if err := recover(); err != nil {
			app.logger.Error(
				"panic recovered in ProcessProposal",
				"height", req.Height,
				"time", req.Time,
				"hash", fmt.Sprintf("%X", req.Hash),
				"panic", err,
			)

			resp = &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
		}
	}()
```

**File:** codec/proto_codec.go (L46-53)
```go
func (pc *ProtoCodec) MustMarshal(o ProtoMarshaler) []byte {
	bz, err := pc.Marshal(o)
	if err != nil {
		panic(err)
	}

	return bz
}
```

**File:** x/upgrade/keeper/keeper.go (L200-201)
```go
	bz := k.cdc.MustMarshal(&plan)
	store.Set(types.PlanKey(), bz)
```
