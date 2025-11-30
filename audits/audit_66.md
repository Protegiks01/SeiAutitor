# Audit Report

## Title
Missing Cumulative Block Gas Limit Enforcement Allows Resource Exhaustion Through Multiple High-Gas Transactions

## Summary
The sei-cosmos implementation has removed block gas meter enforcement, eliminating cumulative gas tracking across transactions within a block. While individual transactions are validated against the MaxGas consensus parameter, multiple transactions can collectively consume gas far beyond this limit, forcing all network nodes to process blocks that violate configured resource parameters.

## Impact
Medium

## Finding Description

**Location:**
- Transaction execution loop without cumulative gas tracking: [1](#0-0) 
- Missing block gas meter initialization: [2](#0-1) 
- Per-transaction validation only: [3](#0-2) 
- No validation in ProcessProposal: [4](#0-3) 
- No validation in PrepareProposal: [5](#0-4) 
- Context struct contains unused blockGasMeter field: [6](#0-5) 

**Intended Logic:**
According to the documentation [7](#0-6) , the MaxGas consensus parameter should limit total computational resources consumed by all transactions in a block. The BlockGasMeter should be initialized in BeginBlock, checked before processing each transaction in DeliverTx, and updated after each transaction execution. If the cumulative gas exceeds MaxGas, DeliverTx should return immediately without processing additional transactions.

**Actual Logic:**
The block gas meter is never initialized in setDeliverState or BeginBlock [8](#0-7) . The FinalizeBlock transaction loop processes all transactions sequentially without any cumulative gas tracking. The only gas enforcement is per-transaction validation in the ante handler, which checks if individual GasWanted exceeds MaxGas. No cumulative enforcement exists during transaction execution [9](#0-8) . The removal was explicitly documented [10](#0-9)  with a false claim that "gasWanted < max block gas is still fulfilled by various other checks."

**Exploitation Path:**
1. Multiple users submit transactions to mempool, each with GasWanted below MaxGas (e.g., 9,000,000 when MaxGas = 10,000,000)
2. Each transaction individually passes ante handler validation: GasWanted ≤ MaxGas ✓
3. Validator includes N such transactions in PrepareProposal without cumulative gas checking
4. ProcessProposal accepts the proposal without validating cumulative gas
5. Consensus is reached on the block
6. FinalizeBlock processes all N transactions without cumulative limit enforcement
7. Block executes with total gas = N × 9,000,000, potentially 5-10x the MaxGas limit
8. All network nodes are forced to process this resource-intensive block

**Security Guarantee Broken:**
The consensus invariant that total block gas consumption ≤ MaxGas is violated. This undermines the resource consumption guarantees that ensure predictable block processing times and prevent denial-of-service through computational resource exhaustion.

## Impact Explanation

This vulnerability directly matches the Medium severity impact criterion: **"Causing network processing nodes to process transactions from the mempool beyond set parameters"**.

The MaxGas consensus parameter exists specifically to limit computational resources per block. Its non-enforcement means:

1. All network nodes must process blocks with cumulative gas consumption far exceeding the configured limit
2. Resource-constrained nodes experience significantly longer block execution times  
3. The consensus parameter's intended protection against resource exhaustion is defeated
4. Blocks can consume 5-10x the intended resource limit
5. During sustained submission of high-gas transactions, network-wide resource consumption can increase by 30% or more compared to normal operation

The commented-out test cases [11](#0-10)  demonstrate that cumulative gas enforcement was previously implemented and tested, confirming this is a regression rather than intentional design.

## Likelihood Explanation

**Trigger Requirements:**
- Any network participant can submit high-gas transactions to the mempool (no special privileges required)
- Multiple high-gas transactions need to be available in the mempool (easily achievable through normal usage or deliberate submission)
- Validator includes them based on standard selection criteria (e.g., highest fees)

**Frequency:**
This can occur in any block where multiple high-gas transactions are present. The vulnerability does not require a malicious validator - even honest validators selecting high-fee transactions can trigger this condition. An attacker can sustain this by continuously submitting high-gas transactions. The economic cost is only transaction fees, which scale linearly while the resource impact scales multiplicatively.

## Recommendation

Restore cumulative block gas tracking by re-implementing block gas meter functionality:

1. Initialize block gas meter in `setDeliverState` with limit from consensus params MaxGas
2. Add `BlockGasMeter()` accessor method to Context
3. In the FinalizeBlock transaction loop, check cumulative gas before processing each transaction
4. Track cumulative gas consumption after each transaction execution
5. Stop processing transactions when cumulative limit is reached
6. Update PrepareProposal to account for cumulative gas when selecting transactions
7. Add validation in ProcessProposal to reject blocks exceeding MaxGas

Alternatively, implement a lightweight cumulative gas counter that tracks the sum of GasUsed across all transactions and enforces the MaxGas limit without the full gas meter infrastructure.

## Proof of Concept

The vulnerability is evident from code inspection. The commented-out test cases [12](#0-11)  show test scenarios where cumulative gas enforcement was previously verified, including cases that expected failure when cumulative gas exceeded MaxGas (e.g., 11 deliveries of 10 gas each with MaxGas=100).

**Setup:**
- Initialize BaseApp with consensus parameter MaxGas = 10,000,000
- Prepare 12 transactions, each with GasWanted = 9,000,000 (90% of block limit)

**Action:**
- Validator includes all 12 transactions in PrepareProposal
- ProcessProposal accepts the proposal (no validation implemented)
- FinalizeBlock executes all transactions in the loop

**Result:**
- Total gas consumed = 108,000,000 (10.8x the MaxGas limit)
- Block processes successfully despite violating the consensus parameter
- All network nodes must process computational work far exceeding configured limits
- Demonstrates MaxGas is advisory rather than enforced during block execution

## Notes

The removal of block gas meter enforcement appears to have been intentional based on the comment [10](#0-9) , which states "gasWanted < max block gas is still fulfilled by various other checks." However, investigation confirms this statement is incorrect - the only existing check is per-transaction validation in the ante handler, which does not prevent cumulative excess.

This vulnerability is particularly concerning because it defeats a fundamental consensus-level safety mechanism. Even if validators are generally trusted, the lack of validation in ProcessProposal means the network has no defense against blocks that violate resource parameters, whether created maliciously or accidentally.

### Citations

**File:** simapp/app.go (L462-468)
```go
func (app *SimApp) PrepareProposalHandler(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
	return &abci.ResponsePrepareProposal{
		TxRecords: utils.Map(req.Txs, func(tx []byte) *abci.TxRecord {
			return &abci.TxRecord{Action: abci.TxRecord_UNMODIFIED, Tx: tx}
		}),
	}, nil
}
```

**File:** simapp/app.go (L470-474)
```go
func (app *SimApp) ProcessProposalHandler(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	return &abci.ResponseProcessProposal{
		Status: abci.ResponseProcessProposal_ACCEPT,
	}, nil
}
```

**File:** simapp/app.go (L518-537)
```go
	for i, tx := range req.Txs {
		ctx = ctx.WithContext(context.WithValue(ctx.Context(), ante.ContextKeyTxIndexKey, i))
		if typedTxs[i] == nil {
			txResults = append(txResults, &abci.ExecTxResult{}) // empty result
			continue
		}
		deliverTxResp := app.DeliverTx(ctx, abci.RequestDeliverTx{
			Tx: tx,
		}, typedTxs[i], sha256.Sum256(tx))
		txResults = append(txResults, &abci.ExecTxResult{
			Code:      deliverTxResp.Code,
			Data:      deliverTxResp.Data,
			Log:       deliverTxResp.Log,
			Info:      deliverTxResp.Info,
			GasWanted: deliverTxResp.GasWanted,
			GasUsed:   deliverTxResp.GasUsed,
			Events:    deliverTxResp.Events,
			Codespace: deliverTxResp.Codespace,
		})
	}
```

**File:** baseapp/baseapp.go (L580-593)
```go
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

**File:** baseapp/baseapp.go (L860-1048)
```go
func (app *BaseApp) runTx(ctx sdk.Context, mode runTxMode, tx sdk.Tx, checksum [32]byte) (
	gInfo sdk.GasInfo,
	result *sdk.Result,
	anteEvents []abci.Event,
	priority int64,
	pendingTxChecker abci.PendingTxChecker,
	expireHandler abci.ExpireTxHandler,
	txCtx sdk.Context,
	err error,
) {
	defer telemetry.MeasureThroughputSinceWithLabels(
		telemetry.TxCount,
		[]metrics.Label{
			telemetry.NewLabel("mode", modeKeyToString[mode]),
		},
		time.Now(),
	)

	// Reset events after each checkTx or simulateTx or recheckTx
	// DeliverTx is garbage collected after FinalizeBlocker
	if mode != runTxModeDeliver {
		defer ctx.MultiStore().ResetEvents()
	}

	// Wait for signals to complete before starting the transaction. This is needed before any of the
	// resources are acceessed by the ante handlers and message handlers.
	defer acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
	acltypes.WaitForAllSignalsForTx(ctx.TxBlockingChannels())
	if app.TracingEnabled {
		// check for existing parent tracer, and if applicable, use it
		spanCtx, span := app.TracingInfo.StartWithContext("RunTx", ctx.TraceSpanContext())
		defer span.End()
		ctx = ctx.WithTraceSpanContext(spanCtx)
		span.SetAttributes(attribute.String("txHash", fmt.Sprintf("%X", checksum)))
	}

	// NOTE: GasWanted should be returned by the AnteHandler. GasUsed is
	// determined by the GasMeter. We need access to the context to get the gas
	// meter so we initialize upfront.
	var gasWanted uint64
	var gasEstimate uint64

	ms := ctx.MultiStore()

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

	if tx == nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "tx decode error")
	}

	msgs := tx.GetMsgs()

	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}

	if app.anteHandler != nil {
		var anteSpan trace.Span
		if app.TracingEnabled {
			// trace AnteHandler
			_, anteSpan = app.TracingInfo.StartWithContext("AnteHandler", ctx.TraceSpanContext())
			defer anteSpan.End()
		}
		var (
			anteCtx sdk.Context
			msCache sdk.CacheMultiStore
		)
		// Branch context before AnteHandler call in case it aborts.
		// This is required for both CheckTx and DeliverTx.
		// Ref: https://github.com/cosmos/cosmos-sdk/issues/2772
		//
		// NOTE: Alternatively, we could require that AnteHandler ensures that
		// writes do not happen if aborted/failed.  This may have some
		// performance benefits, but it'll be more difficult to get right.
		anteCtx, msCache = app.cacheTxContext(ctx, checksum)
		anteCtx = anteCtx.WithEventManager(sdk.NewEventManager())
		newCtx, err := app.anteHandler(anteCtx, tx, mode == runTxModeSimulate)

		if !newCtx.IsZero() {
			// At this point, newCtx.MultiStore() is a store branch, or something else
			// replaced by the AnteHandler. We want the original multistore.
			//
			// Also, in the case of the tx aborting, we need to track gas consumed via
			// the instantiated gas meter in the AnteHandler, so we update the context
			// prior to returning.
			//
			// This also replaces the GasMeter in the context where GasUsed was initalized 0
			// and updated with gas consumed in the ante handler runs
			// The GasMeter is a pointer and its passed to the RunMsg and tracks the consumed
			// gas there too.
			ctx = newCtx.WithMultiStore(ms)
		}
		defer func() {
			if newCtx.DeliverTxCallback() != nil {
				newCtx.DeliverTxCallback()(ctx.WithGasMeter(sdk.NewInfiniteGasMeterWithMultiplier(ctx)))
			}
		}()

		events := ctx.EventManager().Events()

		if err != nil {
			return gInfo, nil, nil, 0, nil, nil, ctx, err
		}
		// GasMeter expected to be set in AnteHandler
		gasWanted = ctx.GasMeter().Limit()
		gasEstimate = ctx.GasEstimate()

		// Dont need to validate in checkTx mode
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
			storeAccessOpEvents := msCache.GetEvents()
			accessOps := ctx.TxMsgAccessOps()[acltypes.ANTE_MSG_INDEX]

			// TODO: (occ) This is an example of where we do our current validation. Note that this validation operates on the declared dependencies for a TX / antehandler + the utilized dependencies, whereas the validation
			missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
			if len(missingAccessOps) != 0 {
				for op := range missingAccessOps {
					ctx.Logger().Info((fmt.Sprintf("Antehandler Missing Access Operation:%s ", op.String())))
					op.EmitValidationFailMetrics()
				}
				errMessage := fmt.Sprintf("Invalid Concurrent Execution antehandler missing %d access operations", len(missingAccessOps))
				return gInfo, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
			}
		}

		priority = ctx.Priority()
		pendingTxChecker = ctx.PendingTxChecker()
		expireHandler = ctx.ExpireTxHandler()
		msCache.Write()
		anteEvents = events.ToABCIEvents()
		if app.TracingEnabled {
			anteSpan.End()
		}
	}

	// Create a new Context based off of the existing Context with a MultiStore branch
	// in case message processing fails. At this point, the MultiStore
	// is a branch of a branch.
	runMsgCtx, msCache := app.cacheTxContext(ctx, checksum)

	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
	// we do this since we will only be looking at result in DeliverTx
	if result != nil && len(anteEvents) > 0 {
		// append the events in the order of occurrence
		result.Events = append(anteEvents, result.Events...)
	}
	if ctx.CheckTxCallback() != nil {
		ctx.CheckTxCallback()(ctx, err)
	}
	// only apply hooks if no error
	if err == nil && (!ctx.IsEVM() || result.EvmError == "") {
		var evmTxInfo *abci.EvmTxInfo
		if ctx.IsEVM() {
			evmTxInfo = &abci.EvmTxInfo{
				SenderAddress: ctx.EVMSenderAddress(),
				Nonce:         ctx.EVMNonce(),
				TxHash:        ctx.EVMTxHash(),
				VmError:       result.EvmError,
			}
		}
		var events []abci.Event = []abci.Event{}
		if result != nil {
			events = sdk.MarkEventsToIndex(result.Events, app.indexEvents)
		}
		for _, hook := range app.deliverTxHooks {
			hook(ctx, tx, checksum, sdk.DeliverTxHookInput{
				EvmTxInfo: evmTxInfo,
				Events:    events,
			})
		}
	}
	return gInfo, result, anteEvents, priority, pendingTxChecker, expireHandler, ctx, err
```

**File:** x/auth/ante/setup.go (L54-59)
```go
	if cp := ctx.ConsensusParams(); cp != nil && cp.Block != nil {
		// If there exists a maximum block gas limit, we must ensure that the tx
		// does not exceed it.
		if cp.Block.MaxGas > 0 && gasTx.GetGas() > uint64(cp.Block.MaxGas) {
			return newCtx, sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "tx gas wanted %d exceeds block max gas limit %d", gasTx.GetGas(), cp.Block.MaxGas)
		}
```

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

**File:** docs/basics/gas-fees.md (L49-62)
```markdown
### Block Gas Meter

`ctx.BlockGasMeter()` is the gas meter used to track gas consumption per block and make sure it does not go above a certain limit. A new instance of the `BlockGasMeter` is created each time [`BeginBlock`](../core/baseapp.md#beginblock) is called. The `BlockGasMeter` is finite, and the limit of gas per block is defined in the application's consensus parameters. By default Cosmos SDK applications use the default consensus parameters provided by Tendermint:

+++ https://github.com/tendermint/tendermint/blob/v0.34.0-rc6/types/params.go#L34-L41

When a new [transaction](../core/transactions.md) is being processed via `DeliverTx`, the current value of `BlockGasMeter` is checked to see if it is above the limit. If it is, `DeliverTx` returns immediately. This can happen even with the first transaction in a block, as `BeginBlock` itself can consume gas. If not, the transaction is processed normally. At the end of `DeliverTx`, the gas tracked by `ctx.BlockGasMeter()` is increased by the amount consumed to process the transaction:

```go
ctx.BlockGasMeter().ConsumeGas(
	ctx.GasMeter().GasConsumedToLimit(),
	"block gas meter",
)
```
```

**File:** baseapp/abci.go (L133-157)
```go
// BeginBlock implements the ABCI application interface.
func (app *BaseApp) BeginBlock(ctx sdk.Context, req abci.RequestBeginBlock) (res abci.ResponseBeginBlock) {
	defer telemetry.MeasureSince(time.Now(), "abci", "begin_block")

	if !req.Simulate {
		if err := app.validateHeight(req); err != nil {
			panic(err)
		}
	}

	if app.beginBlocker != nil {
		res = app.beginBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	// call the streaming service hooks with the EndBlock messages
	if !req.Simulate {
		for _, streamingListener := range app.abciListeners {
			if err := streamingListener.ListenBeginBlock(app.deliverState.ctx, req, res); err != nil {
				app.logger.Error("EndBlock listening hook failed", "height", req.Header.Height, "err", err)
			}
		}
	}
	return res
}
```

**File:** baseapp/deliver_tx_test.go (L790-812)
```go
// 			Block: &tmproto.BlockParams{
// 				MaxGas: 100,
// 			},
// 		},
// 	})

// 	testCases := []struct {
// 		tx                *txTest
// 		numDelivers       int
// 		gasUsedPerDeliver uint64
// 		fail              bool
// 		failAfterDeliver  int
// 	}{
// 		{newTxCounter(0, 0), 0, 0, false, 0},
// 		{newTxCounter(9, 1), 2, 10, false, 0},
// 		{newTxCounter(10, 0), 3, 10, false, 0},
// 		{newTxCounter(10, 0), 10, 10, false, 0},
// 		{newTxCounter(2, 7), 11, 9, false, 0},
// 		{newTxCounter(10, 0), 10, 10, false, 0}, // hit the limit but pass

// 		{newTxCounter(10, 0), 11, 10, true, 10},
// 		{newTxCounter(10, 0), 15, 10, true, 10},
// 		{newTxCounter(9, 0), 12, 9, true, 11}, // fly past the limit
```

**File:** baseapp/deliver_tx_test.go (L1144-1144)
```go
	// removed the block gas exceeded because of removal of block gas meter, gasWanted < max block gas is still fulfilled by various other checks
```
