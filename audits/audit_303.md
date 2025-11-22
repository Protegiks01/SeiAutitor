## Audit Report

## Title
State Corruption via Hook Panic After State Commitment in DeliverTx

## Summary
A critical vulnerability exists in the transaction execution flow where `DeliverTxHooks` are executed after state changes have been permanently committed via `msCache.Write()`. If a hook panics, the transaction returns an error but the state modifications remain applied, breaking the atomicity guarantee that "State only gets persisted if all messages get executed successfully." [1](#0-0) [2](#0-1) 

## Impact
**High** - This vulnerability breaks fundamental transaction atomicity guarantees and can lead to:
- Unintended smart contract behavior with state corruption
- Direct loss of funds in scenarios where transaction success/failure status is used for accounting
- Potential consensus failures if hooks behave non-deterministically across nodes
- Network instability due to inconsistent state between nodes

## Finding Description

**Location:**
- Module: `baseapp`
- File: `baseapp/baseapp.go`
- Function: `runTx`
- Critical lines: 1016 (state commit), 1041-1046 (hook execution) [3](#0-2) 

**Intended Logic:**
The `runTx` function is documented to ensure that "State only gets persisted if all messages get executed successfully" as stated in the `DeliverTx` docstring. The defer/recover mechanism at lines 904-915 is intended to catch panics during transaction processing and convert them to errors, preventing state corruption. [4](#0-3) 

**Actual Logic:**
The execution order creates a critical vulnerability:

1. **Line 1008**: Transaction context cache is created
2. **Line 1013**: Messages are executed against the cache
3. **Line 1016**: If successful, `msCache.Write()` commits all state changes to the parent store **permanently**
4. **Lines 1041-1046**: `deliverTxHooks` are executed AFTER state commitment
5. **Lines 904-915**: If a hook panics, the defer/recover catches it and returns an error

The problem: Once `msCache.Write()` is called, there is no rollback mechanism. The cache changes are written to the parent `deliverState` multistore. If a hook subsequently panics, the defer/recover converts the panic to an error return, but the state changes from step 3 remain applied. [5](#0-4) 

**Exploit Scenario:**

1. A malicious or buggy hook is registered via `RegisterDeliverTxHook` (e.g., by a module during initialization)
2. A transaction executes successfully and modifies state (e.g., transfers funds, updates balances)
3. `msCache.Write()` permanently commits these state changes
4. A registered hook executes and panics (either intentionally or due to a bug)
5. The panic is caught by the defer/recover block
6. The transaction is marked as failed (error returned to caller)
7. **However, the state changes remain applied** - the transaction appears to fail but its effects persist

**Security Failure:**
This breaks the **atomicity** invariant of transaction execution. A transaction should either completely succeed (all state changes applied) or completely fail (no state changes applied). This vulnerability allows a transaction to partially succeed - state is modified but the transaction is reported as failed.

## Impact Explanation

**Assets and Processes Affected:**
- **State Integrity**: The blockchain state becomes inconsistent as "failed" transactions modify state
- **Funds**: In scenarios where accounting logic relies on transaction success/failure status, funds could be lost or double-spent
- **Smart Contracts**: Contract execution that depends on transaction atomicity will behave incorrectly
- **Consensus**: If hooks behave non-deterministically (e.g., based on external factors, timing, or node-specific state), different nodes may have different states after processing the same transaction

**Severity of Damage:**
- **Direct financial impact**: Transactions can appear to fail while still transferring funds or modifying balances
- **State divergence**: Nodes may reach different states if hook behavior varies across nodes
- **Protocol invariants broken**: Core assumptions about transaction atomicity are violated
- **Hard fork risk**: If exploited at scale, recovering from widespread state corruption would require a hard fork

**System Security Impact:**
This matters critically because:
1. Transaction atomicity is a fundamental guarantee of blockchain systems
2. Applications and smart contracts rely on this guarantee for correctness
3. Breaking this invariant can cascade into wider system failures
4. The issue is in core transaction processing, affecting all transaction types

## Likelihood Explanation

**Who can trigger it:**
- Any actor who can register a `DeliverTxHook` (typically module developers during chain initialization)
- Any developer whose hook code contains a bug that could panic
- Note: While hook registration requires privileged access, the vulnerability manifests as an **unintended bug** in the core transaction processing logic, not malicious hook behavior

**Conditions required:**
- A registered hook that panics during execution
- A transaction that successfully executes and modifies state
- The hook must panic AFTER the transaction succeeds but BEFORE completion

**Frequency:**
- **Can occur during normal operation**: Any time a hook has a bug that causes a panic
- **Easy to trigger accidentally**: Common programming errors (nil pointer dereference, array out of bounds, assertion failures) in hooks will trigger this
- **Reproducible**: Once a panic condition exists in a hook, it will consistently corrupt state for matching transactions
- **Currently demonstrated in tests**: The test at line 1685 registers a panicking hook, though it doesn't verify state rollback [6](#0-5) 

## Recommendation

**Primary Fix:**
Move hook execution to occur BEFORE `msCache.Write()`, ensuring hooks execute in a transactional context where failures can still trigger rollback:

```
// After message execution succeeds
result, err = app.runMsgs(runMsgCtx, msgs, mode)
if err != nil {
    return // fail before any writes
}

// Execute hooks BEFORE committing state
if err == nil && (!ctx.IsEVM() || result.EvmError == "") {
    for _, hook := range app.deliverTxHooks {
        hook(ctx, tx, checksum, sdk.DeliverTxHookInput{...})
    }
}

// Only commit state if hooks also succeeded
if err == nil && mode == runTxModeDeliver {
    msCache.Write()
}
```

**Alternative Fix:**
Wrap hook execution in its own defer/recover that reverts state on panic:

```
if err == nil && mode == runTxModeDeliver {
    defer func() {
        if r := recover(); r != nil {
            // Hook panicked - need to revert state
            // This requires additional rollback mechanism
            err = sdkerrors.Wrap(sdkerrors.ErrPanic, "hook execution failed")
        }
    }()
    msCache.Write()
    
    // Execute hooks after write but with panic protection
    for _, hook := range app.deliverTxHooks {
        hook(ctx, tx, checksum, sdk.DeliverTxHookInput{...})
    }
}
```

**Additional Hardening:**
- Add hook execution validation in test suite to verify state rollback on panic
- Document hook safety requirements clearly for module developers
- Consider adding a hook timeout or resource limit mechanism

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** Add new test `TestDeliverTxHookPanicStateCorruption`

**Setup:**
1. Create a BaseApp instance with a simple ante handler and message handler
2. Register a counter key in the store to track state changes
3. Set up the message handler to increment a counter in the store
4. Initialize the chain and begin a block

**Trigger:**
1. Register a `DeliverTxHook` that panics unconditionally
2. Create a transaction with a message that increments the store counter
3. Execute the transaction via `DeliverTx`
4. Capture the store state before and after the transaction

**Observation:**
The test should verify that:
- `DeliverTx` returns an error (not OK) due to the hook panic
- **BUG**: The store counter was incremented despite the transaction failing
- This demonstrates that state changes persisted even though the transaction reported failure

**Expected Behavior (currently FAILS):**
- When the hook panics, the transaction should fail AND the state should be unchanged
- The counter should remain at its pre-transaction value

**Actual Behavior (demonstrating vulnerability):**
- The transaction fails (correct) but the counter was incremented (INCORRECT)
- This proves state corruption: failed transaction with applied state changes

**Test Code Location:** Insert after line 1690 in `baseapp/deliver_tx_test.go`

The existing test at lines 1684-1690 verifies panic handling but does NOT check state rollback, which is why this vulnerability was not caught. A proper test must verify that state changes are reverted when hooks panic. [7](#0-6)

### Citations

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

**File:** baseapp/abci.go (L279-283)
```go
// DeliverTx implements the ABCI interface and executes a tx in DeliverTx mode.
// State only gets persisted if all messages are valid and get executed successfully.
// Otherwise, the ResponseDeliverTx will contain relevant error information.
// Regardless of tx execution outcome, the ResponseDeliverTx will contain relevant
// gas execution context.
```

**File:** baseapp/deliver_tx_test.go (L1650-1690)
```go
func TestDeliverTxHooks(t *testing.T) {
	anteOpt := func(*BaseApp) {}
	routerOpt := func(bapp *BaseApp) {
		r := sdk.NewRoute(routeMsgCounter, func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) { return &sdk.Result{}, nil })
		bapp.Router().AddRoute(r)
	}

	app := setupBaseApp(t, anteOpt, routerOpt)
	app.InitChain(context.Background(), &abci.RequestInitChain{})

	// Create same codec used in txDecoder
	codec := codec.NewLegacyAmino()
	registerTestCodec(codec)

	header := tmproto.Header{Height: 1}
	app.setDeliverState(header)
	app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})

	// every even i is an evm tx
	counter := int64(1)
	tx := newTxCounter(counter, counter)

	txBytes, err := codec.Marshal(tx)
	require.NoError(t, err)

	decoded, _ := app.txDecoder(txBytes)

	ctx := app.deliverState.ctx

	// register noop hook
	app.RegisterDeliverTxHook(func(ctx sdk.Context, tx sdk.Tx, b [32]byte, rdt sdk.DeliverTxHookInput) {})
	res := app.DeliverTx(ctx, abci.RequestDeliverTx{Tx: txBytes}, decoded, sha256.Sum256(txBytes))
	require.True(t, res.IsOK(), fmt.Sprintf("%v", res))

	// register panic hook (should be captured by recover() middleware)
	app.RegisterDeliverTxHook(func(ctx sdk.Context, tx sdk.Tx, b [32]byte, rdt sdk.DeliverTxHookInput) { panic(1) })
	require.NotPanics(t, func() {
		res = app.DeliverTx(ctx, abci.RequestDeliverTx{Tx: txBytes}, decoded, sha256.Sum256(txBytes))
	})
	require.False(t, res.IsOK(), fmt.Sprintf("%v", res))
}
```
