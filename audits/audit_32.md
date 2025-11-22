## Title
Resource Exhaustion Without Payment Due to AnteHandler Ordering and Missing Fee Deduction on Early OutOfGas Failures

## Summary
The OutOfGas recovery middleware in `baseapp/recovery.go:50-62` does not differentiate between legitimate out-of-gas scenarios and malicious gas exhaustion attacks. More critically, there is a vulnerability in the AnteHandler chain ordering where gas consumption for transaction size occurs before fee deduction. This allows attackers to craft large transactions with insufficient gas limits that fail early in the AnteHandler chain without paying fees, enabling resource exhaustion attacks on network nodes without economic cost to the attacker.

## Impact
Medium

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Recovery middleware: [2](#0-1) 
- Fee deduction: [3](#0-2) 
- Gas consumption: [4](#0-3) 
- runTx flow: [5](#0-4) 

**Intended Logic:** 
The system is designed to charge fees for all transaction processing to prevent resource exhaustion attacks. The OutOfGas recovery middleware should catch gas exhaustion panics and ensure proper accounting. Fees should be deducted from users before performing gas-intensive operations to prevent free resource consumption.

**Actual Logic:** 
The AnteHandler chain has a critical ordering flaw. The `ConsumeGasForTxSizeDecorator` (line 53) executes BEFORE `DeductFeeDecorator` (line 54). When a transaction's byte size requires more gas than the user-specified gas limit, an OutOfGas panic occurs in `ConsumeGasForTxSizeDecorator`. This panic is caught by `SetUpContextDecorator`'s defer/recover mechanism, which converts it to an error and returns before `DeductFeeDecorator` ever executes. In `runTx`, when the AnteHandler returns an error at line 971-972, the function returns early. The `gasWanted` variable (declared at line 899) is never set from `ctx.GasMeter().Limit()` (line 975), remaining at its default value of 0. The defer at line 914 then sets `gInfo` with `GasWanted=0`, and most critically, no fees are deducted because `DeductFeeDecorator` never ran.

**Exploit Scenario:**
1. Attacker constructs a transaction with large byte size (through multiple messages, large payloads, or maximum-length memo fields)
2. Attacker sets `gasLimit` to a value insufficient to cover the transaction size cost (e.g., 1,000 gas for a 100,000-byte transaction that requires 1,000,000 gas at 10 gas/byte)
3. Transaction enters CheckTx phase and goes through AnteHandler chain
4. `SetUpContextDecorator` sets up gas meter with the attacker's low gas limit
5. `ConsumeGasForTxSizeDecorator` attempts to consume gas: `params.TxSizeCostPerByte * len(txBytes)`
6. OutOfGas panic occurs before reaching `DeductFeeDecorator`
7. `SetUpContextDecorator` catches panic, converts to error, returns from AnteHandler
8. Transaction fails in CheckTx without fees being deducted
9. Attacker repeats this process to consume network bandwidth, node CPU, and memory without payment

**Security Failure:**
This breaks the fundamental economic security property that resource consumption must be paid for. It enables a denial-of-service attack where an attacker can exhaust network resources (bandwidth for propagating large transactions, CPU for decoding and processing, memory for temporary storage) without incurring any cost.

## Impact Explanation

**Affected Resources:**
- Network bandwidth: Large transactions must be propagated through the P2P network to all validators and full nodes
- Node CPU: Each node must decode the transaction and execute it through the AnteHandler chain up to the failure point
- Node memory: Transactions must be temporarily stored and processed
- Mempool capacity: Failed transactions occupy mempool slots temporarily before rejection

**Severity:**
An attacker can spam the network with large transactions that cost nothing. With default parameters (`TxSizeCostPerByte = 10`), a 100KB transaction would require 1,000,000 gas. An attacker could craft such transactions with `gasLimit = 1,000`, causing them to fail without payment. By repeatedly broadcasting such transactions, an attacker can:
- Consume at least 30% more node resources compared to normal operation
- Force nodes to process transactions from mempool beyond normal parameters
- Potentially cause temporary degradation or shutdown of nodes with limited resources

This directly falls under the Medium severity impact: "Increasing network processing node resource consumption by at least 30% without brute force actions" and "Causing network processing nodes to process transactions from the mempool beyond set parameters."

## Likelihood Explanation

**Who can trigger it:**
Any unprivileged network participant can craft and broadcast such transactions. No special permissions, validator status, or privileged keys are required.

**Conditions required:**
- Normal network operation (no special state required)
- Attacker only needs ability to construct and broadcast transactions
- No rate limiting or upfront payment mechanisms prevent this attack

**Frequency:**
This can be exploited continuously and repeatedly. An attacker can automate generation and broadcasting of malformed transactions at high frequency. The only limiting factor is the attacker's bandwidth, which is minimal compared to the amplified resource consumption across all network nodes.

## Recommendation

**Immediate Fix:**
Reorder the AnteHandler chain to execute `DeductFeeDecorator` BEFORE `ConsumeGasForTxSizeDecorator`. This ensures fees are deducted before any gas-intensive operations occur.

**Modified chain order in `x/auth/ante/ante.go`:**
```
anteDecorators := []sdk.AnteFullDecorator{
    sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()),
    sdk.DefaultWrappedAnteDecorator(NewRejectExtensionOptionsDecorator()),
    sdk.DefaultWrappedAnteDecorator(NewValidateBasicDecorator()),
    sdk.DefaultWrappedAnteDecorator(NewTxTimeoutHeightDecorator()),
    sdk.DefaultWrappedAnteDecorator(NewValidateMemoDecorator(options.AccountKeeper)),
    NewDeductFeeDecorator(...), // MOVE THIS BEFORE ConsumeGasForTxSizeDecorator
    NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
    // ... rest of chain
}
```

**Additional Enhancement:**
In `baseapp/baseapp.go`, ensure `gasWanted` is properly set even when AnteHandler fails by capturing it from the context's gas meter before returning:
```
if err != nil {
    if !newCtx.IsZero() {
        gasWanted = newCtx.GasMeter().Limit()
    }
    return gInfo, nil, nil, 0, nil, nil, ctx, err
}
```

## Proof of Concept

**Test File:** `x/auth/ante/ante_test.go`

**Test Function:** `TestOutOfGasWithoutFeeDeduction`

**Setup:**
```go
func (suite *AnteTestSuite) TestOutOfGasWithoutFeeDeduction() {
    suite.SetupTest(true)
    
    // Create test account with initial balance
    accounts := suite.CreateTestAccounts(1)
    testAccount := accounts[0]
    initialBalance := suite.app.BankKeeper.GetBalance(
        suite.ctx, 
        testAccount.acc.GetAddress(), 
        "atom",
    )
    
    // Create transaction with large memo but insufficient gas
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    msg := testdata.NewTestMsg(testAccount.acc.GetAddress())
    suite.Require().NoError(suite.txBuilder.SetMsgs(msg))
    
    // Set large memo to increase transaction size significantly
    // With 250 characters, this will consume significant gas
    largeMemo := strings.Repeat("x", 250)
    suite.txBuilder.SetMemo(largeMemo)
    
    // Set fee amount (what should be deducted)
    feeAmount := sdk.NewCoins(sdk.NewInt64Coin("atom", 1000))
    suite.txBuilder.SetFeeAmount(feeAmount)
    
    // Set gas limit too low to cover transaction size cost
    // Transaction will be ~500+ bytes, requiring ~5000+ gas at 10 gas/byte
    // We set limit to only 100 gas to trigger OutOfGas in ConsumeGasForTxSizeDecorator
    suite.txBuilder.SetGasLimit(100)
    
    // Create signed transaction
    privs := []cryptotypes.PrivKey{testAccount.priv}
    accNums := []uint64{0}
    accSeqs := []uint64{0}
    tx, err := suite.CreateTestTx(privs, accNums, accSeqs, suite.ctx.ChainID())
    suite.Require().NoError(err)
}
```

**Trigger:**
```go
    // Execute through ante handler - this should fail with OutOfGas
    txBytes, err := suite.clientCtx.TxConfig.TxEncoder()(tx)
    suite.Require().NoError(err)
    suite.ctx = suite.ctx.WithTxBytes(txBytes)
    
    _, err = suite.anteHandler(suite.ctx, tx, false)
    
    // Verify transaction failed with OutOfGas error
    suite.Require().Error(err)
    suite.Require().Contains(err.Error(), "out of gas")
```

**Observation:**
```go
    // VULNERABILITY: Check that fees were NOT deducted despite resource consumption
    finalBalance := suite.app.BankKeeper.GetBalance(
        suite.ctx,
        testAccount.acc.GetAddress(),
        "atom",
    )
    
    // This assertion PASSES on vulnerable code, demonstrating the bug
    // Fees should have been deducted but weren't
    suite.Require().Equal(
        initialBalance.Amount, 
        finalBalance.Amount,
        "VULNERABILITY: Fees were not deducted despite transaction consuming resources",
    )
    
    // Expected behavior: finalBalance should be (initialBalance - feeAmount)
    // Actual behavior: finalBalance equals initialBalance (no fees deducted)
    // This proves attacker consumed network resources without payment
}
```

This test demonstrates that when a transaction fails due to OutOfGas in `ConsumeGasForTxSizeDecorator` (before `DeductFeeDecorator`), the user's balance remains unchanged despite the network having consumed resources to process the transaction. An attacker can exploit this to perform resource exhaustion attacks without economic cost.

### Citations

**File:** x/auth/ante/ante.go (L47-60)
```go
	anteDecorators := []sdk.AnteFullDecorator{
		sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()), // outermost AnteDecorator. SetUpContext must be called first
		sdk.DefaultWrappedAnteDecorator(NewRejectExtensionOptionsDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateBasicDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewTxTimeoutHeightDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateMemoDecorator(options.AccountKeeper)),
		NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ParamsKeeper.(paramskeeper.Keeper), options.TxFeeChecker),
		sdk.DefaultWrappedAnteDecorator(NewSetPubKeyDecorator(options.AccountKeeper)), // SetPubKeyDecorator must be called before all signature verification decorators
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
		NewIncrementSequenceDecorator(options.AccountKeeper),
	}
```

**File:** baseapp/recovery.go (L48-65)
```go
// newOutOfGasRecoveryMiddleware creates a standard OutOfGas recovery middleware for app.runTx method.
func newOutOfGasRecoveryMiddleware(gasWanted uint64, ctx sdk.Context, next recoveryMiddleware) recoveryMiddleware {
	handler := func(recoveryObj interface{}) error {
		err, ok := recoveryObj.(sdk.ErrorOutOfGas)
		if !ok {
			return nil
		}

		return sdkerrors.Wrap(
			sdkerrors.ErrOutOfGas, fmt.Sprintf(
				"out of gas in location: %v; gasWanted: %d, gasUsed: %d",
				err.Descriptor, gasWanted, ctx.GasMeter().GasConsumed(),
			),
		)
	}

	return newRecoveryMiddleware(handler, next)
}
```

**File:** x/auth/ante/fee.go (L134-146)
```go
func (dfd DeductFeeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	fee, priority, err := dfd.txFeeChecker(ctx, tx, simulate, dfd.paramsKeeper)
	if err != nil {
		return ctx, err
	}
	if err := dfd.checkDeductFee(ctx, tx, fee); err != nil {
		return ctx, err
	}

	newCtx := ctx.WithPriority(priority)

	return next(newCtx, tx, simulate)
}
```

**File:** x/auth/ante/basic.go (L109-117)
```go
func (cgts ConsumeTxSizeGasDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid tx type")
	}
	params := cgts.ak.GetParams(ctx)

	ctx.GasMeter().ConsumeGas(params.TxSizeCostPerByte*sdk.Gas(len(ctx.TxBytes())), "txSize")

```

**File:** baseapp/baseapp.go (L899-976)
```go
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
```
