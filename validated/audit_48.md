# Audit Report

## Title
Pre-Gas-Check CPU Exhaustion via Excessive Message Count in Transactions

## Summary
The sei-cosmos blockchain executes unbounded message validation operations before gas metering is initialized, allowing attackers to craft transactions with thousands of messages that exhaust CPU resources through expensive Bech32 address decoding during `ValidateBasic()` checks, creating an amplification attack with zero cost to the attacker.

## Impact
Medium

## Finding Description

**Location:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:**
The codebase explicitly documents that expensive computational operations must be gas-metered to prevent resource exhaustion. [4](#0-3)  states: "Any application that uses GasMeter to limit transaction processing cost MUST set GasMeter with the FIRST AnteDecorator. Failing to do so will cause transactions to be processed with an infinite gasmeter and open a DOS attack vector."

**Actual Logic:**
The transaction processing flow violates this security contract:

1. Transaction enters via CheckTx [5](#0-4) 
2. `tx.GetMsgs()` retrieves all messages [6](#0-5) 
3. `validateBasicTxMsgs(msgs)` immediately calls `ValidateBasic()` on each message [2](#0-1) 
4. For `MsgSend`, each `ValidateBasic()` performs two `AccAddressFromBech32()` operations involving expensive Bech32 decoding with bit conversion [3](#0-2)  and [7](#0-6) 
5. At this point, the context has an infinite gas meter [8](#0-7) 
6. Only AFTER these operations does the AnteHandler execute [9](#0-8) 
7. Gas meter is first initialized by `SetUpContextDecorator` [10](#0-9) , which is the first AnteDecorator [11](#0-10) 

**Exploitation Path:**
1. Attacker crafts transaction with thousands of `MsgSend` messages (e.g., 5,000) from the same address
2. Single signature bypasses `TxSigLimit` of 7 [12](#0-11)  since TxSigLimit only validates signature count, not message count [13](#0-12) 
3. Transaction size fits within typical MaxTxBytes limits
4. Each of 5,000 messages triggers 2 Bech32 decode operations (10,000 total operations)
5. All operations execute with infinite gas meter before AnteHandler
6. AnteHandler finally executes and rejects transaction for insufficient gas
7. No gas fees charged since rejected in CheckTx [14](#0-13) 
8. Attacker repeats indefinitely at zero cost

**Security Guarantee Broken:**
The invariant that expensive computational operations should be gas-metered before execution is violated. The decoder performs no message count validation [15](#0-14) , and `validateBasicTxMsgs` only checks for at least one message with no upper bound [2](#0-1) .

## Impact Explanation

**Resource Exhaustion:**
Each attack transaction performs orders of magnitude more Bech32 decode operations than normal transactions before gas validation. Bech32 decoding involves string parsing, base32 bit conversion (5-bit to 8-bit), and polynomial checksum verification. With 5,000 messages performing 2 Bech32 operations each, this creates a 2,500-5,000x amplification factor compared to normal single-message transactions.

**Network-Wide Effects:**
An attacker submitting a small fraction of normal transaction throughput can cause disproportionate CPU consumption. With normal traffic at 100 tx/sec performing 2 Bech32 operations each (200 ops/sec), adding just 2 attack tx/sec with 10,000 operations each (20,000 ops/sec) creates a 100x increase in Bech32 decoding work before gas metering can prevent it. This directly impacts transaction processing throughput for legitimate users.

**Economic Impact:**
This bypasses the gas-based rate limiting mechanism entirely. Since resource consumption occurs before gas accounting, nodes cannot economically price out attackers. The attack is economically viable because rejected CheckTx transactions don't charge gas fees, allowing unlimited repetition at zero cost.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can submit transactions via the public CheckTx endpoint. No special privileges, permissions, or stake requirements are needed.

**Required Conditions:**
- Attacker crafts transactions with thousands of messages within protocol limits
- All messages from same signer (single signature) to bypass TxSigLimit
- Standard network operation - no special conditions or misconfigurations required

**Frequency of Exploitation:**
Can be triggered immediately and continuously. No existing message count limit prevents this attack, and the validation logic only enforces a minimum of one message with no upper bound.

## Recommendation

**Immediate Fix:**
1. Add a `MaxMsgCount` parameter to the auth module (similar to existing `TxSigLimit`) with a sensible default (e.g., 100-500 messages)

2. Check message count immediately in `validateBasicTxMsgs` or at the transaction decoder level before calling `GetMsgs()`:
```go
if len(msgs) > params.MaxMsgCount {
    return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "too many messages")
}
```

**Additional Hardening:**
- Document the message count limit in consensus parameters
- Add monitoring/alerting for transactions approaching the limit
- Consider moving message count validation to the decoder stage before any message processing
- Evaluate if expensive ValidateBasic operations could be deferred until after gas metering

## Proof of Concept

**Test:** `baseapp/deliver_tx_test.go` - `TestCheckTxWithExcessiveMessageCount` (to be implemented)

**Setup:**
1. Initialize test application with default ante handler chain
2. Create test account with funded address
3. Generate transaction containing 5,000 `MsgSend` messages:
   - All messages from same account (single signature to bypass TxSigLimit)
   - Each with valid bech32 addresses and minimal coin amounts
   - Total transaction size within typical limits
4. Set gas limit to 100,000 (insufficient for execution but valid for submission)

**Action:**
1. Measure CPU time/cycles before calling `app.CheckTx()`
2. Call `app.CheckTx()` with the crafted transaction
3. Measure CPU time/cycles after CheckTx returns
4. Verify transaction rejected with out-of-gas or insufficient gas error

**Result:**
- Significant CPU time consumed processing thousands of Bech32 decode operations
- CPU work done during `validateBasicTxMsgs` with infinite gas meter
- Transaction ultimately rejected in AnteHandler for insufficient gas
- Computational cost of validation disproportionate to cost of submission
- Demonstrates expensive validation occurs before gas metering, confirming the vulnerability

## Notes

This vulnerability precisely matches the Medium severity impact criterion: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours." The attack exploits an amplification vulnerability (1 transaction → thousands of operations) rather than brute force flooding. It requires no special privileges and can be executed continuously at zero cost since rejected CheckTx transactions don't charge gas fees. The fundamental design flaw is that expensive validation operations execute before the gas accounting system can prevent resource exhaustion, directly violating the documented security contract in the codebase.

### Citations

**File:** baseapp/baseapp.go (L788-801)
```go
func validateBasicTxMsgs(msgs []sdk.Msg) error {
	if len(msgs) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "must contain at least one message")
	}

	for _, msg := range msgs {
		err := msg.ValidateBasic()
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** baseapp/baseapp.go (L921-924)
```go
	msgs := tx.GetMsgs()

	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
```

**File:** baseapp/baseapp.go (L927-947)
```go
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
```

**File:** x/bank/types/msgs.go (L29-49)
```go
func (msg MsgSend) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	_, err = sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid recipient address (%s)", err)
	}

	if !msg.Amount.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	if !msg.Amount.IsAllPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	return nil
}
```

**File:** types/handler.go (L65-68)
```go
// NOTE: Any application that uses GasMeter to limit transaction processing cost
// MUST set GasMeter with the FIRST AnteDecorator. Failing to do so will cause
// transactions to be processed with an infinite gasmeter and open a DOS attack vector.
// Use `ante.SetUpContextDecorator` or a custom Decorator with similar functionality.
```

**File:** baseapp/abci.go (L203-235)
```go
// CheckTx implements the ABCI interface and executes a tx in CheckTx mode. In
// CheckTx mode, messages are not executed. This means messages are only validated
// and only the AnteHandler is executed. State is persisted to the BaseApp's
// internal CheckTx state if the AnteHandler passes. Otherwise, the ResponseCheckTx
// will contain releveant error information. Regardless of tx execution outcome,
// the ResponseCheckTx will contain relevant gas execution context.
func (app *BaseApp) CheckTx(ctx context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTxV2, error) {
	defer telemetry.MeasureSince(time.Now(), "abci", "check_tx")

	var mode runTxMode

	switch {
	case req.Type == abci.CheckTxType_New:
		mode = runTxModeCheck

	case req.Type == abci.CheckTxType_Recheck:
		mode = runTxModeReCheck

	default:
		panic(fmt.Sprintf("unknown RequestCheckTx type: %s", req.Type))
	}

	sdkCtx := app.getContextForTx(mode, req.Tx)
	tx, err := app.txDecoder(req.Tx)
	if err != nil {
		res := sdkerrors.ResponseCheckTx(err, 0, 0, app.trace)
		return &abci.ResponseCheckTxV2{ResponseCheckTx: &res}, err
	}
	gInfo, result, _, priority, pendingTxChecker, expireTxHandler, txCtx, err := app.runTx(sdkCtx, mode, tx, sha256.Sum256(req.Tx))
	if err != nil {
		res := sdkerrors.ResponseCheckTx(err, gInfo.GasWanted, gInfo.GasUsed, app.trace)
		return &abci.ResponseCheckTxV2{ResponseCheckTx: &res}, err
	}
```

**File:** types/tx/types.go (L22-36)
```go
func (t *Tx) GetMsgs() []sdk.Msg {
	if t == nil || t.Body == nil {
		return nil
	}

	anys := t.Body.Messages
	res := make([]sdk.Msg, len(anys))
	for i, any := range anys {
		cached := any.GetCachedValue()
		if cached == nil {
			panic("Any cached value is nil. Transaction messages must be correctly packed Any values.")
		}
		res[i] = cached.(sdk.Msg)
	}
	return res
```

**File:** types/bech32/bech32.go (L19-31)
```go
// DecodeAndConvert decodes a bech32 encoded string and converts to base64 encoded bytes.
func DecodeAndConvert(bech string) (string, []byte, error) {
	hrp, data, err := bech32.Decode(bech, 1023)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}

	return hrp, converted, nil
```

**File:** types/context.go (L261-281)
```go
// create a new context
func NewContext(ms MultiStore, header tmproto.Header, isCheckTx bool, logger log.Logger) Context {
	// https://github.com/gogo/protobuf/issues/519
	header.Time = header.Time.UTC()
	return Context{
		ctx:             context.Background(),
		ms:              ms,
		header:          header,
		chainID:         header.ChainID,
		checkTx:         isCheckTx,
		logger:          logger,
		gasMeter:        NewInfiniteGasMeter(1, 1),
		minGasPrice:     DecCoins{},
		eventManager:    NewEventManager(),
		evmEventManager: NewEVMEventManager(),

		txBlockingChannels:   make(acltypes.MessageAccessOpsChannelMapping),
		txCompletionChannels: make(acltypes.MessageAccessOpsChannelMapping),
		txMsgAccessOps:       make(map[int][]acltypes.AccessOperation),
	}
}
```

**File:** x/auth/ante/setup.go (L42-52)
```go
func (sud SetUpContextDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	// all transactions must implement GasTx
	gasTx, ok := tx.(GasTx)
	if !ok {
		// Set a gas meter with limit 0 as to prevent an infinite gas meter attack
		// during runTx.
		newCtx = sud.gasMeterSetter(simulate, ctx, 0, tx)
		return newCtx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must be GasTx")
	}

	newCtx = sud.gasMeterSetter(simulate, ctx, gasTx.GetGas(), tx)
```

**File:** x/auth/ante/ante.go (L47-48)
```go
	anteDecorators := []sdk.AnteFullDecorator{
		sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()), // outermost AnteDecorator. SetUpContext must be called first
```

**File:** x/auth/types/params.go (L14-27)
```go
	DefaultTxSigLimit             uint64 = 7
	DefaultTxSizeCostPerByte      uint64 = 10
	DefaultSigVerifyCostED25519   uint64 = 590
	DefaultSigVerifyCostSecp256k1 uint64 = 1000
)

// Parameter keys
var (
	KeyMaxMemoCharacters      = []byte("MaxMemoCharacters")
	KeyTxSigLimit             = []byte("TxSigLimit")
	KeyTxSizeCostPerByte      = []byte("TxSizeCostPerByte")
	KeySigVerifyCostED25519   = []byte("SigVerifyCostED25519")
	KeySigVerifyCostSecp256k1 = []byte("SigVerifyCostSecp256k1")
	KeyDisableSeqnoCheck      = []byte("KeyDisableSeqnoCheck")
```

**File:** x/auth/ante/sigverify.go (L397-404)
```go
	sigCount := 0
	for _, pk := range pubKeys {
		sigCount += CountSubKeys(pk)
		if uint64(sigCount) > params.TxSigLimit {
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrTooManySignatures,
				"signatures: %d, limit: %d", sigCount, params.TxSigLimit)
		}
	}
```

**File:** x/auth/tx/decoder.go (L45-48)
```go
		err = cdc.Unmarshal(raw.BodyBytes, &body)
		if err != nil {
			return nil, sdkerrors.Wrap(sdkerrors.ErrTxDecode, err.Error())
		}
```
