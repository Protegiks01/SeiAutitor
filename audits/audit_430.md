# Audit Report

## Title
Information Leakage Through Panic Recovery: Sensitive Internal State Exposed in ABCI Error Responses

## Summary
The panic recovery mechanism in `baseapp/recovery.go` exposes full panic values and stack traces to external clients through ABCI error responses, even in production (non-debug) mode. This violates the stated design intent to redact sensitive system information and allows attackers to extract internal state details, memory addresses, file paths, and implementation logic by triggering panics through malicious transactions. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary vulnerability: `baseapp/recovery.go`, function `newDefaultRecoveryMiddleware()` (lines 87-97)
- Error flow path: `baseapp/abci.go` (lines 228, 233, 309, 311, 331) → `types/errors/abci.go` (line 108-110)
- Design intent documented: `types/errors/errors.go` (lines 166-167)

**Intended Logic:** 
According to the comment in the codebase, "ErrPanic is only set when we recover from a panic, so we know to redact potentially sensitive system info." [2](#0-1)  The error handling should prevent internal state leakage to external clients.

**Actual Logic:** 
The panic recovery middleware embeds the complete panic object value and full stack trace directly into the error message string using `fmt.Sprintf("recovered: %v\nstack:\n%v", recoveryObj, string(debug.Stack()))`. [3](#0-2)  This wrapped error then flows to ABCI responses where even in non-debug mode (`app.trace=false`), the `defaultErrEncoder` function simply calls `err.Error()`, returning the full message including all panic details. [4](#0-3) 

**Exploit Scenario:**
1. Attacker crafts a transaction that triggers a panic during execution (e.g., by causing an unexpected condition in a message handler or ante handler)
2. The panic is caught by the defer block in `runTx()` [5](#0-4) 
3. The recovery middleware wraps the panic with full details
4. The error is returned via `ResponseCheckTx` or `ResponseDeliverTx` [6](#0-5) 
5. Attacker receives the ABCI response containing the panic object value, stack trace, internal file paths, function names, and potentially sensitive variable values in the `Log` field

**Security Failure:** 
Information disclosure - internal system state, implementation details, memory addresses, file system structure, and potentially sensitive data are leaked to untrusted external parties through error messages.

## Impact Explanation

**Affected Data/Processes:**
- Internal implementation details (file paths, function names, line numbers)
- Memory addresses and internal data structures
- Panic object contents which may include sensitive state variables, account balances, database connection strings, or cryptographic material in memory
- Stack traces revealing execution paths and internal logic flows

**Severity:**
While this doesn't directly cause loss of funds, it provides critical reconnaissance information that attackers can use to:
- Map the internal codebase structure and identify attack surfaces
- Understand internal logic flows and state management
- Discover memory addresses for potential memory-based attacks
- Extract sensitive configuration or runtime values that may be present in panic objects
- Identify specific code versions and vulnerable code paths

**System Impact:**
This vulnerability undermines defense-in-depth principles by providing attackers with detailed internal information that should remain confidential. It transforms any panic-triggering condition into an information disclosure channel.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can trigger this by submitting transactions that cause panics. No special privileges are required.

**Conditions Required:**
- Attacker identifies or triggers a code path that panics (e.g., invalid type assertions, nil pointer dereferences, unexpected state conditions)
- Normal operation - this occurs whenever any panic happens during transaction processing
- No special timing or race conditions required

**Frequency:**
Can be exploited repeatedly as long as panic-inducing conditions can be triggered. Even if individual panic causes are fixed, new ones may be discovered, and this vulnerability ensures all panics leak information.

## Recommendation

**Immediate Fix:**
Modify `newDefaultRecoveryMiddleware()` in `baseapp/recovery.go` to redact sensitive information from panic recovery:

1. Replace the full panic value formatting with a generic message
2. Remove the stack trace inclusion (or only include it when `app.trace` is true)
3. Log full details server-side for debugging while returning sanitized errors to clients

**Implementation:**
```go
func newDefaultRecoveryMiddleware() recoveryMiddleware {
    handler := func(recoveryObj interface{}) error {
        // Log full details server-side for operators
        // (implementation would log to node logs)
        
        // Return sanitized error to external clients
        return sdkerrors.ErrPanic
    }
    return newRecoveryMiddleware(handler, nil)
}
```

**Additional Measures:**
- Pass the debug flag to recovery middleware and only include details when explicitly enabled
- Audit all panic recovery paths to ensure consistent information sanitization
- Implement a dedicated function for sanitizing panic objects before inclusion in any external-facing error messages

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** `TestPanicInformationLeakageInNonDebugMode`

**Setup:**
```go
func TestPanicInformationLeakageInNonDebugMode(t *testing.T) {
    // Create a sensitive data structure that would leak internal state
    type SensitiveInternalState struct {
        DatabasePassword string
        PrivateKey       string
        InternalAddress  string
    }
    
    sensitiveData := SensitiveInternalState{
        DatabasePassword: "secret_db_password_12345",
        PrivateKey:       "0xdeadbeef_private_key",
        InternalAddress:  "/internal/secret/path/to/config",
    }
    
    // Setup baseapp with an ante handler that panics with sensitive data
    anteOpt := func(bapp *BaseApp) {
        bapp.SetAnteHandler(func(ctx sdk.Context, tx sdk.Tx, simulate bool) (newCtx sdk.Context, err error) {
            // Simulate a panic that includes sensitive internal state
            panic(sensitiveData)
        })
    }
    
    routerOpt := func(bapp *BaseApp) {
        r := sdk.NewRoute(routeMsgCounter, func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
            return &sdk.Result{}, nil
        })
        bapp.Router().AddRoute(r)
    }
    
    app := setupBaseApp(t, anteOpt, routerOpt)
    // Ensure trace is set to false (production/non-debug mode)
    app.trace = false
    
    header := tmproto.Header{Height: 1}
    app.setDeliverState(header)
    app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})
    
    tx := newTxCounter(0, 0)
    txBytes, err := aminoTxEncoder()(tx)
    require.NoError(t, err)
    decoded, _ := app.txDecoder(txBytes)
    
    // Trigger: Execute transaction that causes panic with sensitive data
    res := app.DeliverTx(app.deliverState.ctx, abci.RequestDeliverTx{Tx: txBytes}, decoded, sha256.Sum256(txBytes))
    
    // Observation: Verify that sensitive information is leaked in the error Log
    require.False(t, res.IsOK(), "Transaction should fail due to panic")
    require.NotEmpty(t, res.Log, "Error log should not be empty")
    
    // The vulnerability: sensitive data appears in the response Log field
    require.Contains(t, res.Log, "secret_db_password_12345", 
        "VULNERABILITY: Database password leaked in error response")
    require.Contains(t, res.Log, "0xdeadbeef_private_key",
        "VULNERABILITY: Private key leaked in error response")
    require.Contains(t, res.Log, "/internal/secret/path/to/config",
        "VULNERABILITY: Internal file path leaked in error response")
    require.Contains(t, res.Log, "stack:",
        "VULNERABILITY: Stack trace leaked in error response even in non-debug mode")
    
    // Additional verification: Check that stack trace with file paths is present
    require.Contains(t, res.Log, "baseapp",
        "VULNERABILITY: Internal package names exposed in stack trace")
}
```

**Expected Behavior:**
The test will pass (confirming the vulnerability exists), demonstrating that:
1. Sensitive data from the panic object is visible in the ABCI response Log field
2. Stack traces with internal file paths are exposed
3. This occurs even with `app.trace=false` (production mode)

**To Run:**
Add this test to `baseapp/deliver_tx_test.go` and execute:
```bash
go test -v ./baseapp -run TestPanicInformationLeakageInNonDebugMode
```

The test confirms that panic recovery exposes internal state to external clients, violating the stated design intent of redacting sensitive system information.

### Citations

**File:** baseapp/recovery.go (L87-97)
```go
func newDefaultRecoveryMiddleware() recoveryMiddleware {
	handler := func(recoveryObj interface{}) error {
		return sdkerrors.Wrap(
			sdkerrors.ErrPanic, fmt.Sprintf(
				"recovered: %v\nstack:\n%v", recoveryObj, string(debug.Stack()),
			),
		)
	}

	return newRecoveryMiddleware(handler, nil)
}
```

**File:** types/errors/errors.go (L166-167)
```go
	// redact potentially sensitive system info
	ErrPanic = Register(UndefinedCodespace, 111222, "panic")
```

**File:** types/errors/abci.go (L108-110)
```go
func defaultErrEncoder(err error) string {
	return err.Error()
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

**File:** baseapp/abci.go (L228-234)
```go
		res := sdkerrors.ResponseCheckTx(err, 0, 0, app.trace)
		return &abci.ResponseCheckTxV2{ResponseCheckTx: &res}, err
	}
	gInfo, result, _, priority, pendingTxChecker, expireTxHandler, txCtx, err := app.runTx(sdkCtx, mode, tx, sha256.Sum256(req.Tx))
	if err != nil {
		res := sdkerrors.ResponseCheckTx(err, gInfo.GasWanted, gInfo.GasUsed, app.trace)
		return &abci.ResponseCheckTxV2{ResponseCheckTx: &res}, err
```
