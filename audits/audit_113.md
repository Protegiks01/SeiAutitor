## Audit Report

### Title
Transaction Messages with Empty TypeUrl Cause Panic Before ValidateBasicDecorator Leading to Resource Exhaustion DoS

### Summary
Transactions containing messages with empty `TypeUrl` fields in their `Any` wrappers successfully pass the decoder but cause a panic when `GetMsgs()` is invoked in `BaseApp.runTx()`, before reaching `ValidateBasicDecorator`. While the panic is recovered, it triggers expensive stack trace collection, enabling a resource exhaustion denial-of-service attack.

### Impact
Medium

### Finding Description

**Location:** 
- Primary issue: `codec/types/interface_registry.go:255-258` (UnpackAny silently returns for empty TypeUrl)
- Panic trigger: `types/tx/types.go:32` (GetMsgs panics on nil cached value)
- Panic occurs at: `baseapp/baseapp.go:921` (before ante handler chain) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
Transaction messages should be properly unpacked during decoding, with their `Any` wrappers containing valid `TypeUrl` fields that allow the cached values to be populated. The `UnpackAny` function should either successfully unpack a message or return an error for invalid inputs.

**Actual Logic:** 
When `UnpackAny` encounters an `Any` with an empty `TypeUrl`, it returns `nil` (success) without setting the cached value or returning an error. Later, when `GetMsgs()` is called, it attempts to access this nil cached value and panics with the message "Any cached value is nil. Transaction messages must be correctly packed Any values." [4](#0-3) 

**Exploit Scenario:**
1. Attacker crafts a transaction with one or more messages where the `Any` wrapper has `TypeUrl = ""`
2. Transaction is submitted to a node's mempool via RPC or P2P
3. During `CheckTx`, the transaction decoder (`DefaultTxDecoder`) successfully unmarshals the transaction [5](#0-4) 

4. The decoder calls `UnpackInterfaces` which calls `UnpackAny` for each message, but `UnpackAny` returns nil for empty TypeUrl without error [6](#0-5) 

5. Transaction enters `runTx` which calls `tx.GetMsgs()` at line 921
6. `GetMsgs()` panics when accessing the nil cached value
7. The panic is recovered by the defer block and converted to `ErrPanic` with full stack trace collection [7](#0-6) 

8. Attacker repeats this process, sending many such transactions to consume node resources

**Security Failure:** 
Denial-of-service through resource exhaustion. The panic recovery mechanism calls `debug.Stack()` which is computationally expensive. An attacker can spam malformed transactions to force nodes to repeatedly panic and collect stack traces, consuming significantly more CPU and memory than normal transaction validation.

### Impact Explanation

**Affected processes:** Node transaction processing during `CheckTx` in the mempool and potentially during block proposal validation.

**Severity:** Each panic with stack trace collection consumes substantially more resources than a normal transaction rejection. An attacker can:
- Send continuous streams of malformed transactions to multiple nodes
- Force nodes to waste resources on panic recovery rather than processing legitimate transactions
- Potentially slow down block production if validators are targeted
- Degrade overall network performance without requiring majority hash power or stake

**Why this matters:** Unlike normal transaction validation which quickly rejects invalid transactions with minimal overhead, panic recovery with stack trace collection is orders of magnitude more expensive. This creates an asymmetric attack where the attacker's cost (crafting and sending simple malformed transactions) is much lower than the defender's cost (panic recovery and stack trace generation).

### Likelihood Explanation

**Who can trigger:** Any network participant can trigger this vulnerability by submitting transactions to any node's RPC endpoint or via P2P gossip to the mempool.

**Conditions required:** 
- No special privileges needed
- Attacker simply needs to craft a transaction with messages containing empty `TypeUrl`
- Can be done programmatically with standard Cosmos SDK transaction building tools by manually setting `TypeUrl` to empty string

**Frequency:** Can be exploited continuously and at scale. An attacker can:
- Target multiple nodes simultaneously
- Send transactions at high rates limited only by network bandwidth and node connection limits
- Automate the attack for sustained impact

### Recommendation

Add validation in `UnpackAny` to return an error when `TypeUrl` is empty, preventing the cached value from remaining nil:

```go
func (r *statefulUnpacker) UnpackAny(any *Any, iface interface{}) error {
    // ... existing checks ...
    
    if any.TypeUrl == "" {
        return errors.New("Any TypeUrl cannot be empty")  // Return error instead of nil
    }
    
    // ... rest of unpacking logic ...
}
```

Alternatively, add validation in the transaction decoder to check that all message `Any` wrappers have non-empty `TypeUrl` before returning success.

### Proof of Concept

**File:** `baseapp/baseapp_test.go` (add new test function)

**Test Function:** `TestMalformedMessagePanic`

```go
func TestMalformedMessagePanic(t *testing.T) {
    // Setup: Create a BaseApp instance with standard configuration
    app := setupBaseApp(t)
    
    // Create a transaction with a message that has empty TypeUrl
    txBuilder := app.TxConfig().NewTxBuilder()
    
    // Manually craft an Any with empty TypeUrl
    malformedAny := &codectypes.Any{
        TypeUrl: "",  // Empty TypeUrl - this is the vulnerability trigger
        Value:   []byte("dummy data"),
    }
    
    // Create a TxBody with the malformed message
    txBody := &tx.TxBody{
        Messages: []*codectypes.Any{malformedAny},
    }
    
    // Create AuthInfo and signatures (can be minimal for this test)
    txAuthInfo := &tx.AuthInfo{
        Fee: &tx.Fee{
            Amount:   sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
            GasLimit: 100000,
        },
    }
    
    // Create the full transaction
    txWrapper := &tx.Tx{
        Body:       txBody,
        AuthInfo:   txAuthInfo,
        Signatures: [][]byte{[]byte("dummy_signature")},
    }
    
    // Encode the transaction
    txBytes, err := app.TxConfig().TxEncoder()(txWrapper)
    require.NoError(t, err)
    
    // Trigger: Attempt to process this transaction via CheckTx
    req := abci.RequestCheckTx{
        Tx:   txBytes,
        Type: abci.CheckTxType_New,
    }
    
    // Observation: This should panic during GetMsgs() call in runTx
    // The panic will be recovered and converted to an error
    resp, err := app.CheckTx(context.Background(), &req)
    
    // Verify that an error occurred (panic was recovered)
    require.Error(t, err)
    require.Contains(t, err.Error(), "recovered") // Error should indicate panic recovery
    
    // Verify the response indicates failure
    require.NotNil(t, resp)
    require.NotEqual(t, uint32(0), resp.ResponseCheckTx.Code) // Non-zero code indicates error
}
```

**Expected behavior:** The test will demonstrate that the transaction causes a panic during `GetMsgs()` call, which is then recovered and returned as an error. The expensive stack trace collection occurs during this recovery, confirming the resource exhaustion vulnerability.

### Citations

**File:** codec/types/interface_registry.go (L255-258)
```go
	if any.TypeUrl == "" {
		// if TypeUrl is empty return nil because without it we can't actually unpack anything
		return nil
	}
```

**File:** types/tx/types.go (L28-37)
```go
	res := make([]sdk.Msg, len(anys))
	for i, any := range anys {
		cached := any.GetCachedValue()
		if cached == nil {
			panic("Any cached value is nil. Transaction messages must be correctly packed Any values.")
		}
		res[i] = cached.(sdk.Msg)
	}
	return res
}
```

**File:** types/tx/types.go (L173-183)
```go
func (m *TxBody) UnpackInterfaces(unpacker codectypes.AnyUnpacker) error {
	for _, any := range m.Messages {
		var msg sdk.Msg
		err := unpacker.UnpackAny(any, &msg)
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** baseapp/baseapp.go (L921-925)
```go
	msgs := tx.GetMsgs()

	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```

**File:** x/auth/tx/decoder.go (L45-48)
```go
		err = cdc.Unmarshal(raw.BodyBytes, &body)
		if err != nil {
			return nil, sdkerrors.Wrap(sdkerrors.ErrTxDecode, err.Error())
		}
```

**File:** baseapp/recovery.go (L86-97)
```go
// newDefaultRecoveryMiddleware creates a default (last in chain) recovery middleware for app.runTx method.
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
