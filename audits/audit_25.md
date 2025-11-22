## Audit Report

## Title
EVM Transaction State Persistence Despite Revert Error

## Summary
When an EVM transaction reverts (indicated by `result.EvmError != ""`), the baseapp code in `runTx` commits state changes via `msCache.Write()` because it only checks for standard Go errors (`err == nil`) and does not verify the EVM-specific error field. This allows reverted EVM transactions to persist state modifications while being marked as failed in the response, violating EVM atomicity guarantees and enabling double-counting of transaction results. [1](#0-0) 

## Impact
**High** - This vulnerability results in unintended smart contract behavior where EVM transactions marked as failed can still modify blockchain state, breaking fundamental EVM execution guarantees.

## Finding Description

**Location:** 
- Primary vulnerability: `baseapp/baseapp.go`, lines 1015-1017 in the `runTx` function
- Related handling: `baseapp/abci.go`, lines 329-333 in the `DeliverTx` function [2](#0-1) 

**Intended Logic:** 
According to EVM semantics, when a transaction execution reverts (e.g., via the REVERT opcode), all state changes made during that transaction should be atomically rolled back, with only gas consumption persisting. The transaction should be marked as failed and no storage modifications should be committed to the blockchain state. [3](#0-2) 

**Actual Logic:**
The code path exhibits inconsistent handling of EVM errors:

1. In `runMsgs`, when an EVM message handler completes, if the message execution experiences a revert, the handler returns `err = nil` with `msgResult.EvmError` populated with the revert reason. [4](#0-3) 

2. Since `err == nil`, the message cache is written at line 1149, committing message state changes to the parent cache. [5](#0-4) 

3. The `runMsgs` function returns with `result.EvmError` set and `err = nil`. [6](#0-5) 

4. Back in `runTx`, the condition at line 1015 checks only `err == nil` without verifying `result.EvmError`, causing `msCache.Write()` to commit all cached state changes to the delivery state. [1](#0-0) 

5. Subsequently in `DeliverTx`, when `result.EvmError != ""`, the code wraps it as an error and marks the transaction as failed. [7](#0-6) 

This creates a logical inconsistency where the codebase properly checks for EVM errors before executing hooks: [8](#0-7) 

But fails to apply the same check before committing state changes.

**Exploit Scenario:**
1. An attacker deploys or interacts with an EVM smart contract that performs state modifications (e.g., token transfers, storage writes)
2. The contract logic executes successfully, applying state changes to the cache
3. The contract then intentionally triggers a REVERT operation
4. The EVM message handler returns `err = nil` with `result.EvmError = "execution reverted"`
5. At line 1149, `msgMsCache.Write()` commits the state changes to the parent cache
6. At line 1016, `msCache.Write()` commits all changes to the delivery state
7. At line 329-333, DeliverTx marks the transaction as failed in the ABCI response
8. Result: The blockchain state contains modifications from a "failed" transaction

**Security Failure:**
This breaks the atomicity invariant of EVM transaction execution. In standard EVM implementations, reverted transactions are atomic - either all state changes succeed, or all are rolled back. This vulnerability allows partial execution where state changes persist despite transaction failure, enabling:
- Unintended smart contract state modifications
- Token balance inconsistencies
- Violation of contract invariants that rely on revert semantics
- Consensus divergence if different nodes interpret revert handling differently

## Impact Explanation

**Affected Assets and Processes:**
- All EVM smart contracts relying on revert semantics for error handling
- Token balances and contract storage that should be protected by revert logic
- Transaction finality and state consistency
- Cross-contract interactions that depend on atomic execution

**Severity of Damage:**
This vulnerability creates a fundamental mismatch between:
1. What the transaction response indicates (failed)
2. What actually happened to the state (modified)

This can lead to:
- **Smart contracts with security bugs becoming exploitable**: Contracts that use revert for access control or state protection would have their state modified even when access is denied
- **Economic exploits**: Attackers could extract value by triggering state changes that should have been reverted
- **State inconsistency**: The blockchain state would differ from what clients expect based on transaction receipts
- **Consensus risks**: Different implementations or versions might handle this differently, potentially causing chain splits

**Why This Matters:**
EVM atomicity is a core security guarantee that smart contract developers rely on. When a contract reverts, developers expect NO state changes to persist. Breaking this guarantee undermines the security model of every EVM smart contract deployed on the chain and could lead to direct financial losses. [9](#0-8) 

## Likelihood Explanation

**Who Can Trigger:**
Any user can trigger this vulnerability by submitting EVM transactions that execute and then revert. This requires no special privileges - just the ability to submit transactions to the network.

**Required Conditions:**
- The chain must support EVM transactions (which sei-cosmos does based on the EVM-specific code)
- An EVM message handler that returns `err = nil` with `result.EvmError` populated when reverts occur
- Normal transaction processing during block execution

**Frequency:**
This vulnerability is triggered on EVERY EVM transaction that reverts. Given that reverts are common in EVM execution (used for error handling, access control, and failed operations), this could occur frequently:
- Failed token transfers
- Access control violations
- Out-of-bounds array access
- Failed external calls
- Explicit revert statements

The inconsistency between hooks (which correctly check for EvmError) and state commits (which don't) suggests this is an oversight rather than intentional design. [10](#0-9) 

## Recommendation

Modify the state write condition in `runTx` to check for EVM errors before committing state, consistent with how hooks are handled:

```go
// In baseapp/baseapp.go, replace lines 1015-1017:
if err == nil && (!ctx.IsEVM() || result.EvmError == "") && mode == runTxModeDeliver {
    msCache.Write()
}
```

This ensures that:
1. Non-EVM transactions behave as before (write on `err == nil`)
2. EVM transactions only write state when both `err == nil` AND `result.EvmError == ""`
3. The logic is consistent with the hook execution check at line 1027

Alternative: Modify the EVM message handler to return a proper Go error when reverts occur, ensuring `err != nil` and preventing the cache write at line 1016. However, this would require changes to the EVM module integration and might break other assumptions.

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** `TestEVMRevertStatePersistence` (new test to be added)

**Setup:**
1. Create a BaseApp instance with a test EVM message handler
2. The handler should write a value to the store, then return `err = nil` with `result.EvmError = "execution reverted"`
3. Initialize the chain and set up delivery state

**Trigger:**
1. Mark the context as EVM using `ctx.WithIsEVM(true)`
2. Create a test transaction that will be routed to the EVM handler
3. Call `DeliverTx` on this transaction

**Observation:**
The test should verify that:
1. The transaction response shows `IsOK() == false` (transaction marked as failed)
2. The response contains the EVM error information
3. **Critical assertion**: The store value written by the handler SHOULD NOT be persisted, but currently IS persisted due to the bug

**Expected behavior (after fix):**
Store should remain unchanged because the EVM error should prevent `msCache.Write()`

**Actual behavior (demonstrating vulnerability):**
Store contains the written value even though transaction was marked as failed

```go
func TestEVMRevertStatePersistence(t *testing.T) {
    testKey := []byte("evm-test-key")
    testValue := []byte("should-not-persist")
    
    // Setup handler that writes to store then returns with EvmError
    evmRouterOpt := func(bapp *BaseApp) {
        r := sdk.NewRoute(routeMsgCounter, func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
            // Simulate EVM execution that modifies state then reverts
            store := ctx.KVStore(capKey1)
            store.Set(testKey, testValue)
            
            // Return with EvmError set (simulating EVM revert)
            return &sdk.Result{
                EvmError: "execution reverted",
            }, nil
        })
        bapp.Router().AddRoute(r)
    }
    
    app := setupBaseApp(t, nil, evmRouterOpt)
    app.InitChain(context.Background(), &abci.RequestInitChain{})
    
    codec := codec.NewLegacyAmino()
    registerTestCodec(codec)
    
    header := tmproto.Header{Height: 1}
    app.setDeliverState(header)
    app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})
    
    // Create and deliver EVM transaction
    tx := newTxCounter(0, 0)
    txBytes, err := codec.Marshal(tx)
    require.NoError(t, err)
    
    ctx := app.deliverState.ctx.WithIsEVM(true).WithEVMNonce(1).WithEVMTxHash("0x123")
    decoded, _ := app.txDecoder(txBytes)
    res := app.DeliverTx(ctx, abci.RequestDeliverTx{Tx: txBytes}, decoded, sha256.Sum256(txBytes))
    
    // Verify transaction is marked as failed
    require.False(t, res.IsOK(), "Transaction should be marked as failed")
    require.NotEmpty(t, res.EvmTxInfo.VmError, "Should have EVM error set")
    
    // BUG: State changes persist despite revert
    store := app.deliverState.ctx.KVStore(capKey1)
    persistedValue := store.Get(testKey)
    
    // This assertion FAILS on vulnerable code (value is persisted)
    // This assertion PASSES after fix (value is nil)
    require.Nil(t, persistedValue, "State changes should NOT persist when EVM transaction reverts")
}
```

This test demonstrates that the current code persists state changes from reverted EVM transactions, violating atomicity guarantees. After applying the recommended fix, the test would pass as the state changes would not be committed when `result.EvmError != ""`.

### Citations

**File:** baseapp/baseapp.go (L1010-1017)
```go
	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** baseapp/baseapp.go (L1026-1027)
```go
	// only apply hooks if no error
	if err == nil && (!ctx.IsEVM() || result.EvmError == "") {
```

**File:** baseapp/baseapp.go (L1149-1149)
```go
		msgMsCache.Write()
```

**File:** baseapp/baseapp.go (L1151-1153)
```go
		if msgResult.EvmError != "" {
			evmError = msgResult.EvmError
		}
```

**File:** baseapp/baseapp.go (L1182-1187)
```go
	return &sdk.Result{
		Data:     data,
		Log:      strings.TrimSpace(msgLogs.String()),
		Events:   events.ToABCIEvents(),
		EvmError: evmError,
	}, nil
```

**File:** types/errors/errors.go (L159-160)
```go
	// ErrEVMVMError defines an error for an evm vm error (eg. revert)
	ErrEVMVMError = Register(RootCodespace, 45, "evm reverted")
```

**File:** baseapp/abci.go (L321-335)
```go
	if resCtx.IsEVM() {
		res.EvmTxInfo = &abci.EvmTxInfo{
			SenderAddress: resCtx.EVMSenderAddress(),
			Nonce:         resCtx.EVMNonce(),
			TxHash:        resCtx.EVMTxHash(),
			VmError:       result.EvmError,
		}
		// TODO: populate error data for EVM err
		if result.EvmError != "" {
			evmErr := sdkerrors.Wrap(sdkerrors.ErrEVMVMError, result.EvmError)
			res.Codespace, res.Code, res.Log = sdkerrors.ABCIInfo(evmErr, app.trace)
			resultStr = "failed"
			return
		}
	}
```
