# Audit Report

## Title
EVM Transaction State Persistence Despite Revert Error

## Summary
The baseapp transaction processing logic in sei-cosmos commits state changes for EVM transactions even when they revert, violating EVM atomicity guarantees. The `runTx` function writes state based only on `err == nil` without checking `result.EvmError`, while hook execution correctly checks both conditions. This architectural inconsistency allows reverted EVM transactions to persist state modifications despite being marked as failed.

## Impact
Medium

## Finding Description

**Location:**
- Primary issue: `baseapp/baseapp.go`, lines 1015-1017 in `runTx` function
- Secondary issue: `baseapp/baseapp.go`, line 1149 in `runMsgs` function
- Related handling: `baseapp/abci.go`, lines 329-333 in `DeliverTx` function [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:**
According to the code comments, state should only persist if all messages execute successfully. [5](#0-4) [6](#0-5) 

For EVM transactions that revert, all state changes should be rolled back atomically, with only gas consumption persisting, per standard EVM semantics.

**Actual Logic:**
The codebase exhibits a critical inconsistency in EVM error handling:

1. The `Result` struct includes an `EvmError` field specifically for EVM execution errors [7](#0-6) [8](#0-7) 

2. Message handlers can return `err = nil` with `msgResult.EvmError` populated when EVM execution reverts

3. In `runMsgs`, at line 1149, `msgMsCache.Write()` commits message state changes without checking `EvmError`

4. `runMsgs` captures the `EvmError` and returns it in the result with `err = nil` [9](#0-8) 

5. Back in `runTx`, the state write condition at lines 1015-1016 checks **only** `err == nil` before calling `msCache.Write()`, committing all cached state to delivery state

6. However, at line 1027, hooks correctly check **both** `err == nil` **and** `(!ctx.IsEVM() || result.EvmError == "")` before execution

7. In `DeliverTx`, transactions with `result.EvmError != ""` are explicitly marked as failed

**Exploitation Path:**
1. User submits an EVM transaction performing state modifications (storage writes, balance changes)
2. EVM message handler executes, applying state changes to message cache (`msgMsCache`)
3. Transaction reverts (via REVERT opcode or error condition)
4. Handler returns `err = nil` with `result.EvmError` populated
5. Line 1149: `msgMsCache.Write()` commits state to parent cache (`runMsgCtx`)
6. Line 1016: `msCache.Write()` commits all changes to delivery state (because `err == nil`)
7. Lines 329-333: Transaction is marked as failed in ABCI response
8. **Result**: State modifications persist despite transaction failure

**Security Guarantee Broken:**
The EVM atomicity invariant is violated. Reverted transactions should have ALL state changes rolled back, but the inconsistent error checking allows state persistence for transactions marked as failed, creating a mismatch between transaction status and actual state modifications.

## Impact Explanation

This vulnerability results in unintended smart contract behavior where EVM transactions marked as failed can still modify blockchain state. The impact includes:

- **Smart contract security assumptions violated**: Contracts relying on revert for access control or state protection would have their state modified even when access is denied
- **State inconsistency**: Blockchain state differs from what clients expect based on transaction receipts showing "failed" status
- **Broken atomicity**: The fundamental EVM execution guarantee that "all or nothing" state changes are enforced is violated

This matches the impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity).

## Likelihood Explanation

**Trigger Conditions:**
- Any user can submit EVM transactions (no special privileges required)
- The sei-cosmos SDK has been specifically modified to support the pattern where handlers return `err = nil` with `result.EvmError`
- The existence of the differentiated hook check at line 1027 (`(!ctx.IsEVM() || result.EvmError == "")`) is explicit evidence this pattern is architecturally supported

**Frequency:**
This would occur on every EVM transaction that reverts, which are common in EVM execution:
- Failed token transfers
- Access control violations
- Require statement failures
- Explicit revert calls
- Out-of-gas conditions handled at EVM level

The architectural inconsistency between hook execution (which checks `EvmError`) and state commits (which don't) indicates this is an implementation oversight rather than intentional design.

## Recommendation

Modify the state write condition in `runTx` to check for EVM errors before committing state, making it consistent with the hook execution pattern:

```go
// In baseapp/baseapp.go, replace lines 1015-1017:
if err == nil && (!ctx.IsEVM() || result.EvmError == "") && mode == runTxModeDeliver {
    msCache.Write()
}
```

Similarly, apply the same check in `runMsgs` at line 1149 before `msgMsCache.Write()` to maintain consistency at the message level:

```go
// In baseapp/baseapp.go, at line 1149:
if msgResult.EvmError == "" {
    msgMsCache.Write()
}
```

This ensures:
1. Non-EVM transactions continue normal behavior (write on `err == nil`)
2. EVM transactions only commit state when both `err == nil` AND `result.EvmError == ""`
3. Logic is consistent with hook execution check at line 1027
4. EVM atomicity guarantees are preserved

## Proof of Concept

**Conceptual PoC** (requires sei-chain EVM handler implementation):

**Setup:**
1. Create BaseApp instance with EVM message handler
2. Initialize delivery state context
3. Configure context with `ctx.WithIsEVM(true)`

**Action:**
1. Create transaction with EVM message
2. Handler executes state modifications (writes to KV store)
3. Handler returns `err = nil, msgResult.EvmError = "execution reverted"`
4. Call `DeliverTx` with this transaction

**Result:**
- Line 1149: `msgMsCache.Write()` commits message state to parent cache
- Line 1016: `msCache.Write()` commits to delivery state (because `err == nil`)
- Lines 329-333: Transaction marked as failed (because `result.EvmError != ""`)
- **Bug**: Store contains the value written by handler despite transaction being marked as failed
- **Expected**: Store should NOT contain the value; state should be rolled back for reverted EVM transactions

The inconsistency is architecturally evident by comparing:
- Line 1027 (hooks): checks both `err == nil` and `result.EvmError == ""`
- Line 1016 (state write): checks only `err == nil`

## Notes

The vulnerability is based on the clear architectural inconsistency in the sei-cosmos SDK's EVM error handling. The infrastructure for EVM errors (`EvmError` field, context flags, differentiated hook logic) is extensively present, indicating this execution pattern is designed and expected. The bug is that state persistence logic doesn't properly implement this design, checking only `err` while hooks correctly check both `err` and `EvmError`. While the actual EVM message handlers are in the sei-chain repository, the bug resides in the sei-cosmos SDK's transaction processing logic, which is responsible for correctly handling the error signaling pattern it explicitly supports.

### Citations

**File:** baseapp/baseapp.go (L1010-1012)
```go
	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
```

**File:** baseapp/baseapp.go (L1015-1017)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** baseapp/baseapp.go (L1027-1027)
```go
	if err == nil && (!ctx.IsEVM() || result.EvmError == "") {
```

**File:** baseapp/baseapp.go (L1149-1153)
```go
		msgMsCache.Write()

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

**File:** baseapp/abci.go (L280-281)
```go
// State only gets persisted if all messages are valid and get executed successfully.
// Otherwise, the ResponseDeliverTx will contain relevant error information.
```

**File:** baseapp/abci.go (L329-333)
```go
		if result.EvmError != "" {
			evmErr := sdkerrors.Wrap(sdkerrors.ErrEVMVMError, result.EvmError)
			res.Codespace, res.Code, res.Log = sdkerrors.ABCIInfo(evmErr, app.trace)
			resultStr = "failed"
			return
```

**File:** proto/cosmos/base/abci/v1beta1/abci.proto (L106-107)
```text
  // EVM VM error during execution
  string evmError = 4;
```

**File:** types/errors/errors.go (L159-160)
```go
	// ErrEVMVMError defines an error for an evm vm error (eg. revert)
	ErrEVMVMError = Register(RootCodespace, 45, "evm reverted")
```
