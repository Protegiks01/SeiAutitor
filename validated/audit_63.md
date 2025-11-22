# Audit Report

## Title
EVM Transaction State Persistence Despite Revert Error

## Summary
The baseapp transaction processing code commits state changes for EVM transactions that revert, violating EVM atomicity guarantees. When `runTx` checks whether to commit state via `msCache.Write()`, it only verifies `err == nil` without checking `result.EvmError`, while hook execution correctly checks both conditions. This inconsistency allows reverted EVM transactions to persist state modifications while being marked as failed.

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: `baseapp/baseapp.go`, lines 1015-1017 in `runTx` function
- Secondary issue: `baseapp/baseapp.go`, line 1149 in `runMsgs` function  
- Related handling: `baseapp/abci.go`, lines 329-333 in `DeliverTx` function [1](#0-0) 

**Intended Logic:**
According to EVM semantics and the code comment at lines 280-281 of `baseapp/abci.go`, state should only persist if all messages execute successfully. For EVM transactions that revert, all state changes should be rolled back atomically, with only gas consumption persisting. [2](#0-1) 

**Actual Logic:**
The codebase exhibits an inconsistency in how it handles EVM errors:

1. In `runMsgs`, message handlers can return `err = nil` with `msgResult.EvmError` populated when EVM execution reverts
2. At line 1149, `msgMsCache.Write()` commits message state changes without checking `EvmError`
3. `runMsgs` returns with `result.EvmError` set and `err = nil`
4. In `runTx` at line 1015-1016, the condition checks only `err == nil` before calling `msCache.Write()`, committing all cached state to delivery state
5. At line 1027, hooks correctly check BOTH `err == nil` AND `result.EvmError == ""` before execution
6. In `DeliverTx` at lines 329-333, transactions with `result.EvmError != ""` are marked as failed [3](#0-2) [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. User submits an EVM transaction that performs state modifications (storage writes, balance changes)
2. The EVM message handler executes, applying state changes to the message cache
3. The transaction reverts (via REVERT opcode or error condition)
4. Handler returns `err = nil` with `result.EvmError` populated
5. `msgMsCache.Write()` commits state to parent cache (line 1149)
6. `msCache.Write()` commits all changes to delivery state (line 1016)
7. Transaction is marked as failed in ABCI response (lines 329-333)
8. State modifications persist despite transaction failure

**Security Guarantee Broken:**
EVM atomicity invariant - reverted transactions should have ALL state changes rolled back. The codebase breaks this by committing state for transactions marked as failed, creating a mismatch between transaction status and actual state modifications.

## Impact Explanation

This vulnerability results in unintended smart contract behavior where EVM transactions marked as failed can still modify blockchain state. The impact includes:

- **Smart contract security assumptions violated**: Contracts using revert for access control or state protection would have their state modified even when access is denied
- **State inconsistency**: The blockchain state differs from what clients expect based on transaction receipts showing "failed" status
- **Broken atomicity**: Fundamental EVM execution guarantee that "all or nothing" state changes are enforced is violated

This fits the impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity).

The vulnerability is demonstrated by the explicit inconsistency in the code - hooks check for `EvmError` (line 1027) but state writes do not (lines 1016 and 1149), showing that the pattern of `err = nil` with `EvmError != ""` is expected and supported by the architecture. [6](#0-5) [7](#0-6) 

## Likelihood Explanation

**Trigger Conditions:**
- Any user can submit EVM transactions (no special privileges required)
- EVM message handlers return `err = nil` with `result.EvmError` when reverts occur
- The existence of the hook check at line 1027 that explicitly handles `(!ctx.IsEVM() || result.EvmError == "")` is strong evidence this pattern is expected in the architecture

**Frequency:**
This would occur on every EVM transaction that reverts, which are common in EVM execution:
- Failed token transfers
- Access control violations  
- Require statement failures
- Explicit revert calls
- Out-of-gas conditions handled at EVM level

The inconsistency between hook execution (which checks `EvmError`) and state commits (which don't) indicates this is an oversight rather than intentional design.

## Recommendation

Modify the state write condition in `runTx` to check for EVM errors before committing state, consistent with the hook execution pattern:

```go
// In baseapp/baseapp.go, replace lines 1015-1017:
if err == nil && (!ctx.IsEVM() || result.EvmError == "") && mode == runTxModeDeliver {
    msCache.Write()
}
```

Similarly, consider applying the same check in `runMsgs` at line 1149 before `msgMsCache.Write()` to maintain consistency at the message level.

This ensures:
1. Non-EVM transactions continue normal behavior (write on `err == nil`)
2. EVM transactions only commit state when both `err == nil` AND `result.EvmError == ""`  
3. Logic is consistent with hook execution check at line 1027
4. EVM atomicity guarantees are preserved

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go` (test to be added)

**Setup:**
1. Create BaseApp with test EVM message handler that writes to store then returns `err = nil` with `result.EvmError = "execution reverted"`
2. Initialize chain and delivery state

**Action:**
1. Create transaction with EVM context (`ctx.WithIsEVM(true)`)
2. Call `DeliverTx` with this transaction
3. Handler writes value to store, then returns with `EvmError` set

**Result:**
- Transaction response shows `IsOK() == false` (marked as failed)
- Response contains `EvmTxInfo.VmError` with revert reason
- **Bug**: Store contains the value written by handler, despite transaction being marked as failed
- **Expected**: Store should NOT contain the value, as state should be rolled back for reverted EVM transactions

The inconsistency is demonstrated by comparing line 1027 (hooks check `EvmError`) with line 1016 (state write doesn't check `EvmError`).

## Notes

The vulnerability assessment is based on the clear code inconsistency where hook execution properly checks `result.EvmError` but state writes do not. The infrastructure for handling EVM errors (`EvmError` field, error wrapping, context flags) is extensively present throughout the codebase, indicating this is an expected execution pattern. While the actual EVM message handlers are in a separate repository (likely sei-chain), the sei-cosmos SDK fork has been specifically designed to support the pattern where handlers return `err = nil` with `result.EvmError` set, as evidenced by the explicit conditional logic for EVM transactions in hook processing.

### Citations

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
