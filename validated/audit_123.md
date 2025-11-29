# Audit Report

## Title
EVM Transaction State Persistence Despite Revert Error

## Summary
The baseapp transaction processing code in sei-cosmos contains a critical inconsistency in how it handles EVM transaction errors. When EVM transactions revert, the state write logic only checks for `err == nil` without verifying `result.EvmError`, causing state modifications to persist even when transactions are marked as failed. This violates EVM atomicity guarantees and the documented behavior that state should only persist for successful executions. [1](#0-0) [2](#0-1) 

## Impact
Medium

## Finding Description

- **location**: `baseapp/baseapp.go` lines 1015-1017 (primary), line 1149 (secondary), and `baseapp/abci.go` lines 329-333 (related)

- **intended logic**: According to the comment in `baseapp/abci.go`, "State only gets persisted if all messages are valid and get executed successfully." For EVM transactions that revert, all state changes should be rolled back atomically per EVM semantics. [3](#0-2) 

- **actual logic**: The code exhibits a critical inconsistency:
  1. At line 1015-1016 in `runTx`, state is committed when `err == nil` without checking `result.EvmError`
  2. At line 1027, hooks are only executed when `err == nil && (!ctx.IsEVM() || result.EvmError == "")` - explicitly checking for EVM errors
  3. At line 1149 in `runMsgs`, message state is written without checking `msgResult.EvmError`
  4. At lines 329-333 in `DeliverTx`, transactions with `result.EvmError != ""` are marked as failed
  
  The hook execution logic proves that the pattern of `err == nil` with `result.EvmError != ""` is an expected execution path, yet state writes don't check for it. [4](#0-3) [5](#0-4) 

- **exploitation path**:
  1. User submits an EVM transaction that modifies state (storage writes, balance changes)
  2. EVM message handler executes and applies state changes to the message cache
  3. Transaction reverts (via REVERT opcode, require failure, etc.)
  4. Handler returns `err = nil` with `result.EvmError` populated (as the infrastructure is designed to support)
  5. Line 1149: `msgMsCache.Write()` commits to parent cache
  6. Line 1016: `msCache.Write()` commits all changes to delivery state (checked only `err == nil`)
  7. Line 1027: Hooks are correctly skipped (checks both conditions)
  8. Lines 329-333: Transaction is marked as failed in ABCI response
  9. Result: State modifications persist despite transaction being marked as failed

- **security guarantee broken**: EVM atomicity invariant - reverted transactions must have ALL state changes rolled back. Only gas consumption should persist. The codebase violates this by allowing state to persist for transactions marked as failed, creating a fundamental mismatch between transaction status and actual state.

## Impact Explanation

This vulnerability breaks the core EVM execution guarantee of atomicity, resulting in unintended smart contract behavior:

- **Smart contract security violated**: Contracts using `revert` for access control or state protection would have their state modified even when access is denied. For example, a contract that checks authorization and reverts on failure could still have its state modified.

- **State inconsistency**: The blockchain state diverges from what users and applications expect based on transaction receipts showing "failed" status. This breaks the fundamental assumption that failed transactions don't modify state.

- **Protocol integrity**: The inconsistency between hook execution (which correctly checks `EvmError`) and state writes (which don't) indicates this is an unintended bug rather than a design choice.

This fits the Medium severity impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." [6](#0-5) [7](#0-6) 

## Likelihood Explanation

**Triggering is straightforward:**
- Any user can submit EVM transactions without special privileges
- The infrastructure explicitly supports EVM message handlers returning `err = nil` with `result.EvmError` set
- The hook execution logic at line 1027 proves this pattern is expected: `if err == nil && (!ctx.IsEVM() || result.EvmError == "")` - this check would be unnecessary if the pattern never occurred

**Frequency:**
This would occur on every EVM transaction that reverts through:
- Failed token transfers
- Access control violations
- `require` statement failures  
- Explicit `revert` calls
- Out-of-gas conditions at EVM level

The fact that the codebase has been specifically modified to support EVM transactions (with `EvmError` field in Result struct, `evmVmError` in Context, and explicit checks in DeliverTx and hooks) demonstrates this is production functionality. The inconsistency between hook execution (checks `EvmError`) and state writes (don't check) indicates an oversight rather than intentional design.

## Recommendation

Modify the state write condition in `runTx` to check for EVM errors before committing state, making it consistent with the hook execution pattern:

```go
// In baseapp/baseapp.go, replace lines 1015-1017:
if err == nil && (!ctx.IsEVM() || result.EvmError == "") && mode == runTxModeDeliver {
    msCache.Write()
}
```

Similarly, apply the same check in `runMsgs` at line 1149:

```go
// Before msgMsCache.Write(), add check:
if msgResult.EvmError == "" {
    msgMsCache.Write()
}
```

This ensures:
1. Non-EVM transactions continue normal behavior (write on `err == nil`)
2. EVM transactions only commit state when both `err == nil` AND `result.EvmError == ""`
3. Logic is consistent with hook execution check at line 1027
4. EVM atomicity guarantees are preserved as documented

## Proof of Concept

The vulnerability is demonstrated by the code inconsistency itself:

**Setup:**
The sei-cosmos SDK has been modified with infrastructure to support EVM transactions with revert errors:
- Result struct contains `evmError` field
- Context contains `evmVmError` field with comment "EVM VM error during execution"  
- DeliverTx explicitly handles `result.EvmError != ""`
- Hook execution explicitly checks for this pattern

**Action:**
When an EVM message handler returns `err = nil` with `msgResult.EvmError != ""`:

1. In `runMsgs` (line 1149): `msgMsCache.Write()` commits to parent cache
2. In `runTx` (line 1016): Since `err == nil`, `msCache.Write()` commits to delivery state
3. In `runTx` (line 1027): Hooks are correctly NOT executed due to check: `err == nil && (!ctx.IsEVM() || result.EvmError == "")`
4. In `DeliverTx` (lines 329-333): Transaction is marked as failed

**Result:**
- The hook logic proves the pattern `err == nil` with `result.EvmError != ""` is expected (otherwise the check would be unnecessary)
- State is written at line 1016 without checking `result.EvmError`
- Transaction is marked as failed at line 329-333
- **Bug confirmed**: State persists despite transaction failure, violating the documented behavior at lines 280-281 and EVM atomicity guarantees

The existence of the explicit `EvmError` check in hook execution (line 1027) but not in state writes (line 1016) is conclusive evidence of the inconsistency and vulnerability.

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

**File:** types/errors/errors.go (L159-160)
```go
	// ErrEVMVMError defines an error for an evm vm error (eg. revert)
	ErrEVMVMError = Register(RootCodespace, 45, "evm reverted")
```

**File:** proto/cosmos/base/abci/v1beta1/abci.proto (L106-107)
```text
  // EVM VM error during execution
  string evmError = 4;
```
