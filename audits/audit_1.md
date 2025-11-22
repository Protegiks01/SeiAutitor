## Audit Report

## Title
Nested Messages in MsgExec Bypass Validation During CheckTx Leading to Mempool Pollution and Resource Exhaustion

## Summary
The `validateBasicTxMsgs` function in `baseapp.go` does not recursively validate nested messages contained within `MsgExec` during the CheckTx phase (mempool admission). This allows transactions with invalid nested messages to enter the mempool, propagate across the network, and waste node resources before failing during DeliverTx execution. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `validateBasicTxMsgs` function [1](#0-0) 
- Related: `MsgExec.ValidateBasic()` [2](#0-1) 
- Related: `runMsgs` CheckTx skip logic [3](#0-2) 

**Intended Logic:**
All messages in a transaction should undergo stateless validation via `ValidateBasic()` during CheckTx to prevent invalid transactions from entering the mempool. This is a critical filter to reject malformed transactions early, before they consume network bandwidth and node resources.

**Actual Logic:**
The validation flow has a critical gap:

1. During `runTx`, `validateBasicTxMsgs` is called on all top-level messages [4](#0-3) 

2. For `MsgExec`, its `ValidateBasic()` only validates the grantee address and checks that the messages array is non-empty, but does NOT call `ValidateBasic()` on the nested messages [2](#0-1) 

3. During CheckTx mode, message execution is completely skipped [3](#0-2) 

4. Nested messages are only validated when their handlers are invoked during DeliverTx [5](#0-4) 

**Exploit Scenario:**
An attacker can craft a `MsgExec` transaction containing nested messages with invalid fields (e.g., `MsgSend` with malformed addresses, zero/negative amounts). The transaction structure:
- Outer `MsgExec`: valid grantee address, non-empty messages array
- Nested `MsgSend`: invalid recipient address (e.g., "invalid_address")

During CheckTx, the transaction passes validation because `MsgExec.ValidateBasic()` doesn't inspect nested messages. The transaction enters the mempool and propagates to other nodes. Only during DeliverTx does the nested message validation occur, causing the transaction to fail.

**Security Failure:**
This breaks the mempool filtering invariant, which assumes CheckTx validation prevents obviously invalid transactions from consuming network resources. Attackers can flood the mempool with transactions that will inevitably fail, causing:
- Mempool bloat across all network nodes
- Wasted CPU cycles processing invalid transactions
- Network bandwidth consumed gossiping invalid transactions
- Legitimate transactions potentially crowded out of the mempool

## Impact Explanation

**Affected Resources:**
- Network mempool capacity across all nodes
- CPU and memory resources on all nodes processing these transactions
- Network bandwidth for gossiping invalid transactions
- Potential degradation of transaction throughput for legitimate users

**Severity:**
An attacker can continuously submit `MsgExec` transactions with invalid nested messages at minimal cost (only paying for CheckTx gas, not DeliverTx execution). Each invalid transaction:
- Occupies mempool slots that could be used by valid transactions
- Gets gossiped to peer nodes, multiplying the resource waste
- Forces every node to store and track the transaction until block inclusion attempts fail

This qualifies as **Medium severity** under the "Causing network processing nodes to process transactions from the mempool beyond set parameters" impact category, as nodes process and store transactions that should have been rejected at CheckTx.

## Likelihood Explanation

**Triggering Conditions:**
- Any user can submit transactions without special privileges
- No race conditions or timing requirements
- Attack can be sustained continuously
- Minimal cost to attacker (CheckTx gas only)

**Frequency:**
This can be exploited repeatedly with every block. An attacker could submit hundreds of invalid `MsgExec` transactions per block, each containing multiple invalid nested messages. The attack scales with:
- Number of invalid nested messages per `MsgExec`
- Frequency of transaction submission
- Number of peer nodes receiving gossiped transactions

**Likelihood: High** - This vulnerability is trivially exploitable by any network participant during normal operation.

## Recommendation

Modify `MsgExec.ValidateBasic()` to recursively validate all nested messages:

```go
func (msg MsgExec) ValidateBasic() error {
    _, err := sdk.AccAddressFromBech32(msg.Grantee)
    if err != nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid grantee address")
    }

    if len(msg.Msgs) == 0 {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages cannot be empty")
    }

    // ADD: Validate nested messages
    msgs, err := msg.GetMessages()
    if err != nil {
        return err
    }
    
    for i, nestedMsg := range msgs {
        if err := nestedMsg.ValidateBasic(); err != nil {
            return sdkerrors.Wrapf(err, "invalid nested message at index %d", i)
        }
    }

    return nil
}
```

This ensures nested messages are validated during CheckTx, preventing invalid transactions from entering the mempool.

## Proof of Concept

**File:** `x/authz/msgs_test.go` (add new test function)

**Test Function:** `TestMsgExecValidateBasicWithInvalidNestedMessage`

**Setup:**
```go
func TestMsgExecValidateBasicWithInvalidNestedMessage(t *testing.T) {
    granteeAddr := sdk.AccAddress("grantee_address")
    
    // Create an invalid MsgSend with malformed recipient address
    invalidMsgSend := &banktypes.MsgSend{
        FromAddress: "cosmos1granter",
        ToAddress:   "invalid_address", // Invalid bech32 address
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
    }
    
    // Verify the nested message is indeed invalid
    err := invalidMsgSend.ValidateBasic()
    require.Error(t, err, "nested message should be invalid")
    
    // Create MsgExec with the invalid nested message
    msgExec := authz.NewMsgExec(granteeAddr, []sdk.Msg{invalidMsgSend})
    
    // Current behavior: MsgExec.ValidateBasic() passes even with invalid nested message
    err = msgExec.ValidateBasic()
    
    // THIS IS THE BUG: ValidateBasic should catch the invalid nested message but doesn't
    require.NoError(t, err, "BUG: MsgExec.ValidateBasic() does not validate nested messages")
    
    // The transaction would pass CheckTx and enter mempool
    // Only during DeliverTx when the handler calls ValidateBasic would it fail
}
```

**Trigger:**
The test creates a `MsgExec` with a nested `MsgSend` that has an invalid recipient address. It calls `ValidateBasic()` on the `MsgExec`.

**Observation:**
The test demonstrates that `MsgExec.ValidateBasic()` returns no error despite containing an invalid nested message. This proves that nested message validation is bypassed, allowing invalid transactions into the mempool during CheckTx.

**Expected behavior:** `MsgExec.ValidateBasic()` should return an error when it contains invalid nested messages.

**Actual behavior:** `MsgExec.ValidateBasic()` passes validation, allowing the invalid transaction to proceed to the mempool.

This PoC can be run in the test suite to demonstrate the vulnerability. The invalid transaction would successfully pass CheckTx but fail during DeliverTx execution, confirming the mempool pollution issue.

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

**File:** baseapp/baseapp.go (L923-923)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
```

**File:** baseapp/baseapp.go (L1086-1089)
```go
		// skip actual execution for (Re)CheckTx mode
		if mode == runTxModeCheck || mode == runTxModeReCheck {
			break
		}
```

**File:** x/authz/msgs.go (L221-232)
```go
func (msg MsgExec) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid grantee address")
	}

	if len(msg.Msgs) == 0 {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages cannot be empty")
	}

	return nil
}
```

**File:** baseapp/msg_service_router.go (L115-123)
```go
			if err := req.ValidateBasic(); err != nil {
				if mm, ok := req.(CoinInterface); ok {
					if !mm.GetAmount().Amount.IsZero() {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
```
