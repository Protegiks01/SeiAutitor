Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Let me provide my validation:

## Audit Report

## Title
Nested Messages in MsgExec Bypass Validation During CheckTx Leading to Mempool Pollution and Resource Exhaustion

## Summary
The `MsgExec.ValidateBasic()` function does not recursively validate nested messages during the CheckTx phase, allowing transactions with invalid nested messages to enter the mempool, propagate across the network, and waste node resources before failing during DeliverTx execution. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/authz/msgs.go` lines 221-232 (MsgExec.ValidateBasic)
- Related: `baseapp/baseapp.go` lines 788-801 (validateBasicTxMsgs)
- Related: `baseapp/baseapp.go` lines 1086-1089 (CheckTx execution skip)

**Intended Logic:** 
All messages in a transaction should undergo stateless validation via `ValidateBasic()` during CheckTx to prevent invalid transactions from entering the mempool. This is the standard Cosmos SDK pattern for early rejection of malformed transactions.

**Actual Logic:** 
The validation has a gap: `validateBasicTxMsgs` only calls `ValidateBasic()` on top-level messages [2](#0-1) . For `MsgExec`, its `ValidateBasic()` only validates the grantee address and checks for non-empty messages array, but does NOT validate the nested messages themselves [1](#0-0) . During CheckTx mode, message execution is skipped entirely [3](#0-2) , so nested messages are never validated until DeliverTx when handlers invoke them.

**Exploitation Path:**
1. Attacker crafts a `MsgExec` transaction with valid outer structure (valid grantee address, non-empty messages array)
2. Includes nested messages with invalid fields (e.g., `MsgSend` with malformed addresses or zero/negative amounts)
3. Transaction passes CheckTx because `MsgExec.ValidateBasic()` doesn't inspect nested messages
4. Transaction enters mempool and propagates to all network nodes
5. Each node stores the transaction, consuming mempool resources
6. Transaction is gossiped across the network, consuming bandwidth
7. When block production attempts to include the transaction, it fails during DeliverTx execution
8. Process repeats as attacker submits more invalid transactions

**Security Guarantee Broken:**
The mempool filtering invariant is violated. CheckTx validation is supposed to ensure that only well-formed transactions enter the mempool, preventing resource waste on obviously invalid transactions.

## Impact Explanation

This vulnerability enables network-wide resource exhaustion:
- **Mempool pollution**: Invalid transactions occupy mempool slots that should be available for legitimate transactions
- **Bandwidth waste**: Invalid transactions are gossiped to all peer nodes before being discovered as invalid
- **CPU/Memory waste**: All nodes process, store, and attempt to execute invalid transactions
- **Transaction throughput degradation**: Legitimate transactions may be crowded out or delayed

The attack is particularly effective because:
- Cost to attacker is minimal (only CheckTx gas, typically low or zero)
- Impact multiplies across all network nodes
- No DeliverTx gas is charged since transactions fail before execution
- Attack can be sustained continuously

This matches the Medium severity impact category: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - the validation parameters (ValidateBasic checks) are bypassed, allowing nodes to process invalid transactions that should have been rejected.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is trivially exploitable:
- **No privileges required**: Any user can submit transactions
- **No special conditions**: Works during normal network operation
- **No race conditions**: Attack is deterministic
- **Minimal cost**: Only pays CheckTx gas fees
- **Continuous exploitation**: Can submit invalid transactions with every block
- **Scalable**: Can include multiple invalid nested messages per transaction

An attacker can continuously flood the mempool with hundreds of invalid `MsgExec` transactions per block, each containing multiple invalid nested messages. The attack scales with the number of peer nodes and the frequency of transaction submission.

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

    // Validate nested messages
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

This ensures nested messages undergo stateless validation during CheckTx, preventing invalid transactions from entering the mempool.

## Proof of Concept

**File:** `x/authz/msgs_test.go` (add new test)

**Setup:**
Create a `MsgExec` with an invalid nested `MsgSend` (malformed recipient address):
```go
invalidMsgSend := &banktypes.MsgSend{
    FromAddress: "cosmos1granter",
    ToAddress:   "invalid_address", // Invalid bech32 address
    Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
}
msgExec := authz.NewMsgExec(granteeAddr, []sdk.Msg{invalidMsgSend})
```

**Action:**
Call `ValidateBasic()` on the `MsgExec`:
```go
err := msgExec.ValidateBasic()
```

**Result:**
Current behavior returns NO error, demonstrating that `MsgExec.ValidateBasic()` does not validate nested messages. The invalid transaction would pass CheckTx and enter the mempool, only to fail during DeliverTx execution when the nested message's `ValidateBasic()` is called by the handler [4](#0-3) .

Expected behavior would be to return an error during the `ValidateBasic()` call, preventing the invalid transaction from entering the mempool.

## Notes

The vulnerability is confirmed by examining the existing test suite [5](#0-4) , which only tests `MsgExec` with valid nested messages. There are no tests that verify invalid nested messages are properly rejected, indicating this validation gap was overlooked during development.

### Citations

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

**File:** baseapp/baseapp.go (L1086-1089)
```go
		// skip actual execution for (Re)CheckTx mode
		if mode == runTxModeCheck || mode == runTxModeReCheck {
			break
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

**File:** x/authz/msgs_test.go (L21-46)
```go
func TestMsgExecAuthorized(t *testing.T) {
	tests := []struct {
		title      string
		grantee    sdk.AccAddress
		msgs       []sdk.Msg
		expectPass bool
	}{
		{"nil grantee address", nil, []sdk.Msg{}, false},
		{"zero-messages test: should fail", grantee, []sdk.Msg{}, false},
		{"valid test: msg type", grantee, []sdk.Msg{
			&banktypes.MsgSend{
				Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 2)),
				FromAddress: granter.String(),
				ToAddress:   grantee.String(),
			},
		}, true},
	}
	for i, tc := range tests {
		msg := authz.NewMsgExec(tc.grantee, tc.msgs)
		if tc.expectPass {
			require.NoError(t, msg.ValidateBasic(), "test: %v", i)
		} else {
			require.Error(t, msg.ValidateBasic(), "test: %v", i)
		}
	}
}
```
