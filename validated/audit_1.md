Based on my thorough investigation of the codebase, I have validated the technical claims and found this to be a **valid vulnerability** with important corrections needed.

# Audit Report

## Title
Nested Messages in MsgExec Bypass ValidateBasic During CheckTx Leading to Mempool Pollution

## Summary
The `MsgExec.ValidateBasic()` function does not validate nested messages, allowing transactions with stateless validation errors in nested messages to enter the mempool. This bypasses the standard validation pattern evidenced by `MsgSubmitProposal`, which does validate its nested content. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:**
- Primary: `x/authz/msgs.go` lines 221-232 (MsgExec.ValidateBasic)
- Related: `baseapp/baseapp.go` lines 788-801 (validateBasicTxMsgs)  
- Precedent: `x/gov/types/msgs.go` lines 101-110 (MsgSubmitProposal validates nested content)

**Intended Logic:**
All messages should undergo stateless validation via `ValidateBasic()` during CheckTx to prevent malformed transactions from entering the mempool. The codebase establishes this pattern in `MsgSubmitProposal`, which validates its nested content. [2](#0-1) 

**Actual Logic:**
`MsgExec.ValidateBasic()` only validates the grantee address and checks for a non-empty messages array, but does NOT call `ValidateBasic()` on nested messages. During CheckTx, message execution is skipped, so nested message validation never occurs until DeliverTx. [3](#0-2) 

**Exploitation Path:**
1. Attacker creates `MsgExec` with valid outer structure but invalid nested messages (e.g., `MsgSend` with malformed addresses)
2. Transaction passes `validateBasicTxMsgs` since it only validates top-level messages [4](#0-3) 
3. Transaction enters mempool and propagates across network
4. Transaction is included in a block and fails during DeliverTx when nested message validation occurs [5](#0-4) 
5. Attack can be repeated continuously

**Security Guarantee Broken:**
The mempool filtering invariant that only well-formed transactions (passing stateless validation) should enter the mempool is violated.

## Impact Explanation

This vulnerability causes network-wide resource waste:
- **Mempool pollution**: Invalid transactions occupy mempool slots, potentially crowding out legitimate transactions
- **Bandwidth waste**: Invalid transactions are gossiped to all peer nodes before discovery
- **Processing overhead**: All nodes store and process transactions that will inevitably fail

**Important Correction**: The attacker DOES pay full transaction fees during DeliverTx (fees are deducted in the AnteHandler even when the transaction fails). This limits but does not eliminate the attack vector, as the attacker can still cause disproportionate network-wide resource consumption relative to their cost.

This matches the Medium severity impact: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - the ValidateBasic validation parameter is bypassed for nested messages.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The vulnerability is easily exploitable:
- No privileges required
- Simple to construct invalid nested messages
- Can be executed repeatedly
- Works during normal network operation

However, the attacker must pay transaction fees, which increases cost and reduces likelihood of sustained large-scale attacks compared to a zero-cost exploit.

## Recommendation

Modify `MsgExec.ValidateBasic()` to validate nested messages, following the pattern established by `MsgSubmitProposal`:

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

## Proof of Concept

**Setup**: Create `MsgExec` with invalid nested `MsgSend` (malformed address):
```go
invalidMsgSend := &banktypes.MsgSend{
    FromAddress: "cosmos1granter",
    ToAddress:   "invalid_address",
    Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
}
msgExec := authz.NewMsgExec(granteeAddr, []sdk.Msg{invalidMsgSend})
```

**Action**: Call `ValidateBasic()`:
```go
err := msgExec.ValidateBasic()
```

**Result**: Returns NO error (invalid), allowing malformed transaction to enter mempool. Expected behavior: should return validation error preventing mempool admission. [6](#0-5) 

## Notes

The vulnerability is confirmed by:
1. Code inspection showing `MsgExec.ValidateBasic()` lacks nested validation
2. Precedent in `MsgSubmitProposal` showing nested content SHOULD be validated
3. Existing test suite only tests valid nested messages, indicating oversight

The original report overstated the cost advantage to attackers by incorrectly claiming no DeliverTx fees are charged. In reality, full transaction fees ARE deducted during the AnteHandler even when transactions fail, making the attack more expensive than claimed but still viable for causing network-wide resource waste.

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

**File:** x/gov/types/msgs.go (L101-110)
```go
	content := m.GetContent()
	if content == nil {
		return sdkerrors.Wrap(ErrInvalidProposalContent, "missing content")
	}
	if !IsValidProposalType(content.ProposalType()) {
		return sdkerrors.Wrap(ErrInvalidProposalType, content.ProposalType())
	}
	if err := content.ValidateBasic(); err != nil {
		return err
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
