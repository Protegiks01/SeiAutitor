# Audit Report

## Title
Nested Messages in MsgExec Bypass ValidateBasic During CheckTx Leading to Mempool Pollution

## Summary
The `MsgExec.ValidateBasic()` function in the authz module does not validate nested messages, allowing transactions with stateless validation errors in nested messages to bypass CheckTx validation and enter the mempool. This violates the mempool filtering invariant and causes network-wide resource waste.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
All messages should undergo stateless validation via `ValidateBasic()` during CheckTx to prevent malformed transactions from entering the mempool. The codebase establishes this pattern in `MsgSubmitProposal`, which validates its nested content: [2](#0-1) 

**Actual Logic:**
`MsgExec.ValidateBasic()` only validates the grantee address and checks for a non-empty messages array, but does NOT call `ValidateBasic()` on nested messages. During CheckTx, only top-level messages are validated [3](#0-2) , and message execution is skipped entirely [4](#0-3) , so nested message validation never occurs until DeliverTx when the handler calls ValidateBasic [5](#0-4) .

**Exploitation Path:**
1. Attacker creates `MsgExec` with valid outer structure but invalid nested messages (e.g., `MsgSend` with malformed addresses that would fail `ValidateBasic()`)
2. Transaction passes `validateBasicTxMsgs` during CheckTx since it only validates top-level messages
3. Transaction enters mempool and propagates across the entire network
4. Transaction is included in a block and fails during DeliverTx when nested message validation occurs in the msg_service_router
5. Attack can be repeated continuously to maintain mempool pollution

**Security Guarantee Broken:**
The mempool filtering invariant that only well-formed transactions passing stateless validation should enter the mempool is violated. The ValidateBasic "set parameter" for nested messages is bypassed.

## Impact Explanation

This vulnerability causes network-wide resource waste that matches the Medium severity impact criterion: **"Causing network processing nodes to process transactions from the mempool beyond set parameters"**

Specific consequences:
- **Mempool pollution**: Invalid transactions occupy mempool slots across all nodes, potentially crowding out legitimate transactions
- **Bandwidth waste**: Invalid transactions are gossiped to all peer nodes before their invalidity is discovered
- **Processing overhead**: All network nodes store and process transactions that will inevitably fail in DeliverTx

The attacker does pay full transaction fees during DeliverTx (fees are deducted in the AnteHandler even when transactions fail), which increases the cost but does not eliminate the attack vector, as the attacker can still cause disproportionate network-wide resource consumption relative to their individual cost.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The vulnerability is easily exploitable:
- No special privileges required - any user can submit transactions
- Simple to construct invalid nested messages (e.g., malformed addresses, invalid amounts)
- Can be executed repeatedly without detection
- Works during normal network operation

The attack requires paying transaction fees, which increases the cost to the attacker and reduces the likelihood of sustained large-scale attacks. However, the mempool pollution and network-wide propagation create a force-multiplier effect where one attacker's cost generates disproportionate resource consumption across the entire network.

## Recommendation

Modify `MsgExec.ValidateBasic()` to validate nested messages, following the established pattern in `MsgSubmitProposal`:

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

**Setup**: Create `MsgExec` with invalid nested `MsgSend` (malformed address that would fail ValidateBasic):
```go
invalidMsgSend := &banktypes.MsgSend{
    FromAddress: "cosmos1granter",
    ToAddress:   "invalid_address", // Invalid bech32 address
    Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
}
msgExec := authz.NewMsgExec(granteeAddr, []sdk.Msg{invalidMsgSend})
```

**Action**: Call `ValidateBasic()` on the outer MsgExec:
```go
err := msgExec.ValidateBasic()
```

**Result**: Returns NO error (the vulnerability), allowing the malformed transaction to pass CheckTx validation and enter the mempool. Expected behavior: should return a validation error from the nested message's ValidateBasic check, preventing mempool admission.

The existing test suite [6](#0-5)  only tests valid nested messages, confirming this case was not considered during development.

## Notes

This vulnerability is validated by:
1. Code inspection confirming `MsgExec.ValidateBasic()` lacks nested validation
2. Precedent in `MsgSubmitProposal` demonstrating nested content SHOULD be validated
3. Transaction flow analysis showing CheckTx skips message execution where nested validation would occur
4. Impact matches the defined Medium severity criterion exactly: "Causing network processing nodes to process transactions from the mempool beyond set parameters"

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

**File:** x/gov/types/msgs.go (L108-110)
```go
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
