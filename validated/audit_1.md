Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**.

## Technical Verification

**1. Vulnerability Confirmation:**

The `MsgExec.ValidateBasic()` implementation only validates the grantee address and checks for non-empty messages array, but does NOT validate nested messages: [1](#0-0) 

**2. Transaction Flow Analysis:**

During CheckTx, only top-level messages are validated via `validateBasicTxMsgs`: [2](#0-1) 

Message execution (where nested validation would occur) is explicitly skipped for CheckTx mode: [3](#0-2) 

Nested message validation only happens during handler execution in DeliverTx: [4](#0-3) 

**3. Established Pattern Violation:**

The codebase establishes the correct pattern in `MsgSubmitProposal`, which validates nested content: [5](#0-4) 

**4. Test Coverage Gap:**

Existing tests only validate correctly-formed nested messages, confirming this scenario was not considered: [6](#0-5) 

**5. Exploitability Verification:**

Nested messages like `MsgSend` do validate addresses in their `ValidateBasic()`: [7](#0-6) 

This confirms that invalid nested messages would fail validation if checked, but currently bypass CheckTx.

---

# Audit Report

## Title
Nested Messages in MsgExec Bypass ValidateBasic During CheckTx Leading to Mempool Pollution

## Summary
The `MsgExec.ValidateBasic()` function in the authz module does not validate nested messages, allowing transactions with stateless validation errors in nested messages to bypass CheckTx validation and enter the mempool, causing network-wide resource waste.

## Impact
Medium

## Finding Description

- **Location**: [1](#0-0) 

- **Intended logic**: All messages should undergo stateless validation via `ValidateBasic()` during CheckTx to prevent malformed transactions from entering the mempool. The codebase establishes this pattern in `MsgSubmitProposal` [5](#0-4) 

- **Actual logic**: `MsgExec.ValidateBasic()` only validates the grantee address and non-empty array. During CheckTx, only top-level messages are validated [2](#0-1) , and message execution is skipped entirely [3](#0-2) . Nested message validation only occurs during DeliverTx when handlers execute [4](#0-3) 

- **Exploitation path**:
  1. Attacker creates `MsgExec` with valid outer structure but invalid nested messages (e.g., `MsgSend` with malformed addresses [7](#0-6) )
  2. Transaction passes `validateBasicTxMsgs` during CheckTx since only top-level messages are validated
  3. Transaction enters mempool and propagates across entire network
  4. Transaction is included in block and fails during DeliverTx when nested validation occurs
  5. Attack can be repeated continuously to maintain mempool pollution

- **Security guarantee broken**: The mempool filtering invariant that only well-formed transactions passing stateless validation should enter the mempool is violated. The ValidateBasic "set parameter" for nested messages is bypassed.

## Impact Explanation

This vulnerability causes network-wide resource waste matching the Medium severity criterion: **"Causing network processing nodes to process transactions from the mempool beyond set parameters"**

Specific consequences:
- **Mempool pollution**: Invalid transactions occupy mempool slots across all nodes, potentially crowding out legitimate transactions
- **Bandwidth waste**: Invalid transactions are gossiped to all peer nodes before their invalidity is discovered
- **Processing overhead**: All network nodes store and process transactions that will inevitably fail in DeliverTx

The attacker pays transaction fees during DeliverTx, but this occurs AFTER network-wide resource consumption (mempool propagation, gossip bandwidth), creating a force-multiplier effect where one attacker's cost generates disproportionate resource consumption across the entire network.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The vulnerability is easily exploitable:
- No special privileges required - any user can submit transactions
- Simple to construct invalid nested messages (e.g., malformed addresses, invalid amounts)
- Can be executed repeatedly without detection
- Works during normal network operation

Transaction fees increase attacker cost but don't eliminate the vulnerability, as fees are paid after network-wide mempool pollution has already occurred.

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
    ToAddress:   "invalid_address", // Invalid bech32 - fails ValidateBasic
    Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
}
msgExec := authz.NewMsgExec(granteeAddr, []sdk.Msg{invalidMsgSend})
```

**Action**: Call `ValidateBasic()` on the outer MsgExec:
```go
err := msgExec.ValidateBasic()
```

**Result**: Returns NO error (the vulnerability), allowing the malformed transaction to pass CheckTx validation and enter the mempool. Expected behavior: should return validation error from nested message's ValidateBasic check, preventing mempool admission.

## Notes

The vulnerability is validated by:
1. Code inspection confirming `MsgExec.ValidateBasic()` lacks nested validation
2. Precedent in `MsgSubmitProposal` demonstrating nested content SHOULD be validated  
3. Transaction flow analysis showing CheckTx skips message execution where nested validation would occur
4. Impact matches the defined Medium severity criterion exactly: "Causing network processing nodes to process transactions from the mempool beyond set parameters"
5. Test coverage gap [6](#0-5)  confirms this case was not considered during development

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

**File:** x/gov/types/msgs.go (L108-110)
```go
	if err := content.ValidateBasic(); err != nil {
		return err
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

**File:** x/bank/types/msgs.go (L28-48)
```go
// ValidateBasic Implements Msg.
func (msg MsgSend) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	_, err = sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid recipient address (%s)", err)
	}

	if !msg.Amount.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	if !msg.Amount.IsAllPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	return nil
```
