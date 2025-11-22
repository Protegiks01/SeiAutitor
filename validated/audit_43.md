# Audit Report

## Title
Fee Grant Bypass via Authz MsgExec - AllowedMsgAllowance Validation Only Checks Outer Messages

## Summary
The feegrant module's `AllowedMsgAllowance` only validates top-level transaction messages, failing to check inner messages contained within authz `MsgExec`. This allows grantees to bypass message type restrictions and have fee granters pay for unauthorized transaction types.

## Impact
**Direct loss of funds**

## Finding Description

**Location:**
- Fee deduction ante handler: `x/auth/ante/fee.go` line 168
- Allowance validation: `x/feegrant/filtered_fee.go` lines 65-109  
- Message type checking: `x/feegrant/filtered_fee.go` lines 98-109
- MsgExec execution: `x/authz/keeper/msg_server.go` lines 72-77

**Intended Logic:**
When a fee granter creates an `AllowedMsgAllowance`, they specify which message types the grantee can execute using their fee grant. The feegrant module should validate that ALL messages in a transaction (including nested messages) match the allowed message types before deducting fees from the granter's account.

**Actual Logic:**
The fee deduction ante handler calls `UseGrantedFees` with `sdkTx.GetMsgs()`, which only returns top-level transaction messages. [1](#0-0)  When a transaction contains a `MsgExec`, the validation in `AllowedMsgAllowance.Accept` [2](#0-1)  only checks if `MsgExec` itself is in the allowed list by calling `allMsgTypesAllowed` [3](#0-2) , completely ignoring the inner messages that will be extracted and executed later via `DispatchActions`. [4](#0-3) 

**Exploitation Path:**
1. Attacker (Bob) obtains a fee grant from Alice with `AllowedMsgAllowance` that includes `MsgExec` in the allowed messages list
2. Attacker obtains authz permission from Charlie to execute arbitrary messages (e.g., `MsgBurn`) on Charlie's behalf
3. Attacker creates a transaction containing:
   - Outer message: `MsgExec` wrapping a `MsgBurn` message
   - FeeGranter field: Alice's address
4. Transaction enters ante handler - fee validation sees only `[MsgExec]` from `sdkTx.GetMsgs()`
5. `AllowedMsgAllowance` checks if `MsgExec` is allowed (it is) and approves
6. Alice's account pays the transaction fees
7. `MsgExec` handler extracts inner `MsgBurn` message using `GetMessages()` [5](#0-4) 
8. `MsgBurn` executes via `DispatchActions` without fee grant validation [6](#0-5) 
9. Alice paid fees for `MsgBurn`, which was NOT in her allowed messages list

**Security Guarantee Broken:**
The message type filtering mechanism of `AllowedMsgAllowance` is completely bypassed. Fee granters cannot restrict which message types consume their grants when `MsgExec` is included in the allowed list.

## Impact Explanation

This vulnerability results in direct loss of funds for fee granters through unauthorized fee deductions. The fee granter's token balance decreases to pay transaction fees for message types they explicitly did not authorize. 

The severity is amplified because:
- The entire security model of `AllowedMsgAllowance` is defeated - it cannot fulfill its core purpose
- Attackers can systematically drain fee grants by wrapping any unauthorized message type in `MsgExec`
- Multiple parties can collaborate (one provides authz grants, another exploits the fee grant)
- It's reasonable for fee granters to include `MsgExec` in allowed messages for legitimate authz usage, making this a realistic scenario

## Likelihood Explanation

**Who Can Trigger:**
Any user who has:
1. A fee grant with `AllowedMsgAllowance` that includes `MsgExec` in the allowed messages
2. Authz permissions from any other account to execute messages on their behalf

**Conditions Required:**
- Normal blockchain operation - no special network conditions
- The fee granter must have included `MsgExec` in the allowed messages list (common for users who want to enable authz features)
- The grantee must have authz grants from other accounts (easily obtainable)

**Frequency:**
This can be exploited repeatedly until the fee grant is exhausted. Each transaction drains fees from the granter for unauthorized message types. The exploit is deterministic with no timing dependencies or race conditions.

## Recommendation

Modify the fee grant validation to recursively extract and validate ALL messages, including those nested within `MsgExec`:

1. In the ante handler, before calling `UseGrantedFees`, extract all messages including nested ones from `MsgExec`
2. Implement a recursive helper function:
```go
func extractAllMessages(msgs []sdk.Msg) []sdk.Msg {
    allMsgs := []sdk.Msg{}
    for _, msg := range msgs {
        allMsgs = append(allMsgs, msg)
        if execMsg, ok := msg.(*authz.MsgExec); ok {
            innerMsgs, err := execMsg.GetMessages()
            if err == nil {
                allMsgs = append(allMsgs, extractAllMessages(innerMsgs)...)
            }
        }
    }
    return allMsgs
}
```
3. Pass all extracted messages (including nested ones) to `UseGrantedFees` for validation
4. Update `AllowedMsgAllowance` to validate all message types, not just outer wrappers

This ensures the allowance validates actual messages being executed, not just wrapper messages.

## Proof of Concept

**Setup:**
1. Initialize chain with three accounts: Alice (fee granter), Bob (grantee/attacker), Charlie (authz granter)
2. Fund Alice and Charlie with tokens
3. Alice creates a fee grant to Bob with `AllowedMsgAllowance` allowing `["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]`
4. Charlie creates an authz grant to Bob allowing execution of `"/cosmos.bank.v1beta1.MsgBurn"`
5. Record Alice's initial balance

**Trigger:**
1. Bob constructs a `MsgExec` message containing a `MsgBurn` message (to burn Charlie's tokens)
2. Bob creates a transaction with:
   - Messages: `[MsgExec]` containing the `MsgBurn`
   - FeeGranter: Alice's address
   - FeePayer: Bob's address
3. Submit transaction through ante handler chain and message router

**Expected Result (Vulnerability):**
1. Transaction succeeds - ante handler does not reject it
2. Alice's balance decreases by the fee amount (she paid fees)  
3. Charlie's tokens are burned (inner message executed successfully)
4. Alice paid fees for `MsgBurn`, which was NOT in her allowed messages list

**Observed Behavior:**
The fee grant's message type restrictions are bypassed. `AllowedMsgAllowance` only validated that `MsgExec` was allowed, never checking the inner `MsgBurn` message type. Alice's funds were used to pay fees for an unauthorized message type, demonstrating direct loss of funds.

## Notes

This vulnerability exists at the architectural level where fee validation (ante handler) and message execution (message router) are separated. The fee validation sees only the transaction structure before unpacking, while message execution later unpacks and dispatches nested messages. This temporal separation combined with the lack of recursive message extraction creates the bypass opportunity.

### Citations

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
```

**File:** x/feegrant/filtered_fee.go (L65-86)
```go
func (a *AllowedMsgAllowance) Accept(ctx sdk.Context, fee sdk.Coins, msgs []sdk.Msg) (bool, error) {
	if !a.allMsgTypesAllowed(ctx, msgs) {
		return false, sdkerrors.Wrap(ErrMessageNotAllowed, "message does not exist in allowed messages")
	}

	allowance, err := a.GetAllowance()
	if err != nil {
		return false, err
	}

	remove, err := allowance.Accept(ctx, fee, msgs)
	if err != nil {
		return false, err
	}

	a.Allowance, err = types.NewAnyWithValue(allowance.(proto.Message))
	if err != nil {
		return false, err
	}

    return remove, nil
}
```

**File:** x/feegrant/filtered_fee.go (L98-109)
```go
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
	msgsMap := a.allowedMsgsToMap(ctx)

	for _, msg := range msgs {
		ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
		if !msgsMap[sdk.MsgTypeURL(msg)] {
			return false
		}
	}

	return true
}
```

**File:** x/authz/keeper/msg_server.go (L72-77)
```go
	msgs, err := msg.GetMessages()
	if err != nil {
		return nil, err
	}

	results, err := k.DispatchActions(ctx, grantee, msgs)
```

**File:** x/authz/msgs.go (L198-209)
```go
func (msg MsgExec) GetMessages() ([]sdk.Msg, error) {
	msgs := make([]sdk.Msg, len(msg.Msgs))
	for i, msgAny := range msg.Msgs {
		msg, ok := msgAny.GetCachedValue().(sdk.Msg)
		if !ok {
			return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages contains %T which is not a sdk.MsgRequest", msgAny)
		}
		msgs[i] = msg
	}

	return msgs, nil
}
```

**File:** x/authz/keeper/keeper.go (L76-139)
```go
func (k Keeper) DispatchActions(ctx sdk.Context, grantee sdk.AccAddress, msgs []sdk.Msg) ([][]byte, error) {
	results := make([][]byte, len(msgs))

	for i, msg := range msgs {
		signers := msg.GetSigners()
		if len(signers) != 1 {
			return nil, sdkerrors.ErrInvalidRequest.Wrap("authorization can be given to msg with only one signer")
		}

		granter := signers[0]

		// If granter != grantee then check authorization.Accept, otherwise we
		// implicitly accept.
		if !granter.Equals(grantee) {
			authorization, _ := k.GetCleanAuthorization(ctx, grantee, granter, sdk.MsgTypeURL(msg))
			if authorization == nil {
				return nil, sdkerrors.ErrUnauthorized.Wrap("authorization not found")
			}
			resp, err := authorization.Accept(ctx, msg)
			if err != nil {
				return nil, err
			}

			if resp.Delete {
				err = k.DeleteGrant(ctx, grantee, granter, sdk.MsgTypeURL(msg))
			} else if resp.Updated != nil {
				err = k.update(ctx, grantee, granter, resp.Updated)
			}
			if err != nil {
				return nil, err
			}

			if !resp.Accept {
				return nil, sdkerrors.ErrUnauthorized
			}
		}

		handler := k.router.Handler(msg)
		if handler == nil {
			return nil, sdkerrors.ErrUnknownRequest.Wrapf("unrecognized message route: %s", sdk.MsgTypeURL(msg))
		}

		msgResp, err := handler(ctx, msg)
		if err != nil {
			return nil, sdkerrors.Wrapf(err, "failed to execute message; message %v", msg)
		}

		results[i] = msgResp.Data

		// emit the events from the dispatched actions
		events := msgResp.Events
		sdkEvents := make([]sdk.Event, 0, len(events))
		for _, event := range events {
			e := event
			e.Attributes = append(e.Attributes, abci.EventAttribute{Key: []byte("authz_msg_index"), Value: []byte(strconv.Itoa(i))})

			sdkEvents = append(sdkEvents, sdk.Event(e))
		}

		ctx.EventManager().EmitEvents(sdkEvents)
	}

	return results, nil
}
```
