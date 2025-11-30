# Audit Report

## Title
Fee Grant Bypass via Authz MsgExec - AllowedMsgAllowance Validation Only Checks Outer Messages

## Summary
The feegrant module's `AllowedMsgAllowance` validates only top-level transaction messages and fails to recursively check inner messages wrapped within `authz.MsgExec`. This allows grantees to bypass message type restrictions, causing fee granters to pay for operations they explicitly excluded from their allowance, resulting in direct loss of funds.

## Impact
High

## Finding Description

**Location:**
- Fee deduction ante handler: [1](#0-0) 
- Allowance validation: [2](#0-1) 
- Message type checking: [3](#0-2) 
- MsgExec execution: [4](#0-3) 
- Inner message dispatch: [5](#0-4) 
- Message extraction: [6](#0-5) 

**Intended Logic:**
When a fee granter creates an `AllowedMsgAllowance`, they specify an allowlist of message types the grantee may execute using the fee grant. The feegrant module should validate that ALL messages in the transaction—including nested messages within `MsgExec`—match the allowed types before deducting fees from the granter's account.

**Actual Logic:**
The ante handler calls `UseGrantedFees` with only `sdkTx.GetMsgs()`, which returns top-level transaction messages. [1](#0-0)  When the transaction contains `MsgExec`, the `AllowedMsgAllowance.Accept` method [2](#0-1)  validates only whether `MsgExec` itself appears in the allowed list via `allMsgTypesAllowed`. [3](#0-2)  The inner messages nested within `MsgExec` are never validated against the allowance. Later, the `MsgExec` handler extracts these inner messages [4](#0-3)  and executes them via `DispatchActions` [5](#0-4)  without re-validating fee grant restrictions.

**Exploitation Path:**
1. Alice (fee granter) creates an `AllowedMsgAllowance` for Bob allowing `["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]` but intentionally excluding `/cosmos.bank.v1beta1.MsgBurn`
2. Charlie grants Bob authz permission to execute `MsgBurn` on Charlie's behalf
3. Bob constructs a transaction with outer message `MsgExec` wrapping an inner `MsgBurn` message, with `FeeGranter` field set to Alice's address
4. Ante handler receives transaction and calls `UseGrantedFees(ctx, Alice, Bob, fee, [MsgExec])`
5. `AllowedMsgAllowance` validates only `MsgExec` type (which is allowed) and approves
6. Alice's account is debited for transaction fees
7. `MsgExec` handler extracts inner `MsgBurn` message [6](#0-5) 
8. Inner `MsgBurn` executes via authz validation without fee grant re-validation
9. Result: Alice paid fees for `MsgBurn` execution, which was NOT in her allowed messages list

**Security Guarantee Broken:**
The message type filtering mechanism of `AllowedMsgAllowance` is completely bypassed. Fee granters cannot restrict which message types consume their grants when `MsgExec` is included in the allowed list, defeating the entire purpose of the allowance filtering feature.

## Impact Explanation

This vulnerability results in **direct loss of funds** for fee granters through unauthorized fee deductions. When Alice creates an `AllowedMsgAllowance` to restrict which operations Bob can perform using her fee grant, she expects the system to enforce these restrictions. However, if Alice includes `MsgExec` in the allowed messages (a reasonable configuration for supporting authz workflows), Bob can wrap any unauthorized message type inside `MsgExec` and have Alice pay the fees.

The severity is amplified because:
- **Complete security model bypass**: The entire purpose of `AllowedMsgAllowance` is to restrict message types, but this mechanism is rendered useless
- **Systematic exploitation**: Attackers can drain fee grants by repeatedly wrapping unauthorized messages in `MsgExec`
- **Collaboration attacks**: Multiple parties can coordinate (one provides authz grants, another exploits the fee grant)
- **Financial loss**: Each transaction drains real tokens from the granter's account as fees

## Likelihood Explanation

**Who Can Trigger:**
Any user (grantee) who possesses:
1. A fee grant with `AllowedMsgAllowance` that includes `MsgExec` in the allowed messages list
2. Authz permissions from any other account to execute messages on their behalf

**Conditions Required:**
- Normal blockchain operation with no special network conditions
- Fee granter must have included `MsgExec` in the allowed messages (common for users enabling authz features)
- Grantee must have authz grants from other accounts (easily obtainable through standard authz module operations)
- No admin privileges or special keys required

**Frequency:**
This vulnerability can be exploited repeatedly until the fee grant is exhausted. Each exploit transaction drains fees from the granter for unauthorized message types. The attack is deterministic with no timing dependencies, race conditions, or probabilistic elements.

## Recommendation

Modify the fee grant validation to recursively extract and validate ALL messages, including those nested within `MsgExec`:

1. In the ante handler, implement a recursive message extraction function before calling `UseGrantedFees`:
   - Create a function that traverses the message tree
   - Extract inner messages from `MsgExec` recursively
   - Return a flat list of all messages to be executed

2. Update the ante handler to pass all extracted messages to `UseGrantedFees`:
   - Call the recursive extraction function on `sdkTx.GetMsgs()`
   - Pass the complete list to the feegrant keeper for validation
   - Ensure the allowance validates the actual messages being executed, not merely wrapper messages

This ensures the allowance validates all messages that will consume fees, preventing the bypass.

## Proof of Concept

**Setup:**
- Initialize chain with three accounts: Alice (fee granter), Bob (grantee/attacker), Charlie (authz granter)
- Fund Alice and Charlie with tokens
- Alice creates fee grant to Bob with `AllowedMsgAllowance` allowing `MsgSend` and `MsgExec` (but NOT `MsgBurn`)
- Charlie grants Bob authz to execute `MsgBurn`
- Record Alice's initial balance

**Action:**
- Bob constructs `MsgBurn` to burn Charlie's tokens
- Bob wraps `MsgBurn` inside `MsgExec`
- Bob creates transaction with Alice as fee granter and submits it

**Result:**
- Transaction succeeds
- Alice's balance decreased by fee amount (she paid fees for unauthorized `MsgBurn`)
- Charlie's tokens were burned (inner message executed)
- Alice paid fees for `MsgBurn` which was NOT in her allowed messages list, demonstrating complete bypass of `AllowedMsgAllowance` security guarantee

## Notes

This vulnerability exists at the architectural level where fee validation (ante handler phase) and message execution (message router phase) are temporally separated. The ante handler validates fees using only the transaction structure visible at that point, while message execution later unpacks and dispatches nested messages. This separation, combined with the lack of recursive message extraction in fee grant validation, creates the bypass opportunity. The issue is particularly concerning because including `MsgExec` in allowed messages is a reasonable practice for users leveraging authz functionality, making this a realistic attack vector.

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
