# Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages

## Summary
The `AllowedMsgAllowance` feegrant restriction mechanism can be completely bypassed by wrapping disallowed message types inside an authz `MsgExec`. Fee validation occurs at the AnteHandler level using only top-level messages, while execution proceeds with nested messages that were never validated against the allowance restrictions. This enables complete unauthorized drainage of feegrant balances for any transaction type.

## Impact
Medium (Direct loss of funds)

## Finding Description

**Location:**
- `x/auth/ante/fee.go` line 168
- `x/feegrant/filtered_fee.go` lines 98-109  
- `x/authz/keeper/keeper.go` lines 87-111
- `x/authz/keeper/msg_server.go` lines 65-83
- `types/tx/types.go` lines 22-37

**Intended Logic:**
When a granter creates an `AllowedMsgAllowance` with specific message type restrictions, the system should validate ALL messages in a transaction - including nested messages within wrapper types like `MsgExec` - against the allowed list before deducting fees from the feegrant.

**Actual Logic:**
The `DeductFeeDecorator` only validates top-level messages obtained via `sdkTx.GetMsgs()` [1](#0-0)  which returns only messages from the transaction body, not nested messages. When `UseGrantedFees` is called [2](#0-1) , it passes these top-level messages to `allMsgTypesAllowed()` [3](#0-2)  which performs a simple loop checking only the provided messages array without any recursive validation. During execution phase, `MsgExec.Exec` extracts nested messages [4](#0-3) [5](#0-4)  and the authz module's `DispatchActions` contains implicit acceptance logic: if the message signer equals the MsgExec grantee, no authorization check occurs [6](#0-5) . This architectural separation creates a complete bypass of feegrant message type restrictions.

**Exploitation Path:**
1. Granter creates `AllowedMsgAllowance` with allowed messages: `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
2. Attacker (grantee) constructs transaction: `MsgExec{Grantee: Self, Msgs: [MsgSend{FromAddress: Self, ToAddress: Victim, Amount: X}]}`
3. AnteHandler phase: `UseGrantedFees` receives `[MsgExec]` from `GetMsgs()`, validates only `MsgExec` type (passes), deducts fee from granter's account
4. Execution phase: `MsgExec.Exec` extracts nested `[MsgSend]` via `GetMessages()`, calls `DispatchActions(Self, [MsgSend])`  
5. In `DispatchActions`: Since message signer (FromAddress) equals grantee (Self), implicit acceptance occurs without authorization check
6. `MsgSend` executes successfully using feegrant funds, despite not being in allowed messages list
7. Attacker repeats until entire feegrant balance is drained for unauthorized purposes

**Security Guarantee Broken:**
The fundamental security guarantee of `AllowedMsgAllowance` - that feegrant funds will ONLY be used for explicitly approved message types - is completely violated for nested messages within `MsgExec`.

## Impact Explanation

This vulnerability enables complete unauthorized drainage of feegrant balances for ANY transaction type, regardless of the granter's intended restrictions. A granter who allocates funds specifically for governance voting (believing their funds will only pay for vote transactions) can have their entire feegrant balance drained for token transfers, staking operations, or any other message type. The granter suffers direct financial loss as the allocated feegrant funds are consumed for purposes they never authorized. This breaks the trust model of restricted feegrants and undermines the entire purpose of `AllowedMsgAllowance`.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:
1. Granters commonly and reasonably include `MsgExec` in allowed message lists to enable legitimate authz-based operations
2. No special permissions or prior authz grant setup required - any grantee with a feegrant containing `MsgExec` can exploit immediately
3. The exploit is straightforward: wrap any message in `MsgExec` with yourself as both grantee and message signer
4. Granters are unlikely to understand that including `MsgExec` effectively removes all message type restrictions
5. The implicit acceptance logic when signer equals grantee is a standard authz feature, making the bypass natural and expected behavior
6. No on-chain warnings or protections exist to alert granters to this risk

## Recommendation

Modify `x/feegrant/filtered_fee.go` to recursively validate nested messages:

1. In the `allMsgTypesAllowed()` function, detect when a message is of type `MsgExec` by checking its type URL
2. For each `MsgExec` message, call its `GetMessages()` method to extract nested messages
3. Recursively validate all nested messages against the allowed messages list  
4. Reject the transaction if ANY nested message (at any depth) has a type not in the allowed list
5. Consider implementing a maximum recursion depth to prevent potential DoS attacks

The validation should occur in the feegrant `Accept` method before any fees are deducted, ensuring all messages (including deeply nested ones) are validated against the allowance restrictions.

## Proof of Concept

**Test Location:** `x/feegrant/filtered_fee_test.go`

**Setup:**
- Initialize test environment with accounts for granter and grantee
- Create `BasicAllowance` with sufficient funds
- Wrap in `AllowedMsgAllowance` allowing only `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
- Grant this allowance from granter to grantee
- Create `MsgSend` with `FromAddress = grantee`, `ToAddress = victim`, `Amount = 100tokens`
- Create `MsgExec` with `Grantee = grantee`, containing the `MsgSend` as nested message

**Action:**
- Test 1: Submit transaction with direct `MsgSend` as top-level message with fee granter set
  - Expected: Transaction rejected because `MsgSend` type not in allowed list
  - Actual: Correctly rejected
- Test 2: Submit transaction with `MsgExec` wrapping `MsgSend` as top-level message with fee granter set
  - Expected: Transaction should be rejected because nested `MsgSend` not in allowed list
  - Actual: Transaction succeeds, fees deducted from granter, `MsgSend` executes

**Result:**
The vulnerability is confirmed when Test 2 passes validation and successfully uses feegrant funds despite `MsgSend` not being in the allowed messages list. The feegrant message type restriction is completely bypassed for nested messages within `MsgExec`, enabling unauthorized drainage of the granter's allocated funds.

### Citations

**File:** types/tx/types.go (L22-37)
```go
func (t *Tx) GetMsgs() []sdk.Msg {
	if t == nil || t.Body == nil {
		return nil
	}

	anys := t.Body.Messages
	res := make([]sdk.Msg, len(anys))
	for i, any := range anys {
		cached := any.GetCachedValue()
		if cached == nil {
			panic("Any cached value is nil. Transaction messages must be correctly packed Any values.")
		}
		res[i] = cached.(sdk.Msg)
	}
	return res
}
```

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
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

**File:** x/authz/keeper/msg_server.go (L65-83)
```go
func (k Keeper) Exec(goCtx context.Context, msg *authz.MsgExec) (*authz.MsgExecResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	msgs, err := msg.GetMessages()
	if err != nil {
		return nil, err
	}

	results, err := k.DispatchActions(ctx, grantee, msgs)
	if err != nil {
		return nil, err
	}

	return &authz.MsgExecResponse{Results: results}, nil
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

**File:** x/authz/keeper/keeper.go (L87-111)
```go
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
```
