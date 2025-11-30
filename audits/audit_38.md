# Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages

## Summary
The `AllowedMsgAllowance` feegrant restriction mechanism can be completely bypassed by wrapping disallowed message types inside an authz `MsgExec`. The AnteHandler only validates top-level messages when checking feegrant allowances, while execution proceeds with nested messages that were never validated against the allowance restrictions.

## Impact
Medium (Direct loss of funds)

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:**
When a granter creates an `AllowedMsgAllowance` with specific message type restrictions (e.g., only allowing `/cosmos.gov.v1beta1.MsgVote`), the system should validate ALL messages in a transaction - including nested messages within wrapper types like `MsgExec` - against the allowed list before deducting fees from the feegrant.

**Actual Logic:**
The `DeductFeeDecorator` only validates top-level messages obtained via `sdkTx.GetMsgs()` [1](#0-0) . When a transaction contains `MsgExec`, only the `MsgExec` message type itself is checked by `allMsgTypesAllowed()` [2](#0-1) , never the nested messages inside it. During execution, `MsgExec.Exec` extracts nested messages [5](#0-4)  and the authz module's `DispatchActions` has implicit acceptance logic: if the message signer equals the MsgExec grantee, no authorization check occurs [3](#0-2) . This creates a complete bypass of the feegrant message type restrictions.

**Exploitation Path:**
1. Granter creates `AllowedMsgAllowance` with: `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
2. Attacker (grantee) constructs transaction with: `MsgExec{Grantee: Self, Msgs: [MsgSend{From: Self, To: Victim, Amount: X}]}`
3. AnteHandler phase: `UseGrantedFees` receives `[MsgExec]` from `sdkTx.GetMsgs()` [6](#0-5) , validates only `MsgExec` type (passes), deducts fee from granter's account
4. Execution phase: `MsgExec.Exec` extracts nested `[MsgSend]` via `GetMessages()` [7](#0-6) , calls `DispatchActions(Self, [MsgSend])`
5. In `DispatchActions`: Since `signer == grantee == Self`, implicit acceptance occurs without authorization check [3](#0-2) 
6. `MsgSend` executes successfully using feegrant funds, despite not being in allowed messages list

**Security Guarantee Broken:**
The fundamental security guarantee of `AllowedMsgAllowance` - that feegrant funds will ONLY be used for explicitly approved message types - is completely violated for nested messages within `MsgExec`.

## Impact Explanation

This vulnerability enables complete unauthorized drainage of feegrant balances for ANY transaction type, regardless of the granter's intended restrictions. A granter who allocates funds specifically for governance voting (believing their funds will only pay for vote transactions) can have their entire feegrant balance drained for token transfers, staking operations, or any other message type. This breaks the trust model of restricted feegrants and represents a direct financial loss of the allocated funds to the granter.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:
1. Granters commonly and reasonably include `MsgExec` in allowed message lists to enable authz-based operations
2. No special permissions or prior setup required - any grantee with a feegrant containing `MsgExec` can exploit
3. The exploit is straightforward: wrap any message in `MsgExec` with yourself as grantee where you are also the signer
4. Granters are unlikely to understand that including `MsgExec` effectively removes all message type restrictions
5. The implicit acceptance logic in `DispatchActions` [3](#0-2)  means no authz grant setup is needed

## Recommendation

Modify `x/feegrant/filtered_fee.go` to recursively validate nested messages:

1. In `allMsgTypesAllowed()`, detect when a message is of type `MsgExec`
2. For each `MsgExec` message, call its `GetMessages()` method to extract nested messages
3. Recursively validate all nested messages against the allowed messages list
4. Reject the transaction if ANY nested message (at any depth) has a type not in the allowed list

Example implementation approach:
```go
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
    msgsMap := a.allowedMsgsToMap(ctx)
    
    for _, msg := range msgs {
        ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
        
        msgTypeURL := sdk.MsgTypeURL(msg)
        if !msgsMap[msgTypeURL] {
            return false
        }
        
        // Recursively check nested messages in MsgExec
        if msgTypeURL == "/cosmos.authz.v1beta1.MsgExec" {
            if execMsg, ok := msg.(*authz.MsgExec); ok {
                nestedMsgs, err := execMsg.GetMessages()
                if err != nil {
                    return false
                }
                if !a.allMsgTypesAllowed(ctx, nestedMsgs) {
                    return false
                }
            }
        }
    }
    
    return true
}
```

## Proof of Concept

**Test Location:** `x/feegrant/filtered_fee_test.go`

**Setup:**
- Create feegrant with `AllowedMsgAllowance` allowing only `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
- Create `MsgSend` with `FromAddress = grantee`
- Create `MsgExec` with `Grantee = grantee`, containing the `MsgSend` as nested message

**Action:**
- Test 1: Submit transaction with direct `MsgSend` → correctly rejected because `MsgSend` is not in allowed list [2](#0-1) 
- Test 2: Submit transaction with `MsgExec` wrapping `MsgSend` → bypass succeeds because validation only checks top-level `MsgExec` message type [1](#0-0) 

**Result:**
The vulnerability is confirmed when Test 2 passes validation and successfully uses feegrant funds despite `MsgSend` not being in the allowed messages list. The feegrant message type restriction is completely bypassed for nested messages within `MsgExec`.

## Notes

This is a critical design flaw in the interaction between the feegrant and authz modules. The vulnerability exists because:
1. Fee validation happens at the AnteHandler level with only top-level messages [6](#0-5) 
2. Message execution happens later with full nested message extraction [5](#0-4) 
3. The authz module's implicit acceptance logic (when signer == grantee) [3](#0-2)  requires no prior authorization setup

The impact qualifies as "Direct loss of funds" because the feegrant balance can be completely drained for unauthorized purposes, representing a direct financial loss to the granter who allocated those funds with specific restrictions.

### Citations

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

**File:** types/tx/types.go (L22-36)
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
