Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Let me present my findings:

## Validation Analysis

I've traced through the complete execution flow and verified each claim:

### Code Flow Verification

1. **AnteHandler Entry**: The `DeductFeeDecorator.checkDeductFee` method calls `UseGrantedFees` with `sdkTx.GetMsgs()` [1](#0-0) 

2. **Top-Level Messages Only**: `Tx.GetMsgs()` only returns messages from `t.Body.Messages` without unwrapping nested messages [2](#0-1) 

3. **Feegrant Validation**: `AllowedMsgAllowance.Accept` validates only the messages passed to it [3](#0-2) 

4. **No Recursive Check**: The `allMsgTypesAllowed` method iterates through messages without unwrapping nested messages from `MsgExec` [4](#0-3) 

5. **MsgExec Structure**: `MsgExec` contains nested messages in its `Msgs` field that can be extracted via `GetMessages()` [5](#0-4) 

### Exploit Simplification

I found that the exploit is actually **simpler** than described in the report. The attacker doesn't need to create an authz grant from themselves to themselves (which is actually blocked by validation [6](#0-5) ). 

Instead, when `DispatchActions` executes, it has implicit acceptance logic: if the message signer equals the MsgExec grantee, no authorization check is needed [7](#0-6) . This means the attacker can directly execute any message (where they're the signer) wrapped in `MsgExec` without needing any prior authz grant.

### Impact Assessment

The vulnerability allows unauthorized drainage of feegrant funds for transaction types outside the granter's intended restrictions. This represents a direct loss of allocated funds, though limited to the feegrant balance rather than the main account balance.

---

# Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages

## Summary
The `AllowedMsgAllowance` feegrant restriction can be bypassed by wrapping disallowed message types inside an authz `MsgExec`. The AnteHandler only validates top-level messages when checking feegrant allowances, allowing unauthorized execution of any message type while using a restricted feegrant to pay fees.

## Impact
Medium

## Finding Description

**Location:** 
- x/auth/ante/fee.go (DeductFeeDecorator.checkDeductFee, line 168)
- x/feegrant/filtered_fee.go (AllowedMsgAllowance.Accept, lines 65-86)
- x/feegrant/filtered_fee.go (allMsgTypesAllowed, lines 98-109)
- types/tx/types.go (Tx.GetMsgs, lines 22-36)

**Intended Logic:**
The `AllowedMsgAllowance` should restrict feegrants to only pay fees for specific message types. When a granter creates a feegrant with specific allowed message type URLs, the system should reject any transaction attempting to use this feegrant for other message types, including nested messages within wrapper types like `MsgExec`.

**Actual Logic:**
The `DeductFeeDecorator` calls `UseGrantedFees` with only top-level messages obtained via `sdkTx.GetMsgs()`, which does not extract nested messages from `MsgExec`. The `allMsgTypesAllowed` validation only checks these top-level message types against the allowed list, never examining nested messages within `MsgExec`.

**Exploitation Path:**
1. Attacker obtains a feegrant with `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list
2. Attacker creates a transaction containing a `MsgExec` message where they are the grantee
3. Inside the `MsgExec`, the attacker wraps any disallowed message type (e.g., `/cosmos.bank.v1beta1.MsgSend`) where they are the signer
4. AnteHandler validates only the top-level `MsgExec` against the feegrant allowance and approves it
5. During execution, `DispatchActions` implicitly accepts the nested message (since granter equals grantee)
6. The disallowed nested message executes using the feegrant to pay fees

**Security Guarantee Broken:**
Message type restriction mechanism in feegrant authorization - the guarantee that feegrant funds will only be used for explicitly approved message types is completely bypassed for nested messages.

## Impact Explanation

This vulnerability enables unauthorized drainage of feegrant balances for transaction types outside the granter's intended restrictions. The granter loses control over how their allocated funds are spent, potentially allowing complete exhaustion of the feegrant balance for any message type. This breaks the trust model of restricted feegrants, which are specifically designed for limited delegation scenarios (e.g., allowing governance voting but preventing token transfers).

While the funds are technically still used for fees (their intended purpose), they're applied to unauthorized transaction types, representing a direct loss of the granter's allocated funds.

## Likelihood Explanation

**Likelihood: High**

The vulnerability can be exploited by any grantee whose feegrant includes `MsgExec` in the allowed messages list. Conditions required:
- Granter creates an `AllowedMsgAllowance` including `/cosmos.authz.v1beta1.MsgExec` in the allowed messages
- No additional authz grant is required (contrary to the original report) due to implicit acceptance when granter equals grantee

The exploit is straightforward and requires no special privileges beyond possession of the feegrant. Granters might reasonably include `MsgExec` in allowed lists without understanding the nested message implications, making this highly likely to occur in practice.

## Recommendation

Modify the `AllowedMsgAllowance.Accept` method in `x/feegrant/filtered_fee.go` to recursively validate nested messages within `MsgExec` and other message wrapper types:

1. Update `allMsgTypesAllowed` to detect `MsgExec` message types
2. For each `MsgExec`, call its `GetMessages()` method to extract nested messages
3. Recursively validate all nested messages against the allowed messages list
4. Reject the transaction if any nested message type is not in the allowed list

This ensures comprehensive validation of all messages in a transaction, not just top-level ones.

## Proof of Concept

**Test Location:** x/feegrant/filtered_fee_test.go

**Test Function:** `TestFilteredFeeBypassWithMsgExec`

**Setup:**
- Create a feegrant with `AllowedMsgAllowance` restricting to only `/cosmos.gov.v1beta1.MsgVote` and `/cosmos.authz.v1beta1.MsgExec`
- Create a `MsgSend` (disallowed message type)
- Wrap the `MsgSend` inside a `MsgExec`

**Action:**
- Test 1: Attempt to use feegrant directly with `MsgSend` - correctly rejected
- Test 2: Attempt to use feegrant with `MsgExec` wrapping `MsgSend`

**Result:**
- Test 1: Validation correctly rejects the direct `MsgSend` with "message does not exist in allowed messages" error
- Test 2: **Vulnerability confirmed** - The `MsgExec` wrapping the disallowed `MsgSend` passes validation, even though `MsgSend` is not in the allowed messages list. The nested message is never validated against the feegrant allowance.

This demonstrates that the feegrant message type restriction is completely bypassed for nested messages within `MsgExec`.

## Notes

The exploit is actually simpler than initially described in the report. The attacker does not need to create an authz grant from themselves to themselves (which is blocked by validation). Instead, the authz module's `DispatchActions` has implicit acceptance logic when the message signer equals the `MsgExec` grantee, eliminating the need for any prior authz grant setup.

### Citations

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
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

**File:** x/authz/msgs.go (L64-66)
```go
	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
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
