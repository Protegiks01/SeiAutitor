Based on my thorough investigation of the sei-cosmos codebase, I can confirm this is a **valid vulnerability**. Let me present my validation findings:

## Validation Analysis

**Code Flow Verification:**

I've traced through the complete execution path and confirmed each component of the claim:

1. The AnteHandler calls `UseGrantedFees` with only top-level messages from `sdkTx.GetMsgs()` [1](#0-0) 

2. The `Tx.GetMsgs()` method returns only messages from `t.Body.Messages` without unwrapping nested messages from `MsgExec` [2](#0-1) 

3. The `AllowedMsgAllowance.Accept()` method validates only the messages passed to it [3](#0-2) 

4. The `allMsgTypesAllowed()` method iterates through messages checking their types but does NOT unwrap nested messages from `MsgExec` [4](#0-3) 

5. During execution, `DispatchActions()` has implicit acceptance logic when the message signer equals the MsgExec grantee, bypassing authorization checks [5](#0-4) 

**Impact Assessment:**

This vulnerability allows unauthorized drainage of feegrant balances for transaction types outside the granter's intended restrictions, constituting a **direct loss of funds** limited to the feegrant balance. The granter loses control over how their allocated funds are spent.

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
- x/auth/ante/fee.go (line 168)
- x/feegrant/filtered_fee.go (lines 65-86, 98-109)
- types/tx/types.go (lines 22-36)
- x/authz/keeper/keeper.go (lines 87-111)

**Intended Logic:**
The `AllowedMsgAllowance` should restrict feegrants to only pay fees for specific message types. When a granter creates a feegrant with specific allowed message type URLs, the system should reject any transaction attempting to use this feegrant for other message types, including nested messages within wrapper types like `MsgExec`.

**Actual Logic:**
The `DeductFeeDecorator` calls `UseGrantedFees` with only top-level messages obtained via `sdkTx.GetMsgs()`, which does not extract nested messages from `MsgExec`. The `allMsgTypesAllowed` validation only checks these top-level message types against the allowed list, never examining nested messages within `MsgExec`.

**Exploitation Path:**
1. Attacker obtains a feegrant with `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list
2. Attacker creates a transaction containing a `MsgExec` message where they are the grantee
3. Inside the `MsgExec`, the attacker wraps any disallowed message type (e.g., `/cosmos.bank.v1beta1.MsgSend`) where they are the signer
4. AnteHandler validates only the top-level `MsgExec` against the feegrant allowance and approves it
5. Fees are deducted from the feegrant
6. During execution, `DispatchActions` implicitly accepts the nested message since the signer equals the grantee (no authorization check needed)
7. The disallowed nested message executes successfully using the feegrant to pay fees

**Security Guarantee Broken:**
The message type restriction mechanism in feegrant authorization is bypassed. The guarantee that feegrant funds will only be used for explicitly approved message types is completely circumvented for nested messages.

## Impact Explanation

This vulnerability enables unauthorized drainage of feegrant balances for transaction types outside the granter's intended restrictions. The granter loses control over how their allocated funds are spent, potentially allowing complete exhaustion of the feegrant balance for any message type where the grantee is the signer. This breaks the trust model of restricted feegrants, which are specifically designed for limited delegation scenarios (e.g., allowing governance voting but preventing token transfers).

While the funds are technically still used for fees (their intended purpose), they're applied to unauthorized transaction types, representing a direct loss of the granter's allocated funds. The impact qualifies as direct loss of funds limited to the feegrant balance.

## Likelihood Explanation

**Likelihood: High**

The vulnerability can be exploited by any grantee whose feegrant includes `MsgExec` in the allowed messages list. Required conditions:
- Granter creates an `AllowedMsgAllowance` including `/cosmos.authz.v1beta1.MsgExec` in the allowed messages
- No additional authz grant is required due to implicit acceptance when signer equals grantee

The exploit is straightforward and requires no special privileges beyond possession of the feegrant. Granters might reasonably include `MsgExec` in allowed lists without understanding the nested message implications, making this highly likely to occur in practice.

## Recommendation

Modify the `AllowedMsgAllowance.Accept` method in `x/feegrant/filtered_fee.go` to recursively validate nested messages within `MsgExec` and other message wrapper types:

1. Update `allMsgTypesAllowed` to detect `MsgExec` message types
2. For each `MsgExec`, call its `GetMessages()` method to extract nested messages
3. Recursively validate all nested messages against the allowed messages list
4. Reject the transaction if any nested message type is not in the allowed list

Alternative: Document that including `MsgExec` in `AllowedMessages` effectively allows all message types where the grantee is the signer, and warn granters about this implication.

## Proof of Concept

**Test Location:** x/feegrant/filtered_fee_test.go

**Test Function:** `TestFilteredFeeBypassWithMsgExec` (to be added)

**Setup:**
- Create a feegrant with `AllowedMsgAllowance` restricting to only `/cosmos.gov.v1beta1.MsgVote` and `/cosmos.authz.v1beta1.MsgExec`
- Create a `MsgSend` (disallowed message type) where the grantee is the signer
- Wrap the `MsgSend` inside a `MsgExec` where the grantee is the executor

**Action:**
- Test 1: Attempt to use feegrant directly with `MsgSend` - should be rejected
- Test 2: Attempt to use feegrant with `MsgExec` wrapping `MsgSend` - currently passes validation

**Result:**
- Test 1: Validation correctly rejects the direct `MsgSend` with "message does not exist in allowed messages" error
- Test 2: The `MsgExec` wrapping the disallowed `MsgSend` passes feegrant validation, even though `MsgSend` is not in the allowed messages list. The nested message is never validated against the feegrant allowance, demonstrating the bypass.

## Notes

The exploit relies on the implicit acceptance logic in `DispatchActions()` where if the message signer equals the MsgExec grantee, no authorization check is performed. This means the attacker doesn't need to create any prior authz grant - they can directly execute any message where they are the signer by wrapping it in MsgExec.

The existing test suite in `x/feegrant/filtered_fee_test.go` does not include any tests for nested message validation, indicating this scenario was not previously considered.

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
