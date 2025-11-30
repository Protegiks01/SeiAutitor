After thorough analysis of the codebase and execution flow, I can confirm this is a **valid vulnerability**. Here is my validation:

# Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages

## Summary
The `AllowedMsgAllowance` feegrant restriction mechanism can be bypassed by wrapping disallowed message types inside an authz `MsgExec`. The AnteHandler only validates top-level messages when checking feegrant allowances, while nested messages within `MsgExec` are executed without validation against the allowance restrictions.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
When a granter creates an `AllowedMsgAllowance` with specific message type restrictions (e.g., only allowing `/cosmos.gov.v1beta1.MsgVote`), the system should validate ALL messages in a transaction - including nested messages within wrapper types like `MsgExec` - against the allowed list before deducting fees from the feegrant.

**Actual Logic:**
The `DeductFeeDecorator` calls `UseGrantedFees` with only top-level messages from `sdkTx.GetMsgs()`. [4](#0-3)  This method only returns messages from `t.Body.Messages`, not nested messages within those messages. The `allMsgTypesAllowed()` function iterates only over the provided messages without recursively checking nested content. [2](#0-1) 

During execution, `MsgExec` extracts nested messages and dispatches them via `DispatchActions`. [5](#0-4)  The authz module contains implicit acceptance logic: when the message signer equals the MsgExec grantee, no authorization check occurs and the message executes directly. [3](#0-2) 

**Exploitation Path:**
1. Granter creates `AllowedMsgAllowance` with `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
2. Grantee constructs transaction: `MsgExec{Grantee: Self, Msgs: [MsgSend{From: Self, To: Victim, Amount: X}]}`
3. AnteHandler validates: `UseGrantedFees` receives `[MsgExec]`, checks only `MsgExec` type (passes), deducts fee from granter
4. Execution: `MsgExec.Exec` extracts nested `[MsgSend]`, calls `DispatchActions(Self, [MsgSend])`
5. In `DispatchActions`: signer=Self, grantee=Self → condition `!granter.Equals(grantee)` is false → skips authorization check
6. `MsgSend` executes successfully using feegrant funds, despite not being in allowed messages list

**Security Guarantee Broken:**
The fundamental security guarantee of `AllowedMsgAllowance` - that feegrant funds will ONLY be used for explicitly approved message types - is violated for nested messages within `MsgExec`.

## Impact Explanation

This vulnerability enables unauthorized drainage of feegrant balances for ANY message type, regardless of the granter's intended restrictions. A granter who allocates funds specifically for governance voting can have their entire feegrant balance spent on token transfers, staking operations, or any other message type by a grantee wrapping those messages in `MsgExec`. This represents a direct financial loss of the allocated funds to the granter, as their funds are spent on purposes they explicitly did not authorize through their message type restrictions.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:
1. Granters commonly include `MsgExec` in allowed message lists to enable legitimate authz-based operations
2. No special permissions or setup required - any grantee with a feegrant containing `MsgExec` can exploit this
3. The exploit is straightforward: wrap any unauthorized message in `MsgExec` with yourself as both grantee and message signer
4. Granters are unlikely to understand that including `MsgExec` effectively removes all message type restrictions
5. The implicit acceptance logic in `DispatchActions` means no authz grant setup is needed - the bypass works immediately

## Recommendation

Modify `x/feegrant/filtered_fee.go` to recursively validate nested messages:

1. In the `allMsgTypesAllowed()` function, detect when a message implements an interface for retrieving nested messages (like `MsgExec`)
2. For `MsgExec` messages, call `GetMessages()` to extract nested messages
3. Recursively validate all nested messages against the allowed messages list
4. Reject the transaction if ANY nested message (at any depth) has a type not in the allowed list

Example implementation approach:
- Add a recursive helper function that checks message types
- For known wrapper types like `MsgExec`, unwrap and validate nested content
- Apply this validation before accepting the feegrant usage in the `Accept` method

## Proof of Concept

**Test Location:** `x/feegrant/filtered_fee_test.go`

**Setup:**
- Create accounts: granter and grantee
- Create feegrant with `AllowedMsgAllowance` allowing `["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]`
- Create `MsgSend` with `FromAddress: grantee, ToAddress: victim, Amount: coins`
- Wrap `MsgSend` inside `MsgExec{Grantee: grantee, Msgs: [MsgSend]}`

**Action:**
- Test 1: Submit transaction with direct `MsgSend` using feegrant → correctly rejected (MsgSend not in allowed list)
- Test 2: Submit transaction with `MsgExec` wrapping `MsgSend` using feegrant → incorrectly accepted and executed

**Result:**
Test 2 demonstrates the bypass: the feegrant validation only checks that `MsgExec` is in the allowed list, never validating the nested `MsgSend`. The transaction executes successfully, spending the granter's funds on an unauthorized message type. The feegrant message type restriction is completely bypassed for nested messages within `MsgExec`.

## Notes

This vulnerability exists due to a design flaw in the interaction between the feegrant and authz modules:
1. Fee validation occurs in the AnteHandler with only top-level messages [1](#0-0) 
2. Message execution happens later with full nested message extraction [6](#0-5) 
3. The authz module's implicit acceptance logic (when signer == grantee) requires no prior authorization setup [7](#0-6) 

The impact qualifies as "Direct loss of funds" because the feegrant balance is spent for unauthorized purposes, representing a direct financial loss to the granter who allocated those funds with specific message type restrictions. While the granter voluntarily created the feegrant and included `MsgExec`, they reasonably expected that message type restrictions would apply to all executed messages, not just top-level ones.

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
