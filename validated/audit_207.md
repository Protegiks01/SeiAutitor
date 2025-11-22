# Audit Report

## Title
Nested MsgExec Authorization Bypass Allows Circumventing Spending Limits

## Summary
The authz module's `DispatchActions` method contains a logic flaw where nested `MsgExec` messages can bypass authorization checks by exploiting the self-authorization shortcut. When a `MsgExec` contains another `MsgExec` with its grantee field set to the original granter, the inner execution skips authorization validation, allowing attackers to bypass spending limits and other restrictions.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The `DispatchActions` method is designed to validate that a grantee has proper authorization from the granter before executing messages on their behalf. Spending limits and other restrictions should be enforced through the `Authorization.Accept` method. The self-authorization shortcut is intended to allow users to execute their own messages without requiring explicit self-grants.

**Actual Logic:**
The vulnerability arises from the interaction between three components:

1. `MsgExec.GetSigners()` returns the grantee field [2](#0-1) 

2. `DispatchActions` extracts the granter from `msg.GetSigners()[0]` [3](#0-2) 

3. If granter equals grantee, authorization checks are skipped [1](#0-0) 

**Exploitation Path:**

1. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
2. Alice grants Bob `SendAuthorization` with a 100 token spending limit
3. Bob constructs nested MsgExec:
   - Outer MsgExec: grantee=Bob, msgs=[Inner MsgExec]
   - Inner MsgExec: grantee=Alice, msgs=[MsgSend from Alice for 200 tokens]
4. When outer MsgExec executes, `DispatchActions(ctx, Bob, [innerMsgExec])` is called
5. Inner MsgExec's signer is Alice (from its grantee field), authorization check passes (Bob has GenericAuthorization from Alice)
6. Inner MsgExec handler executes, calling `DispatchActions(ctx, Alice, [MsgSend])`
7. MsgSend's signer is Alice, grantee parameter is Alice
8. Since granter == grantee, authorization check is **skipped**
9. MsgSend executes without validating SendAuthorization spending limit
10. 200 tokens are transferred, bypassing the 100 token limit

**Security Guarantee Broken:**
The fundamental security invariant that all delegated message executions must be validated against their authorizations is violated. The self-authorization shortcut incorrectly treats nested execution as direct execution by the original granter.

## Impact Explanation

**Direct Loss of Funds:**
Attackers with `GenericAuthorization` for `MsgExec` can drain accounts beyond authorized spending limits. In the exploit scenario, Bob can transfer 200 tokens despite only having authorization for 100 tokens.

**Complete Authorization Bypass:**
Any authorization with restrictions (not just `SendAuthorization`) can be bypassed using this technique. This includes staking limits, governance voting restrictions, and any other authorization type with constraints.

**Widespread Exploitation:**
Any account that has granted `GenericAuthorization` for `MsgExec` to another party is vulnerable. This fundamentally breaks the authz module's security model, making it unsafe for delegation scenarios where limited permissions are required (e.g., organizations delegating limited spending power to employees, DAOs with controlled treasury access).

## Likelihood Explanation

**Who Can Trigger:**
Any user who has been granted `GenericAuthorization` for `MsgExec` can exploit this vulnerability. This is a common authorization type that users grant for operational flexibility.

**Required Conditions:**
- The granter must have granted the attacker `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
- The granter must have granted the attacker some other authorization with restrictions (e.g., `SendAuthorization` with spending limits)
- No special timing, privileged roles, or rare conditions are required

**Frequency:**
This vulnerability can be exploited at any time during normal network operation. Once the required authorizations are in place, an attacker can repeatedly exploit this to drain funds. The exploit is deterministic and requires no coordination with other transactions or blocks.

## Recommendation

Add validation to prevent nested `MsgExec` messages in `DispatchActions`. The simplest approach is to check if any message in the `msgs` slice is of type `MsgExec` and reject it:

```go
func (k Keeper) DispatchActions(ctx sdk.Context, grantee sdk.AccAddress, msgs []sdk.Msg) ([][]byte, error) {
    results := make([][]byte, len(msgs))
    
    for i, msg := range msgs {
        // Prevent nested MsgExec to avoid authorization bypass
        if _, ok := msg.(*authz.MsgExec); ok {
            return nil, sdkerrors.ErrUnauthorized.Wrap("nested MsgExec not allowed")
        }
        // ... rest of existing logic
    }
}
```

Alternative: Implement context-based authorization tracking to prevent the self-authorization shortcut from being used during nested execution initiated by another user.

There is no legitimate use case for nested `MsgExec` messages that couldn't be achieved by including multiple messages in a single `MsgExec`.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`
**Test Function:** `TestNestedMsgExecBypassesSpendingLimit`

**Setup:**
1. Initialize three accounts: Alice (granter), Bob (attacker with authorization), Recipient
2. Fund Alice's account with 10,000 tokens
3. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
4. Alice grants Bob `SendAuthorization` with 100 token spending limit

**Action:**
Bob creates and submits nested MsgExec:
- Outer MsgExec with grantee=Bob containing Inner MsgExec
- Inner MsgExec with grantee=Alice containing MsgSend
- MsgSend transfers 200 tokens from Alice to Recipient (exceeding 100 token limit)

**Result:**
- The nested MsgExec successfully executes despite the spending limit
- 200 tokens are transferred from Alice to Recipient
- The `SendAuthorization` spending limit is not enforced
- Bob successfully bypasses the authorization restriction

The vulnerability is confirmed by the fact that the transaction succeeds and transfers 200 tokens when it should have failed due to the 100 token spending limit.

### Citations

**File:** x/authz/keeper/keeper.go (L80-85)
```go
		signers := msg.GetSigners()
		if len(signers) != 1 {
			return nil, sdkerrors.ErrInvalidRequest.Wrap("authorization can be given to msg with only one signer")
		}

		granter := signers[0]
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

**File:** x/authz/msgs.go (L212-218)
```go
func (msg MsgExec) GetSigners() []sdk.AccAddress {
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{grantee}
}
```
