Based on my thorough investigation of the codebase, I can confirm this is a **valid high-severity vulnerability**. Let me validate the technical claims step by step.

## Code Flow Validation

I've traced through the execution flow and confirmed:

1. **MsgExec.GetSigners() returns the grantee field** [1](#0-0) 

2. **DispatchActions uses msg.GetSigners()[0] as granter** [2](#0-1) 

3. **Implicit accept logic bypasses authorization when granter==grantee** [3](#0-2) 

4. **Exec handler calls DispatchActions with the grantee from MsgExec** [4](#0-3) 

5. **MsgSend.GetSigners() returns FromAddress** [5](#0-4) 

6. **No validation prevents granting MsgExec authorization** [6](#0-5) 

7. **MsgExec.ValidateBasic() does not prevent nested MsgExec** [7](#0-6) 

## Exploitation Path Confirmed

The attack works as follows:
- Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
- Bob constructs: `OuterMsgExec(grantee=Bob, msgs=[InnerMsgExec(grantee=Alice, msgs=[MsgSend(from=Alice, to=Bob)])])`
- First DispatchActions (grantee=Bob): InnerMsgExec.GetSigners() returns [Alice], authorization check passes (Bob has MsgExec from Alice)
- Inner MsgExec handler: Calls DispatchActions(ctx, Alice, [MsgSend])
- Second DispatchActions (grantee=Alice): MsgSend.GetSigners() returns [Alice], check evaluates to Alice==Alice, implicit accept triggered
- MsgSend executes **without SendAuthorization check**

# Audit Report

## Title
Nested MsgExec Authorization Bypass Enables Complete Account Takeover and Fund Theft

## Summary
The `x/authz` module contains a critical vulnerability where a grantee with `GenericAuthorization` for `MsgExec` can execute arbitrary message types without proper authorization. By constructing nested MsgExec messages with the inner MsgExec's grantee set to the victim's address, an attacker exploits the implicit accept logic to bypass authorization checks entirely.

## Impact
High - Direct loss of funds

## Finding Description

**Location:**
- `x/authz/keeper/keeper.go` lines 87-111 (implicit accept logic)
- `x/authz/msgs.go` lines 212-218 (MsgExec.GetSigners implementation)
- `x/authz/keeper/msg_server.go` lines 14-42 (no MsgExec grant validation)

**Intended logic:**
The authorization system should enforce that a grantee can only execute message types explicitly authorized by the granter. The `DispatchActions` function validates authorization when the message signer differs from the executing grantee. The implicit accept logic is intended to allow users to execute their own messages without self-authorization.

**Actual logic:**
The vulnerability arises from the interaction between three behaviors:
1. `MsgExec.GetSigners()` returns the grantee field rather than the transaction signer
2. `DispatchActions` uses `msg.GetSigners()[0]` as the granter for authorization lookups
3. When granter==grantee, implicit accept bypasses all authorization checks

By nesting MsgExec with the inner MsgExec's grantee=victim, the second DispatchActions receives grantee=victim. When processing inner messages like MsgSend, GetSigners() returns victim's address, making granter=victim. Since granter==grantee, the implicit accept path executes the message without authorization.

**Exploitation path:**
1. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
2. Bob constructs nested MsgExec: `Outer(grantee=Bob, msgs=[Inner(grantee=Alice, msgs=[MsgSend(from=Alice, to=Bob, amount=all)])])`
3. Bob signs and submits the transaction
4. Outer MsgExec handler: `DispatchActions(ctx, Bob, [InnerMsgExec])`
5. First DispatchActions: `InnerMsgExec.GetSigners()` returns `[Alice]`, authorization check passes (Bob has MsgExec from Alice)
6. Inner MsgExec handler: `DispatchActions(ctx, Alice, [MsgSend])`
7. Second DispatchActions: `MsgSend.GetSigners()` returns `[Alice]`, check `Alice==Alice` triggers implicit accept
8. MsgSend executes without SendAuthorization, funds transferred from Alice to Bob

**Security guarantee broken:**
The authorization invariant that grantees can only execute explicitly authorized message types is completely violated. A single MsgExec grant provides unlimited account access.

## Impact Explanation

This vulnerability enables complete account takeover and direct theft of funds. An attacker with only MsgExec authorization can:

- **Drain all funds**: Execute `MsgSend` to transfer the victim's entire balance
- **Manipulate staking**: Delegate, undelegate, or redelegate tokens  
- **Control governance**: Vote on proposals on behalf of the victim
- **Execute any message type**: The bypass works for all message types in the system

All funds in accounts that have granted `GenericAuthorization` for `MsgExec` are at immediate risk of theft. The impact is critical because granting MsgExec authorization may appear reasonable for legitimate delegation workflows.

## Likelihood Explanation

**Who can trigger:** Any grantee who receives `GenericAuthorization` for `MsgExec` from another account.

**Conditions required:**
- The granter must grant authorization for `/cosmos.authz.v1beta1.MsgExec` to the attacker
- This is the ONLY authorization required - no authorization for the actual message types being executed is needed
- No validation prevents granting MsgExec authorization

**Frequency:**
- Exploitable immediately upon receiving the authorization  
- Works during normal network operation without special conditions
- No privileged access, timing windows, or state coordination required
- Highly likely if users grant MsgExec authorization for advanced delegation workflows

The vulnerability is particularly dangerous because granting MsgExec authorization appears reasonable for nested delegation patterns, making exploitation highly probable.

## Recommendation

**Option 1 (Recommended):** Prevent granting authorization for MsgExec by adding validation in the Grant method:

```go
t := authorization.MsgTypeURL()
if t == sdk.MsgTypeURL(&authz.MsgExec{}) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "cannot grant authorization for MsgExec")
}
```

Add this check after line 31 in `x/authz/keeper/msg_server.go` before the handler validation.

**Option 2:** Track execution depth and disable implicit accept for nested executions by passing a context flag through DispatchActions to indicate when execution is within a MsgExec.

**Option 3:** Modify the implicit accept logic to validate against the actual transaction signer rather than msg.GetSigners() result.

Option 1 is the simplest and safest fix, as nested MsgExec creates complex authorization chains that are inherently difficult to reason about securely.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Setup:**
- Initialize test accounts: Alice (granter/victim), Bob (grantee/attacker)  
- Fund Alice's account: `simapp.FundAccount(app.BankKeeper, ctx, aliceAddr, sdk.NewCoins(sdk.NewInt64Coin("stake", 10000)))`
- Alice grants Bob MsgExec authorization: `app.AuthzKeeper.SaveGrant(ctx, bobAddr, aliceAddr, authz.NewGenericAuthorization(sdk.MsgTypeURL(&authz.MsgExec{})), now.Add(time.Hour))`
- Verify Alice has NOT granted Bob SendAuthorization: `authorization, _ := app.AuthzKeeper.GetCleanAuthorization(ctx, bobAddr, aliceAddr, bankSendAuthMsgType)` returns nil

**Action:**
- Bob constructs nested MsgExec:
  - `msgSend := banktypes.MsgSend{FromAddress: aliceAddr.String(), ToAddress: bobAddr.String(), Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", 10000))}`
  - `innerMsgExec := authz.NewMsgExec(aliceAddr, []sdk.Msg{&msgSend})`
  - `outerMsgExec := authz.NewMsgExec(bobAddr, []sdk.Msg{&innerMsgExec})`
- Extract and execute: `msgs, _ := outerMsgExec.GetMessages(); app.AuthzKeeper.DispatchActions(ctx, bobAddr, msgs)`

**Result:**
- The call succeeds without error (should fail due to lack of SendAuthorization)
- Alice's balance drained to zero: `app.BankKeeper.GetBalance(ctx, aliceAddr, "stake").Amount.Equal(sdk.ZeroInt())`
- Bob receives all 10,000 tokens: `app.BankKeeper.GetBalance(ctx, bobAddr, "stake").Amount.Equal(sdk.NewInt(10000))`
- Authorization bypass confirmed - Bob executed MsgSend without SendAuthorization from Alice

## Notes

The vulnerability fundamentally breaks the x/authz module's security model. The interaction between `MsgExec.GetSigners()` returning the grantee field and the implicit accept logic creates a complete authorization bypass. A single MsgExec grant effectively provides unlimited account access, undermining the entire purpose of the authorization system.

### Citations

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

**File:** x/authz/msgs.go (L220-232)
```go
// ValidateBasic implements Msg
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

**File:** x/authz/keeper/msg_server.go (L14-42)
```go
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	authorization := msg.GetAuthorization()
	if authorization == nil {
		return nil, sdkerrors.ErrUnpackAny.Wrap("Authorization is not present in the msg")
	}

	t := authorization.MsgTypeURL()
	if k.router.HandlerByTypeURL(t) == nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
	}

	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration)
	if err != nil {
		return nil, err
	}

	return &authz.MsgGrantResponse{}, nil
}
```

**File:** x/authz/keeper/msg_server.go (L77-77)
```go
	results, err := k.DispatchActions(ctx, grantee, msgs)
```

**File:** x/bank/types/msgs.go (L57-63)
```go
func (msg MsgSend) GetSigners() []sdk.AccAddress {
	from, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{from}
}
```
