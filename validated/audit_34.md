# Audit Report

## Title
Nested MsgExec Authorization Bypass Enables Unauthorized Fund Theft

## Summary
The `x/authz` module contains a critical authorization bypass vulnerability where a grantee with `GenericAuthorization` for `MsgExec` can execute arbitrary message types without proper authorization by constructing nested MsgExec messages. This enables complete theft of funds from the granter's account.

## Impact
High - Direct loss of funds

## Finding Description

**Location:**
- `x/authz/keeper/keeper.go` lines 87-111 (implicit accept logic) [1](#0-0) 

- `x/authz/msgs.go` lines 212-218 (MsgExec.GetSigners implementation) [2](#0-1) 

- `x/authz/keeper/msg_server.go` lines 14-42 (no MsgExec grant validation) [3](#0-2) 

**Intended logic:**
The authorization system should enforce that a grantee can only execute message types explicitly authorized by the granter. The `DispatchActions` function validates authorization by checking if the grantee has a grant from the message signer. The implicit accept logic (line 89) is intended to allow users to execute their own messages without requiring self-authorization - when a user signs a transaction containing their own messages, those messages should execute without additional authorization checks.

**Actual logic:**
The vulnerability arises from three interacting behaviors:

1. `MsgExec.GetSigners()` returns the `grantee` field from the MsgExec message, not the actual transaction signer [2](#0-1) 

2. `DispatchActions` uses `msg.GetSigners()[0]` as the `granter` for authorization lookups [4](#0-3) 

3. When `granter==grantee`, the implicit accept logic bypasses all authorization checks [1](#0-0) 

By nesting MsgExec messages with the inner MsgExec's grantee set to the victim's address, an attacker causes the second `DispatchActions` call to receive `grantee=victim`. When processing inner messages like `MsgSend`, `GetSigners()` returns the victim's address, making `granter=victim`. Since `granter==grantee`, the implicit accept path executes the message without any authorization check. [5](#0-4) 

**Exploitation path:**
1. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec`
2. Bob constructs nested MsgExec: `OuterMsgExec(grantee=Bob, msgs=[InnerMsgExec(grantee=Alice, msgs=[MsgSend(from=Alice, to=Bob, amount=all)])])`
3. Bob signs and submits the transaction
4. Outer MsgExec handler calls `DispatchActions(ctx, Bob, [InnerMsgExec])` [6](#0-5) 
5. First DispatchActions: `InnerMsgExec.GetSigners()` returns `[Alice]`, authorization check verifies Bob has MsgExec grant from Alice (passes)
6. Inner MsgExec handler calls `DispatchActions(ctx, Alice, [MsgSend])`
7. Second DispatchActions: `MsgSend.GetSigners()` returns `[Alice]`, the check `!Alice.Equals(Alice)` evaluates to FALSE, triggering implicit accept
8. MsgSend executes without SendAuthorization check, transferring all funds from Alice to Bob

**Security guarantee broken:**
The authorization invariant that grantees can only execute message types explicitly authorized by the granter is completely violated. A single MsgExec grant provides unlimited access to execute any message type on behalf of the granter, including fund transfers, staking operations, and governance votes.

## Impact Explanation

This vulnerability enables complete account takeover and direct theft of funds. An attacker with only MsgExec authorization can:

- **Drain all funds**: Execute `MsgSend` to transfer the victim's entire balance to the attacker's address
- **Manipulate staking**: Delegate, undelegate, or redelegate the victim's staked tokens
- **Control governance**: Vote on governance proposals on behalf of the victim
- **Execute any message type**: The bypass works for all message types in the Cosmos SDK

All funds in accounts that have granted `GenericAuthorization` for `MsgExec` are at immediate risk of theft. The authorization system is designed to provide granular control over which operations a grantee can perform, but this vulnerability renders that protection completely ineffective for any account that has granted MsgExec authorization.

## Likelihood Explanation

**Who can trigger:** Any grantee who receives `GenericAuthorization` for `MsgExec` from another account.

**Conditions required:**
- The granter must grant authorization for `/cosmos.authz.v1beta1.MsgExec` to the attacker
- This is the ONLY authorization required - no authorization for the actual message types being executed is needed
- No validation in the Grant method prevents granting MsgExec authorization [7](#0-6) 

**Frequency:**
- Exploitable immediately upon receiving the authorization
- Works during normal network operation without special conditions
- No privileged access, timing windows, or state coordination required
- MsgExec authorization may appear reasonable for advanced delegation workflows, making it likely that users grant this authorization

The vulnerability is particularly dangerous because granting MsgExec authorization appears reasonable for nested delegation patterns or automated transaction execution, making exploitation highly probable in real-world usage.

## Recommendation

**Recommended Fix:** Prevent granting authorization for MsgExec by adding validation in the Grant method in `x/authz/keeper/msg_server.go` after line 31:

```go
t := authorization.MsgTypeURL()
if t == sdk.MsgTypeURL(&authz.MsgExec{}) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "cannot grant authorization for MsgExec")
}
```

**Alternative fixes:**
1. Track execution depth and disable implicit accept for nested executions by passing a context flag through DispatchActions
2. Modify the implicit accept logic to validate against the actual transaction signer (from the context) rather than the result of `msg.GetSigners()`
3. Add validation in `MsgExec.ValidateBasic()` to prevent nested MsgExec messages

The recommended fix is the simplest and safest approach, as nested MsgExec creates complex authorization chains that are inherently difficult to reason about securely.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Setup:**
- Initialize test accounts using simapp: Alice (granter/victim at `addrs[0]`), Bob (grantee/attacker at `addrs[1]`)
- Fund Alice's account with 10,000 stake tokens
- Alice grants Bob GenericAuthorization for MsgExec: `app.AuthzKeeper.SaveGrant(ctx, bobAddr, aliceAddr, authz.NewGenericAuthorization(sdk.MsgTypeURL(&authz.MsgExec{})), now.Add(time.Hour))`
- Verify Alice has NOT granted Bob SendAuthorization by checking `app.AuthzKeeper.GetCleanAuthorization(ctx, bobAddr, aliceAddr, bankSendAuthMsgType)` returns nil

**Action:**
```go
// Bob constructs nested MsgExec to steal Alice's funds
msgSend := banktypes.MsgSend{
    FromAddress: aliceAddr.String(), 
    ToAddress: bobAddr.String(), 
    Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", 10000))
}
innerMsgExec := authz.NewMsgExec(aliceAddr, []sdk.Msg{&msgSend})
outerMsgExec := authz.NewMsgExec(bobAddr, []sdk.Msg{&innerMsgExec})

// Bob executes the nested MsgExec
msgs, _ := outerMsgExec.GetMessages()
results, err := app.AuthzKeeper.DispatchActions(ctx, bobAddr, msgs)
```

**Result:**
- The call succeeds without error (should fail due to lack of SendAuthorization)
- Alice's balance is drained to zero: `app.BankKeeper.GetBalance(ctx, aliceAddr, "stake").Amount.IsZero()` returns true
- Bob receives all 10,000 tokens: `app.BankKeeper.GetBalance(ctx, bobAddr, "stake").Amount.Equal(sdk.NewInt(10000))` returns true
- Authorization bypass confirmed - Bob executed MsgSend without SendAuthorization from Alice

## Notes

The vulnerability fundamentally breaks the x/authz module's security model. The interaction between `MsgExec.GetSigners()` returning the grantee field and the implicit accept logic creates a complete authorization bypass. The implicit accept logic was designed with the assumption that `GetSigners()` returns the actual transaction signer, but `MsgExec.GetSigners()` breaks this assumption by returning its grantee field instead. This allows nested MsgExec messages to manipulate the authorization check logic and bypass all authorization requirements.

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
