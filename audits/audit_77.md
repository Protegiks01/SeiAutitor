# Audit Report

## Title
Nested MsgExec Authorization Bypass Allows Unauthorized Message Execution

## Summary
A critical vulnerability in the x/authz module allows a grantee with `GenericAuthorization` for `MsgExec` to bypass authorization checks and execute arbitrary message types on behalf of the granter. By nesting `MsgExec` messages, an attacker exploits the implicit accept logic to execute unauthorized actions, resulting in direct loss of funds.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended logic:** 
The authorization system is designed to enforce fine-grained access control where a granter explicitly authorizes a grantee to execute specific message types on their behalf. The `DispatchActions` function verifies authorization when the message signer differs from the executing grantee. The implicit accept logic (lines 87-89 in keeper.go) is intended to allow users to execute their own messages without requiring self-authorization.

**Actual logic:** 
The vulnerability arises from three interacting behaviors:
1. `MsgExec.GetSigners()` returns the `grantee` field of the MsgExec message [2](#0-1) , not the actual transaction signer
2. When `DispatchActions` processes a nested `MsgExec`, it uses `msg.GetSigners()[0]` as the "granter" [3](#0-2) 
3. An attacker can set the inner MsgExec's grantee to the victim's address, causing subsequent messages to bypass authorization via the implicit accept path (granter == grantee) [4](#0-3) 

**Exploitation path:**
1. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec` [5](#0-4) 
2. Bob constructs a transaction with nested MsgExec messages:
   - Outer `MsgExec`: grantee=Bob, msgs=[inner_MsgExec]
   - Inner `MsgExec`: grantee=Alice, msgs=[MsgSend(from=Alice, to=Bob)]
3. Bob signs and submits the transaction
4. Outer MsgExec executes via `Keeper.Exec()` [6](#0-5)  calling `DispatchActions(ctx, Bob, [inner_MsgExec])`
   - inner_MsgExec.GetSigners() returns [Alice]
   - Authorization check: Does Bob have MsgExec authorization from Alice? YES [7](#0-6) 
   - `GenericAuthorization.Accept()` returns true [8](#0-7) 
   - Inner MsgExec handler is invoked
5. Inner MsgExec executes: `DispatchActions(ctx, Alice, [MsgSend])`
   - MsgSend.GetSigners() returns [Alice]
   - Check: Alice == Alice? YES → Implicit accept triggered [4](#0-3) 
   - NO authorization check performed
   - MsgSend executes, transferring Alice's funds to Bob

**Security guarantee broken:** 
The authorization invariant that a grantee can only execute message types explicitly authorized by the granter is violated. The system's fundamental security property of fine-grained access control is completely bypassed.

## Impact Explanation

This vulnerability enables direct theft of funds and complete account takeover. An attacker with only `MsgExec` authorization can:

- **Drain all funds**: Execute `MsgSend` to transfer the victim's entire balance
- **Modify staking positions**: Delegate, undelegate, or redelegate tokens
- **Cast governance votes**: Vote on proposals on behalf of the victim
- **Execute any message type**: The bypass works for all message types in the system

The impact is severe because users might grant `MsgExec` authorization believing it provides limited delegation capability for nested authorization workflows, without realizing it grants complete account control. All funds controlled by accounts that have granted `GenericAuthorization` for `MsgExec` are at immediate risk.

## Likelihood Explanation

**Who can trigger:** Any user who receives `GenericAuthorization` for `MsgExec` from another account.

**Conditions required:**
- The granter must grant authorization for `/cosmos.authz.v1beta1.MsgExec` to the attacker
- This is the ONLY authorization required - no authorization for the actual message types being executed is needed

**Frequency:** 
- Exploitable immediately after receiving the authorization
- Works during normal network operation
- No special timing, state conditions, or coordination required
- No privileged access needed
- Highly likely to be exploited if users grant MsgExec authorization for legitimate use cases

The vulnerability is particularly dangerous because granting `MsgExec` authorization might appear reasonable for advanced authorization workflows involving nested delegations, making it likely that users would grant this authorization without understanding the security implications.

## Recommendation

**Option 1 (Recommended):** Prevent granting authorization for `MsgExec` by adding validation in the `Grant` method [9](#0-8) :

```go
if t == sdk.MsgTypeURL(&authz.MsgExec{}) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "cannot grant authorization for MsgExec")
}
```

**Option 2:** Track execution depth and disable implicit accept for nested executions by passing a context flag through `DispatchActions` to indicate when execution is within a MsgExec.

**Option 3:** Modify the implicit accept logic to check the actual transaction signer rather than using the result from `GetSigners()`.

Option 1 is the simplest and safest fix, as nested MsgExec creates complex authorization chains that are inherently difficult to reason about securely.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Setup:**
- Initialize test accounts (Alice as victim/granter, Bob as attacker/grantee) using `simapp.AddTestAddrsIncremental`
- Fund Alice's account with 10,000 tokens using `simapp.FundAccount` [10](#0-9) 
- Alice grants Bob `GenericAuthorization` for `MsgExec` via `app.AuthzKeeper.SaveGrant`
- Verify Alice has NOT granted Bob `SendAuthorization` via `app.AuthzKeeper.GetCleanAuthorization`

**Action:**
- Bob constructs nested MsgExec using `authz.NewMsgExec` [11](#0-10) :
  - Outer: `authz.NewMsgExec(bobAddr, [inner_MsgExec])`
  - Inner: `authz.NewMsgExec(aliceAddr, [MsgSend])`
  - Innermost: `banktypes.MsgSend{FromAddress: aliceAddr, ToAddress: bobAddr, Amount: 10000 tokens}`
- Call `app.AuthzKeeper.DispatchActions(ctx, bobAddr, [inner_MsgExec])` [12](#0-11) 

**Result:**
- The call succeeds (when it should fail due to lack of SendAuthorization)
- Alice's balance is drained to zero
- Bob receives all 10,000 tokens
- This occurs despite Alice never granting Bob authorization for `MsgSend`

The PoC demonstrates complete authorization bypass, enabling arbitrary message execution and direct fund theft with only `MsgExec` authorization.

## Notes

The vulnerability fundamentally breaks the x/authz module's security model by allowing a single authorization grant to effectively grant unlimited account access. The interaction between `MsgExec.GetSigners()` returning the grantee field [2](#0-1)  and the implicit accept logic [4](#0-3)  creates an authorization bypass that undermines the entire purpose of the authorization system. No existing protections against this attack pattern were found in the codebase.

### Citations

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

**File:** x/authz/msgs.go (L180-195)
```go
func NewMsgExec(grantee sdk.AccAddress, msgs []sdk.Msg) MsgExec {
	msgsAny := make([]*cdctypes.Any, len(msgs))
	for i, msg := range msgs {
		any, err := cdctypes.NewAnyWithValue(msg)
		if err != nil {
			panic(err)
		}

		msgsAny[i] = any
	}

	return MsgExec{
		Grantee: grantee.String(),
		Msgs:    msgsAny,
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

**File:** x/authz/keeper/msg_server.go (L14-41)
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
```

**File:** x/authz/keeper/msg_server.go (L65-82)
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
```

**File:** x/authz/generic_authorization.go (L24-26)
```go
func (a GenericAuthorization) Accept(ctx sdk.Context, msg sdk.Msg) (AcceptResponse, error) {
	return AcceptResponse{Accept: true}, nil
}
```

**File:** x/authz/keeper/keeper_test.go (L132-132)
```go
	s.Require().NoError(simapp.FundAccount(app.BankKeeper, s.ctx, granterAddr, sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))))
```
