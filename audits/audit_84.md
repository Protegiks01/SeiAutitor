# Audit Report

## Title
Privilege Escalation Through Unrestricted MsgExec Authorization Enabling Unauthorized Transitive Delegation

## Summary
The authz module's `Grant` method lacks validation to prevent granting authorization for `MsgExec` message types, enabling privilege escalation through delegation chains. When combined with `GenericAuthorization` and the recursive nature of `MsgExec` execution, this allows grantees to re-delegate authorizations to unauthorized third parties, resulting in direct loss of funds.

## Impact
High

## Finding Description

- **location**: [1](#0-0)  (Grant method) and [2](#0-1)  (DispatchActions method)

- **intended logic**: Authorizations should be explicit and non-transitive. When Alice grants Bob authorization to perform actions on her behalf, only Bob should be able to execute those actions, not arbitrary third parties that Bob chooses to delegate to. The authorization model assumes a direct trust relationship between granter and grantee.

- **actual logic**: The `Grant` method only validates that an authorization is present and a handler exists for the message type [3](#0-2) . There is no check preventing authorization of `MsgExec` itself. The `GenericAuthorization.Accept()` method accepts any message without validation [4](#0-3) . The `MsgExec.GetSigners()` returns the grantee field [5](#0-4) , which when combined with `DispatchActions` creates a recursive execution path that enables transitive delegation chains.

- **exploitation path**: 
  1. Alice grants Bob a `SendAuthorization` for 100 tokens
  2. Bob grants Charlie a `GenericAuthorization` for `MsgExec` type URL
  3. Charlie constructs nested `MsgExec` messages: outer `MsgExec` with grantee=Charlie containing inner `MsgExec` with grantee=Bob containing `MsgSend` from Alice
  4. When the outer `MsgExec` is processed by the `Exec` handler [6](#0-5) , it calls `DispatchActions` with grantee=Charlie
  5. `DispatchActions` extracts the signer from the inner `MsgExec` (which returns Bob via `GetSigners()`) and validates Charlie's authorization from Bob for `MsgExec` type
  6. The handler recursively calls `Exec` for the inner `MsgExec`, which then calls `DispatchActions` with grantee=Bob
  7. This validates Bob's authorization from Alice for `MsgSend` and executes the transfer
  8. Alice's funds are transferred without Alice ever authorizing Charlie

- **security guarantee broken**: The principle that authorizations are personal and non-transferable is violated. The authz module design in ADR-030 [7](#0-6)  describes granting privileges "from one account (the _granter_) to another account (the _grantee_)" with no mention of transitive delegation capabilities.

## Impact Explanation
This vulnerability results in **direct loss of funds**. Unauthorized parties can gain access to and steal funds from accounts they were never authorized to access. The trust relationship between granter and grantee is fundamentally broken as grantees can re-delegate to arbitrary third parties without the original granter's knowledge or consent. This affects all assets that can be controlled through authorizations including tokens, staking positions, and governance votes. In the described scenario, Charlie can drain Alice's account despite Alice only trusting Bob.

## Likelihood Explanation
Any user who receives any authorization grant can exploit this vulnerability. The only conditions required are: (1) an initial authorization grant exists between Alice and Bob, and (2) Bob creates a grant for `MsgExec` to Charlie using `GenericAuthorization`. This is trivially achievable through normal transaction submission with no special conditions, race conditions, or timing requirements. No administrative privileges or special access is needed. The vulnerability is persistent and can be exploited at any time after the authorization chain is established.

## Recommendation
Add validation in the `Grant` method to explicitly reject authorization grants for `MsgExec` and `MsgGrant` message types:

```go
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
    // ... existing code ...
    
    t := authorization.MsgTypeURL()
    
    // Prevent recursive delegation chains
    if t == sdk.MsgTypeURL(&authz.MsgExec{}) || t == sdk.MsgTypeURL(&authz.MsgGrant{}) {
        return nil, sdkerrors.ErrUnauthorized.Wrap("cannot grant authorization for MsgExec or MsgGrant to prevent delegation chains")
    }
    
    if k.router.HandlerByTypeURL(t) == nil {
        return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
    }
    
    // ... rest of existing code ...
}
```

Alternatively, the validation could be added in `MsgGrant.ValidateBasic()` [8](#0-7)  to reject such grants earlier in the transaction processing pipeline.

## Proof of Concept

Following the pattern in `TestKeeperFees` [9](#0-8) , a test can be constructed:

**Setup**:
- Initialize three accounts: Alice (addrs[0]), Bob (addrs[1]), Charlie (addrs[2])
- Fund Alice with 10,000 steak tokens using `simapp.FundAccount`
- Set expiration time from `ctx.BlockHeader().Time`

**Action**:
```go
// 1. Alice grants Bob SendAuthorization with 100 token limit
app.AuthzKeeper.SaveGrant(ctx, Bob, Alice, 
    &banktypes.SendAuthorization{SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("steak", 100))}, 
    expiration)

// 2. Bob grants Charlie GenericAuthorization for MsgExec
app.AuthzKeeper.SaveGrant(ctx, Charlie, Bob,
    &authz.GenericAuthorization{Msg: sdk.MsgTypeURL(&authz.MsgExec{})},
    expiration)

// 3. Charlie constructs nested MsgExec
innerMsgExec := authz.NewMsgExec(Bob, []sdk.Msg{
    &banktypes.MsgSend{
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 100)),
        FromAddress: Alice.String(),
        ToAddress:   Recipient.String(),
    },
})

outerMsgExec := authz.NewMsgExec(Charlie, []sdk.Msg{&innerMsgExec})

// 4. Execute the nested MsgExec
msgs, _ := outerMsgExec.GetMessages()
result, err := app.AuthzKeeper.DispatchActions(ctx, Charlie, msgs)
```

**Result**:
- Transaction succeeds (`err == nil`, `result != nil`)
- 100 steak tokens are transferred from Alice to Recipient
- Alice never authorized Charlie, only Bob
- This demonstrates unauthorized transitive delegation

### Citations

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

**File:** x/authz/generic_authorization.go (L23-26)
```go
// Accept implements Authorization.Accept.
func (a GenericAuthorization) Accept(ctx sdk.Context, msg sdk.Msg) (AcceptResponse, error) {
	return AcceptResponse{Accept: true}, nil
}
```

**File:** x/authz/msgs.go (L54-68)
```go
func (msg MsgGrant) ValidateBasic() error {
	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}

	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
	}
	return msg.Grant.ValidateBasic()
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

**File:** docs/architecture/adr-030-authz-module.md (L40-43)
```markdown
We will create a module named `authz` which provides functionality for
granting arbitrary privileges from one account (the _granter_) to another account (the _grantee_). Authorizations
must be granted for a particular `Msg` service methods one by one using an implementation
of `Authorization` interface.
```

**File:** x/authz/keeper/keeper_test.go (L126-197)
```go
func (s *TestSuite) TestKeeperFees() {
	app, addrs := s.app, s.addrs

	granterAddr := addrs[0]
	granteeAddr := addrs[1]
	recipientAddr := addrs[2]
	s.Require().NoError(simapp.FundAccount(app.BankKeeper, s.ctx, granterAddr, sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))))
	now := s.ctx.BlockHeader().Time
	s.Require().NotNil(now)

	smallCoin := sdk.NewCoins(sdk.NewInt64Coin("steak", 20))
	someCoin := sdk.NewCoins(sdk.NewInt64Coin("steak", 123))

	msgs := authz.NewMsgExec(granteeAddr, []sdk.Msg{
		&banktypes.MsgSend{
			Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 2)),
			FromAddress: granterAddr.String(),
			ToAddress:   recipientAddr.String(),
		},
	})

	s.Require().NoError(msgs.UnpackInterfaces(app.AppCodec()))

	s.T().Log("verify dispatch fails with invalid authorization")
	executeMsgs, err := msgs.GetMessages()
	s.Require().NoError(err)
	result, err := app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)

	s.Require().Nil(result)
	s.Require().NotNil(err)

	s.T().Log("verify dispatch executes with correct information")
	// grant authorization
	err = app.AuthzKeeper.SaveGrant(s.ctx, granteeAddr, granterAddr, &banktypes.SendAuthorization{SpendLimit: smallCoin}, now)
	s.Require().NoError(err)
	authorization, _ := app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)

	s.Require().Equal(authorization.MsgTypeURL(), bankSendAuthMsgType)

	executeMsgs, err = msgs.GetMessages()
	s.Require().NoError(err)

	result, err = app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	authorization, _ = app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)

	s.T().Log("verify dispatch fails with overlimit")
	// grant authorization

	msgs = authz.NewMsgExec(granteeAddr, []sdk.Msg{
		&banktypes.MsgSend{
			Amount:      someCoin,
			FromAddress: granterAddr.String(),
			ToAddress:   recipientAddr.String(),
		},
	})

	s.Require().NoError(msgs.UnpackInterfaces(app.AppCodec()))
	executeMsgs, err = msgs.GetMessages()
	s.Require().NoError(err)

	result, err = app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)
	s.Require().Nil(result)
	s.Require().NotNil(err)

	authorization, _ = app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)
}
```
