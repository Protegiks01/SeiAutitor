## Title
Privilege Escalation Through Unrestricted MsgExec Authorization Allowing Unauthorized Re-delegation

## Summary
The authz module lacks protection against granting authorization for `MsgExec` and `MsgGrant` message types, enabling privilege escalation through delegation chains. This allows grantees to re-delegate authorizations to third parties without the original granter's explicit consent, breaking the trust model and enabling unauthorized access to accounts and funds. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** The vulnerability exists in the `Grant` method in `x/authz/keeper/msg_server.go` and the overall authorization validation flow in the authz module. [2](#0-1) 

**Intended Logic:** The authz module should enforce that authorizations are explicit and non-transitive. When Alice grants Bob authorization to perform actions on her behalf, this should only allow Bob to execute those actions directly, not enable Bob to re-delegate Alice's authorization to third parties like Charlie. Each authorization relationship should require explicit consent from the granter.

**Actual Logic:** The `Grant` method only validates that (1) the authorization is present and (2) a handler exists for the message type. There is no check preventing the authorization of `MsgExec` or `MsgGrant` message types themselves. This allows a grantee to grant another party the ability to execute `MsgExec`, which effectively enables unlimited re-delegation chains. [3](#0-2) 

The `GenericAuthorization` type always accepts any message without validation, making it trivial to grant unrestricted `MsgExec` authorization.

**Exploit Scenario:**
1. Alice grants Bob a `SendAuthorization` to send up to 100 tokens from Alice's account
2. Bob grants Charlie a `GenericAuthorization` for the `MsgExec` message type
3. Charlie creates a nested `MsgExec`: `MsgExec{grantee: Charlie, msgs: [MsgExec{grantee: Bob, msgs: [MsgSend{from: Alice, amount: 100}]}]}`
4. When processed by `DispatchActions`, the outer `MsgExec` validates that Charlie has authorization from Bob for `MsgExec` (step 2 grant)
5. The inner `MsgExec` then validates that Bob has authorization from Alice for `MsgSend` (step 1 grant)
6. The `MsgSend` executes, transferring 100 tokens from Alice's account to an address controlled by Charlie
7. Alice never authorized Charlie, yet Charlie successfully accessed Alice's funds through Bob's re-delegation [4](#0-3) 

**Security Failure:** This breaks the authorization security model by allowing transitive delegation without explicit consent. The system fails to enforce the principle that authorizations are personal and non-transferable, enabling privilege escalation through delegation chains.

## Impact Explanation

**Assets Affected:** All assets controlled by accounts that grant authorizations, including tokens, staking positions, governance votes, and any other blockchain operations that can be authorized.

**Severity of Damage:** 
- Unauthorized parties can gain access to funds and execute transactions on behalf of accounts they were never authorized to access
- The trust relationship between granter and grantee is broken, as grantees can re-delegate to arbitrary third parties
- This can lead to direct theft of funds, unauthorized staking operations, malicious governance votes, and other unauthorized actions
- The damage scales with the number of authorization chains, as each intermediate party can re-delegate further

**Why This Matters:** The authz module is designed to enable delegation of specific capabilities while maintaining security through explicit authorization. This vulnerability undermines the entire security model by allowing implicit transitive delegation, effectively making any authorization grant potentially accessible to unlimited third parties. This is a fundamental breach of the authorization trust model.

## Likelihood Explanation

**Who Can Trigger:** Any user who has received any authorization grant can exploit this vulnerability by granting `MsgExec` authorization to another party, thereby enabling re-delegation chains.

**Conditions Required:** 
- An initial authorization grant must exist (e.g., Alice grants Bob some authorization)
- The intermediate party (Bob) must create a grant for `MsgExec` to a third party (Charlie)
- This is trivially achievable through normal transaction submission; no special conditions are required

**Frequency:** This can be exploited at any time during normal network operation. Once an authorization grant exists, any grantee can immediately exploit this by granting `MsgExec` authorization to others. The vulnerability is persistent and does not require any race conditions or timing-specific attacks.

## Recommendation

Add validation in the `Grant` method to explicitly reject authorization grants for `MsgExec` and `MsgGrant` message types. Specifically:

1. In `x/authz/keeper/msg_server.go`, modify the `Grant` method to check if the authorization's `MsgTypeURL()` is for `MsgExec` or `MsgGrant` and reject such grants
2. Add a constant or list of disallowed authorization message types
3. Return an error if someone attempts to grant authorization for these recursive/re-delegation message types

Example pseudocode:
```
func (k Keeper) Grant(...) {
    ...
    t := authorization.MsgTypeURL()
    
    // Prevent authorization for MsgExec and MsgGrant to avoid re-delegation chains
    if t == sdk.MsgTypeURL(&authz.MsgExec{}) || t == sdk.MsgTypeURL(&authz.MsgGrant{}) {
        return nil, sdkerrors.ErrUnauthorized.Wrap("cannot grant authorization for MsgExec or MsgGrant")
    }
    
    if k.router.HandlerByTypeURL(t) == nil {
        return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
    }
    ...
}
```

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`
**Test Function:** `TestPrivilegeEscalationThroughNestedMsgExec` (add as a new test)

**Setup:**
1. Initialize SimApp with three test accounts: Alice (granter), Bob (intermediate grantee), Charlie (final attacker)
2. Fund Alice's account with 10,000 tokens
3. Create a recipient account to receive the stolen funds

**Trigger:**
1. Alice grants Bob a `SendAuthorization` with a 100 token spend limit via `MsgGrant`
2. Bob grants Charlie a `GenericAuthorization` for `MsgExec` message type via `MsgGrant`
3. Charlie constructs a nested `MsgExec`:
   - Outer: `MsgExec{grantee: Charlie, msgs: [innerMsgExec]}`
   - Inner: `MsgExec{grantee: Bob, msgs: [MsgSend{from: Alice, to: recipient, amount: 100}]}`
4. Submit Charlie's transaction containing the nested `MsgExec`

**Observation:**
The test should observe that:
- The nested `MsgExec` transaction succeeds without error
- 100 tokens are transferred from Alice's account to the recipient
- Alice never granted Charlie any authorization
- The balance changes confirm unauthorized fund transfer

This demonstrates that Charlie successfully escalated privileges through Bob's intermediate authorization, accessing Alice's funds without Alice's explicit consent to Charlie. The test would add assertions checking:
- Alice's balance decreased by 100 tokens
- Recipient's balance increased by 100 tokens
- No direct authorization grant exists from Alice to Charlie
- The transaction executed successfully despite the lack of direct authorization

The test code would follow the pattern established in existing tests like `TestKeeperFees` (lines 126-197 of keeper_test.go), using `simapp.FundAccount`, `app.AuthzKeeper.SaveGrant`, and `app.AuthzKeeper.DispatchActions` to set up and execute the attack scenario. [5](#0-4)

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

**File:** x/authz/generic_authorization.go (L23-26)
```go
// Accept implements Authorization.Accept.
func (a GenericAuthorization) Accept(ctx sdk.Context, msg sdk.Msg) (AcceptResponse, error) {
	return AcceptResponse{Accept: true}, nil
}
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
