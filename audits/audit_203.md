After thorough investigation of the sei-cosmos codebase focusing on AnteHandler processing and nested message validation in MsgExec, I have identified a concrete vulnerability.

## Audit Report

## Title
Fee Grant Message Filter Bypass via MsgExec Nested Messages

## Summary
The `AllowedMsgAllowance` fee grant filter in the AnteHandler only validates the outer `MsgExec` message type and does not inspect nested messages within it. This allows grantees to bypass message type restrictions by wrapping unauthorized message types inside a `MsgExec` that is in the allowed list, enabling fee consumption outside the granter's intended parameters. [1](#0-0) 

## Impact
Low - Modification of transaction fees outside of design parameters

## Finding Description

**Location:** 
- `x/auth/ante/fee.go` in `DeductFeeDecorator.checkDeductFee()`
- `x/feegrant/filtered_fee.go` in `AllowedMsgAllowance.Accept()`
- `x/feegrant/keeper/keeper.go` in `UseGrantedFees()`

**Intended Logic:** 
The `AllowedMsgAllowance` fee grant type is designed to restrict which message types can consume a granter's fee allowance. When a transaction is validated, the AnteHandler should ensure that only explicitly allowed message types can use the fee grant. [2](#0-1) 

**Actual Logic:** 
The fee grant validation receives messages via `sdkTx.GetMsgs()` which returns only the top-level messages in the transaction. For a transaction containing `MsgExec`, this returns `[MsgExec]` but does not include the nested messages packed inside the `MsgExec.Msgs` field. The `allMsgTypesAllowed()` function only checks these top-level message types against the allowed list, completely bypassing validation of nested messages that will actually be executed. [3](#0-2) 

**Exploit Scenario:**
1. Alice creates an `AllowedMsgAllowance` fee grant for Bob
2. Alice sets `AllowedMessages = ["/cosmos.gov.v1beta1.MsgVote", "/cosmos.authz.v1beta1.MsgExec"]` because she wants Bob to vote on proposals using her fee grant
3. Alice separately grants Bob authz permission for `MsgSend` (perhaps for a different purpose or context)
4. Bob creates a transaction with `MsgExec` containing a nested `MsgSend` 
5. During CheckTx, the AnteHandler's `DeductFeeDecorator` calls `UseGrantedFees()` with `sdkTx.GetMsgs()` = `[MsgExec]`
6. The `AllowedMsgAllowance.Accept()` method checks if `MsgExec` is in the allowed list - it is, so validation passes
7. The transaction is accepted and executes, with the nested `MsgSend` consuming Alice's fee grant
8. Alice's fee grant was consumed by a message type (`MsgSend`) that she never intended to allow [4](#0-3) 

**Security Failure:** 
The access control invariant of `AllowedMsgAllowance` is violated. The security property that "only explicitly whitelisted message types can consume the fee grant" is broken when `MsgExec` is in the allowed list, as it becomes a bypass mechanism for any message type the grantee has authz permission for.

## Impact Explanation

This vulnerability affects the fee grant system's access control, specifically:
- **Affected Asset:** The granter's fee allowance balance can be depleted by unintended message types
- **Severity:** The granter's fee grant spend limit is consumed outside their intended parameters. While this doesn't directly steal funds from the granter's main balance, it causes unauthorized consumption of the granted fee allowance
- **Systemic Impact:** This undermines the trust model of fee grants with message filtering. Granters who believe they're restricting fee usage to specific message types will have their assumptions violated if they include `MsgExec` in the allowed list

The damage is limited to fee grant consumption (not direct fund theft), but represents a clear violation of the intended access control mechanism.

## Likelihood Explanation

**Triggering Conditions:**
- The granter must have created an `AllowedMsgAllowance` with `MsgExec` in the allowed messages list
- The granter must have also granted authz permission for the nested message type
- The grantee must construct a `MsgExec` with the nested message

**Likelihood:** Medium
- This requires specific configuration by the granter (including `MsgExec` in allowed messages)
- However, it's plausible that granters would include `MsgExec` thinking it's necessary for authorization functionality without understanding it creates a bypass
- Once configured this way, any grantee can exploit it repeatedly until the fee grant is exhausted
- The vulnerability affects a standard module feature (fee grants with message filtering) used across the ecosystem

## Recommendation

Implement recursive message type validation for `MsgExec` nested messages in the fee grant validation logic:

1. **Option A (Recommended):** In `AllowedMsgAllowance.Accept()`, detect when a message is `MsgExec` and recursively validate all nested messages against the allowed list:

```go
// In x/feegrant/filtered_fee.go, modify allMsgTypesAllowed()
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
    msgsMap := a.allowedMsgsToMap(ctx)
    
    for _, msg := range msgs {
        ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
        
        // Check if this message type is allowed
        if !msgsMap[sdk.MsgTypeURL(msg)] {
            return false
        }
        
        // If this is a MsgExec, recursively check nested messages
        if execMsg, ok := msg.(*authz.MsgExec); ok {
            nestedMsgs, err := execMsg.GetMessages()
            if err != nil || !a.allMsgTypesAllowed(ctx, nestedMsgs) {
                return false
            }
        }
    }
    
    return true
}
```

2. **Option B:** Document this behavior clearly and warn granters not to include `MsgExec` in `AllowedMsgAllowance` if they want strict message type filtering.

Option A is strongly recommended as it fixes the security invariant violation at the code level.

## Proof of Concept

**File:** `x/feegrant/filtered_fee_test.go`

**Test Function:** Add this test case to demonstrate the bypass:

```go
func TestAllowedMsgAllowanceBypassViaMsgExec(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{
        Time: time.Now(),
    })
    
    // Setup addresses
    granter := sdk.AccAddress("granter_address___")
    grantee := sdk.AccAddress("grantee_address___")
    recipient := sdk.AccAddress("recipient_address_")
    
    // Create fee allowance that allows MsgVote and MsgExec, but NOT MsgSend
    spendLimit := sdk.NewCoins(sdk.NewInt64Coin("atom", 1000))
    basicAllowance, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
        SpendLimit: spendLimit,
    })
    
    allowance := &feegrant.AllowedMsgAllowance{
        Allowance: basicAllowance,
        AllowedMessages: []string{
            "/cosmos.gov.v1beta1.MsgVote",
            "/cosmos.authz.v1beta1.MsgExec",
        },
    }
    
    // Create a MsgExec with nested MsgSend (which is NOT in allowed list)
    nestedMsg := &banktypes.MsgSend{
        FromAddress: granter.String(),
        ToAddress:   recipient.String(),
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("atom", 100)),
    }
    
    execMsg := authz.NewMsgExec(grantee, []sdk.Msg{nestedMsg})
    
    // Test: The allowance should REJECT this because MsgSend is not allowed
    // But currently it ACCEPTS because only MsgExec is checked
    fee := sdk.NewCoins(sdk.NewInt64Coin("atom", 50))
    
    removed, err := allowance.Accept(ctx, fee, []sdk.Msg{&execMsg})
    
    // Current behavior: This passes (err == nil) - THIS IS THE BUG
    // Expected behavior: This should fail with "message does not exist in allowed messages"
    require.NoError(t, err) // This demonstrates the vulnerability - test passes when it shouldn't
    require.False(t, removed)
    
    // The test passing shows that MsgExec with nested MsgSend bypasses the filter
    // even though MsgSend is not in the AllowedMessages list
}
```

**Setup:** Initialize a simapp context and create three addresses (granter, grantee, recipient)

**Trigger:** Create an `AllowedMsgAllowance` that allows `MsgVote` and `MsgExec` but NOT `MsgSend`. Then create a `MsgExec` containing a nested `MsgSend` and call the `Accept()` method.

**Observation:** The test demonstrates that the `Accept()` method returns success (no error) even though the actual message being executed (`MsgSend`) is not in the allowed list. This confirms that nested messages inside `MsgExec` bypass the message type filter. The expected behavior would be to return an error indicating that `MsgSend` is not allowed, but instead the validation passes because only the outer `MsgExec` type is checked.

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

**File:** x/feegrant/keeper/keeper.go (L147-158)
```go
func (k Keeper) UseGrantedFees(ctx sdk.Context, granter, grantee sdk.AccAddress, fee sdk.Coins, msgs []sdk.Msg) error {
	f, err := k.getGrant(ctx, granter, grantee)
	if err != nil {
		return err
	}

	grant, err := f.GetGrant()
	if err != nil {
		return err
	}

	remove, err := grant.Accept(ctx, fee, msgs)
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
