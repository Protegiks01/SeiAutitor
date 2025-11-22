# Audit Report

## Title
Message Filtering Bypass in AllowedMsgAllowance via MsgExec Wrapping

## Summary
The `AllowedMsgAllowance.Accept()` method in `x/feegrant/filtered_fee.go` only validates top-level message types against the allowed messages list. When `x/authz MsgExec` is included in the allowed messages, attackers can wrap any disallowed messages inside `MsgExec` to bypass the filtering, enabling unauthorized use of fee grants for unintended message types.

## Impact
**Low** - Modification of transaction fees outside of design parameters

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `AllowedMsgAllowance` is designed to restrict fee grants to specific message types. When a grantee attempts to use a fee grant, the `Accept()` method should validate that all messages in the transaction are in the `AllowedMessages` list, rejecting any transactions containing unauthorized message types.

**Actual Logic:** The validation only checks the type URL of top-level messages in the transaction. The `allMsgTypesAllowed()` method iterates through the provided messages and checks each one's type URL: [2](#0-1) 

However, when the ante handler processes fee grants, it only passes top-level messages from `sdkTx.GetMsgs()`: [3](#0-2) 

This means if a transaction contains a `MsgExec` (from the authz module), only the `MsgExec` type itself is validated, not the inner messages it wraps: [4](#0-3) 

The inner messages are extracted and executed later in the message execution phase: [5](#0-4) 

**Exploit Scenario:**
1. Granter creates an `AllowedMsgAllowance` restricting fee grants to specific message types (e.g., only `/cosmos.bank.v1beta1.MsgSend`)
2. Granter includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list (either intentionally for legitimate use or by mistake)
3. Grantee creates a transaction containing a `MsgExec` that wraps disallowed messages (e.g., `/cosmos.staking.v1beta1.MsgDelegate`, `/cosmos.gov.v1beta1.MsgVote`, etc.)
4. During ante handler execution, the fee grant validation only sees the outer `MsgExec` type, which is in the allowed list, so it approves the fee deduction: [6](#0-5) 
5. The transaction proceeds and `MsgExec` executes the wrapped messages that were not intended to be covered by the fee grant
6. The grantee successfully uses the fee allowance for unauthorized message types

**Security Failure:** This breaks the authorization control mechanism of `AllowedMsgAllowance`. The filtering is intended to enforce that fee grants can only be used for specific pre-approved message types, but this can be bypassed, allowing unauthorized message types to be executed using the fee grant.

## Impact Explanation

**Assets Affected:** Fee grant allowances and their associated funds

**Severity:** The vulnerability allows grantees to use fee allowances for message types that granters did not intend to authorize. This means:

- Fee grants can be consumed for unintended purposes (e.g., staking operations, governance votes, IBC transfers when only bank sends were intended)
- The granter's trust model is violated - they may have approved specific low-risk operations but the grantee can execute higher-risk operations
- Fee allowances may be depleted faster than expected or for operations the granter would not have approved
- While this doesn't directly steal funds from the granter (beyond the fee grant itself), it modifies transaction fee usage outside design parameters

The impact is limited because:
- The grantee still needs valid authz authorization for the inner messages (they can't execute arbitrary operations on behalf of others without separate authz grants)
- Only the fee grant is misused; the actual operations still require proper authorization
- The granter voluntarily created the fee grant, limiting direct financial loss

## Likelihood Explanation

**Triggering Conditions:**
- Any grantee with a fee grant that includes both specific allowed messages AND `MsgExec` can exploit this
- Requires no special privileges beyond being a grantee
- Can be triggered during normal operation whenever the grantee has both an authz authorization and a fee grant

**Likelihood:**
- **High likelihood** if granters commonly include `MsgExec` in their allowed messages (which they might do for legitimate authz use cases)
- The vulnerability can be exploited repeatedly by any grantee until the fee grant is exhausted or revoked
- Easy to exploit - just requires constructing a transaction with `MsgExec` wrapping the desired messages

**Frequency:**
- Can occur whenever a fee grant with `MsgExec` in allowed messages exists
- Could affect many existing fee grants if `MsgExec` inclusion is a common pattern
- Exploitation leaves no obvious trace beyond the executed transactions

## Recommendation

The `AllowedMsgAllowance.Accept()` method should recursively validate inner messages when checking `MsgExec` messages. Specifically:

1. When iterating through messages in `allMsgTypesAllowed()`, detect if any message is a `MsgExec`
2. For `MsgExec` messages, call `GetMessages()` to extract the inner messages: [7](#0-6) 
3. Recursively validate that all inner messages are also in the `AllowedMessages` list
4. This should be done recursively to handle nested `MsgExec` scenarios

Example pseudo-code for the fix:
```
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
    msgsMap := a.allowedMsgsToMap(ctx)
    return a.checkMsgsRecursive(ctx, msgs, msgsMap)
}

func (a *AllowedMsgAllowance) checkMsgsRecursive(ctx sdk.Context, msgs []sdk.Msg, msgsMap map[string]bool) bool {
    for _, msg := range msgs {
        ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
        msgTypeURL := sdk.MsgTypeURL(msg)
        
        if !msgsMap[msgTypeURL] {
            return false
        }
        
        // Check inner messages if this is a MsgExec
        if msgExec, ok := msg.(*authz.MsgExec); ok {
            innerMsgs, err := msgExec.GetMessages()
            if err != nil || !a.checkMsgsRecursive(ctx, innerMsgs, msgsMap) {
                return false
            }
        }
    }
    return true
}
```

## Proof of Concept

**File:** `x/feegrant/filtered_fee_test.go`

**Test Function:** Add `TestAllowedMsgAllowanceBypassWithMsgExec` to the existing test file

**Setup:**
1. Initialize test app and context
2. Create granter, grantee, and recipient addresses
3. Create an `AllowedMsgAllowance` that allows only `/cosmos.bank.v1beta1.MsgSend` and `/cosmos.authz.v1beta1.MsgExec`
4. Create a `MsgExec` that wraps a `/cosmos.staking.v1beta1.MsgDelegate` message (which is NOT in the allowed list)

**Trigger:**
1. Call `allowance.Accept()` with the `MsgExec` message
2. The method should reject because the inner message is not allowed
3. However, it will incorrectly accept because it only checks the outer `MsgExec` type

**Observation:**
The test demonstrates that `Accept()` returns `true` (accepts) when it should return an error because the inner `MsgDelegate` message is not in the allowed messages list. This confirms the bypass vulnerability.

**Test Code:**
```go
func TestAllowedMsgAllowanceBypassWithMsgExec(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{
        Time: time.Now(),
    })
    
    addrs := simapp.AddTestAddrsIncremental(app, ctx, 3, sdk.NewInt(30000000))
    granter := addrs[0]
    grantee := addrs[1]
    validator := addrs[2]
    
    // Create fee allowance that only allows MsgSend and MsgExec
    allowedMsgs := []string{
        "/cosmos.bank.v1beta1.MsgSend",
        "/cosmos.authz.v1beta1.MsgExec",
    }
    
    basicAllowance, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
        SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("atom", 1000)),
    })
    
    allowance := &feegrant.AllowedMsgAllowance{
        Allowance:       basicAllowance,
        AllowedMessages: allowedMsgs,
    }
    
    // Create a MsgDelegate (NOT in allowed list) wrapped in MsgExec
    innerMsg := &stakingtypes.MsgDelegate{
        DelegatorAddress: granter.String(),
        ValidatorAddress: validator.String(),
        Amount:           sdk.NewInt64Coin("atom", 100),
    }
    
    msgExec := authz.NewMsgExec(grantee, []sdk.Msg{innerMsg})
    require.NoError(t, msgExec.UnpackInterfaces(app.AppCodec()))
    
    // Attempt to use the allowance with MsgExec containing disallowed inner message
    fee := sdk.NewCoins(sdk.NewInt64Coin("atom", 10))
    
    // This SHOULD fail because MsgDelegate is not in allowed messages
    // But it will succeed because only the outer MsgExec is checked
    removed, err := allowance.Accept(ctx, fee, []sdk.Msg{&msgExec})
    
    // The vulnerability: Accept succeeds when it should fail
    require.NoError(t, err, "Expected Accept to fail for disallowed inner message, but it succeeded - VULNERABILITY CONFIRMED")
    require.False(t, removed)
    
    t.Log("VULNERABILITY: MsgExec bypass successful - inner MsgDelegate was not validated despite not being in allowed messages list")
}
```

The test will pass (showing no error from `Accept`), which confirms the vulnerability - the disallowed `MsgDelegate` message wrapped in `MsgExec` is accepted when it should be rejected.

### Citations

**File:** x/feegrant/filtered_fee.go (L65-86)
```go
func (a *AllowedMsgAllowance) Accept(ctx sdk.Context, fee sdk.Coins, msgs []sdk.Msg) (bool, error) {
	if !a.allMsgTypesAllowed(ctx, msgs) {
		return false, sdkerrors.Wrap(ErrMessageNotAllowed, "message does not exist in allowed messages")
	}

	allowance, err := a.GetAllowance()
	if err != nil {
		return false, err
	}

	remove, err := allowance.Accept(ctx, fee, msgs)
	if err != nil {
		return false, err
	}

	a.Allowance, err = types.NewAnyWithValue(allowance.(proto.Message))
	if err != nil {
		return false, err
	}

    return remove, nil
}
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

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
```

**File:** proto/cosmos/authz/v1beta1/tx.proto (L50-56)
```text
message MsgExec {
  string grantee = 1;
  // Authorization Msg requests to execute. Each msg must implement Authorization interface
  // The x/authz will try to find a grant matching (msg.signers[0], grantee, MsgTypeURL(msg))
  // triple and validate it.
  repeated google.protobuf.Any msgs = 2 [(cosmos_proto.accepts_interface) = "sdk.Msg, authz.Authorization"];
}
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

**File:** x/feegrant/keeper/keeper.go (L147-180)
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

	if remove {
		// Ignoring the `revokeFeeAllowance` error, because the user has enough grants to perform this transaction.
		k.revokeAllowance(ctx, granter, grantee)
		if err != nil {
			return err
		}

		emitUseGrantEvent(ctx, granter.String(), grantee.String())

		return nil
	}

	if err != nil {
		return err
	}

	emitUseGrantEvent(ctx, granter.String(), grantee.String())

	// if fee allowance is accepted, store the updated state of the allowance
	return k.GrantAllowance(ctx, granter, grantee, grant)
}
```

**File:** x/authz/msgs.go (L197-209)
```go
// GetMessages returns the cache values from the MsgExecAuthorized.Msgs if present.
func (msg MsgExec) GetMessages() ([]sdk.Msg, error) {
	msgs := make([]sdk.Msg, len(msg.Msgs))
	for i, msgAny := range msg.Msgs {
		msg, ok := msgAny.GetCachedValue().(sdk.Msg)
		if !ok {
			return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages contains %T which is not a sdk.MsgRequest", msgAny)
		}
		msgs[i] = msg
	}

	return msgs, nil
}
```
