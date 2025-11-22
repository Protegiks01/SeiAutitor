# Audit Report

## Title
Message Filtering Bypass in AllowedMsgAllowance via MsgExec Wrapping

## Summary
The `AllowedMsgAllowance.Accept()` method in the feegrant module only validates top-level message types against the allowed messages list. When `MsgExec` is included in the allowed messages, grantees can wrap disallowed messages inside `MsgExec` to bypass filtering, enabling unauthorized use of fee grants for unintended message types.

## Impact
Low

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `AllowedMsgAllowance` is designed to restrict fee grants to specific message types. When a grantee uses a fee grant, the `Accept()` method should validate that ALL messages (including nested ones) are in the `AllowedMessages` list, rejecting transactions with unauthorized message types.

**Actual Logic:** The validation only checks top-level message type URLs. The `allMsgTypesAllowed()` method iterates through provided messages and checks each `sdk.MsgTypeURL(msg)` [2](#0-1) , but does NOT recursively validate inner messages within `MsgExec`.

When the ante handler processes fee grants, it passes only top-level messages from `sdkTx.GetMsgs()` [3](#0-2)  to the fee grant validation. Inner messages within `MsgExec` are extracted and executed later via `GetMessages()` [4](#0-3)  during message execution [5](#0-4) , completely bypassing the fee grant validation.

**Exploitation Path:**
1. Granter creates `AllowedMsgAllowance` restricting fee grants to specific types (e.g., `/cosmos.bank.v1beta1.MsgSend`)
2. Granter includes `/cosmos.authz.v1beta1.MsgExec` in allowed messages for legitimate authz use cases
3. Grantee constructs transaction with `MsgExec` wrapping disallowed messages (e.g., `/cosmos.staking.v1beta1.MsgDelegate`)
4. Ante handler validates fee grant - only sees outer `MsgExec` type, which passes validation
5. Fee is deducted from the fee grant [6](#0-5) 
6. Message execution extracts and executes wrapped messages that were never validated against the allowed messages list
7. Grantee successfully uses fee allowance for unauthorized message types

**Security Guarantee Broken:** The filtering mechanism of `AllowedMsgAllowance` is designed to enforce that fee grants can only be used for specific pre-approved message types. This bypass allows grantees to use fee grants for any message type (that they have authz authorization for), violating the granter's trust model and intended restrictions.

## Impact Explanation

The vulnerability allows grantees to consume fee grants for message types the granter did not intend to authorize. Specifically:

- Fee grants are depleted for unintended operations (e.g., staking, governance votes, IBC transfers when only bank sends were intended)
- Granter's trust model is violated - they approved specific low-risk operations but grantee executes other operations
- Fee allowances consumed faster than expected or for operations the granter would not have approved

The impact is limited because the grantee still requires valid authz authorization for inner messages - they cannot execute arbitrary operations without separate authz grants. However, the fee grant filtering is completely bypassed, which is the core security guarantee being violated.

This matches the "Modification of transaction fees outside of design parameters" impact category (Low severity).

## Likelihood Explanation

**Triggering Conditions:**
- Grantee has a fee grant with both specific allowed messages AND `MsgExec` in the list
- Grantee has authz authorization for the inner messages they want to execute
- No special privileges required beyond being a grantee

**Likelihood:**
- **High likelihood** if granters commonly include `MsgExec` in allowed messages (which they might for legitimate authz use cases)
- Easy to exploit - just requires constructing a transaction with `MsgExec` wrapping desired messages
- Can be exploited repeatedly until fee grant exhausted or revoked
- Exploitation leaves no obvious trace beyond executed transactions

## Recommendation

Implement recursive validation for inner messages in `MsgExec`. The `allMsgTypesAllowed()` method should:

1. Detect when a message is a `MsgExec` 
2. Extract inner messages using `GetMessages()`
3. Recursively validate all inner messages are in the `AllowedMessages` list
4. Handle nested `MsgExec` scenarios recursively

Example implementation:
```go
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

**Setup:**
1. Initialize test app with `simapp.Setup(false)` and context
2. Create granter, grantee, and validator addresses using `AddTestAddrsIncremental`
3. Create `AllowedMsgAllowance` allowing only `/cosmos.bank.v1beta1.MsgSend` and `/cosmos.authz.v1beta1.MsgExec`
4. Create `MsgExec` wrapping `MsgDelegate` (NOT in allowed list)

**Action:**
Call `allowance.Accept(ctx, fee, []sdk.Msg{&msgExec})` where `msgExec` contains wrapped `MsgDelegate`

**Result:**
The method incorrectly returns no error and accepts the fee deduction, even though the inner `MsgDelegate` message is not in the `AllowedMessages` list. This confirms the bypass - only the outer `MsgExec` type is validated, allowing the disallowed inner message to pass through.

The test demonstrates that the filtering mechanism is completely bypassed when using `MsgExec` to wrap disallowed messages, proving the vulnerability exists in the codebase.

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
