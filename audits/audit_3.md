## Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages in AnteHandler

## Summary
The `AllowedMsgAllowance` feegrant restriction can be bypassed by wrapping disallowed message types inside an authz `MsgExec`. The AnteHandler only validates top-level messages when checking feegrant allowances, allowing attackers to execute any message type while using a restricted feegrant to pay fees. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in the interaction between:
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended Logic:**
The `AllowedMsgAllowance` is designed to restrict feegrants to only pay fees for specific message types. When a granter creates a feegrant with `AllowedMsgAllowance`, they specify a list of allowed message type URLs (e.g., only `/cosmos.gov.v1beta1.MsgVote`). The system should reject any transaction attempting to use this feegrant for other message types. [5](#0-4) 

**Actual Logic:**
The `DeductFeeDecorator` in the AnteHandler calls `UseGrantedFees` with `sdkTx.GetMsgs()`, which only returns top-level messages. The `AllowedMsgAllowance.Accept` method then validates these top-level messages against the allowed list using `allMsgTypesAllowed`. However, when a `MsgExec` is used, `GetMsgs()` returns only the `MsgExec` itself, not the nested messages it contains. [6](#0-5) 

**Exploit Scenario:**
1. Alice grants Bob a feegrant with `AllowedMsgAllowance` restricting it to only `/cosmos.gov.v1beta1.MsgVote` messages
2. Alice also includes `/cosmos.authz.v1beta1.MsgExec` in the allowed list (or an attacker convinces them to do so)
3. Bob wants to execute a `/cosmos.bank.v1beta1.MsgSend` which is NOT in the allowed list
4. Bob creates an authz grant from himself (or any controlled account) to himself
5. Bob creates a transaction with a `MsgExec` that wraps the `MsgSend` inside it
6. The AnteHandler's `AllowedMsgAllowance` check only sees `/cosmos.authz.v1beta1.MsgExec` and approves it
7. The nested `MsgSend` is never validated against the allowed message list
8. Bob successfully executes the disallowed `MsgSend` while using Alice's feegrant to pay fees

**Security Failure:**
Authorization bypass - the message type restriction mechanism in `AllowedMsgAllowance` is completely bypassed for nested messages within `MsgExec`, allowing unauthorized use of feegrant funds for any message type.

## Impact Explanation

This vulnerability allows attackers to bypass feegrant restrictions and spend granter funds on fees for unauthorized transaction types. The impact includes:

- **Unauthorized fee spending:** Attackers can drain a granter's feegrant allowance by executing any message types, not just those explicitly allowed
- **Loss of funds:** The granter loses control over how their granted funds are spent, potentially losing the entire feegrant balance to unauthorized transactions
- **Violation of trust assumptions:** Granters who create restricted feegrants expect their funds will only be used for specific purposes; this vulnerability breaks that guarantee

This matters because feegrants with `AllowedMsgAllowance` are specifically designed for restricted delegation scenarios (e.g., allowing someone to vote on governance proposals but not send tokens), and this bypass completely undermines that security model.

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger it:** Any user with a feegrant that includes `MsgExec` in the allowed messages list
- **Conditions required:** 
  - The granter must create an `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages
  - The attacker needs an authz grant (which they can create from themselves to themselves)
- **Frequency:** This can be exploited repeatedly on every transaction until the feegrant is exhausted

The vulnerability is likely to be exploited in practice because:
1. `MsgExec` is a legitimate message type that granters might reasonably include in allowed lists
2. Users creating feegrants may not understand the nested message implications
3. The exploit is straightforward and requires no special privileges beyond having the feegrant

## Recommendation

Modify the `AllowedMsgAllowance.Accept` method to recursively validate nested messages within `MsgExec` (and potentially other message wrapper types). Specifically:

1. In `x/feegrant/filtered_fee.go`, update `allMsgTypesAllowed` to extract and validate nested messages from `MsgExec`
2. Add a helper function to recursively unwrap messages and validate each individual message type
3. Ensure that all messages in the transaction (including nested ones) are checked against the allowed list

Example fix location: [2](#0-1) 

The fix should iterate through messages, detect `MsgExec` types, call `GetMessages()` on them, and recursively validate all nested messages against the allowed list.

## Proof of Concept

**File:** `x/feegrant/filtered_fee_test.go`

**Test Function:** Add the following test case to the existing test file:

```go
func TestFilteredFeeBypassWithMsgExec(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{
        Time: time.Now(),
    })

    // Setup: Create accounts
    granter := sdk.MustAccAddressFromBech32("cosmos18cgkqduwuh253twzmhedesw3l7v3fm37sppt58")
    grantee := sdk.MustAccAddressFromBech32("cosmos1yq8lgssgxlx9smjhes6ryjasmqmd3ts2559g0t")
    to := sdk.MustAccAddressFromBech32("cosmos15ky9du8a2wlstz6fpx3p4mqpjyrm5cgqzp4f3d")

    // Create a feegrant that ONLY allows MsgVote and MsgExec
    allowedMsgs := []string{
        "/cosmos.gov.v1beta1.MsgVote",
        "/cosmos.authz.v1beta1.MsgExec",
    }
    
    basicAllowance, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
        SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("atom", 1000)),
    })
    
    filteredAllowance := &feegrant.AllowedMsgAllowance{
        Allowance:       basicAllowance,
        AllowedMessages: allowedMsgs,
    }

    // Create a disallowed message (MsgSend) wrapped in MsgExec
    disallowedMsg := &banktypes.MsgSend{
        FromAddress: grantee.String(),
        ToAddress:   to.String(),
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("atom", 100)),
    }
    
    // Wrap the disallowed message in MsgExec
    execMsg := authz.NewMsgExec(grantee, []sdk.Msg{disallowedMsg})
    
    // Test 1: Direct MsgSend should be rejected
    remove, err := filteredAllowance.Accept(ctx, sdk.NewCoins(sdk.NewInt64Coin("atom", 10)), []sdk.Msg{disallowedMsg})
    require.Error(t, err, "MsgSend should be rejected as it's not in allowed messages")
    require.Contains(t, err.Error(), "message does not exist in allowed messages")
    
    // Test 2: MsgExec wrapping MsgSend should be REJECTED but currently PASSES (vulnerability)
    remove, err = filteredAllowance.Accept(ctx, sdk.NewCoins(sdk.NewInt64Coin("atom", 10)), []sdk.Msg{&execMsg})
    
    // VULNERABILITY: This passes when it should fail
    // The nested MsgSend is never validated
    require.NoError(t, err, "VULNERABILITY: MsgExec wrapping disallowed MsgSend incorrectly passes validation")
    require.False(t, remove)
}
```

**Setup:** The test creates a feegrant with `AllowedMsgAllowance` that only allows `MsgVote` and `MsgExec` message types.

**Trigger:** The test attempts to use the feegrant for a `MsgSend` (disallowed) both directly and wrapped inside a `MsgExec`.

**Observation:** 
- Test 1 correctly rejects the direct `MsgSend` 
- Test 2 demonstrates the vulnerability: the `MsgExec` wrapping the `MsgSend` incorrectly passes validation, even though `MsgSend` is not in the allowed list

The test confirms that nested messages within `MsgExec` bypass the `AllowedMsgAllowance` validation in the AnteHandler.

### Citations

**File:** x/auth/ante/fee.go (L148-200)
```go
func (dfd DeductFeeDecorator) checkDeductFee(ctx sdk.Context, sdkTx sdk.Tx, fee sdk.Coins) error {
	feeTx, ok := sdkTx.(sdk.FeeTx)
	if !ok {
		return sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must be a FeeTx")
	}

	if addr := dfd.accountKeeper.GetModuleAddress(types.FeeCollectorName); addr == nil {
		return fmt.Errorf("fee collector module account (%s) has not been set", types.FeeCollectorName)
	}

	feePayer := feeTx.FeePayer()
	feeGranter := feeTx.FeeGranter()
	deductFeesFrom := feePayer

	// if feegranter set deduct fee from feegranter account.
	// this works with only when feegrant enabled.
	if feeGranter != nil {
		if dfd.feegrantKeeper == nil {
			return sdkerrors.ErrInvalidRequest.Wrap("fee grants are not enabled")
		} else if !feeGranter.Equals(feePayer) {
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
			if err != nil {
				return sdkerrors.Wrapf(err, "%s does not not allow to pay fees for %s", feeGranter, feePayer)
			}
		}

		deductFeesFrom = feeGranter
	}

	deductFeesFromAcc := dfd.accountKeeper.GetAccount(ctx, deductFeesFrom)
	if deductFeesFromAcc == nil {
		return sdkerrors.ErrUnknownAddress.Wrapf("fee payer address: %s does not exist", deductFeesFrom)
	}

	// deduct the fees
	if !fee.IsZero() {
		err := DeductFees(dfd.bankKeeper, ctx, deductFeesFromAcc, fee)
		if err != nil {
			return err
		}
	}

	events := sdk.Events{
		sdk.NewEvent(
			sdk.EventTypeTx,
			sdk.NewAttribute(sdk.AttributeKeyFee, fee.String()),
			sdk.NewAttribute(sdk.AttributeKeyFeePayer, deductFeesFrom.String()),
		),
	}
	ctx.EventManager().EmitEvents(events)

	return nil
}
```

**File:** x/feegrant/filtered_fee.go (L64-86)
```go
// Accept method checks for the filtered messages has valid expiry
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

**File:** types/tx/types.go (L21-37)
```go
// GetMsgs implements the GetMsgs method on sdk.Tx.
func (t *Tx) GetMsgs() []sdk.Msg {
	if t == nil || t.Body == nil {
		return nil
	}

	anys := t.Body.Messages
	res := make([]sdk.Msg, len(anys))
	for i, any := range anys {
		cached := any.GetCachedValue()
		if cached == nil {
			panic("Any cached value is nil. Transaction messages must be correctly packed Any values.")
		}
		res[i] = cached.(sdk.Msg)
	}
	return res
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
