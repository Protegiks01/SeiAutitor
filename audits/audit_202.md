# Audit Report

## Title
Fee Grant Bypass via Authz MsgExec - AllowedMsgAllowance Validation Only Checks Outer Message

## Summary
The feegrant module's `AllowedMsgAllowance` validates message types based on the outer transaction messages, not the inner messages contained within an authz `MsgExec`. This allows a grantee to bypass message type restrictions and have a fee granter pay fees for unauthorized actions executed on behalf of other accounts via authz delegation.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Validation logic: [2](#0-1) 
- Message extraction: [3](#0-2) 

**Intended Logic:** 
When a fee granter creates an `AllowedMsgAllowance`, they specify which message types the grantee can execute using their fee grant. The feegrant module should validate that all messages in a transaction match the allowed message types before deducting fees from the granter's account.

**Actual Logic:** 
The fee deduction ante handler calls `UseGrantedFees` with `sdkTx.GetMsgs()`, which only returns the top-level transaction messages. When the transaction contains a `MsgExec` (authz module), the validation in `AllowedMsgAllowance.Accept` only checks if `MsgExec` itself is in the allowed list, completely ignoring the inner messages that will actually be executed via the authz dispatch mechanism.

The vulnerability occurs because:
1. [1](#0-0)  passes `sdkTx.GetMsgs()` to feegrant validation
2. For a `MsgExec` transaction, this only returns `[MsgExec]`, not the inner messages
3. [4](#0-3)  validates only these outer messages
4. The inner messages in `MsgExec` are executed later in [5](#0-4)  but never validated by feegrant

**Exploit Scenario:**
1. Alice grants Bob a feegrant with `AllowedMsgAllowance` allowing only `["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]`
2. Charlie grants Bob authz permission to execute `MsgBurn` on Charlie's behalf
3. Bob creates a transaction with:
   - FeeGranter: Alice
   - Message: `MsgExec` containing `MsgBurn` (to burn Charlie's tokens)
4. The feegrant validation sees `MsgExec` (allowed) and approves
5. Alice's account pays the fees
6. The `MsgBurn` executes via authz dispatch
7. Alice paid fees for burning Charlie's tokens, which she never authorized

**Security Failure:** 
Authorization bypass - the fee granter's message type restrictions are circumvented, allowing unauthorized fee spending for arbitrary actions executed via authz delegation.

## Impact Explanation

**Assets Affected:** Fee granter's token balance (direct loss of funds through unauthorized fee deduction)

**Severity of Damage:** 
- Fee granters lose funds paying for transactions they did not authorize
- The entire purpose of `AllowedMsgAllowance` is defeated - granters cannot restrict which message types consume their fee grants
- Attackers can systematically drain fee grants by routing unauthorized actions through `MsgExec`
- Multiple grantees can collaborate: one provides authz, another has the fee grant, allowing complex exploitation chains

**System Impact:**
This fundamentally breaks the security model of the feegrant module's message filtering capability, making `AllowedMsgAllowance` ineffective for its intended purpose of restricting fee grant usage to specific message types.

## Likelihood Explanation

**Who Can Trigger:** Any user who has both:
1. A fee grant with `AllowedMsgAllowance` that includes `MsgExec`
2. Authz permissions from any other account

**Conditions Required:**
- Normal operation - no special network conditions needed
- The fee granter must have included `MsgExec` in their allowed messages list (which is reasonable if they want the grantee to use authz features)
- The grantee must have authz grants from other accounts

**Frequency:**
This can be exploited repeatedly until the fee grant is exhausted. Each transaction drains fees from the granter for unauthorized message types. The exploit is deterministic and requires no special timing or race conditions.

## Recommendation

Modify the fee grant validation to recursively validate inner messages within `MsgExec`. Specifically:

1. In [6](#0-5) , extract and validate all messages including those nested in `MsgExec`
2. Add a helper function to recursively extract messages from `MsgExec`:
   ```
   func extractAllMessages(msgs []sdk.Msg) []sdk.Msg {
       allMsgs := []sdk.Msg{}
       for _, msg := range msgs {
           allMsgs = append(allMsgs, msg)
           if execMsg, ok := msg.(*authz.MsgExec); ok {
               innerMsgs, _ := execMsg.GetMessages()
               allMsgs = append(allMsgs, extractAllMessages(innerMsgs)...)
           }
       }
       return allMsgs
   }
   ```
3. Pass all extracted messages (including nested ones) to `UseGrantedFees` for validation

This ensures that `AllowedMsgAllowance` validates the actual messages being executed, not just the outer wrapper.

## Proof of Concept

**File:** `x/auth/ante/feegrant_authz_test.go` (new test file)

**Test Function:** `TestFeeGrantBypassViaAuthzMsgExec`

**Setup:**
1. Initialize SimApp with three accounts: Alice (fee granter), Bob (grantee), Charlie (authz granter)
2. Fund Alice and Charlie with tokens
3. Alice grants Bob a feegrant with `AllowedMsgAllowance` allowing `[MsgSend, MsgExec]`
4. Charlie grants Bob authz to execute `MsgBurn` on Charlie's behalf
5. Record Alice's initial balance

**Trigger:**
1. Bob creates a `MsgExec` containing a `MsgBurn` message (burning Charlie's tokens)
2. Bob sets Alice as the FeeGranter in the transaction
3. Submit the transaction through the ante handler chain

**Observation:**
The test observes that:
1. The transaction succeeds (ante handler does not reject it)
2. Alice's balance decreases by the fee amount (she paid fees)
3. Charlie's tokens are burned (the inner message executed)
4. Alice paid fees for `MsgBurn`, which was NOT in her allowed message list

This demonstrates that Alice's `AllowedMsgAllowance` restriction was bypassed, causing her to pay fees for an unauthorized message type. The vulnerability allows the fee grant's message type restrictions to be circumvented via `MsgExec`.

**Test Code Structure:**
```
func TestFeeGrantBypassViaAuthzMsgExec(t *testing.T) {
    // Setup accounts and app
    // Grant feegrant from Alice to Bob (allowing MsgSend, MsgExec)
    // Grant authz from Charlie to Bob (allowing MsgBurn)
    // Record Alice's initial balance
    
    // Create MsgExec containing MsgBurn
    // Set Alice as FeeGranter
    // Execute through ante handler
    
    // Assert: Transaction succeeds
    // Assert: Alice paid fees (balance decreased)
    // Assert: MsgBurn was NOT in Alice's allowed messages
    // This proves the bypass vulnerability
}
```

The test will pass on the vulnerable code (demonstrating the exploit works) and should fail after applying the recommended fix (proving the fix prevents the bypass).

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
