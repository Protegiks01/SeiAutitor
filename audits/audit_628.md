# Audit Report

## Title
Fee Grant Message Filtering Bypass via Nested Messages in MsgExec

## Summary
The `AllowedMsgAllowance` fee grant validation only checks top-level message types and does not validate nested messages within `MsgExec` (from x/authz). This allows a grantee to bypass the message type restrictions by wrapping disallowed messages inside `MsgExec`, causing the granter's funds to be used for unauthorized message types.

## Impact
**Low** - Modification of transaction fees outside of design parameters

## Finding Description

**Location:** 
- Primary: `x/auth/ante/fee.go` [1](#0-0) 
- Secondary: `x/feegrant/filtered_fee.go` [2](#0-1) 
- Interface: `x/feegrant/keeper/keeper.go` [3](#0-2) 

**Intended Logic:** 
When a granter creates an `AllowedMsgAllowance`, they intend to restrict fee grant usage to specific message types listed in `allowed_messages`. The fee grant validation should reject any transaction containing message types not in this list. [4](#0-3) 

**Actual Logic:** 
The fee deduction decorator passes only top-level messages from `sdkTx.GetMsgs()` to the fee grant's `Accept()` method. [1](#0-0)  When a transaction contains `MsgExec` with nested messages, the validation only checks if `MsgExec` itself is in the allowed list, not the nested messages inside it. [5](#0-4)  The nested messages are extracted and executed later by the authz keeper [6](#0-5) , after fee validation has already passed.

**Exploit Scenario:**
1. Granter creates an `AllowedMsgAllowance` with `allowed_messages: ["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]` (including `MsgExec` to allow legitimate authz usage)
2. Grantee creates a transaction with `MsgExec` containing a nested `MsgDelegate` (or any other disallowed message type)
3. Fee grant validation calls `allMsgTypesAllowed(ctx, [MsgExec])` which returns true since `MsgExec` is allowed
4. Transaction passes validation and granter's funds pay the fees
5. The nested `MsgDelegate` executes successfully, bypassing the intended message type restriction

**Security Failure:** 
The authorization control for fee grant message filtering is bypassed. The granter's expectation that their funds will only pay fees for specific message types is violated, allowing the grantee to use the grant for any message type by wrapping it in `MsgExec`.

## Impact Explanation

This vulnerability allows a grantee to misuse a granter's fee allowance for message types the granter did not authorize. When a granter creates an `AllowedMsgAllowance` to restrict fee spending to specific operations (e.g., only bank transfers), they expect their funds to only be used for those purposes. By wrapping unauthorized messages in `MsgExec`, the grantee can execute any operation using the granter's fee grant.

**Affected Assets:**
- The granter's tokens allocated for fee grants are spent on unauthorized message types
- The integrity of the `AllowedMsgAllowance` access control mechanism is compromised

**Severity:**
While this doesn't result in direct theft or loss of principal funds, it causes the granter's fee budget to be consumed for unintended purposes, constituting a modification of transaction fees outside design parameters. The granter loses control over how their delegated fee budget is used.

## Likelihood Explanation

**Who can trigger it:**
Any grantee who has been granted an `AllowedMsgAllowance` that includes `MsgExec` in its allowed message list can exploit this vulnerability. This is a common scenario when granters want to allow both specific operations and authz-delegated operations.

**Conditions required:**
1. A fee grant must exist with `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list
2. The grantee must have a valid authz grant to execute the nested message on behalf of some granter
3. No additional rare conditions are required - this works during normal operation

**Frequency:**
This can be exploited any time a grantee has such a fee grant. Since including `MsgExec` in allowed messages is a reasonable configuration for enabling authz workflows, this vulnerability could be commonly exploitable in production deployments that use both feegrant and authz modules together.

## Recommendation

Modify the fee grant validation to recursively validate all nested messages within `MsgExec` (and any other message types that contain nested messages). Specifically:

1. In `x/auth/ante/fee.go`, extract nested messages from `MsgExec` before passing to `UseGrantedFees()`, or
2. In `x/feegrant/filtered_fee.go`, update `allMsgTypesAllowed()` to recursively check nested messages by detecting `MsgExec` types and calling their `GetMessages()` method to validate nested content

Example approach: Before validating with `allMsgTypesAllowed()`, expand any `MsgExec` messages to include their nested messages in the validation list. This ensures the `AllowedMsgAllowance` filtering applies to all messages that will actually execute, not just the top-level wrapper.

## Proof of Concept

**Test File:** `x/feegrant/filtered_fee_authz_test.go` (new file)

**Setup:**
1. Initialize a test app with feegrant and authz modules enabled
2. Create three accounts: granter (fee payer), grantee (transaction signer), and authzGranter (owner of delegated action)
3. Fund the granter account with sufficient tokens to pay fees
4. Create a validator for delegation testing
5. Grant an authz `SendAuthorization` from authzGranter to grantee for `MsgDelegate`
6. Grant an `AllowedMsgAllowance` from granter to grantee with allowed messages: `["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]`

**Trigger:**
1. Create a `MsgDelegate` from authzGranter to delegate tokens to the validator
2. Wrap this `MsgDelegate` inside a `MsgExec` signed by grantee
3. Create a transaction with the `MsgExec` as the only top-level message
4. Set the transaction's fee granter to be the granter account
5. Execute the transaction through the ante handler chain and message router

**Observation:**
The transaction should pass fee grant validation even though `MsgDelegate` is not in the allowed messages list. The test confirms the vulnerability by:
1. Verifying the fee grant's `Accept()` method succeeds (fees are deducted from granter)
2. Verifying the nested `MsgDelegate` executes successfully
3. Demonstrating that the granter's fee grant was used for a message type (MsgDelegate) not in their allowed list
4. The test should assert this behavior is incorrect by showing that direct `MsgDelegate` transactions without `MsgExec` wrapping are correctly rejected

This proves that `AllowedMsgAllowance` message filtering can be completely bypassed by wrapping disallowed messages in `MsgExec`, violating the intended access control mechanism for fee grants.

### Citations

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
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

**File:** x/authz/keeper/msg_server.go (L72-77)
```go
	msgs, err := msg.GetMessages()
	if err != nil {
		return nil, err
	}

	results, err := k.DispatchActions(ctx, grantee, msgs)
```
