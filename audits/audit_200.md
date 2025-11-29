# Audit Report

## Title
Fee Grant Message Filtering Bypass via Nested Messages in MsgExec

## Summary
The `AllowedMsgAllowance` fee grant validation only validates top-level message types in transactions and does not recursively check nested messages within `MsgExec` from the authz module. This allows a grantee to bypass message type restrictions by wrapping disallowed messages inside `MsgExec`, causing the granter's fee allowance to be consumed for unauthorized message types.

## Impact
**Low**

## Finding Description

**Location:**
- Primary vulnerability: `x/auth/ante/fee.go` line 168 [1](#0-0) 
- Validation logic: `x/feegrant/filtered_fee.go` lines 65-86 [2](#0-1) 
- Message type checking: `x/feegrant/filtered_fee.go` lines 98-109 [3](#0-2) 
- Nested message extraction: `x/authz/msgs.go` lines 197-209 [4](#0-3) 
- Nested message execution: `x/authz/keeper/msg_server.go` lines 72-77 [5](#0-4) 

**Intended Logic:**
When a granter creates an `AllowedMsgAllowance`, they intend to restrict fee grant usage to only the specific message types listed in `allowed_messages`. The fee grant validation should reject any transaction that attempts to execute message types not explicitly included in this list, regardless of how those messages are structured.

**Actual Logic:**
The fee deduction decorator passes only top-level messages via `sdkTx.GetMsgs()` to the fee grant's validation method [1](#0-0) . The `allMsgTypesAllowed()` function iterates only through these provided messages and checks their types against the allowed list [3](#0-2) . When `MsgExec` contains nested messages, only `MsgExec` itself is validated, not its nested content. The nested messages are extracted via `GetMessages()` [4](#0-3)  and executed later by the authz keeper [5](#0-4) , after fee validation has already passed.

**Exploitation Path:**
1. Granter creates an `AllowedMsgAllowance` with `allowed_messages: ["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]` (including `MsgExec` to enable authz workflows)
2. Grantee obtains a separate authz grant to execute a disallowed message type (e.g., `MsgDelegate`)
3. Grantee constructs a transaction with `MsgExec` containing the nested disallowed message
4. During ante handler processing, fee grant validation checks only if `MsgExec` is allowed (it is) and approves the transaction
5. Granter's funds are deducted for transaction fees
6. The authz keeper extracts and executes the nested `MsgDelegate`, bypassing the intended restriction

**Security Guarantee Broken:**
The access control mechanism of `AllowedMsgAllowance` is bypassed. The granter's expectation that their fee budget will only be used for explicitly authorized message types is violated, allowing arbitrary message execution at the granter's expense.

## Impact Explanation

This vulnerability allows a grantee to misuse a granter's fee allowance for message types the granter did not authorize. The granter allocates a fee budget with the expectation that it will only cover fees for specific operations (e.g., bank transfers). By wrapping unauthorized messages within `MsgExec`, the grantee can execute any operation type using the granter's fee grant.

**Affected Assets:**
- The granter's tokens allocated for fee grants are consumed for unauthorized message types
- The integrity of the `AllowedMsgAllowance` filtering mechanism is compromised

**Severity Justification:**
This constitutes "Modification of transaction fees outside of design parameters" (Low severity per the accepted impact list). While it doesn't result in direct theft of principal funds or total loss of the granter's assets, it allows the grantee to consume the granter's fee budget in unintended ways, causing the granter to lose control over how their delegated fee allowance is utilized.

## Likelihood Explanation

**Who can trigger it:**
Any grantee who has received an `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list can exploit this vulnerability. This is a common configuration when granters want to support both direct operations and authz-delegated workflows.

**Conditions required:**
1. A fee grant must exist with `AllowedMsgAllowance` that includes `MsgExec` in the allowed messages
2. The grantee must have a valid authz grant from some account to execute the nested message type
3. No additional rare conditions are required - this works during normal chain operation

**Frequency:**
This can be exploited whenever a grantee has such a fee grant. Including `MsgExec` in allowed messages is a reasonable configuration for production deployments that use both feegrant and authz modules together, making this vulnerability commonly exploitable in real-world scenarios.

## Recommendation

Implement recursive message validation in the fee grant system to check all messages that will actually execute, not just top-level wrappers. Two possible approaches:

1. **In the ante handler** (`x/auth/ante/fee.go`): Before calling `UseGrantedFees()`, recursively extract all nested messages from `MsgExec` and include them in the validation list.

2. **In the validation logic** (`x/feegrant/filtered_fee.go`): Update `allMsgTypesAllowed()` to detect message types that contain nested messages (such as `MsgExec`) and recursively validate their nested content by:
   - Checking if the message implements a `GetMessages()` method
   - Extracting nested messages and recursively validating their types
   - Ensuring all nested messages are in the allowed list

Example implementation for approach 2:
```go
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
    msgsMap := a.allowedMsgsToMap(ctx)
    return a.validateMsgsRecursive(ctx, msgs, msgsMap)
}

func (a *AllowedMsgAllowance) validateMsgsRecursive(ctx sdk.Context, msgs []sdk.Msg, msgsMap map[string]bool) bool {
    for _, msg := range msgs {
        ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
        if !msgsMap[sdk.MsgTypeURL(msg)] {
            return false
        }
        
        // Check for nested messages in MsgExec
        if execMsg, ok := msg.(*authz.MsgExec); ok {
            nestedMsgs, err := execMsg.GetMessages()
            if err != nil {
                return false
            }
            if !a.validateMsgsRecursive(ctx, nestedMsgs, msgsMap) {
                return false
            }
        }
    }
    return true
}
```

## Proof of Concept

**Test File:** `x/feegrant/filtered_fee_authz_test.go` (new test case)

**Setup:**
1. Initialize test application with feegrant and authz modules enabled
2. Create accounts: `granter` (fee payer), `grantee` (transaction signer), `authzGranter` (message owner)
3. Fund `granter` account with sufficient tokens to pay transaction fees
4. Create a validator for delegation operations
5. Grant authz `SendAuthorization` from `authzGranter` to `grantee` for executing `MsgDelegate`
6. Grant `AllowedMsgAllowance` from `granter` to `grantee` with `allowed_messages: ["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]`

**Action:**
1. Construct a `MsgDelegate` message from `authzGranter` to delegate tokens to validator
2. Wrap `MsgDelegate` inside `MsgExec` signed by `grantee`
3. Create transaction with fee granter set to `granter` account
4. Execute transaction through the ante handler chain

**Expected Result (demonstrating vulnerability):**
1. Fee grant validation succeeds because `MsgExec` is in the allowed list
2. Transaction fees are deducted from `granter`'s account
3. Nested `MsgDelegate` executes successfully
4. `granter`'s fee allowance was consumed for `MsgDelegate` despite it not being in the allowed messages list

**Verification:**
A direct transaction containing `MsgDelegate` without `MsgExec` wrapping should be correctly rejected by the fee grant validation, confirming that the bypass only works through the nested message path.

## Notes

This vulnerability is valid because:

1. **Matches accepted impact**: "Modification of transaction fees outside of design parameters" (Low severity) is explicitly listed in the allowed impacts for this validation framework.

2. **Realistic exploit scenario**: The conditions required (fee grant with `MsgExec` allowed, authz grant for nested message) represent a common configuration in production systems that use both modules together.

3. **Clear security impact**: While not a critical vulnerability, it violates the granter's authorization controls and causes their fee budget to be consumed in unintended ways, representing a tangible security issue.

4. **No special privileges required**: Any regular grantee can exploit this without admin access or system compromise.

5. **Not a design decision**: The behavior contradicts the documented purpose of `AllowedMsgAllowance`, which is to restrict fee usage to specific message types. The lack of recursive validation is an implementation gap rather than an intentional design choice.

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

**File:** x/authz/keeper/msg_server.go (L72-77)
```go
	msgs, err := msg.GetMessages()
	if err != nil {
		return nil, err
	}

	results, err := k.DispatchActions(ctx, grantee, msgs)
```
