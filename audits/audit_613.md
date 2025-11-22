## Audit Report

### Title
AllowedMsgAllowance Message Type Filter Bypass via Nested Messages in MsgExec

### Summary
The `allMsgTypesAllowed` function in the feegrant module only validates top-level message types and does not recursively check nested messages within composite messages like `MsgExec`. This allows attackers to bypass fee allowance message type restrictions by wrapping unauthorized messages inside authorized composite messages.

### Impact
**Medium**

### Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `AllowedMsgAllowance` type is designed to restrict fee allowances to specific message types defined in the `AllowedMessages` list. When a transaction uses a fee grant, the system should validate that ALL messages in the transaction (including nested messages) are in the allowed list before accepting the fee payment.

**Actual Logic:** 
The `allMsgTypesAllowed` function only iterates through the top-level messages passed in the `msgs` parameter and checks each message's type URL against the allowed list. It does not recursively inspect composite messages like `MsgExec` that contain nested messages within them.

The flow works as follows:
1. During ante handler execution, `UseGrantedFees` is called with `sdkTx.GetMsgs()` [2](#0-1) 
2. `GetMsgs()` returns only the transaction's top-level messages [3](#0-2) 
3. The `allMsgTypesAllowed` check validates only these top-level message types
4. Later during execution, `MsgExec.GetMessages()` extracts nested messages [4](#0-3) 
5. These nested messages are dispatched for execution without being validated against the fee allowance's allowed messages list [5](#0-4) 

**Exploit Scenario:**
1. Attacker convinces a granter to create a fee allowance with `AllowedMessages = ["/cosmos.authz.v1beta1.MsgExec"]` only
2. Attacker creates a transaction containing a `MsgExec` with nested unauthorized messages (e.g., `MsgSend`, `MsgDelegate`, etc.)
3. Attacker submits the transaction using the fee granter
4. The `allMsgTypesAllowed` validation passes because it only sees the outer `MsgExec` message
5. During execution, the nested unauthorized messages are extracted and executed
6. The attacker successfully executes messages that should have been blocked by the allowance filter

**Security Failure:** 
This breaks the authorization invariant that fee allowances can restrict which message types are permitted. The security boundary intended by `AllowedMsgAllowance` is completely bypassed, allowing execution of arbitrary messages under the guise of authorized composite messages.

### Impact Explanation

**Affected Components:**
- Fee allowance authorization system
- Message type filtering security boundary
- Granter's intent enforcement

**Severity:**
While this does not directly cause loss of funds (the granter still pays the fees they committed to), it violates a critical security property:
- Granters explicitly configure allowed message types to limit how their fee grants can be used
- This restriction can be completely bypassed by wrapping unauthorized messages in `MsgExec`
- The granter's account could be used to pay fees for operations they explicitly did not authorize
- This constitutes "unintended smart contract behavior" as the allowance filtering mechanism does not work as designed

This fits the **Medium** severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"

### Likelihood Explanation

**Triggerable By:** Any unprivileged network participant who can obtain a fee allowance

**Conditions Required:**
- A granter creates an `AllowedMsgAllowance` that includes `MsgExec` in the allowed messages list
- The attacker has authorization to execute messages on behalf of others (via authz module)
- No special privileges, timing, or rare conditions required

**Frequency:** 
This can be exploited repeatedly for any fee allowance that includes `MsgExec` as an allowed message type. The vulnerability is deterministic and can be triggered at will during normal network operation.

### Recommendation

The `allMsgTypesAllowed` function should recursively validate nested messages within composite messages. Specifically:

1. Add a recursive message extraction function that handles composite message types like `MsgExec`
2. Modify `allMsgTypesAllowed` to recursively check all messages, including nested ones
3. For `MsgExec`, call `GetMessages()` to extract nested messages and validate them recursively
4. Apply similar logic for any other composite message types that may contain nested messages

Example fix approach:
```
func (a *AllowedMsgAllowance) allMsgTypesAllowed(ctx sdk.Context, msgs []sdk.Msg) bool {
    msgsMap := a.allowedMsgsToMap(ctx)
    return a.checkMsgsRecursive(ctx, msgs, msgsMap)
}

func (a *AllowedMsgAllowance) checkMsgsRecursive(ctx sdk.Context, msgs []sdk.Msg, msgsMap map[string]bool) bool {
    for _, msg := range msgs {
        ctx.GasMeter().ConsumeGas(gasCostPerIteration, "check msg")
        if !msgsMap[sdk.MsgTypeURL(msg)] {
            return false
        }
        
        // Check for nested messages in MsgExec
        if msgExec, ok := msg.(*authz.MsgExec); ok {
            nestedMsgs, err := msgExec.GetMessages()
            if err != nil {
                return false
            }
            if !a.checkMsgsRecursive(ctx, nestedMsgs, msgsMap) {
                return false
            }
        }
    }
    return true
}
```

### Proof of Concept

**Test File:** `x/feegrant/filtered_fee_test.go`

**Test Function:** `TestFilteredFeeNestedMsgBypass`

**Setup:**
1. Initialize a SimApp test environment with blockchain context
2. Create three test addresses: granter, grantee, and recipient
3. Fund the granter account with tokens
4. Create an `AllowedMsgAllowance` that ONLY allows `/cosmos.authz.v1beta1.MsgExec` (specifically excluding `/cosmos.bank.v1beta1.MsgSend`)
5. Grant this fee allowance from granter to grantee

**Trigger:**
1. Create a `MsgSend` that transfers tokens from granter to recipient (this message type is NOT in the allowed list)
2. Wrap the `MsgSend` inside a `MsgExec` message
3. Call `Accept()` on the `AllowedMsgAllowance` with the `MsgExec` as the top-level message

**Observation:**
The test demonstrates that:
1. `Accept()` returns `true` (no error), indicating the fee allowance accepted the message
2. The `MsgExec` passes validation because it's in the allowed messages list
3. The nested `MsgSend` is never validated against the allowed messages list
4. This proves the vulnerability: unauthorized message types can be executed by wrapping them in authorized composite messages

**Expected Behavior:** The `Accept()` call should fail because the nested `MsgSend` is not in the allowed messages list.

**Actual Behavior:** The `Accept()` call succeeds, allowing the bypass.

The test code structure:
```go
func TestFilteredFeeNestedMsgBypass(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Time: time.Now()})
    
    granter := sdk.AccAddress("granter_address___")
    grantee := sdk.AccAddress("grantee_address___")
    recipient := sdk.AccAddress("recipient_address_")
    
    // Create allowance that ONLY allows MsgExec (NOT MsgSend)
    allowedMessages := []string{"/cosmos.authz.v1beta1.MsgExec"}
    basicAllowance := &feegrant.BasicAllowance{
        SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("stake", 1000)),
    }
    any, _ := types.NewAnyWithValue(basicAllowance)
    allowance := &feegrant.AllowedMsgAllowance{
        Allowance:       any,
        AllowedMessages: allowedMessages,
    }
    
    // Create a MsgSend (which is NOT in allowed messages)
    unauthorizedMsg := &banktypes.MsgSend{
        FromAddress: granter.String(),
        ToAddress:   recipient.String(),
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
    }
    
    // Wrap it in MsgExec (which IS in allowed messages)
    msgExec := authz.NewMsgExec(grantee, []sdk.Msg{unauthorizedMsg})
    
    // Test: The Accept should reject because nested MsgSend is not allowed
    // But it actually passes, demonstrating the vulnerability
    fee := sdk.NewCoins(sdk.NewInt64Coin("stake", 10))
    remove, err := allowance.Accept(ctx, fee, []sdk.Msg{&msgExec})
    
    // This assertion SHOULD pass (err should not be nil) but it fails
    // demonstrating that the nested message is not validated
    require.Error(t, err, "Should reject nested unauthorized message")
    require.False(t, remove)
}
```

This PoC can be added to `x/feegrant/filtered_fee_test.go` and will demonstrate that the current implementation incorrectly allows nested unauthorized messages to bypass the allowance filter.

### Citations

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

**File:** types/tx_msg.go (L41-41)
```go
		GetMsgs() []Msg
```

**File:** x/authz/msgs.go (L198-209)
```go
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
