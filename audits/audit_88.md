# Audit Report

## Title
Message Filtering Bypass in AllowedMsgAllowance via MsgExec Wrapping

## Summary
The `AllowedMsgAllowance` fee grant filtering mechanism in the feegrant module only validates top-level message types and does not recursively inspect nested messages within `MsgExec`. This allows grantees to consume fee allowances for message types that granters did not authorize, violating the documented security guarantee that all messages must conform to the filter.

## Impact
Low

## Finding Description

- **location:** `x/feegrant/filtered_fee.go`, lines 98-109 in the `allMsgTypesAllowed()` method [1](#0-0) 

- **intended logic:** According to the module specification, the SDK should "iterate over the messages being sent by the grantee to ensure the messages adhere to the filter" and "stop iterating and fail the transaction if it finds a message that does not conform to the filter." [2](#0-1)  The proto documentation states `AllowedMsgAllowance` "creates allowance only for specified message types." [3](#0-2) 

- **actual logic:** The `allMsgTypesAllowed()` method only iterates through top-level messages and checks their type URLs against the allowed list. It does not recursively inspect nested messages within `MsgExec`. The ante handler passes only top-level messages via `sdkTx.GetMsgs()` to the fee grant validation. [4](#0-3) 

- **exploitation path:**
  1. Granter creates an `AllowedMsgAllowance` with specific allowed message types (e.g., `/cosmos.bank.v1beta1.MsgSend`)
  2. Granter includes `/cosmos.authz.v1beta1.MsgExec` in the allowed list for legitimate authz use cases
  3. Grantee constructs a `MsgExec` that wraps disallowed messages (e.g., `/cosmos.staking.v1beta1.MsgDelegate`)
  4. During ante handler execution, only the outer `MsgExec` type is validated, which passes the filter check
  5. The transaction proceeds to execution phase where `MsgExec.GetMessages()` extracts the wrapped messages [5](#0-4) 
  6. The inner disallowed messages are executed via `DispatchActions()` using the fee grant [6](#0-5) 

- **security guarantee broken:** The documented guarantee that "all messages must conform to the filter" is violated. The system fails to enforce message type restrictions for nested messages within `MsgExec`, allowing fee consumption for unauthorized message types.

## Impact Explanation

This vulnerability allows grantees to consume fee allowances for message types that granters did not intend to authorize. Fee grants can be depleted for operations like staking, governance, or IBC transfers when only basic transfers were intended. While the grantee still needs valid authz authorization for the inner messages (preventing completely arbitrary operations), the granter's trust model and fee budget restrictions are violated. This constitutes "modification of transaction fees outside of design parameters" as classified in the Low severity impact category.

## Likelihood Explanation

The vulnerability can be exploited whenever:
- A granter includes `MsgExec` in their allowed messages list (a reasonable choice for legitimate authz use cases)
- A grantee has both a fee grant and authz authorization for the desired inner messages

Granters may not realize that allowing `MsgExec` effectively bypasses all message filtering, as this behavior contradicts the documented specification that promises all messages will be validated. The exploit requires no special privileges beyond being a grantee and is repeatable until the fee grant is exhausted. No existing tests cover this nested message scenario. [7](#0-6) 

## Recommendation

Modify the `allMsgTypesAllowed()` method in `x/feegrant/filtered_fee.go` to recursively validate nested messages when encountering `MsgExec`:

1. Detect `MsgExec` messages during iteration by checking the message type URL
2. Extract inner messages using the `GetMessages()` method
3. Recursively validate inner messages against the allowed list
4. Handle nested `MsgExec` scenarios through recursion

The fix should consume appropriate gas for each nested message checked (following the existing pattern of 10 gas per message) and reject transactions containing any disallowed nested message types.

## Proof of Concept

**Scenario:**
- **Setup:** Granter creates `AllowedMsgAllowance` for grantee with allowed messages: `["/cosmos.bank.v1beta1.MsgSend", "/cosmos.authz.v1beta1.MsgExec"]`. Grantee has authz authorization for `/cosmos.staking.v1beta1.MsgDelegate` from another account.

- **Action:** Grantee submits transaction with:
  - Fee granter set to the granter's address
  - Messages: `[MsgExec{ Grantee: grantee, Msgs: [MsgDelegate{...}] }]`
  
- **Result:** 
  - The ante handler calls `allMsgTypesAllowed()` with `[MsgExec]` (top-level only)
  - Validation passes because `MsgExec` is in the allowed list
  - Fee grant is accepted and consumed
  - During execution, `MsgDelegate` is extracted and executed
  - The disallowed `MsgDelegate` message executes using the fee grant, despite not being in the granter's allowed message list

This demonstrates that the filtering mechanism fails to enforce restrictions on nested messages, violating the documented security guarantee and the granter's intended fee budget restrictions.

## Notes

The vulnerability is valid because:
1. It matches the explicitly listed impact "Modification of transaction fees outside of design parameters" (Low severity)
2. The code flow demonstrates that fee grant validation only checks top-level messages in the ante handler
3. The documented specification promises that all messages will be validated, but this is violated for nested messages
4. The exploitation path is realistic and requires no special privileges beyond being a grantee with authz authorization
5. The granter's fee budget policy is bypassed, allowing consumption for unauthorized message types

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

**File:** x/feegrant/spec/01_concepts.md (L76-76)
```markdown
In order to prevent DoS attacks, using a filtered `x/feegrant` incurs gas. The SDK must assure that the `grantee`'s transactions all conform to the filter set by the `granter`. The SDK does this by iterating over the allowed messages in the filter and charging 10 gas per filtered message. The SDK will then iterate over the messages being sent by the `grantee` to ensure the messages adhere to the filter, also charging 10 gas per message. The SDK will stop iterating and fail the transaction if it finds a message that does not conform to the filter.
```

**File:** proto/cosmos/feegrant/v1beta1/feegrant.proto (L56-66)
```text
// AllowedMsgAllowance creates allowance only for specified message types.
message AllowedMsgAllowance {
  option (gogoproto.goproto_getters)         = false;
  option (cosmos_proto.implements_interface) = "FeeAllowanceI";

  // allowance can be any of basic and filtered fee allowance.
  google.protobuf.Any allowance = 1 [(cosmos_proto.accepts_interface) = "FeeAllowanceI"];

  // allowed_messages are the messages for which the grantee has the access.
  repeated string allowed_messages = 2;
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

**File:** x/authz/keeper/msg_server.go (L65-82)
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
```

**File:** x/feegrant/filtered_fee_test.go (L1-100)
```go
package feegrant_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/simapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
)

func TestFilteredFeeValidAllow(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{
		Time: time.Now(),
	})

	eth := sdk.NewCoins(sdk.NewInt64Coin("eth", 10))
	atom := sdk.NewCoins(sdk.NewInt64Coin("atom", 555))
	smallAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 43))
	bigAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 1000))
	leftAtom := bigAtom.Sub(smallAtom)
	now := ctx.BlockTime()
	oneHour := now.Add(1 * time.Hour)
	from := sdk.MustAccAddressFromBech32("cosmos18cgkqduwuh253twzmhedesw3l7v3fm37sppt58")
	to := sdk.MustAccAddressFromBech32("cosmos1yq8lgssgxlx9smjhes6ryjasmqmd3ts2559g0t")

	// small fee without expire
	msgType := "/cosmos.bank.v1beta1.MsgSend"
	any, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: bigAtom,
	})

	// all fee without expire
	any2, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: smallAtom,
	})

	// wrong fee
	any3, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: bigAtom,
	})

	// wrong fee
	any4, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: bigAtom,
	})

	// expired
	any5, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: bigAtom,
		Expiration: &now,
	})

	// few more than allowed
	any6, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: atom,
		Expiration: &now,
	})

	// with out spend limit
	any7, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		Expiration: &oneHour,
	})

	// expired no spend limit
	any8, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		Expiration: &now,
	})

	// msg type not allowed
	msgType2 := "/cosmos.ibc.applications.transfer.v1.MsgTransfer"
	any9, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		Expiration: &now,
	})

	cases := map[string]struct {
		allowance *feegrant.AllowedMsgAllowance
		msgs      []sdk.Msg
		fee       sdk.Coins
		blockTime time.Time
		valid     bool
		accept    bool
		remove    bool
		remains   sdk.Coins
	}{
		"small fee without expire": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any,
				AllowedMessages: []string{msgType},
			},
			msgs: []sdk.Msg{&banktypes.MsgSend{
				FromAddress: from.String(),
				ToAddress:   to.String(),
```
