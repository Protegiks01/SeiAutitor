# Audit Report

## Title
AllowedMsgAllowance Bypass via Nested MsgExec Messages

## Summary
The `AllowedMsgAllowance` feegrant restriction can be bypassed by wrapping disallowed message types inside an authz `MsgExec`. The AnteHandler only validates top-level messages, allowing unauthorized message types to execute while using a restricted feegrant to pay fees.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
The `AllowedMsgAllowance` should restrict feegrants to only pay fees for specific message types. When a granter creates a feegrant with specific allowed message type URLs, the system should reject any transaction attempting to use this feegrant for unauthorized message types, including nested messages within wrapper types like `MsgExec`.

**Actual Logic:**
The `DeductFeeDecorator` calls `UseGrantedFees` with only top-level messages obtained via `sdkTx.GetMsgs()`. [1](#0-0)  This method returns messages from `t.Body.Messages` without extracting nested messages from `MsgExec`. [3](#0-2)  The `allMsgTypesAllowed` validation only checks these top-level message types against the allowed list. [4](#0-3)  Nested messages within `MsgExec` are never validated against the feegrant allowance during the ante handler phase.

**Exploitation Path:**
1. Grantee obtains a feegrant with `AllowedMsgAllowance` that includes `/cosmos.authz.v1beta1.MsgExec` in the allowed messages list
2. Grantee creates a transaction containing a `MsgExec` message where they are the grantee
3. Inside the `MsgExec`, the grantee wraps any disallowed message type (e.g., `/cosmos.bank.v1beta1.MsgSend`) where they are also the signer
4. AnteHandler validates only the top-level `MsgExec` against the feegrant allowance and approves it
5. Fees are deducted from the feegrant using `UseGrantedFees` [5](#0-4) 
6. During execution, `DispatchActions` implicitly accepts the nested message since the signer equals the grantee [6](#0-5) 
7. The disallowed nested message executes successfully using the feegrant to pay fees

**Security Guarantee Broken:**
The message type restriction mechanism in feegrant authorization is completely bypassed. The guarantee that feegrant funds will only be used for explicitly approved message types is circumvented for any nested messages within `MsgExec`.

## Impact Explanation

This vulnerability enables unauthorized usage of feegrant balances for transaction types outside the granter's intended restrictions. The granter loses control over how their allocated funds are spent, potentially allowing complete exhaustion of the feegrant balance for any message type where the grantee is the signer.

This breaks the trust model of restricted feegrants, which are specifically designed for limited delegation scenarios (e.g., allowing governance voting but preventing token transfers). While the funds are technically still used for fees (their intended purpose), they're applied to unauthorized transaction types, representing a loss of control over the granter's allocated resources.

This qualifies as "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity) from the impact criteria, as it results in unintended authorization bypass behavior within the Cosmos SDK's feegrant system.

## Likelihood Explanation

**Likelihood: High**

The vulnerability can be exploited by any grantee whose feegrant includes `MsgExec` in the allowed messages list. Required conditions:
- Granter creates an `AllowedMsgAllowance` including `/cosmos.authz.v1beta1.MsgExec` in the allowed messages
- No additional authz grant is required due to implicit acceptance when signer equals grantee [6](#0-5) 

The exploit is straightforward and requires no special privileges beyond possession of the feegrant. Granters might reasonably include `MsgExec` in allowed lists without understanding the nested message implications, making this highly likely to occur in practice. The existing test suite [7](#0-6)  does not include any tests for nested message validation, indicating this scenario was not considered during development.

## Recommendation

Modify the `AllowedMsgAllowance.Accept` method to recursively validate nested messages within `MsgExec`:

1. Update `allMsgTypesAllowed` to detect `MsgExec` message types
2. For each `MsgExec`, call its `GetMessages()` method to extract nested messages [8](#0-7) 
3. Recursively validate all nested messages against the allowed messages list
4. Reject the transaction if any nested message type is not in the allowed list

Alternative mitigation: Document that including `MsgExec` in `AllowedMessages` effectively allows all message types where the grantee is the signer, and warn granters about this implication.

## Proof of Concept

**Test Location:** `x/feegrant/filtered_fee_test.go` (new test to be added)

**Setup:**
- Create a feegrant with `AllowedMsgAllowance` restricting to only `/cosmos.gov.v1beta1.MsgVote` and `/cosmos.authz.v1beta1.MsgExec`
- Create accounts for granter and grantee
- Fund granter account with sufficient balance
- Grant the allowance from granter to grantee using `GrantAllowance`

**Action:**
- Test 1: Create transaction with direct `MsgSend` from grantee using the feegrant - should be rejected
- Test 2: Create transaction with `MsgExec` (grantee as executor) wrapping `MsgSend` (grantee as signer) using the feegrant

**Result:**
- Test 1: Validation correctly rejects with "message does not exist in allowed messages" error
- Test 2: The `MsgExec` wrapping the disallowed `MsgSend` passes feegrant validation during the ante handler check. The nested `MsgSend` is never validated against the feegrant allowance, demonstrating the bypass. The feegrant balance is depleted for an unauthorized message type.

## Notes

The vulnerability relies on two key implementation details:

1. **Top-level message validation only**: The `GetMsgs()` method only returns top-level transaction messages without recursively extracting nested messages from wrapper types like `MsgExec`. [3](#0-2) 

2. **Implicit authorization acceptance**: The `DispatchActions` logic implicitly accepts messages when the signer equals the grantee, meaning no separate authz grant is required for the grantee to execute messages on their own behalf through `MsgExec`. [6](#0-5) 

These two behaviors combine to create the bypass: the feegrant check passes because only `MsgExec` is validated, and the nested messages execute without requiring authorization because the grantee is executing their own messages.

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

**File:** types/tx/types.go (L22-36)
```go
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

**File:** x/authz/keeper/keeper.go (L87-111)
```go
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
```

**File:** x/feegrant/filtered_fee_test.go (L1-281)
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
				Amount:      bigAtom,
			}},
			fee:     smallAtom,
			accept:  true,
			remove:  false,
			remains: leftAtom,
		},
		"all fee without expire": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any2,
				AllowedMessages: []string{msgType},
			},
			fee:    smallAtom,
			accept: true,
			remove: true,
		},
		"wrong fee": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any3,
				AllowedMessages: []string{msgType},
			},
			fee:    eth,
			accept: false,
		},
		"non-expired": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any4,
				AllowedMessages: []string{msgType},
			},
			valid:     true,
			fee:       smallAtom,
			blockTime: now,
			accept:    true,
			remove:    false,
			remains:   leftAtom,
		},
		"expired": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any5,
				AllowedMessages: []string{msgType},
			},
			valid:     true,
			fee:       smallAtom,
			blockTime: oneHour,
			accept:    false,
			remove:    true,
		},
		"fee more than allowed": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any6,
				AllowedMessages: []string{msgType},
			},
			valid:     true,
			fee:       bigAtom,
			blockTime: now,
			accept:    false,
		},
		"with out spend limit": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any7,
				AllowedMessages: []string{msgType},
			},
			valid:     true,
			fee:       bigAtom,
			blockTime: now,
			accept:    true,
		},
		"expired no spend limit": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any8,
				AllowedMessages: []string{msgType},
			},
			valid:     true,
			fee:       bigAtom,
			blockTime: oneHour,
			accept:    false,
		},
		"msg type not allowed": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       any9,
				AllowedMessages: []string{msgType2},
			},
			msgs: []sdk.Msg{&banktypes.MsgSend{
				FromAddress: from.String(),
				ToAddress:   to.String(),
				Amount:      bigAtom,
			}},
			valid:  true,
			fee:    bigAtom,
			accept: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.allowance.ValidateBasic()
			require.NoError(t, err)

			ctx := app.BaseApp.NewContext(false, tmproto.Header{}).WithBlockTime(tc.blockTime)

			removed, err := tc.allowance.Accept(ctx, tc.fee, tc.msgs)
			if !tc.accept {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tc.remove, removed)
			if !removed {
				allowance, _ := tc.allowance.GetAllowance()
				assert.Equal(t, tc.remains, allowance.(*feegrant.BasicAllowance).SpendLimit)
			}
		})
	}
}

func TestFilteredFeeValidAllowance(t *testing.T) {
	app := simapp.Setup(false)

	smallAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 488))
	bigAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 1000))
	leftAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 512))

	basicAllowance, _ := types.NewAnyWithValue(&feegrant.BasicAllowance{
		SpendLimit: bigAtom,
	})

	cases := map[string]struct {
		allowance *feegrant.AllowedMsgAllowance
		// all other checks are ignored if valid=false
		fee       sdk.Coins
		blockTime time.Time
		valid     bool
		accept    bool
		remove    bool
		remains   sdk.Coins
	}{
		"internal fee is updated": {
			allowance: &feegrant.AllowedMsgAllowance{
				Allowance:       basicAllowance,
				AllowedMessages: []string{"/cosmos.bank.v1beta1.MsgSend"},
			},
			fee:     smallAtom,
			accept:  true,
			remove:  false,
			remains: leftAtom,
		},
	}

	for name, stc := range cases {
		tc := stc // to make scopelint happy
		t.Run(name, func(t *testing.T) {
			err := tc.allowance.ValidateBasic()
			require.NoError(t, err)

			ctx := app.BaseApp.NewContext(false, tmproto.Header{}).WithBlockTime(tc.blockTime)

			// now try to deduct
			removed, err := tc.allowance.Accept(ctx, tc.fee, []sdk.Msg{
				&banktypes.MsgSend{
					FromAddress: "gm",
					ToAddress:   "gn",
					Amount:      tc.fee,
				},
			})
			if !tc.accept {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tc.remove, removed)
			if !removed {
				var basicAllowanceLeft feegrant.BasicAllowance
				app.AppCodec().Unmarshal(tc.allowance.Allowance.Value, &basicAllowanceLeft)

				assert.Equal(t, tc.remains, basicAllowanceLeft.SpendLimit)
			}
		})
	}
}
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
