# Audit Report

## Title
Reward Theft via Authz-Enabled Withdraw Address Manipulation

## Summary
The authz module allows a grantee to redirect a granter's staking rewards to an arbitrary address by first modifying the granter's withdraw address, then claiming rewards. When a granter grants authorization for both `MsgSetWithdrawAddress` and `MsgWithdrawDelegatorReward`, the grantee can steal all accumulated staking rewards by changing the withdraw address to their own address before claiming.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:**
- Authz dispatch logic: [1](#0-0) 
- Distribution withdraw address setter: [2](#0-1) 
- Distribution reward withdrawal: [3](#0-2) 
- Distribution message handler: [4](#0-3) 

**Intended Logic:**
The authz module is designed to allow a granter to delegate the ability to perform certain actions on their behalf. For distribution rewards, the intended behavior is that when a grantee claims rewards using authz, those rewards should be sent to the granter (the owner of the staked tokens) or their designated withdraw address.

**Actual Logic:**
The system fails to protect the withdraw address from being modified through authz. The authz module executes messages without modification [5](#0-4) , and the distribution module allows withdraw address changes without verifying whether the request comes directly from the delegator or through an authorization [2](#0-1) . When rewards are withdrawn, they are sent to whatever withdraw address is currently stored [6](#0-5) .

**Exploit Scenario:**
1. Alice (granter) stakes tokens and accumulates rewards
2. Alice grants Bob (grantee) authorization for both `MsgSetWithdrawAddress` and `MsgWithdrawDelegatorReward` (perhaps intending for Bob to claim rewards on her behalf when she's unavailable)
3. Bob executes `MsgExec` containing `MsgSetWithdrawAddress` with `DelegatorAddress=Alice` and `WithdrawAddress=Bob`
4. Bob executes `MsgExec` containing `MsgWithdrawDelegatorReward` with `DelegatorAddress=Alice`
5. All of Alice's accumulated staking rewards are sent to Bob's address
6. Bob can optionally reset Alice's withdraw address back to Alice's address to hide the attack

**Security Failure:**
This breaks the authorization security model. The granter expects that authorizing reward claims will result in rewards being sent to their own address (or their previously set withdraw address), not to an arbitrary address chosen by the grantee. The vulnerability enables theft of staking rewards through a two-step attack combining authorized operations in an unintended sequence.

## Impact Explanation

**Affected Assets:**
All staking rewards accumulated by any delegator who has granted authz permissions for both `MsgSetWithdrawAddress` and `MsgWithdrawDelegatorReward`.

**Severity of Damage:**
Complete loss of staking rewards for affected users. The grantee can claim 100% of the granter's accumulated rewards by redirecting them to their own address. This represents a direct financial loss that is irreversible once the rewards are transferred.

**System Security Impact:**
This undermines user trust in the authz delegation mechanism. Users who grant permissions expecting their assets to remain secure will have their staking rewards stolen. The vulnerability affects a core protocol feature (staking rewards) and a fundamental trust mechanism (authorization delegation).

## Likelihood Explanation

**Who Can Trigger:**
Any grantee who has been granted authorization for both `MsgSetWithdrawAddress` and `MsgWithdrawDelegatorReward` message types by a granter with staking rewards.

**Conditions Required:**
- Granter must have granted both message type authorizations to the grantee
- Granter must have accumulated staking rewards
- No additional rare conditions required - this can be executed at any time during normal network operation

**Frequency:**
This attack can be executed immediately after authorization is granted and can be repeated for each new batch of accumulated rewards. While users may not commonly grant both permissions together, the scenario is realistic: a user might grant comprehensive permissions to a trusted service or bot that manages their staking operations. The vulnerability can be exploited 100% of the time when these conditions are met.

## Recommendation

Implement a restriction in the distribution module's `SetWithdrawAddr` function to prevent withdraw address changes when executed through authz. Specifically:

1. Add a check to detect if the current transaction is being executed via authz (check if the message signer differs from the transaction signer in the context)
2. If executed through authz, reject the withdraw address change operation
3. Alternatively, create a separate authorization type for distribution that explicitly validates the withdraw address remains unchanged or only allows it to be set to the granter's address

The fix should be applied at: [2](#0-1) 

A code-level fix would add validation before line 65 to detect authz execution context and reject withdraw address modifications in that case, or create a specialized distribution authorization type that enforces the invariant that rewards must flow to the granter.

## Proof of Concept

**Test File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add new test `TestAuthzWithdrawAddressExploit`

**Setup:**
1. Initialize SimApp with 3 test addresses: granter, grantee, attacker
2. Fund granter account with staking tokens
3. Create a validator and have granter delegate tokens to it
4. Advance blocks to accumulate rewards for the granter
5. Granter grants grantee authorization for `MsgSetWithdrawAddress` with `GenericAuthorization`
6. Granter grants grantee authorization for `MsgWithdrawDelegatorReward` with `GenericAuthorization`

**Trigger:**
1. Grantee creates `MsgSetWithdrawAddress` with `DelegatorAddress=granter` and `WithdrawAddress=grantee`
2. Wrap it in `MsgExec` and execute through authz keeper's `DispatchActions`
3. Query and verify the withdraw address is now set to grantee's address
4. Grantee creates `MsgWithdrawDelegatorReward` with `DelegatorAddress=granter`
5. Wrap it in `MsgExec` and execute through authz keeper
6. Check grantee's balance increased by the reward amount

**Observation:**
The test demonstrates that:
1. The withdraw address was successfully changed from granter to grantee via authz
2. The rewards were sent to grantee's address instead of granter's address
3. Granter lost their staking rewards to the grantee
4. This confirms the granter's rewards were stolen through authorized but malicious operations

The test would show that the grantee's balance increases by the full reward amount while the granter receives nothing, proving the vulnerability allows direct theft of staking rewards.

### Citations

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

**File:** x/distribution/keeper/keeper.go (L64-82)
```go
func (k Keeper) SetWithdrawAddr(ctx sdk.Context, delegatorAddr sdk.AccAddress, withdrawAddr sdk.AccAddress) error {
	if k.blockedAddrs[withdrawAddr.String()] {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", withdrawAddr)
	}

	if !k.GetWithdrawAddrEnabled(ctx) {
		return types.ErrSetWithdrawAddrDisabled
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSetWithdrawAddress,
			sdk.NewAttribute(types.AttributeKeyWithdrawAddress, withdrawAddr.String()),
		),
	)

	k.SetDelegatorWithdrawAddr(ctx, delegatorAddr, withdrawAddr)
	return nil
}
```

**File:** x/distribution/keeper/delegation.go (L139-211)
```go
func (k Keeper) withdrawDelegationRewards(ctx sdk.Context, val stakingtypes.ValidatorI, del stakingtypes.DelegationI) (sdk.Coins, error) {
	// check existence of delegator starting info
	if !k.HasDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr()) {
		return nil, types.ErrEmptyDelegationDistInfo
	}

	// end current period and calculate rewards
	endingPeriod := k.IncrementValidatorPeriod(ctx, val)
	rewardsRaw := k.CalculateDelegationRewards(ctx, val, del, endingPeriod)
	outstanding := k.GetValidatorOutstandingRewardsCoins(ctx, del.GetValidatorAddr())

	// defensive edge case may happen on the very final digits
	// of the decCoins due to operation order of the distribution mechanism.
	rewards := rewardsRaw.Intersect(outstanding)
	if !rewards.IsEqual(rewardsRaw) {
		logger := k.Logger(ctx)
		logger.Info(
			"rounding error withdrawing rewards from validator",
			"delegator", del.GetDelegatorAddr().String(),
			"validator", val.GetOperator().String(),
			"got", rewards.String(),
			"expected", rewardsRaw.String(),
		)
	}

	// truncate reward dec coins, return remainder to community pool
	finalRewards, remainder := rewards.TruncateDecimal()

	// add coins to user account
	if !finalRewards.IsZero() {
		withdrawAddr := k.GetDelegatorWithdrawAddr(ctx, del.GetDelegatorAddr())
		err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, finalRewards)
		if err != nil {
			return nil, err
		}
	}

	// update the outstanding rewards and the community pool only if the
	// transaction was successful
	k.SetValidatorOutstandingRewards(ctx, del.GetValidatorAddr(), types.ValidatorOutstandingRewards{Rewards: outstanding.Sub(rewards)})
	feePool := k.GetFeePool(ctx)
	feePool.CommunityPool = feePool.CommunityPool.Add(remainder...)
	k.SetFeePool(ctx, feePool)

	// decrement reference count of starting period
	startingInfo := k.GetDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr())
	startingPeriod := startingInfo.PreviousPeriod
	k.decrementReferenceCount(ctx, del.GetValidatorAddr(), startingPeriod)

	// remove delegator starting info
	k.DeleteDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr())

	if finalRewards.IsZero() {
		baseDenom, _ := sdk.GetBaseDenom()
		if baseDenom == "" {
			baseDenom = sdk.DefaultBondDenom
		}

		// Note, we do not call the NewCoins constructor as we do not want the zero
		// coin removed.
		finalRewards = sdk.Coins{sdk.NewCoin(baseDenom, sdk.ZeroInt())}
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeWithdrawRewards,
			sdk.NewAttribute(sdk.AttributeKeyAmount, finalRewards.String()),
			sdk.NewAttribute(types.AttributeKeyValidator, val.GetOperator().String()),
		),
	)

	return finalRewards, nil
}
```

**File:** x/distribution/keeper/msg_server.go (L52-87)
```go
func (k msgServer) WithdrawDelegatorReward(goCtx context.Context, msg *types.MsgWithdrawDelegatorReward) (*types.MsgWithdrawDelegatorRewardResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return nil, err
	}
	delegatorAddress, err := sdk.AccAddressFromBech32(msg.DelegatorAddress)
	if err != nil {
		return nil, err
	}
	amount, err := k.WithdrawDelegationRewards(ctx, delegatorAddress, valAddr)
	if err != nil {
		return nil, err
	}

	defer func() {
		for _, a := range amount {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "withdraw_reward"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
			sdk.NewAttribute(sdk.AttributeKeySender, msg.DelegatorAddress),
		),
	)
	return &types.MsgWithdrawDelegatorRewardResponse{}, nil
```
