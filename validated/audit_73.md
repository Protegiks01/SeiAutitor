# Audit Report

## Title
MsgExec Self-Execution Bypasses ValidateBasic Enabling Governance Vote Weight Manipulation

## Summary
The authz module's `MsgExec` does not validate inner messages during stateless validation. When combined with self-execution (granter equals grantee), attackers can submit `MsgVoteWeighted` with invalid total weights that bypass validation checks, enabling vote weight amplification during governance tallying.

## Impact
Medium

## Finding Description

**Location:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended logic:** All transaction messages should undergo stateless validation via `ValidateBasic()` during `CheckTx`. For `MsgVoteWeighted`, this includes verifying the total weight equals exactly 1.0 [5](#0-4) . The ante handler system is designed to call `ValidateBasic()` on all messages [6](#0-5) .

**Actual logic:** `MsgExec.ValidateBasic()` only validates the grantee address and non-empty messages array - it does NOT call `ValidateBasic()` on inner messages [1](#0-0) . During execution, when granter equals grantee (self-execution), `DispatchActions()` bypasses authorization checks [2](#0-1) . The `VoteWeighted` handler calls `AddVote()` directly, which only validates individual option weights via `ValidWeightedVoteOption()` [7](#0-6) , but does NOT validate that the total weight sum equals 1.0 [3](#0-2) .

**Exploitation path:**
1. Attacker constructs `MsgVoteWeighted` with invalid weights (e.g., YES: 0.8, NO: 0.7, total: 1.5)
2. Wraps it in `MsgExec` where Grantee = Voter = attacker's own address
3. Transaction passes `CheckTx` because `MsgExec.ValidateBasic()` doesn't validate inner messages
4. During `DeliverTx`, `DispatchActions()` extracts granter from inner message's signer (voter address), compares with grantee (same address), and implicitly accepts without authorization checks
5. `VoteWeighted` handler executes, calling `AddVote()` without invoking `ValidateBasic()`
6. Invalid vote is stored with total weight > 1.0
7. During tally, voting power is multiplied by each option's weight [8](#0-7)  and [9](#0-8) 

**Security guarantee broken:** The validation invariant that all messages must pass `ValidateBasic()` before execution is violated. This breaks the governance integrity assumption that each voter's weight distribution must sum to exactly 1.0.

## Impact Explanation

An attacker can manipulate their effective voting power by submitting votes with total weight > 1.0. For example, with total weight = 1.5, a voter with 10% of staking power effectively casts 15% of the vote weight. The tally code directly multiplies voting power by option weights without validation [8](#0-7) , allowing vote weight amplification.

This can swing close proposal outcomes, enabling minority stakeholders to pass or reject proposals against the majority's will. While this doesn't directly steal funds, it corrupts the governance process which controls critical protocol operations including parameter changes, community pool spending, and protocol upgrades. This qualifies as Medium severity under "A bug in the network code that results in unintended behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger:** Any user with voting power (staked tokens or delegations).

**Conditions required:**
- An active governance proposal in voting period
- Single transaction submission containing `MsgExec` with invalid inner `MsgVoteWeighted`

**Frequency:** Can be exploited during any proposal's voting period. No special setup, timing requirements, or authorization grants needed. The attacker simply submits `MsgExec` with grantee set to their own address, containing `MsgVoteWeighted` with voter also set to their address, causing the granter == grantee condition to skip authorization checks.

## Recommendation

Add validation of inner messages in `MsgExec.ValidateBasic()`:

```go
func (msg MsgExec) ValidateBasic() error {
    _, err := sdk.AccAddressFromBech32(msg.Grantee)
    if err != nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid grantee address")
    }

    if len(msg.Msgs) == 0 {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages cannot be empty")
    }

    // Validate inner messages
    msgs, err := msg.GetMessages()
    if err != nil {
        return err
    }
    
    for _, innerMsg := range msgs {
        if err := innerMsg.ValidateBasic(); err != nil {
            return sdkerrors.Wrapf(err, "invalid inner message")
        }
    }

    return nil
}
```

This ensures all messages undergo stateless validation regardless of how they are submitted.

## Proof of Concept

**Test scenario:**
1. **Setup:** Create a governance proposal in voting period and a voter account with voting power
2. **Action:** Submit `MsgExec` with Grantee = voter address, containing `MsgVoteWeighted` with Voter = same address and invalid weights (total > 1.0, e.g., YES: 0.8, NO: 0.7)
3. **Result:** Transaction succeeds, invalid vote is stored with total weight 1.5, and during tally the voter's power is multiplied by 1.5x

The vulnerability is reproducible by:
- Creating `MsgVoteWeighted` with options [YES: 0.8, NO: 0.7] (total: 1.5)
- Verifying it fails `ValidateBasic()` when submitted directly [10](#0-9) 
- Wrapping it in `MsgExec` where grantee = voter address
- Observing that `MsgExec.ValidateBasic()` passes [1](#0-0) 
- Confirming the vote is stored with total weight 1.5
- Verifying during tally the voter's power is multiplied by inflated weights [8](#0-7) 

## Notes

This vulnerability exists because `MsgExec.ValidateBasic()` does not validate inner messages [1](#0-0) , and the self-execution code path bypasses authorization when granter == grantee [2](#0-1) . The governance module's `AddVote()` only validates individual option validity [3](#0-2) , not total weight constraints, allowing invalid votes to be stored and tallied with amplified weight.

### Citations

**File:** x/authz/msgs.go (L221-232)
```go
func (msg MsgExec) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid grantee address")
	}

	if len(msg.Msgs) == 0 {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages cannot be empty")
	}

	return nil
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

**File:** x/gov/keeper/vote.go (L21-25)
```go
	for _, option := range options {
		if !types.ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(types.ErrInvalidVote, option.String())
		}
	}
```

**File:** x/gov/keeper/msg_server.go (L93-121)
```go
func (k msgServer) VoteWeighted(goCtx context.Context, msg *types.MsgVoteWeighted) (*types.MsgVoteWeightedResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	accAddr, accErr := sdk.AccAddressFromBech32(msg.Voter)
	if accErr != nil {
		return nil, accErr
	}
	err := k.Keeper.AddVote(ctx, msg.ProposalId, accAddr, msg.Options)
	if err != nil {
		return nil, err
	}

	defer telemetry.IncrCounterWithLabels(
		[]string{types.ModuleName, "vote"},
		1,
		[]metrics.Label{
			telemetry.NewLabel("proposal_id", strconv.Itoa(int(msg.ProposalId))),
		},
	)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
			sdk.NewAttribute(sdk.AttributeKeySender, msg.Voter),
		),
	)

	return &types.MsgVoteWeightedResponse{}, nil
}
```

**File:** x/gov/types/msgs.go (L243-274)
```go
func (msg MsgVoteWeighted) ValidateBasic() error {
	if msg.Voter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, msg.Voter)
	}

	if len(msg.Options) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, WeightedVoteOptions(msg.Options).String())
	}

	totalWeight := sdk.NewDec(0)
	usedOptions := make(map[VoteOption]bool)
	for _, option := range msg.Options {
		if !ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(ErrInvalidVote, option.String())
		}
		totalWeight = totalWeight.Add(option.Weight)
		if usedOptions[option.Option] {
			return sdkerrors.Wrap(ErrInvalidVote, "Duplicated vote option")
		}
		usedOptions[option.Option] = true
	}

	if totalWeight.GT(sdk.NewDec(1)) {
		return sdkerrors.Wrap(ErrInvalidVote, "Total weight overflow 1.00")
	}

	if totalWeight.LT(sdk.NewDec(1)) {
		return sdkerrors.Wrap(ErrInvalidVote, "Total weight lower than 1.00")
	}

	return nil
}
```

**File:** x/auth/ante/basic.go (L18-39)
```go
// ValidateBasicDecorator will call tx.ValidateBasic and return any non-nil error.
// If ValidateBasic passes, decorator calls next AnteHandler in chain. Note,
// ValidateBasicDecorator decorator will not get executed on ReCheckTx since it
// is not dependent on application state.
type ValidateBasicDecorator struct{}

func NewValidateBasicDecorator() ValidateBasicDecorator {
	return ValidateBasicDecorator{}
}

func (vbd ValidateBasicDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	// no need to validate basic on recheck tx, call next antehandler
	if ctx.IsReCheckTx() {
		return next(ctx, tx, simulate)
	}

	if err := tx.ValidateBasic(); err != nil {
		return ctx, err
	}

	return next(ctx, tx, simulate)
}
```

**File:** x/gov/types/vote.go (L80-85)
```go
func ValidWeightedVoteOption(option WeightedVoteOption) bool {
	if !option.Weight.IsPositive() || option.Weight.GT(sdk.NewDec(1)) {
		return false
	}
	return ValidVoteOption(option.Option)
}
```

**File:** x/gov/keeper/tally.go (L59-62)
```go
				for _, option := range vote.Options {
					subPower := votingPower.Mul(option.Weight)
					results[option.Option] = results[option.Option].Add(subPower)
				}
```

**File:** x/gov/keeper/tally.go (L82-85)
```go
		for _, option := range val.Vote {
			subPower := votingPower.Mul(option.Weight)
			results[option.Option] = results[option.Option].Add(subPower)
		}
```
