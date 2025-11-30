# Audit Report

## Title
Governance Vote Weight Manipulation via Nested Message Validation Bypass in MsgExec

## Summary
The `MsgExec` message in the authz module fails to recursively validate nested messages, allowing attackers to bypass `ValidateBasic()` checks on `MsgVoteWeighted`. This enables submission of governance votes with total weight exceeding 1.0, amplifying voting influence beyond actual voting power through manipulation of the governance threshold calculation.

## Impact
Medium

## Finding Description

**Location:**
- `x/authz/msgs.go` lines 221-232 (MsgExec.ValidateBasic)
- `x/authz/keeper/keeper.go` lines 87-111 (DispatchActions authorization bypass)
- `x/gov/keeper/msg_server.go` lines 93-121 (VoteWeighted handler)
- `x/gov/keeper/vote.go` lines 21-25 (AddVote validation)
- `x/gov/keeper/tally.go` lines 59-63 (vote weight multiplication)

**Intended Logic:**
All transaction messages should have their `ValidateBasic()` method called during ante handler processing. For `MsgVoteWeighted`, this validation ensures total weight equals exactly 1.0, preventing vote amplification. [1](#0-0) 

**Actual Logic:**
The ante handler only validates top-level messages through `validateBasicTxMsgs()`, which iterates through the transaction's messages and calls `ValidateBasic()` on each. [2](#0-1) [3](#0-2) 

When `MsgExec` is submitted, only its `ValidateBasic()` is called, which does not validate nested messages: [4](#0-3) 

During execution in `DispatchActions()`, when granter equals grantee (voter acting on their own behalf), the authorization check is skipped with implicit acceptance: [5](#0-4) 

The `VoteWeighted` handler directly calls `keeper.AddVote()` without validating the message: [6](#0-5) 

The `AddVote()` function only validates individual option weights (each must be ≤ 1.0), not total weight across all options: [7](#0-6) [8](#0-7) 

**Exploitation Path:**
1. Attacker creates `MsgExec` with grantee set to their own address
2. Nests `MsgVoteWeighted` with voter = their address and multiple options with total weight > 1.0 (e.g., {Yes: 0.9, Abstain: 0.9})
3. Transaction passes ante handler validation since only `MsgExec.ValidateBasic()` is checked (which doesn't validate nested messages)
4. During execution in the MsgExec handler, `DispatchActions()` is called with the grantee address
5. For the nested `MsgVoteWeighted`, granter is extracted from `GetSigners()[0]` which returns the voter address
6. Since granter (voter address) equals grantee (from MsgExec) equals attacker's address, the authorization check is skipped per the "implicit accept" logic
7. `VoteWeighted` handler calls `keeper.AddVote()` which validates each option individually (both 0.9 ≤ 1.0) but not the total weight
8. Vote is stored with total weight 1.8
9. During tally, voting power is multiplied by each weight and accumulated separately [9](#0-8) 

**Security Guarantee Broken:**
The governance voting invariant that each voter's influence equals exactly their voting power is violated. The total weight constraint (must equal 1.0) can be bypassed, allowing arbitrary vote amplification.

## Impact Explanation

This vulnerability enables manipulation of governance proposals by allowing voters to amplify their influence beyond their actual voting power. An attacker with voting power of 100 who votes {Yes: 0.9, Abstain: 0.9} contributes 90 to Yes votes while also adding 90 to Abstain votes, but totalVotingPower only increases by 100 (not 180).

During threshold calculation: [10](#0-9) 

This yields: 90/(100-90) = 90/10 = 9 = 900%, versus the normal case of 100/(100-0) = 100%, representing a 9x amplification in the effective threshold calculation.

Governance in Cosmos chains controls critical functions including protocol parameter changes, software upgrades, and treasury management. Manipulation could lead to unauthorized parameter changes, malicious upgrades, or improper fund allocations. While no concrete funds are at immediate direct risk from the vote manipulation itself, the governance system's integrity is fundamentally compromised, qualifying this as "unintended behavior with no concrete funds at direct risk" per the Medium severity criteria.

## Likelihood Explanation

**Triggerable by:** Any network participant with voting power (staked tokens)

**Conditions:**
- Active governance proposal in voting period
- Standard transaction submission capability  
- No special privileges or pre-existing authorization grants required

**Frequency:** Exploitable deterministically on any governance proposal. The attack requires no timing, race conditions, or rare circumstances. Any token holder can execute this attack at will during any active voting period. The amplification factor can reach up to 4x by using all four vote options (Yes, No, Abstain, NoWithVeto) each at 0.9 weight, though strategic combinations like {Yes: 0.9, Abstain: 0.9} provide maximum manipulation of the threshold calculation.

## Recommendation

Modify `MsgExec.ValidateBasic()` to recursively validate all nested messages:

```go
func (msg MsgExec) ValidateBasic() error {
    _, err := sdk.AccAddressFromBech32(msg.Grantee)
    if err != nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid grantee address")
    }

    if len(msg.Msgs) == 0 {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, "messages cannot be empty")
    }

    // Validate all nested messages
    msgs, err := msg.GetMessages()
    if err != nil {
        return err
    }
    
    for _, m := range msgs {
        if err := m.ValidateBasic(); err != nil {
            return err
        }
    }

    return nil
}
```

This ensures that all nested messages undergo proper stateless validation, preventing the bypass of critical checks like the total weight validation in `MsgVoteWeighted`.

## Proof of Concept

**Setup:**
1. Create test chain environment with governance module enabled
2. Create attacker account with voting power (staked tokens)
3. Submit governance proposal and wait for voting period to begin

**Action:**
```go
// Create malicious vote with total weight > 1.0
maliciousVote := &govtypes.MsgVoteWeighted{
    ProposalId: proposalId,
    Voter:      attackerAddr.String(),
    Options: govtypes.WeightedVoteOptions{
        {Option: govtypes.OptionYes, Weight: sdk.MustNewDecFromStr("0.9")},
        {Option: govtypes.OptionAbstain, Weight: sdk.MustNewDecFromStr("0.9")},
    },
}

// Wrap in MsgExec with grantee = attacker's own address
msgExec := authz.NewMsgExec(attackerAddr, []sdk.Msg{maliciousVote})

// Submit transaction (signed by attacker)
txBytes := encodeTx(msgExec)
result := app.DeliverTx(abci.RequestDeliverTx{Tx: txBytes})
```

**Result:**
- Transaction is accepted and executed successfully
- Vote is stored with total weight 1.8 (> 1.0), violating the governance invariant
- During tally, the attacker's voting power is multiplied by 0.9 for Yes and 0.9 for Abstain separately
- The threshold calculation becomes: Yes/(Total-Abstain) = 0.9P/(P-0.9P) = 900%, severely distorting the governance outcome
- This allows the attacker to manipulate proposal passage/failure with amplified influence beyond their actual voting power

## Notes

This constitutes a Medium severity issue per the impact category "A bug in the respective layer 0/1/2 network code that results in unintended behavior with no concrete funds at direct risk." The attack requires no special privileges beyond normal voting power (staked tokens) and can be executed by any token holder during any active governance proposal. The vulnerability fundamentally breaks the governance system's assumption that one token equals one unit of voting power, enabling disproportionate influence through weight manipulation.

### Citations

**File:** x/gov/types/msgs.go (L252-271)
```go
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
```

**File:** baseapp/baseapp.go (L787-800)
```go
// validateBasicTxMsgs executes basic validator calls for messages.
func validateBasicTxMsgs(msgs []sdk.Msg) error {
	if len(msgs) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "must contain at least one message")
	}

	for _, msg := range msgs {
		err := msg.ValidateBasic()
		if err != nil {
			return err
		}
	}

	return nil
```

**File:** baseapp/baseapp.go (L921-925)
```go
	msgs := tx.GetMsgs()

	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```

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

**File:** x/gov/keeper/vote.go (L21-25)
```go
	for _, option := range options {
		if !types.ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(types.ErrInvalidVote, option.String())
		}
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

**File:** x/gov/keeper/tally.go (L59-63)
```go
				for _, option := range vote.Options {
					subPower := votingPower.Mul(option.Weight)
					results[option.Option] = results[option.Option].Add(subPower)
				}
				totalVotingPower = totalVotingPower.Add(votingPower)
```

**File:** x/gov/keeper/tally.go (L119-119)
```go
	if results[types.OptionYes].Quo(totalVotingPower.Sub(results[types.OptionAbstain])).GT(voteYesThreshold) {
```
