Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Here is my audit report:

---

Audit Report

## Title
MsgExec Bypasses ValidateBasic Allowing Invalid Weighted Votes with Manipulated Total Weights

## Summary
The `MsgExec` message in the authz module does not call `ValidateBasic()` on its inner messages, allowing malformed `MsgVoteWeighted` messages with total weight not equal to 1.0 to bypass validation. When a user executes their own vote through `MsgExec`, the "implicitly accept" code path skips both authorization and validation checks, enabling governance voting power manipulation.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended logic:** All transaction messages should pass through `ValidateBasic()` during `CheckTx` to ensure stateless validation. For `MsgVoteWeighted`, this includes verifying total weight equals exactly 1.0 and no duplicate options exist. [5](#0-4) 

**Actual logic:** When `MsgExec` contains inner messages, `MsgExec.ValidateBasic()` only validates the grantee address and messages array existence - it does NOT call `ValidateBasic()` on inner messages. During execution in `DispatchActions()`, when granter equals grantee (self-execution), the code "implicitly accepts" and skips authorization checks, proceeding directly to message execution without validation. The governance `AddVote()` handler only validates individual option validity via `ValidWeightedVoteOption()`, not total weight sum or duplicates. [6](#0-5) 

**Exploitation path:**
1. Attacker constructs a `MsgVoteWeighted` with invalid weights (e.g., YES: 0.8, NO: 0.7, total: 1.5)
2. Attacker wraps this in `MsgExec` where Grantee = their own address and the inner vote's Voter = their own address
3. Transaction passes `CheckTx` because `MsgExec.ValidateBasic()` doesn't validate inner messages
4. During `DeliverTx`, `DispatchActions()` sees granter (from inner message signer) == grantee (from MsgExec) and "implicitly accepts" without authorization or validation checks
5. The invalid vote is executed and stored
6. During tally, voting power is multiplied by each option's weight, amplifying the attacker's effective voting power beyond their actual stake

**Security guarantee broken:** The validation invariant that all messages must pass `ValidateBasic()` before execution is violated. This breaks the governance integrity assumption that each voter's weight distribution must sum to exactly 1.0.

## Impact Explanation

An attacker can manipulate their effective voting power by submitting votes with total weight > 1.0. For example, with total weight = 1.5, a voter with 10% of staking power effectively casts 15% of the vote weight. This can swing close proposal outcomes, allowing minority stakeholders to pass or reject proposals against the true will of the majority.

While this doesn't directly steal funds, it corrupts the governance process which controls critical protocol operations including parameter changes, community pool spending, and protocol upgrades. The tally calculation multiplies voting power by option weights without validation, directly incorporating the manipulated weights into final results. [7](#0-6) 

## Likelihood Explanation

**Who can trigger:** Any user with voting power (staked tokens or delegations) can exploit this vulnerability.

**Conditions required:** 
- An active governance proposal in voting period
- Single transaction submission containing MsgExec with invalid inner MsgVoteWeighted

**Frequency:** Can be exploited during any proposal's voting period. No special setup, timing requirements, or authorization grants needed - the attacker simply submits MsgExec executing their own vote. Multiple attackers can independently exploit this on the same proposal.

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

This ensures all messages undergo stateless validation regardless of how they are submitted, maintaining the security invariant.

## Proof of Concept

**Test scenario:**
1. **Setup:** Create a governance proposal in voting period and a voter account with voting power
2. **Action:** Submit `MsgExec` with Grantee = voter address, containing `MsgVoteWeighted` with Voter = same address and invalid weights (total > 1.0)
3. **Result:** Transaction succeeds, invalid vote is stored, and during tally the voter's power is multiplied by the inflated weight sum

The vulnerability can be reproduced by:
- Creating a `MsgVoteWeighted` with options [YES: 0.8, NO: 0.7] (total: 1.5)
- Verifying it fails `ValidateBasic()` when submitted directly
- Wrapping it in `MsgExec` where grantee = voter
- Observing that `MsgExec.ValidateBasic()` passes
- Executing and confirming the vote is stored with total weight 1.5
- During tally, confirming the voter's power is multiplied by 1.5 total instead of 1.0

**Note:** The report's mention of creating a self-grant (granter = grantee) is unnecessary, as `MsgGrant.ValidateBasic()` prevents this at line 64-66. However, the vulnerability still exists through direct self-execution via MsgExec without any grant. [8](#0-7) 

---

## Notes

This vulnerability qualifies as **Medium severity** under the category "A bug in the network code that results in unintended behavior" as it allows manipulation of governance voting outcomes, which is a critical protocol mechanism. While there is no direct fund loss from the vote manipulation itself, governance controls protocol parameters, upgrades, and community pool spending, making this a significant security issue.

### Citations

**File:** x/authz/msgs.go (L64-66)
```go
	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
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

**File:** x/gov/keeper/vote.go (L21-25)
```go
	for _, option := range options {
		if !types.ValidWeightedVoteOption(option) {
			return sdkerrors.Wrap(types.ErrInvalidVote, option.String())
		}
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

**File:** x/gov/types/vote.go (L80-85)
```go
func ValidWeightedVoteOption(option WeightedVoteOption) bool {
	if !option.Weight.IsPositive() || option.Weight.GT(sdk.NewDec(1)) {
		return false
	}
	return ValidVoteOption(option.Option)
}
```
