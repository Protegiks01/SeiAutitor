## Audit Report

## Title
Validator Can Set Minimum Self-Delegation Above Actual Self-Delegation via EditValidator

## Summary
The `EditValidator` message handler incorrectly validates the new `MinSelfDelegation` against the validator's total tokens instead of their actual self-delegation. This allows validators to set a minimum self-delegation requirement higher than their current self-delegation, violating the protocol's security invariant that validators must maintain minimum "skin in the game."

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When a validator increases their `MinSelfDelegation`, the system should verify that their current self-delegation (the validator operator's own delegation to themselves) meets or exceeds the new minimum. This ensures validators cannot commit to a minimum they don't actually maintain.

**Actual Logic:** 
The validation check compares the new `MinSelfDelegation` against `validator.Tokens`, which represents the total tokens delegated to the validator from ALL delegators (including both self-delegation and external delegations), not just the validator operator's self-delegation. [2](#0-1) 

**Exploit Scenario:**
1. Alice creates a validator with 100 tokens of self-delegation and sets `MinSelfDelegation = 100`
2. External delegators add 900 tokens to Alice's validator, bringing total tokens to 1000
3. Alice calls `EditValidator` to increase `MinSelfDelegation` to 500
4. The check at line 167 passes because `500 < 1000` (comparing against total tokens)
5. Alice's validator now has `MinSelfDelegation = 500` but only 100 tokens of actual self-delegation
6. Alice continues operating as a bonded validator despite being 400 tokens below her declared minimum

**Security Failure:** 
This breaks the accounting invariant that validators must maintain their declared minimum self-delegation. The minimum self-delegation mechanism is designed to ensure validators have sufficient stake at risk to align their incentives with the network. By allowing validators to set a minimum they don't meet, the protocol's security model is undermined.

## Impact Explanation

**Affected Assets and Processes:**
- Validator stake accountability and protocol security model
- Delegator trust assumptions when choosing validators based on their declared minimum self-delegation
- Post-slashing state integrity (validators below their minimum cannot unjail)

**Severity of Damage:**
- Validators can falsely signal high self-delegation commitments without actually maintaining them
- If such a validator is slashed (for downtime or double-signing), their already-insufficient self-delegation drops further
- The validator cannot unjail without meeting the (incorrectly set) minimum, as the unjail check correctly validates self-delegation [3](#0-2) 
- Delegators who chose this validator based on their high `MinSelfDelegation` are misled about the validator's actual stake
- The protocol's security assumption that validators with high minimum self-delegation have more "skin in the game" is violated

**System Reliability Impact:**
This undermines a core security mechanism of proof-of-stake systems where validators must maintain minimum stake to ensure honest behavior.

## Likelihood Explanation

**Who Can Trigger:**
Any validator operator can trigger this vulnerability by submitting a `MsgEditValidator` transaction with an increased `MinSelfDelegation` value.

**Required Conditions:**
- Validator must have external delegations (tokens from other delegators)
- The new `MinSelfDelegation` must be less than total tokens but greater than actual self-delegation
- This is a common scenario as validators typically have both self-delegation and external delegations

**Frequency:**
- Can be exploited during normal validator operations
- Does not require any special timing or network conditions
- Can be repeatedly exploited by any validator meeting the conditions
- Particularly likely when validators have significant external delegations (common for successful validators)

## Recommendation

Modify the validation in the `EditValidator` handler to check the new `MinSelfDelegation` against the validator operator's actual self-delegation, not total tokens:

```go
if msg.MinSelfDelegation != nil {
    if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
        return nil, types.ErrMinSelfDelegationDecreased
    }

    // Get the validator operator's self-delegation
    selfDel := k.Delegation(ctx, sdk.AccAddress(validator.GetOperator()), validator.GetOperator())
    if selfDel == nil {
        return nil, types.ErrMissingSelfDelegation
    }
    
    // Calculate self-delegation tokens from shares
    selfDelTokens := validator.TokensFromShares(selfDel.GetShares()).TruncateInt()
    
    // Check that current self-delegation meets the new minimum
    if msg.MinSelfDelegation.GT(selfDelTokens) {
        return nil, types.ErrSelfDelegationBelowMinimum
    }

    validator.MinSelfDelegation = (*msg.MinSelfDelegation)
}
```

This change ensures validators can only set a `MinSelfDelegation` they actually meet.

## Proof of Concept

**Test File:** `x/staking/handler_test.go`

**Test Function:** `TestEditValidatorIncreaseMinSelfDelegationAboveSelfDelegation` (new test to be added)

**Setup:**
1. Initialize a blockchain context with staking keeper
2. Create a validator with 100 tokens of self-delegation and `MinSelfDelegation = 100`
3. Bond the validator to make it active
4. Have an external delegator add 900 tokens to the validator (total becomes 1000)
5. Verify the validator's self-delegation is still 100 tokens

**Trigger:**
1. Validator operator submits `MsgEditValidator` with `MinSelfDelegation = 500`
2. Process the message through the handler

**Observation:**
1. The message is accepted (should be rejected but isn't due to the bug)
2. Validator's `MinSelfDelegation` is updated to 500
3. Validator's actual self-delegation remains 100 (below the minimum)
4. Validator continues to be bonded and active
5. If validator later tries to unbond any amount, they will be jailed by the check at [4](#0-3) 
6. If validator is slashed, they cannot unjail without adding 400+ tokens to meet the minimum

The test demonstrates that a validator can successfully set `MinSelfDelegation` to 500 while maintaining only 100 tokens of self-delegation, confirming the vulnerability.

### Citations

**File:** x/staking/keeper/msg_server.go (L162-172)
```go
	if msg.MinSelfDelegation != nil {
		if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
			return nil, types.ErrMinSelfDelegationDecreased
		}

		if msg.MinSelfDelegation.GT(validator.Tokens) {
			return nil, types.ErrSelfDelegationBelowMinimum
		}

		validator.MinSelfDelegation = (*msg.MinSelfDelegation)
	}
```

**File:** x/slashing/keeper/unjail.go (L23-29)
```go
	tokens := validator.TokensFromShares(selfDel.GetShares()).TruncateInt()
	minSelfBond := validator.GetMinSelfDelegation()
	if tokens.LT(minSelfBond) {
		return sdkerrors.Wrapf(
			types.ErrSelfDelegationTooLowToUnjail, "%s less than %s", tokens, minSelfBond,
		)
	}
```

**File:** x/staking/keeper/delegation.go (L770-774)
```go
	if isValidatorOperator && !validator.Jailed &&
		validator.TokensFromShares(delegation.Shares).TruncateInt().LT(validator.MinSelfDelegation) {
		k.jailValidator(ctx, validator)
		validator = k.mustGetValidator(ctx, validator.GetOperator())
	}
```
