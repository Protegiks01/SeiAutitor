# Audit Report

## Title
Validator Can Set Minimum Self-Delegation Above Actual Self-Delegation via EditValidator

## Summary
The `EditValidator` message handler in the staking module incorrectly validates the new `MinSelfDelegation` against the validator's total delegated tokens (`validator.Tokens`) instead of their actual self-delegation. This allows validators to set a minimum self-delegation requirement higher than what they actually maintain, violating a core security invariant of the proof-of-stake system.

## Impact
Medium

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: When a validator increases their `MinSelfDelegation`, the system should verify that their current self-delegation (the validator operator's own delegation to themselves) meets or exceeds the new minimum. This ensures validators maintain the minimum "skin in the game" they commit to.

**Actual Logic**: The validation check at line 167 compares the new `MinSelfDelegation` against `validator.Tokens`, which represents the total tokens delegated to the validator from ALL delegators (both self-delegation and external delegations). [2](#0-1)  This is incorrect because it allows validators to set a minimum they don't personally meet if they have sufficient external delegations.

**Exploitation Path**:
1. Validator creates a validator with 100 tokens of self-delegation and `MinSelfDelegation = 100`
2. External delegators add 900 tokens to the validator (total `validator.Tokens = 1000`)
3. Validator operator submits `MsgEditValidator` with `MinSelfDelegation = 500`
4. The check at line 167 evaluates `500 > 1000` which is false, so it passes
5. The validator now has `MinSelfDelegation = 500` but only 100 tokens of actual self-delegation
6. The validator continues operating normally despite violating their declared minimum

**Security Guarantee Broken**: The protocol's invariant that a validator's actual self-delegation must always be greater than or equal to their declared `MinSelfDelegation` is violated. This is a core security assumption used by delegators to assess validator commitment.

## Impact Explanation

This vulnerability undermines the staking module's security model in several ways:

1. **Misleading Information**: Delegators who choose validators based on their `MinSelfDelegation` value are given false information about the validator's actual stake and commitment level.

2. **Post-Slashing Consequences**: If a validator with this misconfiguration is slashed (for downtime or double-signing), they cannot unjail without meeting their incorrectly-set minimum. The unjail logic correctly checks actual self-delegation [3](#0-2)  and would reject the unjail attempt.

3. **Protocol Security Model**: The minimum self-delegation mechanism exists to ensure validators have sufficient stake at risk. Allowing validators to falsely declare higher minimums without maintaining them defeats this purpose and could enable validators to attract delegations under false pretenses.

4. **Inconsistent Enforcement**: The unbonding logic correctly enforces the minimum self-delegation requirement [4](#0-3) , creating an inconsistency where validators can set a value they cannot maintain if they try to unbond.

This qualifies as **Medium severity** under the criteria: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who Can Trigger**: Any validator operator can trigger this vulnerability through normal operations.

**Required Conditions**:
- Validator must have external delegations (extremely common for any active validator)
- The new `MinSelfDelegation` must be greater than actual self-delegation but less than total tokens
- This scenario naturally occurs as successful validators accumulate external delegations

**Frequency**: This can be exploited at any time during normal validator operations. It does not require special timing, network conditions, or coordination. The conditions are commonly met by active validators who have attracted external delegators.

## Recommendation

Modify the validation in the `EditValidator` handler to check against the validator operator's actual self-delegation:

```go
if msg.MinSelfDelegation != nil {
    if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
        return nil, types.ErrMinSelfDelegationDecreased
    }

    // Get the validator operator's actual self-delegation
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

This approach matches the correct implementation pattern used in the unjail logic and unbonding checks.

## Proof of Concept

**Test File**: `x/staking/handler_test.go`

**Test Function**: `TestEditValidatorIncreaseMinSelfDelegationAboveSelfDelegation` (to be added)

**Setup**:
1. Initialize a test blockchain context with staking keeper
2. Create a validator with 100 tokens of self-delegation and `MinSelfDelegation = 100`
3. Bond the validator to make it active
4. Have an external delegator add 900 tokens to the validator (bringing `validator.Tokens` to 1000)
5. Verify the validator's self-delegation remains 100 tokens

**Action**:
1. Validator operator submits `MsgEditValidator` with `MinSelfDelegation = 500`
2. Process the message through the handler

**Expected Result (Bug)**: 
- The message is accepted (should be rejected)
- Validator's `MinSelfDelegation` is updated to 500
- Validator's actual self-delegation remains 100 (below the minimum)
- The validator continues to be bonded and active
- If the validator is later slashed or tries to unbond, they will be jailed and cannot unjail without adding 400 more tokens

This demonstrates that a validator can successfully set `MinSelfDelegation` to 500 while maintaining only 100 tokens of self-delegation, confirming the vulnerability exists and can be exploited through normal transaction flows.

## Notes

The vulnerability is particularly significant because:

1. Other parts of the codebase correctly implement self-delegation checks (unjail and unbonding logic), proving this is a bug rather than intended behavior
2. The proto definition explicitly states that `validator.Tokens` includes all delegations, not just self-delegation
3. The security model of proof-of-stake systems relies on validators maintaining their declared minimum self-delegation
4. This creates an inconsistency where validators can set a value they cannot later maintain without being jailed

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

**File:** proto/cosmos/staking/v1beta1/staking.proto (L97-98)
```text
  // tokens define the delegated tokens (incl. self-delegation).
  string tokens = 5 [(gogoproto.customtype) = "github.com/cosmos/cosmos-sdk/types.Int", (gogoproto.nullable) = false];
```

**File:** x/slashing/keeper/unjail.go (L18-29)
```go
	selfDel := k.sk.Delegation(ctx, sdk.AccAddress(validatorAddr), validatorAddr)
	if selfDel == nil {
		return types.ErrMissingSelfDelegation
	}

	tokens := validator.TokensFromShares(selfDel.GetShares()).TruncateInt()
	minSelfBond := validator.GetMinSelfDelegation()
	if tokens.LT(minSelfBond) {
		return sdkerrors.Wrapf(
			types.ErrSelfDelegationTooLowToUnjail, "%s less than %s", tokens, minSelfBond,
		)
	}
```

**File:** x/staking/keeper/delegation.go (L766-774)
```go
	isValidatorOperator := delegatorAddress.Equals(validator.GetOperator())

	// If the delegation is the operator of the validator and undelegating will decrease the validator's
	// self-delegation below their minimum, we jail the validator.
	if isValidatorOperator && !validator.Jailed &&
		validator.TokensFromShares(delegation.Shares).TruncateInt().LT(validator.MinSelfDelegation) {
		k.jailValidator(ctx, validator)
		validator = k.mustGetValidator(ctx, validator.GetOperator())
	}
```
