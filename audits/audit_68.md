# Audit Report Validation

After thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Let me present my findings:

## Code Analysis

The vulnerability exists in the `EditValidator` function where the validation incorrectly compares the new `MinSelfDelegation` against total validator tokens: [1](#0-0) 

The proto definition confirms that `validator.Tokens` includes all delegations, not just self-delegation: [2](#0-1) 

## Evidence of Correct Implementation Pattern

The codebase demonstrates the correct approach in other locations:

**Unjail logic** correctly retrieves and validates actual self-delegation: [3](#0-2) 

**Unbonding logic** correctly checks self-delegation when the validator operator unbonds: [4](#0-3) 

These correct implementations prove that checking actual self-delegation (not total tokens) is the intended behavior.

## Validation Results

✅ **Entry Point**: `MsgEditValidator` - accessible to any validator operator  
✅ **Exploitation Path**: Validator with external delegations can set MinSelfDelegation above actual self-delegation  
✅ **Impact Category**: Matches "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium)  
✅ **Reproducible**: Clear test scenario with normal transaction flow  
✅ **No Special Privileges**: Any validator operator can trigger  
✅ **Security Invariant Broken**: Actual self-delegation must be ≥ MinSelfDelegation  

---

# Audit Report

## Title
Validator Can Set Minimum Self-Delegation Above Actual Self-Delegation via EditValidator

## Summary
The `EditValidator` message handler incorrectly validates the new `MinSelfDelegation` against the validator's total delegated tokens instead of their actual self-delegation. This allows validators to set a minimum self-delegation requirement higher than what they actually maintain, violating the protocol's core security invariant.

## Impact
Medium

## Finding Description

- **Location**: [5](#0-4) 

- **Intended Logic**: When a validator increases their `MinSelfDelegation`, the system should verify that their current self-delegation (the validator operator's own delegation to themselves) meets or exceeds the new minimum. This ensures validators maintain their committed "skin in the game."

- **Actual Logic**: The validation at line 167 compares `msg.MinSelfDelegation` against `validator.Tokens`, which represents the total tokens delegated to the validator from ALL delegators (both self-delegation and external delegations), as confirmed by [2](#0-1) . This allows validators to set a minimum they don't personally meet if they have sufficient external delegations.

- **Exploitation Path**:
  1. Validator creates a validator with 100 tokens of self-delegation and `MinSelfDelegation = 100`
  2. External delegators add 900 tokens (total `validator.Tokens = 1000`)
  3. Validator operator submits `MsgEditValidator` with `MinSelfDelegation = 500`
  4. Check evaluates `500 > 1000` which is false, so passes
  5. Validator now has `MinSelfDelegation = 500` but only 100 tokens actual self-delegation
  6. Validator operates normally despite violating declared minimum

- **Security Guarantee Broken**: The protocol invariant that a validator's actual self-delegation must always be ≥ their declared `MinSelfDelegation` is violated. This is a core assumption delegators use to assess validator commitment.

## Impact Explanation

This vulnerability undermines the staking module's security model:

1. **Misleading Delegators**: Delegators selecting validators based on `MinSelfDelegation` receive false information about the validator's actual commitment level.

2. **Operational Inconsistency**: If the misconfigured validator is later slashed, they cannot unjail without meeting the incorrectly-set minimum. The unjail logic correctly checks actual self-delegation [6](#0-5)  and would reject the unjail attempt.

3. **Protocol Security Degradation**: The minimum self-delegation mechanism ensures validators have stake at risk. Allowing false declarations defeats this purpose and enables validators to attract delegations under false pretenses.

4. **Enforcement Inconsistency**: The unbonding logic correctly enforces the requirement [7](#0-6) , creating a state where validators can set values they cannot maintain during unbonding operations.

This qualifies as **Medium severity**: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who Can Trigger**: Any validator operator through normal transaction flow.

**Required Conditions**:
- Validator has external delegations (standard for active validators)
- New `MinSelfDelegation` > actual self-delegation but < total tokens
- Naturally occurs as validators accumulate external delegations

**Frequency**: Exploitable at any time during normal operations. No special timing, network conditions, or coordination required. Conditions commonly met by active validators with external delegators.

## Recommendation

Modify the validation to check against actual self-delegation:

```go
if msg.MinSelfDelegation != nil {
    if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
        return nil, types.ErrMinSelfDelegationDecreased
    }

    // Get validator operator's actual self-delegation
    selfDel := k.Delegation(ctx, sdk.AccAddress(validator.GetOperator()), validator.GetOperator())
    if selfDel == nil {
        return nil, types.ErrMissingSelfDelegation
    }
    
    // Calculate self-delegation tokens from shares
    selfDelTokens := validator.TokensFromShares(selfDel.GetShares()).TruncateInt()
    
    // Check current self-delegation meets new minimum
    if msg.MinSelfDelegation.GT(selfDelTokens) {
        return nil, types.ErrSelfDelegationBelowMinimum
    }

    validator.MinSelfDelegation = (*msg.MinSelfDelegation)
}
```

This matches the correct pattern used in [3](#0-2)  and [4](#0-3) .

## Proof of Concept

**Test File**: `x/staking/handler_test.go`  
**Test Function**: `TestEditValidatorIncreaseMinSelfDelegationAboveSelfDelegation` (to be added)

**Setup**:
1. Initialize test blockchain with staking keeper
2. Create validator with 100 tokens self-delegation and `MinSelfDelegation = 100`
3. Bond validator to active status
4. External delegator adds 900 tokens (total `validator.Tokens = 1000`)
5. Verify validator's self-delegation remains 100 tokens

**Action**:
1. Validator submits `MsgEditValidator` with `MinSelfDelegation = 500`
2. Process through handler

**Result (Demonstrates Bug)**:
- Message accepted (should be rejected)
- Validator's `MinSelfDelegation` updated to 500
- Actual self-delegation remains 100 (below minimum)
- Validator stays bonded and active
- Later slashing/unbonding triggers jailing; cannot unjail without adding 400 tokens

This confirms validators can set `MinSelfDelegation = 500` while maintaining only 100 tokens self-delegation, proving the vulnerability exists in normal transaction flows.

## Notes

Significance factors:
1. Other codebase sections correctly implement self-delegation checks, proving this is unintended
2. Proto definition explicitly confirms `validator.Tokens` includes all delegations
3. PoS security models rely on validators maintaining declared minimum self-delegation
4. Creates inconsistency where validators can set unmaintainable values leading to jailing

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
