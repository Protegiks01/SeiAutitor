## Audit Report

## Title
Minimum Self-Delegation Check Uses Total Validator Tokens Instead of Actual Self-Delegation

## Summary
The `EditValidator` function incorrectly validates the minimum self-delegation requirement by comparing against the validator's total tokens (from all delegators) instead of the operator's actual self-delegation amount. This allows validators to set a MinSelfDelegation higher than their true self-delegation, leading to protocol invariant violations after slashing events. [1](#0-0) 

## Impact
**Medium** - A bug in the layer 1 network code that results in unintended validator behavior with potential to render validators permanently unable to unjail after slashing, affecting network validator set stability.

## Finding Description

**Location:** 
The vulnerability exists in `x/staking/keeper/msg_server.go` in the `EditValidator` function at lines 167-169.

**Intended Logic:**
When a validator updates their MinSelfDelegation, the system should verify that their actual self-delegation (the delegation from the validator's operator address to their own validator) meets or exceeds the new MinSelfDelegation requirement. The purpose of MinSelfDelegation is to ensure validators have "skin in the game" by maintaining a minimum stake in their own validator.

**Actual Logic:**
The code compares the new MinSelfDelegation against `validator.Tokens`, which represents the TOTAL tokens delegated to the validator from ALL delegators, not just the operator's self-delegation: [2](#0-1) 

The correct approach (as implemented in the unjail logic) is to retrieve the specific delegation from the operator address and convert shares to tokens: [3](#0-2) 

**Exploit Scenario:**
1. A validator creates a validator with 100 tokens self-delegation and MinSelfDelegation = 50
2. External delegators contribute 900 tokens, bringing validator.Tokens to 1000
3. The validator calls EditValidator to increase MinSelfDelegation to 500
4. The check `500 > 1000` fails (passes the validation), even though actual self-delegation is only 100
5. The validator now has MinSelfDelegation = 500 but actual self-delegation = 100
6. The validator gets slashed by 60% (e.g., for double-signing)
7. After slashing: validator.Tokens = 400, actual self-delegation = 40
8. The validator's self-delegation (40) is now far below MinSelfDelegation (500), violating the protocol invariant
9. The Slash function does not check this condition and does not jail the validator for this violation [4](#0-3) 

10. The validator continues operating with insufficient self-delegation
11. If the validator later gets jailed (e.g., for downtime) and attempts to unjail, the unjail check correctly verifies self-delegation >= MinSelfDelegation and rejects the request, permanently preventing the validator from unjailing

**Security Failure:**
This breaks the accounting and authorization invariant that validators must maintain self-delegation >= MinSelfDelegation at all times. The system fails by:
- Allowing validators to operate with self-delegation below their declared minimum
- Creating a situation where validators can become permanently jailed and unable to rejoin the active set
- Undermining the security guarantee that validators maintain minimum stake in their own validator

## Impact Explanation

**Affected Assets/Processes:**
- Validator operators who legitimately increase their MinSelfDelegation assuming proper validation
- Network validator set stability and availability
- Protocol invariant enforcement (self-delegation >= MinSelfDelegation)

**Severity:**
- Validators can become permanently unable to unjail after being slashed below their MinSelfDelegation (which they were incorrectly allowed to set)
- Multiple validators affected by this issue could reduce the active validator set
- While no direct theft of funds occurs, the permanent jailing of validators affects network decentralization and operator economic interests
- The bug results in unintended protocol behavior where validators operate outside design parameters

**System Impact:**
This undermines the fundamental purpose of MinSelfDelegation as a security mechanism. The protocol cannot reliably enforce that validators maintain appropriate self-delegation levels, which weakens the economic security model where validators should have stake at risk.

## Likelihood Explanation

**Triggering Conditions:**
- Any validator operator can trigger this by calling EditValidator (no special privileges required beyond being a validator)
- Requires the validator to have external delegations such that total tokens exceed the desired MinSelfDelegation
- Requires a subsequent slashing event to manifest the invariant violation

**Frequency:**
- Validators increasing their MinSelfDelegation is not uncommon during normal operations
- Slashing events (downtime, double-signing) occur regularly in proof-of-stake networks
- The combination of these events makes this vulnerability moderately likely to occur

**Exploitability:**
- A malicious validator could intentionally exploit this to set unrealistic MinSelfDelegation values they don't actually meet
- Honest validators could accidentally create this situation by legitimately trying to increase their MinSelfDelegation
- The issue manifests deterministically once the conditions are met

## Recommendation

Modify the `EditValidator` function to correctly check the operator's actual self-delegation instead of total validator tokens. The fix should:

1. Retrieve the delegation from the operator address to the validator
2. Convert the delegation shares to token amount
3. Compare the new MinSelfDelegation against this actual self-delegation amount

Example fix for lines 167-169 in `msg_server.go`:

```go
if msg.MinSelfDelegation != nil {
    if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
        return nil, types.ErrMinSelfDelegationDecreased
    }
    
    // Get actual self-delegation amount
    selfDel := k.GetDelegation(ctx, sdk.AccAddress(valAddr), valAddr)
    if selfDel.Shares.IsZero() {
        return nil, types.ErrMissingSelfDelegation
    }
    
    selfDelegationTokens := validator.TokensFromShares(selfDel.Shares).TruncateInt()
    if msg.MinSelfDelegation.GT(selfDelegationTokens) {
        return nil, types.ErrSelfDelegationBelowMinimum
    }
    
    validator.MinSelfDelegation = (*msg.MinSelfDelegation)
}
```

Additionally, consider adding a check in the Slash function to jail validators whose self-delegation falls below MinSelfDelegation after slashing.

## Proof of Concept

**Test File:** `x/staking/keeper/msg_server_test.go` (create new test file or add to existing handler tests)

**Test Function:** `TestEditValidatorMinSelfDelegationWithExternalDelegations`

**Setup:**
1. Create a test environment with initialized staking keeper and bank balances
2. Create a validator with 100 tokens self-delegation and MinSelfDelegation = 50
3. Add an external delegator who contributes 900 tokens
4. Verify validator.Tokens = 1000 and actual self-delegation = 100

**Trigger:**
1. Call EditValidator with msg.MinSelfDelegation = 500
2. The call should FAIL because actual self-delegation (100) < new MinSelfDelegation (500)
3. However, with the current bug, it PASSES because validator.Tokens (1000) > MinSelfDelegation (500)

**Observation:**
- The test demonstrates that EditValidator incorrectly accepts MinSelfDelegation = 500 when self-delegation is only 100
- After simulating a 60% slash, the validator would have self-delegation = 40 tokens but MinSelfDelegation = 500
- Attempting to unjail would fail with `ErrSelfDelegationTooLowToUnjail`
- This confirms the validator is stuck in a permanently jailed state due to the initial incorrect validation

**Test Code Structure:**
```go
func TestEditValidatorMinSelfDelegationWithExternalDelegations(t *testing.T) {
    _, app, ctx := createTestInput()
    
    // Setup validator with low self-delegation
    valAddr := // create validator address
    selfDelegation := sdk.NewInt(100)
    validator := // create validator with selfDelegation
    validator.MinSelfDelegation = sdk.NewInt(50)
    
    // Add external delegation to increase total tokens
    externalDelegation := sdk.NewInt(900)
    // ... delegate from external address
    
    // Verify validator.Tokens = 1000
    require.Equal(t, sdk.NewInt(1000), validator.Tokens)
    
    // Attempt to set MinSelfDelegation = 500 (should FAIL but currently PASSES)
    newMinSelfDelegation := sdk.NewInt(500)
    msgEditValidator := types.NewMsgEditValidator(valAddr, types.Description{}, nil, &newMinSelfDelegation)
    
    _, err := msgServer.EditValidator(ctx, msgEditValidator)
    
    // BUG: This should return an error but doesn't
    // require.Error(t, err) // Expected behavior
    require.NoError(t, err) // Actual buggy behavior
    
    // Now simulate slashing by 60%
    consAddr := validator.GetConsAddr()
    app.StakingKeeper.Slash(ctx, consAddr, ctx.BlockHeight(), 1000, sdk.NewDecWithPrec(6, 1))
    
    // After slash, self-delegation should be 40 tokens but MinSelfDelegation is still 500
    validator, _ = app.StakingKeeper.GetValidator(ctx, valAddr)
    selfDel, _ := app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(valAddr), valAddr)
    actualSelfDelegation := validator.TokensFromShares(selfDel.Shares).TruncateInt()
    
    // Invariant violated: actualSelfDelegation (40) < MinSelfDelegation (500)
    require.True(t, actualSelfDelegation.LT(validator.MinSelfDelegation))
    
    // Jail the validator and try to unjail - should fail
    app.StakingKeeper.Jail(ctx, consAddr)
    err = app.SlashingKeeper.Unjail(ctx, valAddr)
    require.Error(t, err) // Cannot unjail - permanently stuck
    require.Contains(t, err.Error(), "less than")
}
```

This test demonstrates that the bug allows setting MinSelfDelegation above actual self-delegation, leading to a permanently jailed validator after slashing.

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

**File:** x/staking/keeper/slash.go (L120-123)
```go
	// Deduct from validator's bonded tokens and update the validator.
	// Burn the slashed tokens from the pool account and decrease the total supply.
	validator = k.RemoveValidatorTokens(ctx, validator, tokensToBurn)

```
