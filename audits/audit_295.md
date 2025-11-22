# Audit Report

## Title
EditValidator Allows Setting MinSelfDelegation Above Actual Self-Delegation Due to Incorrect Validation

## Summary
The `EditValidator` function in `msg_server.go` contains a logic error that validates the new `MinSelfDelegation` against total validator tokens instead of actual self-delegation. This allows validators with external delegations to set `MinSelfDelegation` higher than their actual self-delegation, causing immediate jailing upon any subsequent unbonding operation. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** `x/staking/keeper/msg_server.go`, lines 162-172, specifically line 167 in the `EditValidator` function.

**Intended Logic:** When a validator increases their `MinSelfDelegation`, the system should verify that their current self-delegation (tokens delegated by the validator operator to themselves) meets or exceeds the new minimum. This ensures the validator cannot set a minimum self-delegation requirement that they themselves do not satisfy.

**Actual Logic:** The code incorrectly validates the new `MinSelfDelegation` against `validator.Tokens` (the total tokens delegated to the validator from all sources) instead of checking the actual self-delegation amount. [2](#0-1) 

The check compares `msg.MinSelfDelegation.GT(validator.Tokens)`, but `validator.Tokens` represents the sum of all delegations including external delegators, not just the validator's own self-delegation. [3](#0-2) 

**Exploit Scenario:**
1. A validator has 100 tokens self-delegated and 900 tokens delegated from external users (total: 1000 tokens)
2. Current `MinSelfDelegation` is 50 tokens
3. Validator calls `EditValidator` to increase `MinSelfDelegation` to 150 tokens
4. The validation check passes because 150 < 1000 (total tokens)
5. `MinSelfDelegation` is set to 150, even though actual self-delegation is only 100
6. On the next unbonding operation (even 1 token), the validator is immediately jailed [4](#0-3) 

The jailing occurs because the unbonding logic correctly checks actual self-delegation against `MinSelfDelegation`, finding the validator below the minimum.

**Security Failure:** This breaks the protocol invariant that a validator's self-delegation must always meet or exceed their `MinSelfDelegation`. The validator enters an inconsistent state where recovery requires adding more self-delegation before they can unjail. [5](#0-4) 

## Impact Explanation

**Affected Processes:**
- Validator operations and consensus participation
- Validator reward accumulation
- Network stability if multiple validators are affected

**Severity:**
- Validators can inadvertently place themselves in a state requiring immediate jailing on any unbonding
- Once jailed, validators cannot unjail without first increasing self-delegation above the incorrectly set `MinSelfDelegation`
- Jailed validators do not participate in consensus and do not earn rewards
- This represents unintended validator behavior with operational and financial consequences

**System Impact:**
While no funds are directly stolen or permanently locked, this bug causes validators to enter an invalid state that disrupts their operations, leading to:
- Loss of validator rewards during jailing period
- Reduced network decentralization if multiple validators are affected
- Requirement for additional capital injection to meet the incorrectly set minimum
- Potential confusion and operational issues for validator operators

## Likelihood Explanation

**Who Can Trigger:**
Only validator operators can trigger this on their own validators through the `EditValidator` message.

**Conditions Required:**
- The validator must have external delegations (delegations from addresses other than the validator operator)
- The validator attempts to increase `MinSelfDelegation` to a value between their actual self-delegation and total delegated tokens

**Frequency:**
This can occur during normal operations when:
- A validator with significant external delegations wants to demonstrate commitment by increasing their minimum
- The validator incorrectly believes they have more self-delegation than they actually do
- The validator miscalculates or misunderstands the relationship between total delegation and self-delegation

This is moderately likely because validators with large external delegations are common in Cosmos chains, and operators may not realize the check uses total tokens rather than self-delegation.

## Recommendation

Modify the validation logic in `EditValidator` to check against actual self-delegation instead of total validator tokens:

```go
if msg.MinSelfDelegation != nil {
    if !msg.MinSelfDelegation.GT(validator.MinSelfDelegation) {
        return nil, types.ErrMinSelfDelegationDecreased
    }
    
    // Get the validator's self-delegation
    selfDel := k.GetDelegation(ctx, sdk.AccAddress(valAddr), valAddr)
    if selfDel == nil {
        return nil, types.ErrMissingSelfDelegation
    }
    
    // Check against actual self-delegation, not total tokens
    selfDelegationAmount := validator.TokensFromShares(selfDel.GetShares()).TruncateInt()
    if msg.MinSelfDelegation.GT(selfDelegationAmount) {
        return nil, types.ErrSelfDelegationBelowMinimum
    }
    
    validator.MinSelfDelegation = (*msg.MinSelfDelegation)
}
```

This matches the pattern used in the unjail logic for consistency. [6](#0-5) 

## Proof of Concept

**File:** `x/staking/handler_test.go`

**Test Function:** Add the following test function:

```go
func TestEditValidatorMinSelfDelegationAboveSelfDelegation(t *testing.T) {
    initPower := int64(1000)
    app, ctx, delAddrs, valAddrs := bootstrapHandlerGenesisTest(t, initPower, 2, sdk.TokensFromConsensusPower(initPower, sdk.DefaultPowerReduction))
    
    validatorAddr := valAddrs[0]
    delegatorAddr := delAddrs[1]
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    // Create validator with 100 tokens self-delegation and MinSelfDelegation of 50
    selfDelegationAmt := app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
    msgCreateValidator := tstaking.CreateValidatorMsg(validatorAddr, PKs[0], selfDelegationAmt)
    msgCreateValidator.MinSelfDelegation = app.StakingKeeper.TokensFromConsensusPower(ctx, 50)
    tstaking.Handle(msgCreateValidator, true)
    
    // End block to bond the validator
    updates, err := app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
    require.NoError(t, err)
    require.Equal(t, 1, len(updates))
    
    // External user delegates 900 tokens to the validator
    externalDelegationAmt := app.StakingKeeper.TokensFromConsensusPower(ctx, 900)
    tstaking.Delegate(delegatorAddr, validatorAddr, externalDelegationAmt)
    
    updates, err = app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
    require.NoError(t, err)
    
    // Verify total validator tokens is 1000
    validator, found := app.StakingKeeper.GetValidator(ctx, validatorAddr)
    require.True(t, found)
    require.Equal(t, app.StakingKeeper.TokensFromConsensusPower(ctx, 1000), validator.Tokens)
    
    // Verify self-delegation is only 100
    selfDel, found := app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(validatorAddr), validatorAddr)
    require.True(t, found)
    selfDelTokens := validator.TokensFromShares(selfDel.Shares).TruncateInt()
    require.Equal(t, selfDelegationAmt, selfDelTokens)
    
    // BUG: Try to increase MinSelfDelegation to 150 (higher than self-delegation of 100)
    // This should fail but succeeds because check uses validator.Tokens (1000) instead of self-delegation (100)
    newMinSelfDelegation := app.StakingKeeper.TokensFromConsensusPower(ctx, 150)
    msgEditValidator := types.NewMsgEditValidator(validatorAddr, types.Description{}, nil, &newMinSelfDelegation)
    tstaking.Handle(msgEditValidator, true) // This succeeds due to the bug
    
    // Verify MinSelfDelegation is now 150 but self-delegation is still only 100
    validator, found = app.StakingKeeper.GetValidator(ctx, validatorAddr)
    require.True(t, found)
    require.Equal(t, newMinSelfDelegation, validator.MinSelfDelegation)
    
    selfDel, found = app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(validatorAddr), validatorAddr)
    require.True(t, found)
    selfDelTokens = validator.TokensFromShares(selfDel.Shares).TruncateInt()
    require.Equal(t, selfDelegationAmt, selfDelTokens) // Still 100, less than MinSelfDelegation of 150
    
    // Validator is now in invalid state: self-delegation (100) < MinSelfDelegation (150)
    // Any unbonding will cause immediate jailing
    
    // Unbond 1 token from self-delegation
    unbondAmt := app.StakingKeeper.TokensFromConsensusPower(ctx, 1)
    tstaking.Undelegate(sdk.AccAddress(validatorAddr), validatorAddr, unbondAmt, true)
    
    // End block to process unbonding
    updates, err = app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
    require.NoError(t, err)
    
    // VULNERABILITY CONFIRMED: Validator is jailed because self-delegation (99) < MinSelfDelegation (150)
    validator, found = app.StakingKeeper.GetValidator(ctx, validatorAddr)
    require.True(t, found)
    require.True(t, validator.Jailed, "validator should be jailed due to self-delegation below MinSelfDelegation")
}
```

**Setup:** The test creates a validator with 100 tokens self-delegation and MinSelfDelegation of 50, then adds 900 tokens from an external delegator.

**Trigger:** The test calls `EditValidator` to increase `MinSelfDelegation` to 150, which succeeds despite self-delegation being only 100. Then it unbonds 1 token.

**Observation:** The validator is immediately jailed after unbonding because their self-delegation (99) is below `MinSelfDelegation` (150), confirming they were allowed to enter an invalid state. The test demonstrates the vulnerability by showing the validator can set `MinSelfDelegation` above their actual self-delegation when they have external delegations.

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

**File:** proto/cosmos/staking/v1beta1/staking.proto (L70-72)
```text
  string security_contact = 4 [(gogoproto.moretags) = "yaml:\"security_contact\""];
  // details define other optional details.
  string details = 5;
```

**File:** x/staking/keeper/delegation.go (L770-774)
```go
	if isValidatorOperator && !validator.Jailed &&
		validator.TokensFromShares(delegation.Shares).TruncateInt().LT(validator.MinSelfDelegation) {
		k.jailValidator(ctx, validator)
		validator = k.mustGetValidator(ctx, validator.GetOperator())
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
