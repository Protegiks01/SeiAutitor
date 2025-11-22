## Audit Report

## Title
Asymmetric Commission Rate Change Validation Allows Economic Exploitation of Delegators

## Summary
The `ValidateNewRate` function in the staking module only enforces `MaxChangeRate` limits on commission increases but not on decreases. This allows validators to bypass the protection mechanism by dropping commission rates arbitrarily in a single update, then slowly increasing them back while delegators are locked in the unbonding period. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary vulnerability: `x/staking/types/commission.go`, lines 97-99 in `ValidateNewRate` function
- Called from: `x/staking/keeper/validator.go`, line 137 in `UpdateValidatorCommission` function [2](#0-1) 

**Intended Logic:** 
The `MaxChangeRate` parameter is designed to protect delegators from sudden commission changes by limiting how much a validator can adjust their commission rate in a single update. The protection should apply symmetrically to both increases and decreases to prevent market manipulation and protect delegators from being lured by artificially low rates that can then be quickly increased.

**Actual Logic:**
The validation check at line 97 only validates commission increases:
```go
case newRate.Sub(c.Rate).GT(c.MaxChangeRate):
```

When `newRate < c.Rate` (a decrease), the subtraction `newRate.Sub(c.Rate)` produces a negative value. A negative value is never greater than `MaxChangeRate` (which is positive), so the check passes regardless of the magnitude of the decrease.

This is confirmed by the existing test case which shows a decrease from 0.40 to 0.10 (0.30 decrease, exceeding MaxChangeRate of 0.10) is considered valid: [3](#0-2) 

**Exploit Scenario:**
1. Validator creates a validator with initial commission of 5%, MaxRate of 50%, and MaxChangeRate of 1%
2. Over 45 days, validator increases commission to 50% in daily 1% increments (respecting MaxChangeRate)
3. After collecting high commissions, validator waits 24 hours then drops commission to 5% in a single update (45% decrease, bypassing MaxChangeRate check)
4. The artificially low commission attracts new delegators who delegate significant amounts
5. Over the next 21+ days (during the unbonding period), validator increases commission back to 50% in daily 1% increments
6. Delegators who were attracted by the low rate are now locked in for 21 days and must either accept the high commission or unbond and lose 21 days of staking rewards
7. Cycle repeats, systematically extracting value from delegators

**Security Failure:**
The security invariant that `MaxChangeRate` should protect delegators from sudden commission changes is violated. This breaks the economic protection mechanism and enables a validator to manipulate delegation flows through asymmetric rate changes, leading to direct loss of staking rewards for affected delegators.

## Impact Explanation

**Affected Assets:**
- Delegator staking rewards (lost to excessive validator commissions)
- Market integrity of the validator delegation system
- Trust in the staking mechanism's protection parameters

**Severity:**
- Delegators can lose substantial staking rewards by being lured into delegation during artificially low commission periods, then exploited during high commission periods while locked in unbonding
- The 21-day unbonding period (default) provides a large window for validators to extract value
- This creates a systemic vulnerability where rational validators are incentivized to game the system rather than compete fairly

**System Impact:**
This matters because it undermines the fundamental trust model of the staking system. The `MaxChangeRate` parameter is explicitly designed to provide predictability and protection, but it only works in one direction, creating an exploitable asymmetry.

## Likelihood Explanation

**Who can trigger it:**
Any validator operator can execute this exploit. No special privileges beyond operating a validator are required.

**Conditions required:**
- Validator must wait 24 hours between commission updates (normal cooldown)
- Validator must respect `MaxChangeRate` when increasing (but can bypass it when decreasing)
- Exploits the default 21-day unbonding period to lock in delegators

**Frequency:**
- Can be executed repeatedly in cycles
- Each cycle takes approximately 45 days (increase phase) + 21-45 days (exploit phase) = 2-3 months
- Multiple validators could coordinate this behavior simultaneously for greater market impact
- Highly likely to occur in practice as it's economically rational for validators

## Recommendation

Modify the `ValidateNewRate` function to enforce `MaxChangeRate` symmetrically for both increases and decreases:

```go
func (c Commission) ValidateNewRate(newRate sdk.Dec, blockTime time.Time) error {
    switch {
    case blockTime.Sub(c.UpdateTime).Hours() < 24:
        return ErrCommissionUpdateTime
    case newRate.IsNegative():
        return ErrCommissionNegative
    case newRate.GT(c.MaxRate):
        return ErrCommissionGTMaxRate
    case newRate.Sub(c.Rate).Abs().GT(c.MaxChangeRate):  // Use Abs() to check both directions
        return ErrCommissionGTMaxChangeRate
    }
    return nil
}
```

This ensures that both increases and decreases are limited by `MaxChangeRate`, preventing asymmetric exploitation.

## Proof of Concept

**File:** `x/staking/keeper/validator_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func TestCommissionRateAsymmetricExploit(t *testing.T) {
    app, ctx, _, addrVals := bootstrapValidatorTest(t, 1000, 1)
    
    // Start at a time that allows commission updates
    initialTime := time.Now().UTC()
    ctx = ctx.WithBlockHeader(tmproto.Header{Time: initialTime})
    
    // Create validator with commission: Rate=5%, MaxRate=50%, MaxChangeRate=1%
    commission := types.NewCommissionWithTime(
        sdk.MustNewDecFromStr("0.05"), // rate 5%
        sdk.MustNewDecFromStr("0.50"), // max rate 50%
        sdk.MustNewDecFromStr("0.01"), // max change rate 1%
        initialTime.Add(-48 * time.Hour), // Set update time in past to allow immediate update
    )
    
    validator := teststaking.NewValidator(t, addrVals[0], PKs[0])
    validator, _ = validator.SetInitialCommission(commission)
    app.StakingKeeper.SetValidator(ctx, validator)
    
    // Phase 1: Increase commission to 50% over time (respecting MaxChangeRate of 1%)
    currentRate := sdk.MustNewDecFromStr("0.05")
    targetRate := sdk.MustNewDecFromStr("0.50")
    
    // Simulate daily increases of 1% until reaching 50%
    for currentRate.LT(targetRate) {
        ctx = ctx.WithBlockHeader(tmproto.Header{Time: ctx.BlockTime().Add(24 * time.Hour)})
        newRate := currentRate.Add(sdk.MustNewDecFromStr("0.01"))
        if newRate.GT(targetRate) {
            newRate = targetRate
        }
        
        updatedCommission, err := app.StakingKeeper.UpdateValidatorCommission(ctx, validator, newRate)
        require.NoError(t, err, "Should allow 1%% increase per day")
        
        validator.Commission = updatedCommission
        app.StakingKeeper.SetValidator(ctx, validator)
        currentRate = newRate
    }
    
    require.Equal(t, targetRate, currentRate, "Should reach 50%% commission")
    
    // Phase 2: Drop commission to 5% in a SINGLE update (45% decrease - bypassing MaxChangeRate!)
    ctx = ctx.WithBlockHeader(tmproto.Header{Time: ctx.BlockTime().Add(24 * time.Hour)})
    exploitRate := sdk.MustNewDecFromStr("0.05")
    
    // This decrease of 45% (from 50% to 5%) exceeds MaxChangeRate of 1%
    // but the validation INCORRECTLY allows it
    updatedCommission, err := app.StakingKeeper.UpdateValidatorCommission(ctx, validator, exploitRate)
    
    // THE VULNERABILITY: This should fail but doesn't!
    require.NoError(t, err, "VULNERABILITY: Allows 45%% decrease despite 1%% MaxChangeRate")
    require.Equal(t, exploitRate, updatedCommission.Rate, "Commission dropped to 5%% in one update")
    
    // Demonstrate the exploit: The validator can now attract delegators with 5% commission,
    // then increase back to 50% over 45 days while they're locked in unbonding period
    t.Logf("EXPLOIT DEMONSTRATED: Validator decreased commission by 45%% (from 50%% to 5%%) in a single update, despite MaxChangeRate being only 1%%")
}
```

**Setup:**
1. Initialize test environment with one validator address
2. Create validator with initial commission of 5%, MaxRate 50%, MaxChangeRate 1%

**Trigger:**
1. Simulate daily commission increases over 45 days from 5% to 50% (all respecting 1% MaxChangeRate)
2. After 24 hours, attempt to decrease commission from 50% to 5% in a single update (45% decrease)

**Observation:**
The test demonstrates that the 45% decrease succeeds despite MaxChangeRate being only 1%. This confirms the vulnerability: decreases bypass the MaxChangeRate protection, allowing economic exploitation of delegators. The test passes when it should fail, proving the asymmetric validation logic.

**Notes:**
- The default minimum commission rate is 5%, so the test uses 5% as the low rate
- The unbonding period is 21 days by default, providing ample time for the exploit
- Multiple validators could coordinate this behavior for systematic market manipulation

### Citations

**File:** x/staking/types/commission.go (L83-103)
```go
func (c Commission) ValidateNewRate(newRate sdk.Dec, blockTime time.Time) error {
	switch {
	case blockTime.Sub(c.UpdateTime).Hours() < 24:
		// new rate cannot be changed more than once within 24 hours
		return ErrCommissionUpdateTime

	case newRate.IsNegative():
		// new rate cannot be negative
		return ErrCommissionNegative

	case newRate.GT(c.MaxRate):
		// new rate cannot be greater than the max rate
		return ErrCommissionGTMaxRate

	case newRate.Sub(c.Rate).GT(c.MaxChangeRate):
		// new rate % points change cannot be greater than the max change rate
		return ErrCommissionGTMaxChangeRate
	}

	return nil
}
```

**File:** x/staking/keeper/validator.go (L130-148)
```go
// UpdateValidatorCommission attempts to update a validator's commission rate.
// An error is returned if the new commission rate is invalid.
func (k Keeper) UpdateValidatorCommission(ctx sdk.Context,
	validator types.Validator, newRate sdk.Dec) (types.Commission, error) {
	commission := validator.Commission
	blockTime := ctx.BlockHeader().Time

	if err := commission.ValidateNewRate(newRate, blockTime); err != nil {
		return commission, err
	}

	if newRate.LT(k.MinCommissionRate(ctx)) {
		return commission, fmt.Errorf("cannot set validator commission to less than minimum rate of %s", k.MinCommissionRate(ctx))
	}
	commission.Rate = newRate
	commission.UpdateTime = blockTime

	return commission, nil
}
```

**File:** x/staking/types/commission_test.go (L62-62)
```go
		{c1, sdk.MustNewDecFromStr("0.10"), now.Add(48 * time.Hour), false},
```
