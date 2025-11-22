## Title
Commission Rate Decrease Bypass - MaxChangeRate Validation Only Enforced for Increases

## Summary
The validator commission rate update validation in `x/staking/types/commission.go` only enforces the `MaxChangeRate` limit on rate increases, allowing validators to decrease their commission rate by any amount regardless of the configured `MaxChangeRate`. This violates the intended invariant that commission changes (both increases and decreases) should be gradual and limited. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in the `ValidateNewRate()` function in `x/staking/types/commission.go` at line 97. [2](#0-1) 

**Intended Logic:** The `MaxChangeRate` parameter is designed to limit how much a validator can change their commission rate in a 24-hour period. According to the specification, commission rate changes should not exceed the `MaxChangeRate`, and the code comment states "new rate % points change cannot be greater than the max change rate." This should apply to both increases and decreases to ensure gradual, predictable commission changes. [3](#0-2) 

**Actual Logic:** The validation check at line 97 uses `newRate.Sub(c.Rate).GT(c.MaxChangeRate)`, which only catches when `newRate > c.Rate` by more than `MaxChangeRate`. When a validator decreases their rate (i.e., `newRate < c.Rate`), the subtraction yields a negative value. Since a negative value is never greater than a positive `MaxChangeRate`, the check passes regardless of how large the decrease is. [4](#0-3) 

**Exploit Scenario:**
1. A validator creates their validator with commission rate = 50%, MaxRate = 100%, MaxChangeRate = 1%
2. After 24 hours, the validator submits a `MsgEditValidator` transaction to decrease commission to 0%
3. Despite the MaxChangeRate being only 1%, the 50% decrease is allowed because the validation logic doesn't check the absolute value of the change
4. This attracts many delegators who see the 0% commission
5. The validator can then gradually increase commission back up (respecting the 1% MaxChangeRate on increases), extracting value from delegators who were attracted by the artificially low rate [5](#0-4) 

**Security Failure:** This breaks the commission rate change invariant and allows validators to manipulate delegation flows through sudden commission drops, creating an unfair competitive advantage and potentially destabilizing the validator set distribution.

## Impact Explanation

This vulnerability affects the staking module's validator commission system, which directly impacts:

- **Delegation Market Integrity:** Validators can bypass rate change restrictions to artificially attract delegators through sudden commission drops, creating unfair competition
- **Delegator Protection:** The MaxChangeRate parameter exists to protect delegators from validators who might lure them with low rates then gradually increase. This protection is circumvented for decreases
- **Validator Set Stability:** Sudden large commission drops can cause rapid delegation shifts, potentially destabilizing the validator set distribution

The existing test suite actually demonstrates this issue - a validator with rate 0.40 and MaxChangeRate 0.10 can drop to rate 0.10 (a 0.30 decrease, 3x the configured limit) and it's considered valid: [6](#0-5) 

This qualifies as **Medium severity** under the bug bounty scope: "A bug in the layer 1 network code that results in unintended behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger it:** Any validator operator can exploit this through normal `MsgEditValidator` transactions. No special privileges beyond being a validator are required.

**Conditions required:** 
- The validator must wait 24 hours between commission updates (standard cooldown period)
- No other special conditions are needed - this works during normal chain operation

**Frequency:** This can be exploited repeatedly by any validator once per 24-hour period. Given that validators have direct financial incentives to attract more delegations, this vulnerability is likely to be discovered and exploited in practice.

## Recommendation

Modify the validation logic in `ValidateNewRate()` to check the absolute value of the rate change:

Replace the check at line 97 with:
```go
case newRate.Sub(c.Rate).Abs().GT(c.MaxChangeRate):
    // new rate % points change cannot be greater than the max change rate
    return ErrCommissionGTMaxChangeRate
```

This ensures that both increases and decreases are subject to the `MaxChangeRate` limit, maintaining the intended invariant that commission changes should be gradual regardless of direction.

## Proof of Concept

**Test Location:** Add this test to `x/staking/types/commission_test.go`

**Test Function:**
```go
func TestCommissionLargeDecreaseBypassesMaxChangeRate(t *testing.T) {
    // Setup: Create a commission with high rate and low MaxChangeRate
    now := time.Now().UTC()
    commission := types.NewCommission(
        sdk.MustNewDecFromStr("0.50"), // Current rate: 50%
        sdk.MustNewDecFromStr("1.00"), // Max rate: 100%
        sdk.MustNewDecFromStr("0.01"), // Max change rate: 1%
    )
    commission.UpdateTime = now
    
    // Trigger: Attempt to decrease rate by 50% (50x the MaxChangeRate limit)
    blockTime := now.Add(48 * time.Hour) // 48 hours later, past the 24h cooldown
    newRate := sdk.ZeroDec() // Drop to 0%
    
    err := commission.ValidateNewRate(newRate, blockTime)
    
    // Observation: The validation INCORRECTLY passes
    // This should fail because the change (0.50) exceeds MaxChangeRate (0.01)
    // But it passes because the code only checks increases, not decreases
    require.NoError(t, err, "Large commission decrease should fail but passes - vulnerability confirmed")
    
    // To verify this is indeed a bypass: try the same magnitude increase
    commission2 := types.NewCommission(
        sdk.ZeroDec(),
        sdk.MustNewDecFromStr("1.00"),
        sdk.MustNewDecFromStr("0.01"),
    )
    commission2.UpdateTime = now
    
    err2 := commission2.ValidateNewRate(sdk.MustNewDecFromStr("0.50"), blockTime)
    
    // The increase correctly fails
    require.Error(t, err2, "Large commission increase correctly fails")
}
```

**Expected Result:** This test will pass on the vulnerable code, demonstrating that large decreases bypass the MaxChangeRate validation while large increases are properly rejected. The asymmetric behavior confirms the vulnerability.

### Citations

**File:** x/staking/types/commission.go (L81-103)
```go
// ValidateNewRate performs basic sanity validation checks of a new commission
// rate. If validation fails, an SDK error is returned.
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

**File:** x/staking/spec/03_messages.md (L43-48)
```markdown
This message is expected to fail if:

- the initial `CommissionRate` is either negative or > `MaxRate`
- the `CommissionRate` has already been updated within the previous 24 hours
- the `CommissionRate` is > `MaxChangeRate`
- the description fields are too large
```

**File:** types/decimal.go (L211-211)
```go
func (d Dec) GT(d2 Dec) bool    { return (d.i).Cmp(d2.i) > 0 }        // greater than
```

**File:** x/staking/keeper/msg_server.go (L130-160)
```go
func (k msgServer) EditValidator(goCtx context.Context, msg *types.MsgEditValidator) (*types.MsgEditValidatorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return nil, err
	}
	// validator must already be registered
	validator, found := k.GetValidator(ctx, valAddr)
	if !found {
		return nil, types.ErrNoValidatorFound
	}

	// replace all editable fields (clients should autofill existing values)
	description, err := validator.Description.UpdateDescription(msg.Description)
	if err != nil {
		return nil, err
	}

	validator.Description = description

	if msg.CommissionRate != nil {
		commission, err := k.UpdateValidatorCommission(ctx, validator, *msg.CommissionRate)
		if err != nil {
			return nil, err
		}

		// call the before-modification hook since we're about to update the commission
		k.BeforeValidatorModified(ctx, valAddr)

		validator.Commission = commission
	}
```

**File:** x/staking/types/commission_test.go (L62-62)
```go
		{c1, sdk.MustNewDecFromStr("0.10"), now.Add(48 * time.Hour), false},
```
