# Audit Report

## Title
Commission Rate Decrease Bypass - MaxChangeRate Validation Only Enforced for Increases

## Summary
The `ValidateNewRate()` function in the staking module only validates `MaxChangeRate` limits for commission rate increases, allowing validators to decrease their commission by any amount regardless of the configured `MaxChangeRate` parameter. This bypasses the intended gradual rate change mechanism.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `MaxChangeRate` parameter is designed to enforce that commission rate changes (in either direction) cannot exceed a specified limit within a 24-hour period. The code comment explicitly states "new rate % points change cannot be greater than the max change rate" [2](#0-1) , indicating that the absolute value of any change should be validated.

**Actual Logic:** The validation uses `newRate.Sub(c.Rate).GT(c.MaxChangeRate)` which performs: `(newRate - currentRate) > MaxChangeRate`. This only catches cases where the result is positive and exceeds the limit. When validators decrease their rate (newRate < currentRate), the subtraction yields a negative value. Since negative values are never greater than positive `MaxChangeRate` values [3](#0-2) , the validation always passes for decreases regardless of magnitude.

**Exploitation Path:**
1. Any validator sends a `MsgEditValidator` transaction with a new commission rate [4](#0-3) 
2. The transaction is processed through `UpdateValidatorCommission` [5](#0-4) 
3. `ValidateNewRate()` is called to validate the change [6](#0-5) 
4. For rate decreases, the check at line 97 passes regardless of how large the decrease is
5. The commission rate is updated, bypassing the intended `MaxChangeRate` restriction

**Security Guarantee Broken:** The invariant that commission rate changes must be gradual and limited by `MaxChangeRate` is violated for decreases. The existing test suite confirms this: a validator with rate 0.40 and MaxChangeRate 0.10 can decrease to 0.10 (a 0.30 or 30% decrease, 3x the limit) [7](#0-6) .

## Impact Explanation

This vulnerability allows validators to manipulate the delegation market by:

1. **Market Manipulation:** Validators can suddenly drop their commission to 0% to attract delegators, then gradually increase it back up (respecting the limit for increases), effectively luring delegators with artificially low rates
2. **Unfair Competition:** Creates an asymmetric competitive advantage where validators can rapidly decrease rates but competitors cannot respond as quickly
3. **Delegator Protection Bypass:** The `MaxChangeRate` mechanism is designed to protect delegators from sudden rate changes, but this protection only applies to increases
4. **Validator Set Instability:** Large sudden commission drops can trigger rapid delegation shifts, potentially destabilizing the validator set distribution

This qualifies as Medium severity under: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Exploitability:** High
- Any validator can trigger this through normal `MsgEditValidator` transactions
- No special privileges or conditions required beyond being a validator
- Can be executed once every 24 hours (after the standard cooldown period)

**Motivation:** Validators have direct financial incentives to attract more delegations to increase their rewards. The ability to bypass rate change restrictions provides a competitive advantage that rational validators would exploit.

**Frequency:** Can be exploited repeatedly by any validator in the network once per 24-hour period.

## Recommendation

Modify the validation logic in `ValidateNewRate()` to check the absolute value of the rate change:

Replace line 97 with:
```go
case newRate.Sub(c.Rate).Abs().GT(c.MaxChangeRate):
    // new rate % points change cannot be greater than the max change rate
    return ErrCommissionGTMaxChangeRate
```

This ensures both increases and decreases are subject to the `MaxChangeRate` limit, maintaining the intended invariant that commission changes must be gradual regardless of direction. The `Abs()` method is already available in the decimal type [8](#0-7) .

## Proof of Concept

**Test Setup:** The vulnerability is already demonstrated in the existing test suite.

**Existing Test Evidence:**
From `x/staking/types/commission_test.go` lines 40-62:
- Commission c1 is created with: Rate=0.40 (40%), MaxRate=0.80 (80%), MaxChangeRate=0.10 (10%)
- Test case at line 62: `{c1, sdk.MustNewDecFromStr("0.10"), now.Add(48 * time.Hour), false}`
- This tests changing from 0.40 to 0.10 with expectErr=false

**Action:** The change from 0.40 to 0.10 represents a 0.30 decrease (30%)

**Result:** Despite MaxChangeRate being only 0.10 (10%), this 3x bypass is expected to pass validation (expectErr=false), confirming the vulnerability

**Additional PoC:** A validator could:
1. Set commission to 50% with MaxChangeRate of 1%
2. After 24 hours, decrease commission to 0% in a single transaction (bypassing the 1% limit)
3. Attract delegators with 0% commission
4. Gradually increase commission back to desired level (respecting the 1% limit for increases)

## Notes

The code comment at line 98 clearly states "new rate % points **change**" (emphasis added), not "increase", indicating that the validation should apply to changes in both directions. The asymmetric enforcement creates an exploitable loophole that violates the intended design of gradual, predictable commission rate changes.

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

**File:** types/decimal.go (L211-211)
```go
func (d Dec) GT(d2 Dec) bool    { return (d.i).Cmp(d2.i) > 0 }        // greater than
```

**File:** types/decimal.go (L216-216)
```go
func (d Dec) Abs() Dec          { return Dec{new(big.Int).Abs(d.i)} } // absolute value
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

**File:** x/staking/keeper/validator.go (L131-147)
```go
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
```

**File:** x/staking/types/commission_test.go (L62-62)
```go
		{c1, sdk.MustNewDecFromStr("0.10"), now.Add(48 * time.Hour), false},
```
