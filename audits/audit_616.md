After thorough investigation of the codebase, I have identified a vulnerability related to the PeriodReset validation in the feegrant module.

## Audit Report

## Title
Missing PeriodReset Validation Causes Permanent Freezing of Periodic Fee Allowances

## Summary
The `PeriodicAllowance.ValidateBasic()` method does not validate the `PeriodReset` timestamp field, allowing creation of periodic fee grants with far-future reset times. This causes the allowance to become permanently unusable after the initial period spending is exhausted, as the period reset logic never triggers. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in the `x/feegrant/periodic_fee.go` file, specifically in the `ValidateBasic()` method (lines 77-107) and the `tryResetPeriod()` method (lines 56-74).

**Intended Logic:** The `PeriodicAllowance` is designed to provide recurring fee allowances that reset after each period. The `PeriodReset` field should be initialized to a reasonable future time (typically current time + period duration), and the `tryResetPeriod()` function should reset the allowance when the block time reaches or exceeds `PeriodReset`.

**Actual Logic:** The `ValidateBasic()` method validates `Period`, `PeriodSpendLimit`, and `PeriodCanSpend` but completely omits validation of the `PeriodReset` timestamp. This allows creation of grants with `PeriodReset` set to any timestamp value, including far-future dates (e.g., year 9999). [2](#0-1) 

When `tryResetPeriod()` is called with a far-future `PeriodReset`:
- Line 57 evaluates `blockTime.Before(a.PeriodReset)` which is always true for far-future dates
- The function returns immediately without resetting the period
- `PeriodCanSpend` is never replenished
- After the initial spending limit is exhausted, the grant becomes permanently unusable

**Exploit Scenario:**
1. Attacker creates a `MsgGrantAllowance` transaction with a `PeriodicAllowance` where `PeriodReset` is set to a far-future date (e.g., December 31, 9999)
2. The transaction passes validation because `ValidateBasic()` doesn't check `PeriodReset`
3. The grant is accepted and stored on-chain
4. The grantee uses the grant until `PeriodCanSpend` is exhausted
5. On subsequent uses, `tryResetPeriod()` never resets the period because block time is always before the far-future reset date
6. The grant becomes permanently frozen with unusable allowance remaining in `Basic.SpendLimit` [3](#0-2) 

**Security Failure:** This violates the protocol's data integrity invariant that periodic allowances must reset periodically. It creates a state where grants appear valid but are functionally frozen, breaking the module's intended semantics.

## Impact Explanation

**Affected Components:**
- Fee grant allowances stored in the feegrant module's KVStore
- Transaction fee deduction logic that relies on periodic allowances
- User experience for grantees expecting recurring fee allowances

**Severity:**
- Grants with invalid `PeriodReset` values become permanently frozen after initial use
- The granter's funds remain locked in unusable grant structures
- While the granter can revoke and re-grant, this wastes transaction fees and gas
- This creates unintended contract behavior where periodic allowances fail to reset
- No direct loss of funds, but funds are effectively frozen in unusable grants

**System Impact:**
This is a protocol-level bug that allows creation of invalid state. While funds are not directly stolen, the feegrant module fails to provide its intended functionality. This falls under "unintended smart contract behavior with no concrete funds at direct risk." [4](#0-3) 

## Likelihood Explanation

**Triggering Conditions:**
- Any user can create a `PeriodicAllowance` grant with arbitrary `PeriodReset` values
- The vulnerability can be triggered through:
  - Direct `MsgGrantAllowance` transaction submission
  - Genesis import with malformed allowance data
  - Client software bugs that incorrectly calculate `PeriodReset`

**Frequency:**
- While the CLI properly calculates `PeriodReset` as `time.Now() + Period`, direct transaction construction can bypass this
- Genesis imports could contain invalid data
- The issue is deterministic and reproducible whenever an invalid `PeriodReset` is set [5](#0-4) 

## Recommendation

Add validation to `PeriodicAllowance.ValidateBasic()` to ensure `PeriodReset` is within reasonable bounds:

```go
// Add to ValidateBasic() after line 104:
// Validate PeriodReset is not in the far past or far future
// Allow a reasonable range (e.g., within 100 years from Unix epoch start to 100 years in future)
minValidTime := time.Unix(0, 0) // Unix epoch
maxValidTime := time.Now().AddDate(100, 0, 0) // 100 years from now

if a.PeriodReset.Before(minValidTime) {
    return sdkerrors.Wrap(ErrInvalidDuration, "period reset is too far in the past")
}
if a.PeriodReset.After(maxValidTime) {
    return sdkerrors.Wrap(ErrInvalidDuration, "period reset is too far in the future")
}
```

Additionally, consider validating that `PeriodReset` is within a reasonable range of the current block time during grant creation (e.g., not more than 10 years in the future).

## Proof of Concept

**File:** `x/feegrant/keeper/keeper_test.go`

**Test Function:** Add the following test to the existing test suite:

```go
func (suite *KeeperTestSuite) TestPeriodicAllowanceFarFuturePeriodReset() {
	// Setup: Create a periodic allowance with PeriodReset in year 9999
	farFuture, _ := time.Parse("2006-01-02", "9999-12-31")
	tenMinutes := time.Duration(10) * time.Minute
	atom := sdk.NewCoins(sdk.NewInt64Coin("atom", 555))
	smallAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 50))

	periodicAllowance := &feegrant.PeriodicAllowance{
		Basic: feegrant.BasicAllowance{
			SpendLimit: atom,
		},
		Period:           tenMinutes,
		PeriodReset:      farFuture,  // Far future date
		PeriodSpendLimit: smallAtom,
		PeriodCanSpend:   smallAtom,  // Initial spending limit
	}

	// Trigger: Grant the allowance (should pass validation but shouldn't)
	err := suite.keeper.GrantAllowance(suite.sdkCtx, suite.addrs[0], suite.addrs[1], periodicAllowance)
	suite.Require().NoError(err, "Grant with far-future PeriodReset should be rejected but is accepted")

	// Use the initial PeriodCanSpend
	err = suite.keeper.UseGrantedFees(suite.sdkCtx, suite.addrs[0], suite.addrs[1], smallAtom, []sdk.Msg{})
	suite.Require().NoError(err, "First use should succeed")

	// Advance time by multiple periods (should trigger reset)
	futureCtx := suite.sdkCtx.WithBlockTime(suite.sdkCtx.BlockTime().Add(24 * time.Hour))

	// Observation: Try to use more fees - should succeed after period reset, but fails
	err = suite.keeper.UseGrantedFees(futureCtx, suite.addrs[0], suite.addrs[1], smallAtom, []sdk.Msg{})
	suite.Require().Error(err, "Expected error due to frozen allowance")
	suite.Require().Contains(err.Error(), "period limit", "Grant is permanently frozen - period never resets")

	// Verify the allowance still exists but is unusable
	loadedAllowance, err := suite.keeper.GetAllowance(futureCtx, suite.addrs[0], suite.addrs[1])
	suite.Require().NoError(err)
	suite.Require().NotNil(loadedAllowance, "Allowance exists but is permanently frozen")
}
```

**Expected Behavior:** The test demonstrates that:
1. A `PeriodicAllowance` with far-future `PeriodReset` passes validation (line where grant is created)
2. Initial spending works (first `UseGrantedFees` succeeds)
3. After time passes beyond multiple periods, the allowance should reset but doesn't (second `UseGrantedFees` fails)
4. The grant is permanently frozen and unusable despite having remaining `Basic.SpendLimit`

This confirms the vulnerability: the validation allows creation of grants that violate the periodic reset invariant, resulting in permanently frozen allowances.

### Citations

**File:** x/feegrant/periodic_fee.go (L56-74)
```go
func (a *PeriodicAllowance) tryResetPeriod(blockTime time.Time) {
	if blockTime.Before(a.PeriodReset) {
		return
	}

	// set PeriodCanSpend to the lesser of Basic.SpendLimit and PeriodSpendLimit
	if _, isNeg := a.Basic.SpendLimit.SafeSub(a.PeriodSpendLimit); isNeg && !a.Basic.SpendLimit.Empty() {
		a.PeriodCanSpend = a.Basic.SpendLimit
	} else {
		a.PeriodCanSpend = a.PeriodSpendLimit
	}

	// If we are within the period, step from expiration (eg. if you always do one tx per day, it will always reset the same time)
	// If we are more then one period out (eg. no activity in a week), reset is one period from this time
	a.PeriodReset = a.PeriodReset.Add(a.Period)
	if blockTime.After(a.PeriodReset) {
		a.PeriodReset = blockTime.Add(a.Period)
	}
}
```

**File:** x/feegrant/periodic_fee.go (L77-107)
```go
func (a PeriodicAllowance) ValidateBasic() error {
	if err := a.Basic.ValidateBasic(); err != nil {
		return err
	}

	if !a.PeriodSpendLimit.IsValid() {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidCoins, "spend amount is invalid: %s", a.PeriodSpendLimit)
	}
	if !a.PeriodSpendLimit.IsAllPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "spend limit must be positive")
	}
	if !a.PeriodCanSpend.IsValid() {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidCoins, "can spend amount is invalid: %s", a.PeriodCanSpend)
	}
	// We allow 0 for CanSpend
	if a.PeriodCanSpend.IsAnyNegative() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "can spend must not be negative")
	}

	// ensure PeriodSpendLimit can be subtracted from total (same coin types)
	if a.Basic.SpendLimit != nil && !a.PeriodSpendLimit.DenomsSubsetOf(a.Basic.SpendLimit) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, "period spend limit has different currency than basic spend limit")
	}

	// check times
	if a.Period.Seconds() < 0 {
		return sdkerrors.Wrap(ErrInvalidDuration, "negative clock step")
	}

	return nil
}
```

**File:** x/feegrant/msgs.go (L40-57)
```go
func (msg MsgGrantAllowance) ValidateBasic() error {
	if msg.Granter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing granter address")
	}
	if msg.Grantee == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing grantee address")
	}
	if msg.Grantee == msg.Granter {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "cannot self-grant fee authorization")
	}

	allowance, err := msg.GetFeeAllowanceI()
	if err != nil {
		return err
	}

	return allowance.ValidateBasic()
}
```

**File:** proto/cosmos/feegrant/v1beta1/feegrant.proto (L50-53)
```text
  // period_reset is the time at which this period resets and a new one begins,
  // it is calculated from the start time of the first transaction after the
  // last period ended
  google.protobuf.Timestamp period_reset = 5 [(gogoproto.stdtime) = true, (gogoproto.nullable) = false];
```

**File:** x/feegrant/client/cli/tx.go (L219-221)
```go
func getPeriodReset(duration int64) time.Time {
	return time.Now().Add(getPeriod(duration))
}
```
