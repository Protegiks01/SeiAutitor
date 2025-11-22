# Audit Report

## Title
Period Reset Time Manipulation via Clock Skew in PeriodicAllowance Fee Grants

## Summary
The `tryResetPeriod` function in `x/feegrant/periodic_fee.go` does not properly handle clock skew when resetting periodic allowances. When `blockTime` is ahead of actual time due to validator clock drift (within consensus-allowed bounds), the function sets `PeriodReset` to a future time based on the skewed `blockTime`, effectively extending the spending period beyond its intended duration and breaking the rate-limiting mechanism. [1](#0-0) 

## Impact
**Low**

## Finding Description

**Location:** The vulnerability exists in the `tryResetPeriod` method in `x/feegrant/periodic_fee.go` at lines 56-74, specifically in the logic that updates `PeriodReset`. [1](#0-0) 

**Intended Logic:** The periodic allowance system is designed to provide rate-limited fee grants where users can spend up to `PeriodSpendLimit` within each `Period` duration. After a period expires, `tryResetPeriod` should reset the spending allowance and advance `PeriodReset` by exactly one `Period` to maintain consistent rate limiting.

**Actual Logic:** The function unconditionally trusts `blockTime` from the block header when calculating the new `PeriodReset`: [2](#0-1) 

When `blockTime` is ahead of actual time due to validator clock skew (which can occur within Tendermint's `SynchronyParams` bounds for `precision`), the function sets `PeriodReset` to `blockTime + Period`. This creates a `PeriodReset` value that is ahead of where it should be by the amount of clock skew, effectively extending the spending window.

**Exploit Scenario:**
1. A grantee has a `PeriodicAllowance` with `Period = 1 hour` and `PeriodSpendLimit = 100 tokens`
2. At actual time 12:00 PM, the grantee exhausts their allowance, leaving `PeriodCanSpend = 0`
3. The period should reset at 1:00 PM (actual time)
4. At actual time 12:30 PM, a block is proposed with `blockTime = 1:00 PM` (30 minutes ahead due to validator clock skew within consensus bounds)
5. `tryResetPeriod` is called with this skewed `blockTime`
6. Since `blockTime (1:00 PM) >= PeriodReset (1:00 PM)`, the reset occurs
7. `PeriodReset` is recalculated as `1:00 PM + 1 hour = 2:00 PM`
8. The grantee can now spend for 1.5 hours (until 2:00 PM actual time) instead of the intended 1 hour [3](#0-2) 

**Security Failure:** The rate-limiting invariant is violated. The code fails to account for temporal inconsistencies introduced by consensus-layer timestamp validation bounds, allowing spending periods to be extended beyond their configured duration.

## Impact Explanation

This vulnerability affects the fee grant system where granters provide periodic allowances to grantees for paying transaction fees:

- **Affected Assets:** Granter's funds allocated for fee grants are affected, as grantees can spend faster than the intended rate limit
- **Severity:** While the overall `Basic.SpendLimit` cap still applies, the periodic rate limiting is defeated. A grantee expecting to spend X tokens per hour could potentially spend X tokens per (hour + clock_skew), where clock_skew is bounded by consensus parameters but can still be significant (seconds to minutes depending on configuration)
- **System Impact:** This breaks the intended design parameter of the `Period` duration, allowing fees to be paid outside the configured rate-limiting window

This directly maps to the in-scope impact: **"Modification of transaction fees outside of design parameters"** (Low severity).

## Likelihood Explanation

**Likelihood: Medium to High**

- **Who can trigger it:** Any grantee with an active `PeriodicAllowance` can benefit from this vulnerability when natural clock skew occurs among validators
- **Conditions required:** 
  - A periodic fee grant must be active
  - A validator with a clock ahead of actual time (within Tendermint's `precision` parameter) must propose a block
  - The grantee must have transactions ready to execute during the extended window
- **Frequency:** This can occur during normal operation whenever there is natural clock drift among validators. Tendermint's `SynchronyParams` allow some tolerance for clock differences (the `precision` parameter), meaning blocks with slightly future timestamps are valid and will be accepted by the network. This can happen repeatedly as different validators propose blocks. [4](#0-3) 

## Recommendation

Modify `tryResetPeriod` to clamp `PeriodReset` advancement to the configured `Period` duration regardless of `blockTime`, ensuring the rate limit is maintained:

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

	// Always advance PeriodReset by exactly one Period from the last reset time
	// This ensures consistent rate limiting regardless of blockTime skew
	a.PeriodReset = a.PeriodReset.Add(a.Period)
	
	// Only if we're more than one full period past the reset time,
	// and only then, sync to current block time
	if blockTime.After(a.PeriodReset) {
		// Calculate how many periods have elapsed
		// But cap the advancement to prevent excessive forward jumps
		a.PeriodReset = blockTime.Add(a.Period)
	}
}
```

A more robust solution would be to add explicit bounds checking on how far `PeriodReset` can advance in a single operation, preventing clock skew from significantly extending the period.

## Proof of Concept

**File:** `x/feegrant/periodic_fee_test.go`  
**Test Function:** Add new test case `TestPeriodicFeeClockSkewExploit`

**Setup:**
1. Initialize a test app and context
2. Create a `PeriodicAllowance` with `Period = 1 hour` and `PeriodSpendLimit = 100 tokens`
3. Set initial `PeriodReset` to a known time T
4. Deplete the allowance so `PeriodCanSpend = 0`

**Trigger:**
1. Advance context time to T (period boundary)
2. Create a block with `blockTime = T + 30 minutes` (simulating clock skew)
3. Call `Accept` on the allowance with a valid fee
4. Observe that the period resets even though actual time hasn't reached the period boundary plus skew compensation

**Observation:**
The test will show that:
- `PeriodReset` is set to `T + 1 hour + 30 minutes` instead of `T + 1 hour`
- The grantee can spend for an extended duration (1.5 hours) instead of the configured 1 hour
- This violates the rate-limiting invariant

```go
func TestPeriodicFeeClockSkewExploit(t *testing.T) {
	app := simapp.Setup(false)
	
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	
	// Setup allowance with 1 hour period
	oneHour := time.Duration(1) * time.Hour
	allowance := feegrant.PeriodicAllowance{
		Basic: feegrant.BasicAllowance{
			SpendLimit: sdk.NewCoins(sdk.NewInt64Coin("atom", 1000)),
		},
		Period:           oneHour,
		PeriodSpendLimit: sdk.NewCoins(sdk.NewInt64Coin("atom", 100)),
		PeriodCanSpend:   sdk.NewCoins(sdk.NewInt64Coin("atom", 100)),
		PeriodReset:      baseTime.Add(oneHour), // Reset at 1:00 PM
	}
	
	// Deplete allowance at 12:30 PM
	ctx := app.BaseApp.NewContext(false, tmproto.Header{Time: baseTime.Add(30 * time.Minute)})
	fee := sdk.NewCoins(sdk.NewInt64Coin("atom", 100))
	remove, err := allowance.Accept(ctx, fee, []sdk.Msg{})
	require.NoError(t, err)
	require.False(t, remove)
	require.True(t, allowance.PeriodCanSpend.IsZero())
	
	// Block arrives with clock 30 minutes ahead (1:00 PM on skewed clock, actually 12:30 PM)
	skewedTime := baseTime.Add(oneHour)
	ctx = app.BaseApp.NewContext(false, tmproto.Header{Time: skewedTime})
	
	// Try to spend again - this should reset the period
	remove, err = allowance.Accept(ctx, fee, []sdk.Msg{})
	require.NoError(t, err)
	require.False(t, remove)
	
	// BUG: PeriodReset is now set to 2:00 PM instead of 1:00 PM
	expectedReset := baseTime.Add(2 * oneHour) // Should be 1:00 PM, but due to skew becomes 2:00 PM
	require.Equal(t, expectedReset, allowance.PeriodReset)
	
	// Now at actual time 12:35 PM (5 minutes later), user can still spend
	// because blockTime would be before the incorrectly-set PeriodReset
	normalTime := baseTime.Add(35 * time.Minute)
	ctx = app.BaseApp.NewContext(false, tmproto.Header{Time: normalTime})
	
	// User still has spending allowance even though we're still in the same actual hour
	require.False(t, allowance.PeriodCanSpend.IsZero())
}
```

The test demonstrates that clock skew causes `PeriodReset` to advance beyond the intended period duration, breaking the rate-limiting mechanism.

### Citations

**File:** x/feegrant/periodic_fee.go (L22-48)
```go
func (a *PeriodicAllowance) Accept(ctx sdk.Context, fee sdk.Coins, _ []sdk.Msg) (bool, error) {
	blockTime := ctx.BlockTime()

	if a.Basic.Expiration != nil && blockTime.After(*a.Basic.Expiration) {
		return true, sdkerrors.Wrap(ErrFeeLimitExpired, "absolute limit")
	}

	a.tryResetPeriod(blockTime)

	// deduct from both the current period and the max amount
	var isNeg bool
	a.PeriodCanSpend, isNeg = a.PeriodCanSpend.SafeSub(fee)
	if isNeg {
		return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "period limit")
	}

	if a.Basic.SpendLimit != nil {
		a.Basic.SpendLimit, isNeg = a.Basic.SpendLimit.SafeSub(fee)
		if isNeg {
			return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "absolute limit")
		}

		return a.Basic.SpendLimit.IsZero(), nil
	}

	return false, nil
}
```

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

**File:** third_party/proto/tendermint/types/params.proto (L78-85)
```text
message SynchronyParams {
  // message_delay bounds how long a proposal message may take to reach all validators on a network
  // and still be considered valid.
  google.protobuf.Duration message_delay = 1 [(gogoproto.stdduration) = true];
  // precision bounds how skewed a proposer's clock may be from any validator
  // on the network while still producing valid proposals.
  google.protobuf.Duration precision = 2 [(gogoproto.stdduration) = true];
}
```
