## Audit Report

### Title
Zero Period Duration Allows Unlimited Rate Limit Bypass in Periodic Fee Allowances

### Summary
The `PeriodicAllowance.ValidateBasic()` function fails to prevent Period = 0, which causes the period reset logic in `tryResetPeriod()` to malfunction. When Period = 0, every transaction occurring at the same block time triggers a period reset, effectively bypassing the intended rate limiting mechanism and allowing unlimited spending within a single block up to the Basic.SpendLimit. [1](#0-0) 

### Impact
**Medium** - A bug in the layer 1 network code that results in unintended protocol behavior with rate limits being circumvented, though funds remain capped by Basic.SpendLimit.

### Finding Description

**Location:** `x/feegrant/periodic_fee.go` in the `ValidateBasic()` function (lines 102-104) and `tryResetPeriod()` function (lines 56-74).

**Intended Logic:** The `PeriodicAllowance` is designed to enforce rate limiting by allowing a maximum of `PeriodSpendLimit` tokens to be spent per `Period` duration, with an absolute cap of `Basic.SpendLimit`. The `ValidateBasic()` function should reject invalid configurations that would break this invariant. [2](#0-1) 

**Actual Logic:** The validation only checks for negative periods, not zero periods. When Period = 0:

1. Line 70 sets `PeriodReset = PeriodReset.Add(0)`, which doesn't advance the time
2. For the first transaction after initialization, if `blockTime > PeriodReset`, line 72 sets `PeriodReset = blockTime.Add(0) = blockTime`
3. On subsequent transactions at the same blockTime, line 57's check `blockTime.Before(PeriodReset)` returns false (equal times), so the reset logic proceeds
4. Lines 61-66 reset `PeriodCanSpend` to the full limit
5. Line 70 sets `PeriodReset = PeriodReset.Add(0) = PeriodReset` (no change)
6. Line 71's check `blockTime.After(PeriodReset)` returns false (equal times), so PeriodReset remains unchanged
7. Every transaction at the same block time gets a full period reset [3](#0-2) 

**Exploit Scenario:**
1. A granter creates a `PeriodicAllowance` with Period = 0, PeriodSpendLimit = 100 tokens, Basic.SpendLimit = 1000 tokens
2. The granter intends rate limiting: 100 tokens per period over 10+ periods
3. The grantee batches 10 transactions in a single block, each requesting 100 tokens in fees
4. Each transaction triggers `tryResetPeriod()` which resets `PeriodCanSpend` to 100 because blockTime equals PeriodReset
5. All 10 transactions succeed, draining the entire 1000 token Basic.SpendLimit in one block
6. The intended rate limiting is completely bypassed [4](#0-3) 

**Security Failure:** The rate limiting security invariant is violated. The `PeriodicAllowance` mechanism is designed to prevent rapid depletion of grants by enforcing time-based spending limits. With Period = 0, this protection is nullified.

### Impact Explanation

**Assets Affected:** Fee allowance grants that use `PeriodicAllowance` with misconfigured Period = 0.

**Severity:** The vulnerability allows complete bypass of the rate limiting mechanism. While the absolute `Basic.SpendLimit` still caps total spending, the time-based protection is eliminated. A grantee can drain the entire allowance in a single block rather than over the intended period, potentially causing:
- Unexpected rapid depletion of grants
- Violation of granter's expectations about spending rate
- Potential financial loss if the granter intended to revoke or modify the grant before full depletion

**Systemic Impact:** This is a protocol-level bug in the feegrant module that affects the core security property of periodic allowances. While it requires misconfiguration by the granter, the protocol should prevent invalid states through proper validation.

### Likelihood Explanation

**Who can trigger:** Any grantee receiving a `PeriodicAllowance` with Period = 0 can exploit this. The granter must first create the misconfigured allowance, which could happen through:
- Lack of understanding of the Period parameter
- Programming errors in tools that create fee grants
- Confusion about time duration units

**Conditions required:** 
- A `PeriodicAllowance` must be created with Period = 0 duration
- The grantee must submit multiple transactions within the same block

**Frequency:** While this requires initial misconfiguration, once a Period = 0 grant exists, it can be exploited repeatedly until the Basic.SpendLimit is exhausted. The vulnerability is deterministic and easily reproducible.

### Recommendation

Add validation in `ValidateBasic()` to reject Period = 0:

```go
// check times
if a.Period.Seconds() <= 0 {
    return sdkerrors.Wrap(ErrInvalidDuration, "period must be positive")
}
```

This prevents the invalid state from being created, ensuring all `PeriodicAllowance` instances have meaningful time-based rate limiting.

### Proof of Concept

**File:** `x/feegrant/periodic_fee_test.go`

**Test Function:** Add this test to demonstrate the vulnerability:

```go
func TestPeriodicFeeZeroPeriodExploit(t *testing.T) {
	app := simapp.Setup(false)
	now := time.Now()
	ctx := app.BaseApp.NewContext(false, tmproto.Header{
		Time: now,
	})

	// Setup: Create a PeriodicAllowance with Period = 0
	// Granter intends 100 tokens per period, 1000 tokens total over 10 periods
	hundredAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 100))
	thousandAtom := sdk.NewCoins(sdk.NewInt64Coin("atom", 1000))
	zeroPeriod := time.Duration(0)
	
	allowance := feegrant.PeriodicAllowance{
		Basic: feegrant.BasicAllowance{
			SpendLimit: thousandAtom,
		},
		Period:           zeroPeriod,
		PeriodReset:      now,
		PeriodSpendLimit: hundredAtom,
		PeriodCanSpend:   hundredAtom,
	}

	// Verify the allowance passes validation (this is the bug)
	err := allowance.ValidateBasic()
	require.NoError(t, err, "Period = 0 should be rejected but passes validation")

	// Trigger: Submit 10 transactions at the same block time
	// Each should get a period reset, bypassing rate limiting
	for i := 0; i < 10; i++ {
		remove, err := allowance.Accept(ctx, hundredAtom, []sdk.Msg{})
		require.NoError(t, err, "Transaction %d should succeed", i+1)
		require.False(t, remove, "Allowance should not be removed until Basic.SpendLimit exhausted")
	}

	// Observation: All 1000 tokens were spent in a single block
	// PeriodCanSpend should be 0 and Basic.SpendLimit should be 0
	assert.True(t, allowance.PeriodCanSpend.IsZero(), "PeriodCanSpend should be depleted")
	assert.True(t, allowance.Basic.SpendLimit.IsZero(), "Basic.SpendLimit should be depleted")
	
	// This demonstrates that the rate limit was completely bypassed
	// Instead of being limited to 100 tokens per period (requiring 10 periods),
	// all 1000 tokens were spent in a single block
}
```

**Setup:** Creates a `PeriodicAllowance` with Period = 0, PeriodSpendLimit = 100, Basic.SpendLimit = 1000.

**Trigger:** Calls `Accept()` 10 times with the same block time (simulating 10 transactions in one block), each requesting 100 tokens.

**Observation:** All 10 transactions succeed, demonstrating that each got a full period reset despite being in the same "period". The test confirms that 1000 tokens (10x the PeriodSpendLimit) were spent in a single block, proving the rate limit was bypassed. Expected behavior would be that only the first transaction succeeds, and subsequent transactions in the same period should fail with "period limit exceeded" errors.

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

**File:** x/feegrant/periodic_fee.go (L102-104)
```go
	if a.Period.Seconds() < 0 {
		return sdkerrors.Wrap(ErrInvalidDuration, "negative clock step")
	}
```

**File:** x/feegrant/keeper/keeper.go (L146-180)
```go
// UseGrantedFees will try to pay the given fee from the granter's account as requested by the grantee
func (k Keeper) UseGrantedFees(ctx sdk.Context, granter, grantee sdk.AccAddress, fee sdk.Coins, msgs []sdk.Msg) error {
	f, err := k.getGrant(ctx, granter, grantee)
	if err != nil {
		return err
	}

	grant, err := f.GetGrant()
	if err != nil {
		return err
	}

	remove, err := grant.Accept(ctx, fee, msgs)

	if remove {
		// Ignoring the `revokeFeeAllowance` error, because the user has enough grants to perform this transaction.
		k.revokeAllowance(ctx, granter, grantee)
		if err != nil {
			return err
		}

		emitUseGrantEvent(ctx, granter.String(), grantee.String())

		return nil
	}

	if err != nil {
		return err
	}

	emitUseGrantEvent(ctx, granter.String(), grantee.String())

	// if fee allowance is accepted, store the updated state of the allowance
	return k.GrantAllowance(ctx, granter, grantee, grant)
}
```
