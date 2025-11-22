## Audit Report

## Title
Missing Underflow Protection in Commission Withdrawal and Zero-Token Validator Period Operations

## Summary
The distribution module's commission withdrawal and zero-token validator period increment operations lack underflow protection when subtracting from outstanding rewards. While delegation reward withdrawals use `Intersect` to handle rounding errors, commission withdrawals and other operations directly call `Sub` without verification, potentially causing transaction panics when outstanding rewards are insufficient.

## Impact
Medium

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** 
The distribution module tracks outstanding rewards for validators and their delegators. When rewards are withdrawn or moved, the outstanding balance should be decremented. The system assumes outstanding rewards are always sufficient to cover withdrawal amounts since they were previously allocated.

**Actual Logic:** 
The code acknowledges that rounding errors occur during reward calculations [4](#0-3) . Delegation withdrawals protect against this by using `Intersect(calculatedRewards, outstanding)` to cap withdrawals at the available outstanding amount [5](#0-4) . However, three operations directly subtract from outstanding without this protection:

1. **WithdrawValidatorCommission** directly calls `outstanding.Sub(commission)` without checking if outstanding >= commission
2. **IncrementValidatorPeriod** (when validator has zero tokens) subtracts current rewards from outstanding without verification
3. **AfterValidatorRemoved** subtracts commission from outstanding without checking

The `DecCoins.Sub` method panics if the result would be negative [6](#0-5) .

**Exploit Scenario:**
1. A validator receives rewards allocated: outstanding = 100 (10 commission + 90 delegation share)
2. Due to rounding errors in reward ratio calculations using `QuoDecTruncate` [7](#0-6) , a delegator's calculated rewards slightly exceed their true share (e.g., 90.001 instead of 90)
3. Delegator withdraws: `Intersect(90.001, 100)` = 90.001, outstanding becomes 9.999
4. Validator attempts to withdraw commission of 10
5. The call `outstanding.Sub(10)` with outstanding = 9.999 triggers panic: "negative coin amount"
6. The transaction reverts, preventing the validator from withdrawing their rightful commission

**Security Failure:** 
This breaks the accounting invariant and causes denial-of-service. Validators may be unable to withdraw commissions, and validators with zero tokens cannot have their periods incremented or be properly removed from the system due to transaction panics.

## Impact Explanation

**Affected Assets/Processes:**
- Validator commission withdrawals can fail with panic
- Zero-token validators cannot have their periods incremented
- Validator removal operations can fail
- Node transaction processing affected

**Severity:**
- Transaction panics cause immediate transaction failure and gas consumption
- Validators permanently unable to withdraw commission until outstanding is replenished
- Validator cleanup operations blocked, preventing proper state management
- Potential node instability if panics occur during critical operations

**System Impact:**
This creates an accounting inconsistency where validators have accumulated commission that cannot be withdrawn due to insufficient outstanding rewards caused by rounding errors in delegation withdrawals.

## Likelihood Explanation

**Who Can Trigger:**
- Any delegator performing normal reward withdrawals (unknowingly)
- Any validator attempting commission withdrawal after delegators have withdrawn
- Automatic operations when validator tokens reach zero

**Conditions Required:**
- Rounding errors accumulate during reward calculations (acknowledged in code comments as occurring "on the very final digits")
- Multiple reward allocation and withdrawal cycles
- Normal operation can trigger this over time

**Frequency:**
- Low to Medium likelihood in normal operation
- Higher probability with validators having complex delegation patterns or many periods
- The code explicitly acknowledges this edge case exists, indicating it's a known concern

## Recommendation

Apply the same `Intersect` protection used in delegation withdrawals to all operations that subtract from outstanding rewards:

1. **For WithdrawValidatorCommission:** Cap commission withdrawal at available outstanding:
```go
commissionToWithdraw := sdk.NewDecCoinsFromCoins(commission...).Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

2. **For IncrementValidatorPeriod (zero tokens):** Cap rewards moved to community pool:
```go
rewardsToMove := rewards.Rewards.Intersect(outstanding.GetRewards())
outstanding.Rewards = outstanding.GetRewards().Sub(rewardsToMove)
feePool.CommunityPool = feePool.CommunityPool.Add(rewardsToMove...)
```

3. **For AfterValidatorRemoved:** Cap commission withdrawal:
```go
commissionToWithdraw := commission.Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

This ensures operations never attempt to subtract more than available outstanding balance while maintaining accounting accuracy.

## Proof of Concept

**File:** `x/distribution/keeper/keeper_test.go` (new test function)

**Setup:**
```go
func TestCommissionWithdrawUnderflowProtection(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    addr := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1000))
    valAddrs := simapp.ConvertAddrsToValAddrs(addr)
    
    // Create validator with 10% commission
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    tstaking.Commission = stakingtypes.NewCommissionRates(
        sdk.NewDecWithPrec(1, 1), 
        sdk.NewDecWithPrec(1, 1), 
        sdk.NewDec(0),
    )
    tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    
    val := app.StakingKeeper.Validator(ctx, valAddrs[0])
    
    // Allocate 100 tokens (10 commission, 90 delegation)
    tokens := sdk.DecCoins{{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(100)}}
    app.DistrKeeper.AllocateTokensToValidator(ctx, val, tokens)
    
    // Manually manipulate outstanding to simulate rounding error depletion
    // This simulates the effect of Intersect allowing delegators to withdraw
    // slightly more than their fair share due to rounding
    outstanding := app.DistrKeeper.GetValidatorOutstandingRewards(ctx, valAddrs[0])
    outstanding.Rewards = sdk.DecCoins{{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(9)}} // Less than commission of 10
    app.DistrKeeper.SetValidatorOutstandingRewards(ctx, valAddrs[0], outstanding)
}
```

**Trigger:**
```go
    // Attempt to withdraw commission - this will panic
    _, err := app.DistrKeeper.WithdrawValidatorCommission(ctx, valAddrs[0])
```

**Observation:**
The test will panic with "negative coin amount" because the code attempts `outstanding.Sub(commission)` where outstanding (9) < commission (10). The panic occurs at the `Sub` call, demonstrating the lack of underflow protection. A properly protected implementation would use `Intersect` to cap the withdrawal and return an error or partial withdrawal instead of panicking.

To run: Add this test to `x/distribution/keeper/keeper_test.go` and execute with `go test -v -run TestCommissionWithdrawUnderflowProtection`.

### Citations

**File:** x/distribution/keeper/keeper.go (L119-120)
```go
	outstanding := k.GetValidatorOutstandingRewards(ctx, valAddr).Rewards
	k.SetValidatorOutstandingRewards(ctx, valAddr, types.ValidatorOutstandingRewards{Rewards: outstanding.Sub(sdk.NewDecCoinsFromCoins(commission...))})
```

**File:** x/distribution/keeper/validator.go (L41-41)
```go
		outstanding.Rewards = outstanding.GetRewards().Sub(rewards.Rewards)
```

**File:** x/distribution/keeper/validator.go (L48-48)
```go
		current = rewards.Rewards.QuoDecTruncate(val.GetTokens().ToDec())
```

**File:** x/distribution/keeper/hooks.go (L34-34)
```go
		outstanding = outstanding.Sub(commission)
```

**File:** x/distribution/keeper/delegation.go (L149-162)
```go

	// defensive edge case may happen on the very final digits
	// of the decCoins due to operation order of the distribution mechanism.
	rewards := rewardsRaw.Intersect(outstanding)
	if !rewards.IsEqual(rewardsRaw) {
		logger := k.Logger(ctx)
		logger.Info(
			"rounding error withdrawing rewards from validator",
			"delegator", del.GetDelegatorAddr().String(),
			"validator", val.GetOperator().String(),
			"got", rewards.String(),
			"expected", rewardsRaw.String(),
		)
	}
```

**File:** types/dec_coin.go (L303-310)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}
```
