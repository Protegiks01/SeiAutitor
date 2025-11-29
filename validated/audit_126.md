# Audit Report

## Title
Missing Underflow Protection in Commission Withdrawal and Zero-Token Validator Period Operations

## Summary
The distribution module's commission withdrawal operations directly call `Sub()` on outstanding rewards without protection against underflow, while delegation withdrawals use `Intersect()` to handle rounding errors. This asymmetry can cause transaction panics when outstanding rewards are depleted below commission amounts due to accumulated rounding errors from delegation withdrawals. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:**
- `x/distribution/keeper/keeper.go` line 120 (WithdrawValidatorCommission)
- `x/distribution/keeper/validator.go` line 41 (IncrementValidatorPeriod for zero-token validators)
- `x/distribution/keeper/hooks.go` line 34 (AfterValidatorRemoved) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
Outstanding rewards should always be sufficient to cover all accumulated commission and delegation rewards since they are allocated together. When commission is withdrawn, the system should subtract the commission amount from outstanding.

**Actual Logic:**
The code explicitly acknowledges that rounding errors occur during reward calculations "on the very final digits" and protects delegation withdrawals with `Intersect()` to cap withdrawals at available outstanding: [4](#0-3) 

However, commission withdrawals and other validator operations directly call `outstanding.Sub()` without this protection. The `DecCoins.Sub()` method panics if the result would be negative: [5](#0-4) 

When multiple delegators withdraw rewards with small rounding errors in their favor (each capped by `Intersect()`), the cumulative effect depletes outstanding beyond the delegation portion, consuming what should be reserved for commission.

**Exploitation Path:**
1. Rewards are allocated to validator: commission and delegation portions both added to outstanding [6](#0-5) 

2. During reward calculations, truncation operations introduce rounding errors: [7](#0-6) 

3. Multiple delegators withdraw rewards using `Intersect()` protection, each potentially withdrawing slightly more than their precise share due to rounding: [4](#0-3) 

4. Cumulative rounding errors deplete outstanding to less than the recorded commission amount

5. Validator attempts to withdraw commission via normal transaction: [8](#0-7) 

6. Call to `outstanding.Sub(commission)` where outstanding < commission causes panic with "negative coin amount"

7. Transaction fails, validator cannot withdraw commission; similar issues occur during delegation to zero-token validators and validator removal

**Security Guarantee Broken:**
- Accounting invariant: outstanding rewards should always be >= sum of withdrawable commission and delegation rewards
- Availability: validators should always be able to withdraw their recorded commission  
- Consistency: delegation withdrawals use defensive protection but commission withdrawals do not

## Impact Explanation

**Direct Impacts:**
- Validators cannot withdraw their recorded commission (denial of service for specific validators)
- Transaction panics consume gas without completing operations
- Commission remains recorded in state but becomes temporarily unwithdrawable until outstanding is replenished

**Broader Impacts:**
- When `IncrementValidatorPeriod` is called via `BeforeDelegationCreated` hook for zero-token validators, it can panic, preventing ANY user from delegating to that validator: [9](#0-8) 

- The `AfterValidatorRemoved` cleanup operation can fail, preventing proper state cleanup when validators are removed

This qualifies as "a bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity) because it affects the Cosmos SDK distribution module, causes unintended transaction panics preventing valid operations, has no permanent fund loss (commission still recorded), but has broader system impact.

## Likelihood Explanation

**Who Can Trigger:**
- Any delegator performing normal reward withdrawals (unknowingly contributes to outstanding depletion)
- Any validator attempting commission withdrawal after sufficient depletion has occurred
- Any user attempting to delegate to a zero-token validator
- System operations during validator removal

**Conditions Required:**
- Rounding errors accumulate during reward calculations using truncation operations (`QuoDecTruncate`, `MulDecTruncate`)
- Multiple reward allocation and withdrawal cycles over time
- The code explicitly acknowledges this edge case exists with defensive comments and logging

**Frequency:**
The developers' awareness is evidenced by the `Intersect()` protection for delegations and explicit comments about "defensive edge case may happen on the very final digits." This indicates a real concern, not merely theoretical. Likelihood increases with validators having many delegators and frequent withdrawal patterns.

## Recommendation

Apply the same `Intersect()` protection used in delegation withdrawals to all operations that subtract from outstanding rewards:

**For WithdrawValidatorCommission (keeper.go:120):**
```go
commissionDecCoins := sdk.NewDecCoinsFromCoins(commission...)
commissionToWithdraw := commissionDecCoins.Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

**For IncrementValidatorPeriod zero-token case (validator.go:41):**
```go
rewardsToMove := rewards.Rewards.Intersect(outstanding.GetRewards())
outstanding.Rewards = outstanding.GetRewards().Sub(rewardsToMove)
feePool.CommunityPool = feePool.CommunityPool.Add(rewardsToMove...)
```

**For AfterValidatorRemoved (hooks.go:34):**
```go
commissionToWithdraw := commission.Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

This ensures operations never panic due to insufficient outstanding balance while maintaining accounting accuracy.

## Proof of Concept

**Test File:** `x/distribution/keeper/keeper_test.go`

**Setup:**
1. Create validator with 10% commission rate
2. Allocate 100 tokens through normal reward distribution: commission accumulates 10, outstanding = 100
3. Manually set outstanding to 9 (simulating the cumulative effect of rounding errors from multiple delegation withdrawals with Intersect protection)

**Action:**
```go
_, err := app.DistrKeeper.WithdrawValidatorCommission(ctx, valAddr)
```

**Expected Result:**
Transaction panics with "negative coin amount" because the code attempts `outstanding.Sub(commission)` where outstanding (9) < commission (10), demonstrating the lack of underflow protection.

**Notes:**
The PoC manually manipulates outstanding to demonstrate the panic condition. In practice, this state would be reached through accumulated rounding errors across multiple delegation withdrawals. The code's explicit use of `Intersect()` for delegation withdrawals with logging confirms developers knew about rounding issues but didn't apply consistent protection across all withdrawal operations.

### Citations

**File:** x/distribution/keeper/keeper.go (L119-120)
```go
	outstanding := k.GetValidatorOutstandingRewards(ctx, valAddr).Rewards
	k.SetValidatorOutstandingRewards(ctx, valAddr, types.ValidatorOutstandingRewards{Rewards: outstanding.Sub(sdk.NewDecCoinsFromCoins(commission...))})
```

**File:** x/distribution/keeper/validator.go (L39-43)
```go
		outstanding := k.GetValidatorOutstandingRewards(ctx, val.GetOperator())
		feePool.CommunityPool = feePool.CommunityPool.Add(rewards.Rewards...)
		outstanding.Rewards = outstanding.GetRewards().Sub(rewards.Rewards)
		k.SetFeePool(ctx, feePool)
		k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), outstanding)
```

**File:** x/distribution/keeper/validator.go (L48-48)
```go
		current = rewards.Rewards.QuoDecTruncate(val.GetTokens().ToDec())
```

**File:** x/distribution/keeper/hooks.go (L30-34)
```go
	// force-withdraw commission
	commission := h.k.GetValidatorAccumulatedCommission(ctx, valAddr).Commission
	if !commission.IsZero() {
		// subtract from outstanding
		outstanding = outstanding.Sub(commission)
```

**File:** x/distribution/keeper/hooks.go (L79-82)
```go
func (h Hooks) BeforeDelegationCreated(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) {
	val := h.k.stakingKeeper.Validator(ctx, valAddr)
	h.k.IncrementValidatorPeriod(ctx, val)
}
```

**File:** x/distribution/keeper/delegation.go (L150-152)
```go
	// defensive edge case may happen on the very final digits
	// of the decCoins due to operation order of the distribution mechanism.
	rewards := rewardsRaw.Intersect(outstanding)
```

**File:** types/dec_coin.go (L303-309)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
```

**File:** x/distribution/keeper/allocation.go (L143-145)
```go
	outstanding := k.GetValidatorOutstandingRewards(ctx, val.GetOperator())
	outstanding.Rewards = outstanding.Rewards.Add(tokens...)
	k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), outstanding)
```

**File:** x/distribution/keeper/msg_server.go (L90-100)
```go
func (k msgServer) WithdrawValidatorCommission(goCtx context.Context, msg *types.MsgWithdrawValidatorCommission) (*types.MsgWithdrawValidatorCommissionResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return nil, err
	}
	amount, err := k.Keeper.WithdrawValidatorCommission(ctx, valAddr)
	if err != nil {
		return nil, err
	}
```
