# Audit Report

## Title
Missing Underflow Protection in Commission Withdrawal and Zero-Token Validator Period Operations

## Summary
The distribution module's commission withdrawal operations directly call `Sub()` on outstanding rewards without protection against underflow, while delegation withdrawals use `Intersect()` to handle rounding errors. This asymmetry can cause transaction panics when outstanding rewards are depleted below commission amounts due to accumulated rounding errors from delegation withdrawals.

## Impact
Medium

## Finding Description

**Location:**
- `x/distribution/keeper/keeper.go` line 120 (WithdrawValidatorCommission) [1](#0-0) 

- `x/distribution/keeper/validator.go` line 41 (IncrementValidatorPeriod for zero-token validators) [2](#0-1) 

- `x/distribution/keeper/hooks.go` line 34 (AfterValidatorRemoved) [3](#0-2) 

**Intended Logic:**
Outstanding rewards should always be sufficient to cover all accumulated commission and delegation rewards since they were previously allocated together. When commission is withdrawn, the system should simply subtract the commission amount from outstanding.

**Actual Logic:**
The code acknowledges rounding errors occur during reward calculations "on the very final digits" and protects delegation withdrawals with `Intersect()` to cap withdrawals at available outstanding: [4](#0-3) 

However, commission withdrawals and other operations directly call `outstanding.Sub()` without this protection. The `DecCoins.Sub()` method panics if the result would be negative: [5](#0-4) 

When multiple delegators withdraw rewards with small rounding errors in their favor (each capped by `Intersect()`), the cumulative effect depletes outstanding beyond the delegation portion, eating into the commission reserve.

**Exploitation Path:**
1. Validator receives 100 tokens allocated: commission = 10, delegation rewards = 90, outstanding = 100
2. Due to rounding in `QuoDecTruncate` operations during reward calculations, delegators' computed rewards slightly exceed their true share (e.g., 45.001 each instead of 45.000) [6](#0-5) 

3. First delegator withdraws: `Intersect(45.001, 100)` = 45.001, outstanding becomes 54.999
4. Second delegator withdraws: `Intersect(45.001, 54.999)` = 45.001, outstanding becomes 9.998
5. Validator attempts to withdraw commission of 10
6. Call to `outstanding.Sub(10)` with outstanding = 9.998 panics with "negative coin amount"
7. Transaction reverts, validator cannot withdraw commission

**Security Guarantee Broken:**
- Accounting invariant: outstanding rewards should always be >= sum of withdrawable commission and delegation rewards
- Availability: validators should always be able to withdraw their recorded commission
- Consistency: delegation withdrawals use protection but commission withdrawals do not

## Impact Explanation

**Direct Impacts:**
- Validators cannot withdraw commission (denial of service for specific validators)
- Transaction panics consume gas without completing operations
- Commission remains recorded in state but becomes temporarily unwithdrawable until outstanding is replenished through new allocations

**Broader Impacts:**
- Zero-token validators: When `IncrementValidatorPeriod` is called (via `BeforeDelegationCreated` hook), it can panic, preventing ANY user from delegating to that validator [7](#0-6) 

- Validator removal: The `AfterValidatorRemoved` cleanup operation can fail, preventing proper state cleanup when validators are removed

This qualifies as "a bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity) because:
- It affects Cosmos SDK distribution module (layer 0/1 code)
- Causes unintended behavior (transaction panics preventing valid operations)
- No permanent fund loss (commission still recorded, can be withdrawn when outstanding replenished)
- Has broader impact beyond initiating validator (affects delegators and system cleanup)

## Likelihood Explanation

**Who Can Trigger:**
- Any delegator performing normal reward withdrawals (unknowingly contributes to depletion)
- Any validator attempting commission withdrawal after sufficient depletion
- System operations when validator tokens reach zero

**Conditions Required:**
- Rounding errors accumulate during reward calculations using `QuoDecTruncate`
- Multiple reward allocation and withdrawal cycles over time
- The code explicitly acknowledges this edge case exists with comments about "rounding error withdrawing rewards from validator"

**Frequency:**
- Low to Medium likelihood in normal operation
- Higher probability with validators having many delegators and frequent withdrawal patterns
- The developers' awareness (evidenced by `Intersect` protection for delegations) indicates this is a real concern, not theoretical

## Recommendation

Apply the same `Intersect` protection used in delegation withdrawals to all operations that subtract from outstanding rewards:

**For WithdrawValidatorCommission:**
```go
commissionDecCoins := sdk.NewDecCoinsFromCoins(commission...)
commissionToWithdraw := commissionDecCoins.Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

**For IncrementValidatorPeriod (zero tokens):**
```go
rewardsToMove := rewards.Rewards.Intersect(outstanding.GetRewards())
outstanding.Rewards = outstanding.GetRewards().Sub(rewardsToMove)
feePool.CommunityPool = feePool.CommunityPool.Add(rewardsToMove...)
```

**For AfterValidatorRemoved:**
```go
commissionToWithdraw := commission.Intersect(outstanding)
outstanding = outstanding.Sub(commissionToWithdraw)
```

This ensures operations never panic due to insufficient outstanding balance while maintaining accounting accuracy.

## Proof of Concept

**Test File:** `x/distribution/keeper/keeper_test.go`

**Setup:**
1. Create validator with 10% commission rate
2. Allocate 100 tokens: commission accumulates 10, outstanding = 100
3. Manually set outstanding to 9 (simulating the cumulative effect of rounding errors from multiple delegation withdrawals with Intersect)

**Action:**
```go
_, err := app.DistrKeeper.WithdrawValidatorCommission(ctx, valAddr)
```

**Expected Result:**
Transaction panics with "negative coin amount" because the code attempts `outstanding.Sub(commission)` where outstanding (9) < commission (10), demonstrating the lack of underflow protection.

**Notes:**
- The PoC manually manipulates outstanding to demonstrate the panic condition
- In practice, this state would be reached through accumulated rounding errors across multiple delegation withdrawals
- The code's explicit use of `Intersect` for delegation withdrawals with logging confirms the developers knew about rounding issues but didn't apply consistent protection
- This creates an accounting vulnerability where the sum of what can be withdrawn exceeds outstanding due to asymmetric protections

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

**File:** x/distribution/keeper/hooks.go (L79-81)
```go
func (h Hooks) BeforeDelegationCreated(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) {
	val := h.k.stakingKeeper.Validator(ctx, valAddr)
	h.k.IncrementValidatorPeriod(ctx, val)
```

**File:** x/distribution/keeper/delegation.go (L150-152)
```go
	// defensive edge case may happen on the very final digits
	// of the decCoins due to operation order of the distribution mechanism.
	rewards := rewardsRaw.Intersect(outstanding)
```

**File:** types/dec_coin.go (L303-306)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
```
