# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function in the staking module contains an accounting vulnerability where it calculates the theoretical slash amount based on `InitialBalance` but returns this value instead of the actual burned tokens. When the destination validator's exchange rate has deteriorated, fewer tokens are actually burned than reported, causing systematic under-slashing of validators.

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296) [1](#0-0) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should ensure that the amount reported to the caller matches the actual tokens burned. The code comment at line 11 states the intent to "burn the specified slashFactor" of the contributing stake. [2](#0-1) 

**Actual logic:** The function performs the following steps:
1. Calculates `slashAmount = slashFactor * entry.InitialBalance` and accumulates this in `totalSlashAmount` (lines 238-240)
2. Calculates `sharesToUnbond = slashFactor * entry.SharesDst` using shares stored at redelegation time (line 243)
3. Calls `k.Unbond(sharesToUnbond)` which converts shares to tokens at the destination validator's **current** exchange rate (line 265)
4. The actual `tokensToBurn` from unbonding is accumulated for burning (lines 279, 281)
5. Returns `totalSlashAmount` instead of the sum of actual `tokensToBurn` values (line 295)

The share-to-token conversion uses the validator's current exchange rate via `TokensFromShares`: [3](#0-2) [4](#0-3) 

When the destination validator's exchange rate has deteriorated since redelegation time, the result is `tokensToBurn < slashAmount`, creating an accounting mismatch.

**Exploitation path:**
1. User redelegates from Validator A to Validator B through standard redelegation transaction
2. `BeginRedelegation` creates a `RedelegationEntry` storing `InitialBalance` (original tokens) and `SharesDst` (shares received at destination): [5](#0-4) 

3. Validator B's exchange rate deteriorates (e.g., B gets slashed independently, reducing tokens while shares remain constant)
4. Validator A is later slashed for an earlier infraction
5. `SlashRedelegation` calculates theoretical slash based on `InitialBalance` but burns fewer actual tokens due to deteriorated exchange rate at B
6. Main `Slash` function receives the inflated amount and reduces `remainingSlashAmount` by this value: [6](#0-5) 

7. Validator A is under-slashed by the difference between reported and actual burned amounts

**Security guarantee broken:** The protocol's slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's health rather than solely on the source validator's infraction and severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security model:

1. **Systematic Under-Slashing:** When destination validators have deteriorating exchange rates (common due to slashing events, validator operations, or precision losses), actual slashing is less than intended. With significant exchange rate deterioration, a substantial portion of the slashing penalty can be avoided.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, potentially encouraging infractions since the expected cost is lower than designed.

3. **Protocol Invariant Violation:** The fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. The actual penalty varies based on factors unrelated to the infraction (destination validator performance).

This qualifies as Medium severity under the criterion: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." The staking module is core layer-1 protocol code, and this bug causes unintended slashing behavior that systematically reduces penalties below intended levels.

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Validator infractions occur regularly in PoS networks through downtime or double-signing
2. **Natural exchange rate fluctuations:** Exchange rates change frequently due to slashing events, validator operations, or precision losses
3. **Wide redelegation usage:** Redelegation is a core feature widely used by delegators for instant validator switching without unbonding period
4. **Extended vulnerability window:** The unbonding period (typically 21 days) provides ample time for exchange rate changes between redelegation and potential slashing events

**No special requirements:**
- Any delegator can perform redelegations (no special privileges needed)
- The bug causes systematic under-slashing even without intentional exploitation
- Occurs through normal protocol operations
- No attack needed - simply normal network dynamics trigger the issue

The vulnerability affects the fundamental slashing mechanism underpinning network security and can be triggered through standard user actions combined with natural network events.

## Recommendation

Modify `SlashRedelegation` to ensure the return value matches the actual tokens burned. The function should calculate shares to unbond based on the target token amount at the current exchange rate:

```go
// Calculate target tokens to burn based on original stake
slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
targetTokensToBurn := slashAmountDec.TruncateInt()

// Get destination validator
dstValidator, found := k.GetValidator(ctx, valDstAddr)
if !found {
    panic("destination validator not found")
}

// Convert target token amount to shares at CURRENT exchange rate
sharesToUnbond, err := dstValidator.SharesFromTokens(targetTokensToBurn)
if err != nil {
    // Handle edge case where validator has no tokens
    continue
}

// Cap at available delegation shares
delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
if !found {
    continue
}
if sharesToUnbond.GT(delegation.Shares) {
    sharesToUnbond = delegation.Shares
}

// Unbond and accumulate ACTUAL tokens burned
actualTokensBurned, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
if err != nil {
    panic(fmt.Errorf("error unbonding delegator: %v", err))
}

// Accumulate actual burned amount, not theoretical
totalSlashAmount = totalSlashAmount.Add(actualTokensBurned)
```

The key principle: Calculate the intended token amount to burn first (based on `InitialBalance`), then convert to shares at the current exchange rate to determine how many shares to unbond, and return the actual tokens burned rather than the theoretical amount.

## Proof of Concept

**Conceptual scenario demonstrating the vulnerability:**

**Setup:**
1. Validator A and Validator B both exist with 1:1 exchange rates initially
2. User has 100 tokens delegated to Validator A
3. Validator B gets independently slashed by 50%, reducing its exchange rate to 0.5:1 (tokens/shares ratio decreases)
4. User redelegates 100 tokens from A to B:
   - Receives 200 shares for 100 tokens (at B's 0.5:1 rate)
   - `RedelegationEntry` stores: `InitialBalance=100`, `SharesDst=200`

**Action:**
1. Validator B's exchange rate deteriorates further to 0.33:1 before Validator A is slashed
2. Validator A commits an infraction and is slashed with 50% slash factor
3. `SlashRedelegation` executes:
   - Calculates: `slashAmount = 0.5 * 100 = 50` tokens (line 238-240)
   - Adds 50 to `totalSlashAmount`
   - Calculates: `sharesToUnbond = 0.5 * 200 = 100` shares (line 243)
   - Calls `k.Unbond(100 shares)` at B's current rate (0.33:1)
   - Unbonding yields: `100 * 0.33 = 33` tokens actually burned
   - Function returns `totalSlashAmount = 50`

**Result:**
1. Main `Slash` function receives 50 as `amountSlashed`
2. Reduces `remainingSlashAmount` by 50
3. But only 33 tokens were actually burned from the redelegation
4. Validator A is slashed for `(target - 50)` instead of `(target - 33)`
5. **Total under-slash = 17 tokens (34% of the intended redelegation slash)**

**Verification approach:**
- Monitor bonded pool balance changes vs reported slash amounts
- Compare `remainingSlashAmount` reduction to actual tokens burned from pools
- Verify total tokens burned < `slashFactor * power_at_infraction`

## Notes

The vulnerability stems from storing `SharesDst` as a fixed value at redelegation time, then using it for slash calculations when the exchange rate may have changed. While `InitialBalance` correctly captures the original tokens, the actual burning uses share-based calculations with the destination validator's current exchange rate. This creates a systematic accounting mismatch whenever destination validator exchange rates deteriorate - a common occurrence in PoS networks due to slashing events, validator operations, or rounding effects. The destination validator's health should not affect how much is slashed from the source validator's infraction, but the current implementation violates this principle.

### Citations

**File:** x/staking/keeper/slash.go (L11-11)
```go
// Find the contributing stake at that height and burn the specified slashFactor
```

**File:** x/staking/keeper/slash.go (L96-101)
```go
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
```

**File:** x/staking/keeper/slash.go (L219-296)
```go
func (k Keeper) SlashRedelegation(ctx sdk.Context, srcValidator types.Validator, redelegation types.Redelegation,
	infractionHeight int64, slashFactor sdk.Dec) (totalSlashAmount sdk.Int) {
	now := ctx.BlockHeader().Time
	totalSlashAmount = sdk.ZeroInt()
	bondedBurnedAmount, notBondedBurnedAmount := sdk.ZeroInt(), sdk.ZeroInt()

	// perform slashing on all entries within the redelegation
	for _, entry := range redelegation.Entries {
		// If redelegation started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}

		if entry.IsMature(now) {
			// Redelegation no longer eligible for slashing, skip it
			continue
		}

		// Calculate slash amount proportional to stake contributing to infraction
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)

		// Unbond from target validator
		sharesToUnbond := slashFactor.Mul(entry.SharesDst)
		if sharesToUnbond.IsZero() {
			continue
		}

		valDstAddr, err := sdk.ValAddressFromBech32(redelegation.ValidatorDstAddress)
		if err != nil {
			panic(err)
		}

		delegatorAddress := sdk.MustAccAddressFromBech32(redelegation.DelegatorAddress)

		delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
		if !found {
			// If deleted, delegation has zero shares, and we can't unbond any more
			continue
		}

		if sharesToUnbond.GT(delegation.Shares) {
			sharesToUnbond = delegation.Shares
		}

		tokensToBurn, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
		if err != nil {
			panic(fmt.Errorf("error unbonding delegator: %v", err))
		}

		dstValidator, found := k.GetValidator(ctx, valDstAddr)
		if !found {
			panic("destination validator not found")
		}

		// tokens of a redelegation currently live in the destination validator
		// therefor we must burn tokens from the destination-validator's bonding status
		switch {
		case dstValidator.IsBonded():
			bondedBurnedAmount = bondedBurnedAmount.Add(tokensToBurn)
		case dstValidator.IsUnbonded() || dstValidator.IsUnbonding():
			notBondedBurnedAmount = notBondedBurnedAmount.Add(tokensToBurn)
		default:
			panic("unknown validator status")
		}
	}

	if err := k.burnBondedTokens(ctx, bondedBurnedAmount); err != nil {
		panic(err)
	}

	if err := k.burnNotBondedTokens(ctx, notBondedBurnedAmount); err != nil {
		panic(err)
	}

	return totalSlashAmount
}
```

**File:** x/staking/types/validator.go (L304-306)
```go
func (v Validator) TokensFromShares(shares sdk.Dec) sdk.Dec {
	return (shares.MulInt(v.Tokens)).Quo(v.DelegatorShares)
}
```

**File:** x/staking/types/validator.go (L410-433)
```go
//	the exchange rate of future shares of this validator can increase.
func (v Validator) RemoveDelShares(delShares sdk.Dec) (Validator, sdk.Int) {
	remainingShares := v.DelegatorShares.Sub(delShares)

	var issuedTokens sdk.Int
	if remainingShares.IsZero() {
		// last delegation share gets any trimmings
		issuedTokens = v.Tokens
		v.Tokens = sdk.ZeroInt()
	} else {
		// leave excess tokens in the validator
		// however fully use all the delegator shares
		issuedTokens = v.TokensFromShares(delShares).TruncateInt()
		v.Tokens = v.Tokens.Sub(issuedTokens)

		if v.Tokens.IsNegative() {
			panic("attempting to remove more tokens than available in validator")
		}
	}

	v.DelegatorShares = remainingShares

	return v, issuedTokens
}
```

**File:** x/staking/keeper/delegation.go (L936-960)
```go
	returnAmount, err := k.Unbond(ctx, delAddr, valSrcAddr, sharesAmount)
	if err != nil {
		return time.Time{}, err
	}

	if returnAmount.IsZero() {
		return time.Time{}, types.ErrTinyRedelegationAmount
	}

	sharesCreated, err := k.Delegate(ctx, delAddr, returnAmount, srcValidator.GetStatus(), dstValidator, false)
	if err != nil {
		return time.Time{}, err
	}

	// create the unbonding delegation
	completionTime, height, completeNow := k.getBeginInfo(ctx, valSrcAddr)

	if completeNow { // no need to create the redelegation object
		return completionTime, nil
	}

	red := k.SetRedelegationEntry(
		ctx, delAddr, valSrcAddr, valDstAddr,
		height, completionTime, returnAmount, sharesAmount, sharesCreated,
	)
```
