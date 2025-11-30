# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function contains a critical accounting vulnerability where it calculates the slash amount based on the original token balance (`InitialBalance`) but actually burns fewer tokens when converting shares at the destination validator's current (potentially deteriorated) exchange rate. The function returns the theoretical slash amount rather than the actual burned amount, causing `remainingSlashAmount` to be over-reduced and resulting in systematic under-slashing of validators.

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296) [1](#0-0) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should burn exactly `slashFactor * InitialBalance` tokens from each redelegation entry, where `InitialBalance` represents the tokens at stake during the infraction. The total slashed should equal `slashFactor * power_at_infraction`.

**Actual logic:** The function performs the following steps:
1. Line 238-240: Calculates `slashAmount = slashFactor * entry.InitialBalance` and adds to `totalSlashAmount`
2. Line 243: Calculates `sharesToUnbond = slashFactor * entry.SharesDst` (using shares stored at redelegation time)
3. Line 265: Calls `k.Unbond(sharesToUnbond)` which converts shares to tokens using the destination validator's **current** exchange rate
4. Lines 279-281: The actual `tokensToBurn` (potentially less than `slashAmount`) is accumulated for burning
5. Line 295: Returns `totalSlashAmount` instead of the sum of actual `tokensToBurn` values

The exchange rate conversion occurs in `validator.TokensFromShares`: [2](#0-1) 

When the destination validator's exchange rate deteriorates between redelegation and slashing, `tokensToBurn < slashAmount`. The main `Slash` function then reduces `remainingSlashAmount` by the full `totalSlashAmount`: [3](#0-2) 

This causes the validator to be slashed for `remainingSlashAmount = (target_slash - totalSlashAmount)` instead of `(target_slash - actual_tokens_burned)`, resulting in under-slashing.

**Exploitation path:**
1. Validator A commits an infraction at height H (evidence not yet submitted)
2. User redelegates from A to Validator B using standard redelegation transaction
3. RedelegationEntry is created with `InitialBalance` (original tokens) and `SharesDst` (shares at B's current rate): [4](#0-3) 
4. Validator B's exchange rate deteriorates (e.g., B gets slashed independently)
5. Evidence of A's infraction is submitted and `Slash` is called
6. `SlashRedelegation` calculates theoretical slash but burns fewer actual tokens
7. Validator A is under-slashed by the difference

**Security guarantee broken:** The protocol's slashing invariant `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's health rather than solely on infraction severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security model:

1. **Systematic Under-Slashing:** Whenever destination validators have deteriorating exchange rates (common due to slashing, validator operations, or rounding), the actual slashing is less than intended. The discrepancy can be substantial - with a 50% exchange rate deterioration, up to 50% of the slashing penalty can be avoided.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, potentially encouraging infractions since the expected cost is lower than designed.

3. **Accounting Invariant Violation:** The protocol's fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. Instead, the actual penalty varies based on factors unrelated to the infraction (destination validator performance).

4. **Potential Gaming:** While the issue occurs naturally, sophisticated actors monitoring validator infractions could deliberately redelegate to validators with declining exchange rates to minimize their slashing exposure, creating "slashing havens."

The impact fits the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." While this doesn't constitute direct fund theft, it represents a failure of the protocol's core security mechanism.

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Validator infractions (downtime, double-signing) occur regularly in PoS networks
2. **Natural exchange rate fluctuations:** Exchange rates change frequently due to slashing events, validator operations, or precision losses
3. **Wide redelegation usage:** Redelegation is a core feature allowing instant validator switching, widely used by delegators
4. **Extended vulnerability window:** The unbonding period (typically 21 days) provides ample time for exchange rate changes

**No special requirements:**
- Any delegator can perform redelegations (no special privileges)
- The bug causes systematic under-slashing even without intentional exploitation
- Occurs through normal protocol operations

The vulnerability affects the fundamental slashing mechanism that underpins network security and can be triggered through standard user actions.

## Recommendation

Modify `SlashRedelegation` to calculate the target token amount first, then convert to shares at the current exchange rate:

```go
// Calculate target tokens to burn based on original stake
slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
tokensToBurn := slashAmountDec.TruncateInt()

// Get destination validator
dstValidator, found := k.GetValidator(ctx, valDstAddr)
if !found {
    panic("destination validator not found")
}

// Convert target token amount to shares at CURRENT exchange rate
sharesToUnbond, err := dstValidator.SharesFromTokens(tokensToBurn)
if err != nil {
    continue // Handle edge case where validator has no tokens
}

// Cap at available delegation shares
delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
if !found {
    continue
}
if sharesToUnbond.GT(delegation.Shares) {
    sharesToUnbond = delegation.Shares
    // Recalculate actual tokens that can be burned
    tokensToBurn = dstValidator.TokensFromShares(sharesToUnbond).TruncateInt()
}

// Unbond the calculated shares
actualTokens, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
// actualTokens should equal tokensToBurn
totalSlashAmount = totalSlashAmount.Add(actualTokens)
```

The key principle: Calculate the token amount to burn first (based on `InitialBalance`), then convert to shares at the current rate, ensuring the return value matches actual tokens burned.

## Proof of Concept

**Conceptual scenario:**

**Setup:**
1. Create validators A (source) and B (destination) with 1:1 exchange rates
2. User has 100 tokens delegated to A
3. Validator B gets independently slashed by 50%, reducing exchange rate to 0.5:1 (100 shares now worth 50 tokens)
4. User redelegates 100 tokens from A to B at this poor exchange rate
   - Receives 200 shares for 100 tokens (at 0.5:1 rate)
   - `RedelegationEntry`: `InitialBalance=100`, `SharesDst=200`

**Action:**
1. Validator A is slashed for an infraction with 50% slash factor (committed before redelegation)
2. `SlashRedelegation` executes:
   - Calculates: `totalSlashAmount = 0.5 * 100 = 50` tokens
   - Calculates: `sharesToUnbond = 0.5 * 200 = 100` shares
   - Unbonds 100 shares at B's current rate: `100 * 0.5 = 50` tokens (matches in this case)

**Result if B deteriorates further to 0.33:1 before slashing:**
1. B now has rate 0.33:1 (66 tokens for 200 shares)
2. Unbonding 100 shares yields: `100 * 0.33 = 33` tokens
3. But `totalSlashAmount` reports 50 tokens
4. `remainingSlashAmount` reduced by 50, but only 33 actually burned
5. Validator A slashed for (target - 50) instead of (target - 33)
6. **Total under-slash = 17 tokens (34% of intended redelegation slash)**

**Verification points:**
- Monitor bonded pool balance decrease vs reported slash amounts
- Compare `remainingSlashAmount` reduction to actual tokens burned
- Verify total slashed < `slashFactor * power_at_infraction`

## Notes

The vulnerability stems from storing `SharesDst` as a fixed value at redelegation time, then using it for slash calculations when the exchange rate may have changed. The `InitialBalance` correctly captures original tokens, but the actual burning uses share-based calculations with a potentially stale exchange rate relationship. This creates a systematic accounting mismatch whenever destination validator exchange rates deteriorate - a common occurrence in PoS networks.

### Citations

**File:** x/staking/keeper/slash.go (L93-107)
```go
		// Iterate through redelegations from slashed source validator
		redelegations := k.GetRedelegationsFromSrcValidator(ctx, operatorAddress)
		for _, redelegation := range redelegations {
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}
	}

	// cannot decrease balance below zero
	tokensToBurn := sdk.MinInt(remainingSlashAmount, validator.Tokens)
	tokensToBurn = sdk.MaxInt(tokensToBurn, sdk.ZeroInt()) // defensive.
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
