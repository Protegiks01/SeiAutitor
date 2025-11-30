# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function in the staking module contains an accounting vulnerability where it calculates the theoretical slash amount based on `InitialBalance` but returns this value instead of the actual burned tokens. When the destination validator's exchange rate has deteriorated, fewer tokens are actually burned than reported, causing the main `Slash` function to over-reduce `remainingSlashAmount` and resulting in systematic under-slashing of validators.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should burn exactly `slashFactor * InitialBalance` tokens from each redelegation entry and report this amount back to the caller. The code comment states "burn the specified slashFactor of it" [2](#0-1) , indicating the intent to burn the full calculated amount.

**Actual logic:** The function performs these steps:
1. Calculates `slashAmount = slashFactor * entry.InitialBalance` and adds to `totalSlashAmount` [3](#0-2) 
2. Calculates `sharesToUnbond = slashFactor * entry.SharesDst` using shares stored at redelegation time [4](#0-3) 
3. Calls `k.Unbond(sharesToUnbond)` which converts shares to tokens at the destination validator's **current** exchange rate [5](#0-4) 
4. The actual `tokensToBurn` returned by `Unbond` is accumulated for burning [6](#0-5) 
5. Returns `totalSlashAmount` instead of the sum of actual `tokensToBurn` values [7](#0-6) 

The share-to-token conversion uses the validator's current exchange rate [8](#0-7)  via the `RemoveDelShares` method [9](#0-8) . When this rate has deteriorated since redelegation, `tokensToBurn < slashAmount`.

**Exploitation path:**
1. User redelegates from Validator A to Validator B using standard redelegation transaction [10](#0-9) 
2. RedelegationEntry stores `InitialBalance` (original tokens) and `SharesDst` (shares received) [11](#0-10) 
3. Validator B's exchange rate deteriorates (e.g., B gets slashed independently, reducing tokens while shares remain)
4. Validator A is slashed for an earlier infraction
5. `SlashRedelegation` calculates theoretical slash but burns fewer actual tokens due to deteriorated exchange rate
6. Main `Slash` function reduces `remainingSlashAmount` by the reported amount [12](#0-11) 
7. Validator A is under-slashed by the difference between reported and actual burned amounts

**Security guarantee broken:** The protocol's slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's health rather than solely on infraction severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security model:

1. **Systematic Under-Slashing:** When destination validators have deteriorating exchange rates (common due to slashing, validator operations, or rounding), actual slashing is less than intended. With a 50% exchange rate deterioration, up to 50% of the slashing penalty can be avoided.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, potentially encouraging infractions since the expected cost is lower than designed.

3. **Protocol Invariant Violation:** The fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. The actual penalty varies based on factors unrelated to the infraction (destination validator performance).

This qualifies as Medium severity under the criterion: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." The staking module is core layer-1 protocol code, and this bug causes unintended slashing behavior without direct fund theft.

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Validator infractions occur regularly in PoS networks
2. **Natural exchange rate fluctuations:** Exchange rates change frequently due to slashing events, validator operations, or precision losses
3. **Wide redelegation usage:** Redelegation is a core feature widely used by delegators for instant validator switching
4. **Extended vulnerability window:** The unbonding period (typically 21 days) provides ample time for exchange rate changes between redelegation and slashing

**No special requirements:**
- Any delegator can perform redelegations (no special privileges needed)
- The bug causes systematic under-slashing even without intentional exploitation
- Occurs through normal protocol operations

The vulnerability affects the fundamental slashing mechanism underpinning network security and can be triggered through standard user actions.

## Recommendation

Modify `SlashRedelegation` to calculate the target token amount first, then convert to shares at the current exchange rate, ensuring the return value matches actual tokens burned:

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

The key principle: Calculate the token amount to burn first (based on `InitialBalance`), then convert to shares at the current rate, ensuring the return value reflects actual burned tokens.

## Proof of Concept

**Conceptual scenario demonstrating the vulnerability:**

**Setup:**
1. Validator A and Validator B both exist with 1:1 exchange rates initially
2. User has 100 tokens delegated to Validator A
3. Validator B gets independently slashed by 50%, reducing exchange rate to 0.5:1 (100 shares now worth 50 tokens)
4. User redelegates 100 tokens from A to B
   - Receives 200 shares for 100 tokens (at 0.5:1 rate)
   - `RedelegationEntry`: `InitialBalance=100`, `SharesDst=200`

**Action:**
1. Validator A commits infraction with 50% slash factor
2. `SlashRedelegation` executes:
   - Calculates: `totalSlashAmount = 0.5 * 100 = 50` tokens (line 238-240)
   - Calculates: `sharesToUnbond = 0.5 * 200 = 100` shares (line 243)
   - Unbonds 100 shares at B's current rate: `100 * 0.5 = 50` tokens

**Result if B deteriorates further to 0.33:1 before slashing:**
1. B now has rate 0.33:1 (66 tokens for 200 shares)
2. Unbonding 100 shares yields: `100 * 0.33 = 33` tokens actually burned
3. But `totalSlashAmount` reports 50 tokens to caller
4. Main `Slash` function reduces `remainingSlashAmount` by 50, but only 33 were actually burned
5. Validator A slashed for `(target - 50)` instead of `(target - 33)`
6. **Total under-slash = 17 tokens (34% of intended redelegation slash)**

**Verification approach:**
- Monitor bonded pool balance decrease vs reported slash amounts
- Compare `remainingSlashAmount` reduction to actual tokens burned from pool
- Verify total slashed < `slashFactor * power_at_infraction`

## Notes

The vulnerability stems from storing `SharesDst` as a fixed value at redelegation time, then using it for slash calculations when the exchange rate may have changed. The `InitialBalance` correctly captures original tokens, but the actual burning uses share-based calculations with a potentially stale exchange rate relationship. This creates a systematic accounting mismatch whenever destination validator exchange rates deteriorate - a common occurrence in PoS networks.

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

**File:** x/staking/keeper/validator.go (L108-117)
```go
// Update the tokens of an existing validator, update the validators power index key
func (k Keeper) RemoveValidatorTokensAndShares(ctx sdk.Context, validator types.Validator,
	sharesToRemove sdk.Dec) (valOut types.Validator, removedTokens sdk.Int) {
	k.DeleteValidatorByPowerIndex(ctx, validator)
	validator, removedTokens = validator.RemoveDelShares(sharesToRemove)
	k.SetValidator(ctx, validator)
	k.SetValidatorByPowerIndex(ctx, validator)

	return validator, removedTokens
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

**File:** x/staking/types/delegation.go (L188-195)
```go
func NewRedelegationEntry(creationHeight int64, completionTime time.Time, balance sdk.Int, sharesDst sdk.Dec) RedelegationEntry {
	return RedelegationEntry{
		CreationHeight: creationHeight,
		CompletionTime: completionTime,
		InitialBalance: balance,
		SharesDst:      sharesDst,
	}
}
```
