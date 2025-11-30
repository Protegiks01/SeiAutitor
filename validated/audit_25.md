# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function contains an accounting vulnerability where it returns a theoretical slash amount based on `InitialBalance` instead of the actual tokens burned. When the destination validator's exchange rate has deteriorated between redelegation and slashing, this creates a systematic under-slashing of validators, violating the protocol's slashing invariant.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should burn `slashFactor * stake_at_infraction` total tokens. The amount slashed from redelegations should be subtracted from what's slashed from the validator itself, as specified in the protocol documentation. [2](#0-1) 

**Actual logic:** The function performs these steps:
1. Calculates theoretical `slashAmount = slashFactor * entry.InitialBalance` (tokens at redelegation time)
2. Accumulates this in `totalSlashAmount` 
3. Calculates `sharesToUnbond = slashFactor * entry.SharesDst` using shares stored at redelegation time
4. Calls `k.Unbond()` which converts shares to tokens using the destination validator's **current** exchange rate [3](#0-2) [4](#0-3) 
5. The actual `tokensToBurn` from unbonding is less than `slashAmount` when exchange rate deteriorated
6. Returns `totalSlashAmount` (theoretical) instead of sum of actual `tokensToBurn` values

**Exploitation path:**
1. User redelegates from Validator A to Validator B through standard transaction [5](#0-4) 
2. `BeginRedelegation` stores `InitialBalance` (original tokens) and `SharesDst` (shares at destination)
3. Validator B's exchange rate deteriorates (through slashing, rewards distribution, etc.)
4. Validator A is later slashed for an earlier infraction
5. `SlashRedelegation` calculates theoretical slash but burns fewer actual tokens due to deteriorated exchange rate
6. Main `Slash` function receives inflated amount and reduces `remainingSlashAmount` accordingly [6](#0-5) 
7. Validator A is under-slashed by the difference between reported and actual burned amounts

**Security guarantee broken:** The protocol's slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The specification states that "Each amount slashed from redelegations and unbonding delegations is subtracted from the total slash amount" [7](#0-6) , implying the actual amount slashed should be used, not the theoretical amount.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security:

1. **Systematic Under-Slashing**: When destination validators have deteriorating exchange rates (common due to slashing events, validator operations, or precision losses), the actual total tokens burned is less than `slashFactor * power_at_infraction`. The validator retains more stake than intended.

2. **Economic Security Weakening**: Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, as the expected cost of infractions becomes lower than designed.

3. **Protocol Invariant Violation**: The fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. The actual penalty becomes dependent on the destination validator's health rather than solely on the source validator's infraction.

This qualifies as **Medium severity** under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." The staking module is core layer-1 protocol code, and this causes unintended slashing behavior that systematically reduces penalties below intended levels.

## Likelihood Explanation

**High likelihood:**

1. **Common triggers**: Validator infractions occur regularly through downtime or double-signing
2. **Natural exchange rate fluctuations**: Exchange rates change frequently due to slashing events, validator operations, or precision losses  
3. **Wide redelegation usage**: Redelegation is a core feature widely used for instant validator switching
4. **Extended vulnerability window**: The unbonding period (typically 21 days) provides ample time for exchange rate changes between redelegation and slashing

**No special requirements:**
- Any delegator can perform redelegations (no special privileges)
- Occurs through normal protocol operations  
- No intentional attack needed - natural network dynamics trigger it

## Recommendation

Modify `SlashRedelegation` to return the sum of actual tokens burned instead of the theoretical amount. The function should:

1. Calculate the target token amount to burn based on `InitialBalance`
2. Convert this to shares at the current exchange rate (not the stored `SharesDst`)  
3. Unbond those shares to get actual tokens burned
4. Accumulate and return the sum of actual `tokensToBurn` values, not theoretical `totalSlashAmount`

This ensures that `remainingSlashAmount` in the main `Slash` function is reduced only by what was actually burned, allowing the validator to be properly slashed for the remainder.

## Proof of Concept

**Setup:**
1. Validator A has power of 1000 at infraction height
2. User redelegates 100 tokens from Validator A to Validator B
3. At redelegation: B has 1:1 exchange rate, user gets 100 shares
4. `RedelegationEntry` stores: `InitialBalance=100`, `SharesDst=100`

**Action:**
1. Validator B gets independently slashed 50%, exchange rate becomes 0.5:1 (50 tokens, 100 shares)
2. Validator A is slashed with `slashFactor=0.1` (10%)
3. `SlashRedelegation` executes:
   - Calculates: `slashAmount = 0.1 * 100 = 10` tokens (theoretical)
   - Adds 10 to `totalSlashAmount`
   - Calculates: `sharesToUnbond = 0.1 * 100 = 10` shares
   - Calls `k.Unbond(10 shares)` at B's current rate (0.5:1)
   - Unbonding yields: `10 * 0.5 = 5` tokens actually burned
   - **Returns `totalSlashAmount = 10`** (not 5)

**Result:**
1. Main `Slash` function receives 10 as `amountSlashed`
2. Intended total slash: 0.1 * 1000 = 100 tokens
3. Reduces `remainingSlashAmount` by 10, leaving 90 to slash from validator
4. Total actually burned: 5 (from redelegation) + 90 (from validator) = **95 tokens**
5. **Under-slash: 5 tokens (5% of intended total)**

## Notes

The vulnerability stems from the design decision to store `SharesDst` as a fixed value at redelegation time and use it for slash calculations when the exchange rate may have changed. While this approach correctly tracks the original stake contribution, it creates an accounting mismatch between reported and actual slashed amounts. The destination validator's subsequent performance should not affect how much is slashed from the source validator's infraction, but the current implementation violates this principle by returning theoretical rather than actual amounts.

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

**File:** x/staking/spec/02_state_transitions.md (L134-138)
```markdown
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```
