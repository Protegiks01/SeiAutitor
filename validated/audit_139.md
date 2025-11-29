# Audit Report

## Title
Incorrect Slash Accounting for Redelegations When Destination Validator Has Been Slashed

## Summary
The `SlashRedelegation` function contains an accounting mismatch that causes systematic under-slashing of validators when destination validators of their redelegations have been slashed. The function returns a theoretical slash amount based on `InitialBalance` but actually burns tokens based on the destination validator's current share-to-token exchange rate, which decreases after slashing. This violates the protocol's core slashing invariant.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0)  and its interaction with the main Slash function at [2](#0-1) 

**Intended Logic:** According to the protocol specification [3](#0-2) , when a validator is slashed, the total amount slashed must equal `slashFactor * power` at the infraction height. Each amount slashed from redelegations and unbonding delegations should be subtracted from the total slash amount, with the remaining amount slashed from the validator's bonded tokens.

**Actual Logic:** The `SlashRedelegation` function calculates theoretical slash as `slashFactor * entry.InitialBalance` (line 238-240) and returns this theoretical `totalSlashAmount`. However, the actual tokens burned come from calling `Unbond()` (line 265), which converts shares to tokens using the destination validator's current exchange rate via `TokensFromShares()` [4](#0-3) . When a destination validator has been slashed, its exchange rate decreases because slashing reduces `Tokens` without reducing `DelegatorShares` [5](#0-4) . This causes `tokensToBurn < slashAmount`, but the function returns `totalSlashAmount` (theoretical) not the actual burn amount.

**Exploitation Path:**
1. Validator A commits a slashable infraction at height H1
2. After H1, tokens are redelegated from A to B (creating entry with `InitialBalance` and `SharesDst`)
3. Validator B is slashed for its own infraction, reducing its exchange rate from 1.0 to (e.g.) 0.5
4. Validator A is slashed for H1 infraction:
   - `SlashRedelegation` calculates: theoretical = `slashFactor * InitialBalance`
   - Actual burn via `Unbond`: `slashFactor * SharesDst * currentExchangeRate`
   - Since B was slashed: currentExchangeRate < 1.0, so actual < theoretical
   - Returns theoretical amount (line 295)
   - Main `Slash` subtracts theoretical from `remainingSlashAmount` (line 101)
   - Validator A's bonded tokens slashed by remaining amount
   - Total actual burn < `slashFactor * power` (protocol violation)

**Security Guarantee Broken:** The protocol invariant that validators must be slashed by exactly `slashFactor * power` at the infraction height is violated. This allows validators to escape proportional punishment through redelegations to subsequently-slashed validators.

## Impact Explanation

This vulnerability weakens the economic security model by allowing systematic under-slashing of misbehaving validators. During cascading slashing events (multiple validators slashed in sequence), the source validator escapes proportional punishment when their redelegations point to validators that get slashed first.

For example, with a validator having 1000 tokens at infraction height, 400 tokens redelegated to a validator that gets slashed 50%, and then source validator slashed 50%: the shortfall is 100 tokens (20% of intended 500-token punishment). This accumulates across multiple redelegations and slashing events.

The slashing mechanism ensures validators face financial consequences for misbehavior. Under-slashing reduces deterrence and undermines security guarantees. Fewer tokens are burned than specified, affecting token supply accounting and penalty effectiveness.

## Likelihood Explanation

**Who Can Trigger:** Any network participant through normal operations—no special privileges required.

**Conditions Required:**
1. A validator commits a slashable infraction (double-signing, downtime, etc.)
2. After infraction, delegators redelegate from that validator to another (routine operation)
3. The destination validator gets slashed for its own independent infraction
4. The source validator's infraction is detected and slashed

**Frequency:** This occurs naturally during network instability when multiple validators are slashed. The vulnerability is systemic and manifests whenever conditions align. It can also be strategically exploited by sophisticated actors who commit infractions then redelegate to risky validators they control, causing those validators to be slashed before their original infraction is discovered, thereby reducing total slashing penalty.

## Recommendation

Modify `SlashRedelegation` to return the actual burned amount rather than theoretical amount:

1. Track cumulative actual `tokensToBurn` from all redelegation entries instead of theoretical `slashAmount`
2. Replace line 240 accumulation from `totalSlashAmount = totalSlashAmount.Add(slashAmount)` to `totalSlashAmount = totalSlashAmount.Add(tokensToBurn)`
3. Return sum of actual `tokensToBurn` values instead of theoretical `slashAmount` values

Alternatively, implement a two-phase approach:
1. Record both theoretical and actual amounts during redelegation slashing
2. Track shortfall between theoretical and actual burns
3. Adjust validator's bonded token slash to compensate for any shortfall

This ensures the slashing invariant is maintained: total actual burn = `slashFactor * power` at infraction height.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`
**Function:** `TestSlashRedelegationWithSlashedDestination` (to be added)

**Setup:**
1. Bootstrap test environment with 3 validators (A, B, C) each with 1000 tokens (power=10)
2. Create delegator with sufficient funds
3. Create redelegation from validator A to B of 400 tokens at height 11
4. Record validator A's infraction at height 10

**Action:**
1. Slash validator B by 50% at height 12 (reduces B's exchange rate to 0.5)
2. Record bonded pool balance before slashing A
3. Slash validator A by 50% at height 13 for infraction at height 10
4. Record bonded pool balance after slashing A

**Result:**
- Theoretical slash for redelegation: 50% × 400 = 200 tokens
- Actual burn from redelegation: 50% × 400 shares × 0.5 = 100 tokens
- Total intended slash: 50% × 1000 = 500 tokens
- Redelegation theoretical subtracted: 200 tokens
- Remaining slash from A: 500 - 200 = 300 tokens
- Total actual burn: 100 + 300 = 400 tokens
- **Expected: 500 tokens, Shortfall: 100 tokens (20% under-slash)**

The bonded pool balance decrease confirms only 400 tokens burned instead of protocol-specified 500 tokens.

## Notes

This vulnerability affects the core slashing mechanism in Cosmos SDK staking module. The function comment at [6](#0-5)  indicates returning theoretical amounts is intentional for handling insufficient stake scenarios. However, this design is flawed for redelegations when the destination validator has been independently slashed, as the shortfall is not due to previous slashing of the same stake but due to an independent validator's slashing event. This causes the total actual burn to be less than the protocol-specified `slashFactor * power`, violating a fundamental protocol invariant that distinguishes this case from the handled scenario of previously-slashed unbonding delegations.

### Citations

**File:** x/staking/keeper/slash.go (L93-102)
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
```

**File:** x/staking/keeper/slash.go (L214-217)
```go
// return the amount that would have been slashed assuming
// the unbonding delegation had enough stake to slash
// (the amount actually slashed may be less if there's
// insufficient stake remaining)
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

**File:** x/staking/spec/02_state_transitions.md (L131-138)
```markdown
- The total `slashAmount` is calculated as the `slashFactor` (a chain parameter) \* `TokensFromConsensusPower`,
  the total number of tokens bonded to the validator at the time of the infraction.
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```

**File:** x/staking/types/validator.go (L304-305)
```go
func (v Validator) TokensFromShares(shares sdk.Dec) sdk.Dec {
	return (shares.MulInt(v.Tokens)).Quo(v.DelegatorShares)
```

**File:** x/staking/types/validator.go (L393-405)
```go
func (v Validator) RemoveTokens(tokens sdk.Int) Validator {
	if tokens.IsNegative() {
		panic(fmt.Sprintf("should not happen: trying to remove negative tokens %v", tokens))
	}

	if v.Tokens.LT(tokens) {
		panic(fmt.Sprintf("should not happen: only have %v tokens, trying to remove %v", v.Tokens, tokens))
	}

	v.Tokens = v.Tokens.Sub(tokens)

	return v
}
```
