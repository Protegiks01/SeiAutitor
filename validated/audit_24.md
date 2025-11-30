# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function contains an accounting vulnerability where it returns a theoretical slash amount calculated from `InitialBalance` but actually burns fewer tokens when converted through the destination validator's current exchange rate. This mismatch causes systematic under-slashing of validators when destination validators have deteriorating exchange rates. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296)

**Intended logic:** When slashing a validator with active redelegations, the protocol should slash `slashFactor * InitialBalance` tokens from each redelegation entry and subtract the actual burned amount from `remainingSlashAmount` to determine how much to slash from the validator itself. The total slashed should equal `slashFactor * power_at_infraction`. [2](#0-1) 

**Actual logic:** 
1. Line 238-240: Calculates `slashAmount = slashFactor * entry.InitialBalance` and accumulates in `totalSlashAmount`
2. Line 243: Calculates `sharesToUnbond = slashFactor * entry.SharesDst` using shares stored at redelegation time
3. Line 265: Calls `k.Unbond()` which converts shares to tokens at the destination validator's **current** exchange rate via `RemoveDelShares` -> `TokensFromShares`
4. Lines 279, 281: Accumulates actual `tokensToBurn` for burning
5. Line 295: Returns `totalSlashAmount` instead of sum of actual tokens burned [3](#0-2) [4](#0-3) 

When the destination validator's exchange rate deteriorates (tokens/shares ratio decreases), `sharesToUnbond` converts to fewer tokens than the `slashAmount`, creating an accounting mismatch.

**Exploitation path:**
1. User redelegates from Validator A to Validator B, creating `RedelegationEntry` with `InitialBalance` and `SharesDst` [5](#0-4) 

2. Validator B's exchange rate deteriorates (due to slashing, rounding, or other factors)
3. Validator A is slashed for an earlier infraction
4. `SlashRedelegation` reports slashing 50 tokens (based on `InitialBalance`) but only burns 33 tokens (based on current exchange rate)
5. Main `Slash` function subtracts 50 from `remainingSlashAmount` but only 33 were actually burned [6](#0-5) 

6. Validator A is under-slashed by 17 tokens

**Security guarantee broken:** The protocol's slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's exchange rate rather than solely on the infraction severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security:

1. **Systematic Under-Slashing:** When destination validators have deteriorating exchange rates, validators are slashed for less than intended. The discrepancy can be substantial (e.g., 34% in the provided scenario).

2. **Economic Security Weakening:** Slashing is the primary deterrent against validator misbehavior. Reduced penalties weaken this mechanism and may encourage infractions since the expected cost is lower.

3. **Protocol Invariant Violation:** The total amount slashed deviates from the designed `slashFactor * power_at_infraction` formula based on factors unrelated to the infraction.

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Redelegations are widely used for instant validator switching. Validator infractions occur regularly through downtime or double-signing.

2. **Natural exchange rate changes:** Exchange rates change frequently due to:
   - Slashing events on destination validators
   - Reward distribution
   - Precision/rounding losses
   - Normal validator operations

3. **Extended window:** The unbonding period (typically 21 days) provides ample time for exchange rate changes between redelegation and slashing.

4. **No special requirements:** Any delegator can perform redelegations. The bug manifests through normal protocol operations without intentional exploitation.

## Recommendation

Modify `SlashRedelegation` to calculate shares to unbond based on the target token amount at the current exchange rate:

```go
// Calculate target tokens to burn
slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
targetTokens := slashAmountDec.TruncateInt()

// Get destination validator
dstValidator, found := k.GetValidator(ctx, valDstAddr)
if !found {
    panic("destination validator not found")
}

// Convert target tokens to shares at CURRENT rate
sharesToUnbond, err := dstValidator.SharesFromTokens(targetTokens)
if err != nil {
    continue
}

// Cap at available shares
if sharesToUnbond.GT(delegation.Shares) {
    sharesToUnbond = delegation.Shares
}

// Unbond and accumulate ACTUAL tokens burned
actualTokensBurned, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
if err != nil {
    panic(err)
}

// Return actual burned amount
totalSlashAmount = totalSlashAmount.Add(actualTokensBurned)
``` [7](#0-6) 

## Proof of Concept

**Conceptual scenario:**

**Setup:**
- Validator A and B start with 1:1 exchange rates
- User has 100 tokens delegated to A
- Validator B gets slashed 50%, exchange rate becomes 0.5:1
- User redelegates 100 tokens from A to B, receiving 200 shares
- `RedelegationEntry` stores: `InitialBalance=100`, `SharesDst=200`

**Action:**
- B's exchange rate deteriorates to 0.33:1
- A commits infraction, slashed with 50% factor
- `SlashRedelegation` executes:
  - Calculates: `slashAmount = 0.5 * 100 = 50` tokens (line 238-240)
  - Adds 50 to `totalSlashAmount`
  - Calculates: `sharesToUnbond = 0.5 * 200 = 100` shares (line 243)
  - Unbonds 100 shares at 0.33:1 rate = 33 tokens actually burned
  - Returns `totalSlashAmount = 50`

**Result:**
- Main `Slash` reduces `remainingSlashAmount` by 50
- Only 33 tokens actually burned from redelegation
- Validator under-slashed by 17 tokens (34% of intended redelegation slash)

**Verification:**
The existing test at lines 118-183 of `slash_test.go` only covers the 1:1 exchange rate case and doesn't detect this bug because it assumes the destination validator's exchange rate remains constant. [8](#0-7) 

## Notes

The specification confirms that redelegations should be slashed by `slashFactor * InitialBalance` and this amount should be subtracted from the total slash amount. However, the specification doesn't address exchange rate changes at the destination validator. [9](#0-8) 

The vulnerability stems from storing `SharesDst` at redelegation time and using it for slashing calculations when the exchange rate may have changed. The destination validator's health should not affect how much is slashed from the source validator's infraction, but the current implementation violates this principle.

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

**File:** x/staking/types/validator.go (L319-327)
```go
// SharesFromTokens returns the shares of a delegation given a bond amount. It
// returns an error if the validator has no tokens.
func (v Validator) SharesFromTokens(amt sdk.Int) (sdk.Dec, error) {
	if v.Tokens.IsZero() {
		return sdk.ZeroDec(), ErrInsufficientShares
	}

	return v.GetDelegatorShares().MulInt(amt).QuoInt(v.GetTokens()), nil
}
```

**File:** x/staking/types/validator.go (L411-433)
```go
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

**File:** x/staking/keeper/slash_test.go (L118-183)
```go
// tests slashRedelegation
func TestSlashRedelegation(t *testing.T) {
	app, ctx, addrDels, addrVals := bootstrapSlashTest(t, 10)
	fraction := sdk.NewDecWithPrec(5, 1)

	// add bonded tokens to pool for (re)delegations
	startCoins := sdk.NewCoins(sdk.NewInt64Coin(app.StakingKeeper.BondDenom(ctx), 15))
	bondedPool := app.StakingKeeper.GetBondedPool(ctx)
	balances := app.BankKeeper.GetAllBalances(ctx, bondedPool.GetAddress())

	require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, bondedPool.GetName(), startCoins))
	app.AccountKeeper.SetModuleAccount(ctx, bondedPool)

	// set a redelegation with an expiration timestamp beyond which the
	// redelegation shouldn't be slashed
	rd := types.NewRedelegation(addrDels[0], addrVals[0], addrVals[1], 0,
		time.Unix(5, 0), sdk.NewInt(10), sdk.NewDec(10))

	app.StakingKeeper.SetRedelegation(ctx, rd)

	// set the associated delegation
	del := types.NewDelegation(addrDels[0], addrVals[1], sdk.NewDec(10))
	app.StakingKeeper.SetDelegation(ctx, del)

	// started redelegating prior to the current height, stake didn't contribute to infraction
	validator, found := app.StakingKeeper.GetValidator(ctx, addrVals[1])
	require.True(t, found)
	slashAmount := app.StakingKeeper.SlashRedelegation(ctx, validator, rd, 1, fraction)
	require.True(t, slashAmount.Equal(sdk.NewInt(0)))

	// after the expiration time, no longer eligible for slashing
	ctx = ctx.WithBlockHeader(tmproto.Header{Time: time.Unix(10, 0)})
	app.StakingKeeper.SetRedelegation(ctx, rd)
	validator, found = app.StakingKeeper.GetValidator(ctx, addrVals[1])
	require.True(t, found)
	slashAmount = app.StakingKeeper.SlashRedelegation(ctx, validator, rd, 0, fraction)
	require.True(t, slashAmount.Equal(sdk.NewInt(0)))

	balances = app.BankKeeper.GetAllBalances(ctx, bondedPool.GetAddress())

	// test valid slash, before expiration timestamp and to which stake contributed
	ctx = ctx.WithBlockHeader(tmproto.Header{Time: time.Unix(0, 0)})
	app.StakingKeeper.SetRedelegation(ctx, rd)
	validator, found = app.StakingKeeper.GetValidator(ctx, addrVals[1])
	require.True(t, found)
	slashAmount = app.StakingKeeper.SlashRedelegation(ctx, validator, rd, 0, fraction)
	require.True(t, slashAmount.Equal(sdk.NewInt(5)))
	rd, found = app.StakingKeeper.GetRedelegation(ctx, addrDels[0], addrVals[0], addrVals[1])
	require.True(t, found)
	require.Len(t, rd.Entries, 1)

	// end block
	applyValidatorSetUpdates(t, ctx, app.StakingKeeper, 1)

	// initialbalance unchanged
	require.Equal(t, sdk.NewInt(10), rd.Entries[0].InitialBalance)

	// shares decreased
	del, found = app.StakingKeeper.GetDelegation(ctx, addrDels[0], addrVals[1])
	require.True(t, found)
	require.Equal(t, int64(5), del.Shares.RoundInt64())

	// pool bonded tokens should decrease
	burnedCoins := sdk.NewCoins(sdk.NewCoin(app.StakingKeeper.BondDenom(ctx), slashAmount))
	require.Equal(t, balances.Sub(burnedCoins), app.BankKeeper.GetAllBalances(ctx, bondedPool.GetAddress()))
}
```

**File:** x/staking/spec/02_state_transitions.md (L151-158)
```markdown
### Slash Redelegation

When a validator is slashed, so are all redelegations from the validator that began after the
infraction. Redelegations are slashed by `slashFactor`.
Redelegations that began before the infraction are not slashed.
The amount slashed is calculated from the `InitialBalance` of the delegation and is capped to
prevent a resulting negative balance.
Mature redelegations (that have completed pseudo-unbonding) are not slashed.
```
