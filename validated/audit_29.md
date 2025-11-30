# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function in the staking module calculates a theoretical slash amount based on the original token balance (`InitialBalance`) but returns this theoretical value instead of the actual tokens burned. When the destination validator's exchange rate deteriorates between redelegation and slashing, the actual tokens burned are less than the theoretical amount, causing systematic under-slashing of the source validator.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should burn exactly `slashFactor * power_at_infraction` tokens total. The `remainingSlashAmount` in the main `Slash` function should be reduced by the actual tokens burned from redelegations to ensure the total slashed equals the intended amount.

**Actual logic:** 
1. `SlashRedelegation` calculates theoretical slash: `slashAmount = slashFactor * entry.InitialBalance` [3](#0-2) 

2. Calculates shares to unbond using shares recorded at redelegation time: `sharesToUnbond = slashFactor * entry.SharesDst` [4](#0-3) 

3. Calls `k.Unbond()` which converts shares to tokens at the destination validator's **current** exchange rate via `TokensFromShares` [5](#0-4) [6](#0-5) 

4. Returns `totalSlashAmount` (theoretical) instead of actual tokens burned [7](#0-6) 

5. Main `Slash` function reduces `remainingSlashAmount` by this theoretical amount [8](#0-7) 

**Exploitation path:**
1. User redelegates from Validator A to Validator B via standard `BeginRedelegation` [9](#0-8) 

2. `RedelegationEntry` created with `InitialBalance` (original tokens) and `SharesDst` (shares at B's rate at that time) [10](#0-9) 

3. Validator B's exchange rate deteriorates (e.g., B gets independently slashed by 50%)
4. Validator A is slashed for an infraction that occurred after the redelegation
5. `SlashRedelegation` calculates theoretical 50 tokens but only burns 25 tokens (due to B's 0.5:1 rate)
6. `remainingSlashAmount` reduced by 50, but only 25 actually burned
7. Total burned is less than intended `slashFactor * power_at_infraction`

**Security guarantee broken:** The protocol's core slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's health rather than solely on the infraction severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security model:

1. **Systematic Under-Slashing:** Whenever destination validators have deteriorating exchange rates (common due to slashing events, validator operations, or rounding), actual slashing is less than intended. With a 50% exchange rate deterioration, up to 50% of the redelegation slashing penalty can be lost.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, potentially encouraging infractions since the expected cost is lower than designed.

3. **Accounting Invariant Violation:** The protocol's fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. The actual penalty varies based on the destination validator's subsequent performance, which is unrelated to the source validator's infraction.

This matches the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Validator infractions occur regularly in PoS networks (downtime, double-signing, etc.)
2. **Natural exchange rate fluctuations:** Validator exchange rates change frequently due to slashing events, commission changes, and rounding
3. **Wide redelegation usage:** Redelegation is a core feature used by delegators to move stake without unbonding delay
4. **Extended vulnerability window:** The unbonding/redelegation period (typically 21 days) provides ample time for destination validator exchange rates to change

**No special requirements:**
- Any delegator can perform redelegations (no special privileges needed)
- The bug causes systematic under-slashing through normal protocol operations
- No intentional exploitation required - occurs naturally

## Recommendation

Modify `SlashRedelegation` to calculate the target token amount first, then convert to shares at the current exchange rate to ensure the full intended amount is slashed:

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
    continue
}

// Cap at available delegation shares
delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
if !found {
    continue
}
if sharesToUnbond.GT(delegation.Shares) {
    sharesToUnbond = delegation.Shares
    tokensToBurn = dstValidator.TokensFromShares(sharesToUnbond).TruncateInt()
}

// Unbond and accumulate actual tokens burned
actualTokens, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
totalSlashAmount = totalSlashAmount.Add(actualTokens)
```

Ensure the return value of `SlashRedelegation` matches actual tokens burned, not theoretical amounts.

## Proof of Concept

**Setup:**
1. Create validators A (source) and B (destination) with 1:1 exchange rates
2. User delegates 100 tokens to A
3. User redelegates 100 tokens from A to B
4. RedelegationEntry created: `InitialBalance=100`, `SharesDst=100`
5. Validator B gets independently slashed by 50%
   - B's tokens: 100 → 50
   - B's shares: 100 (unchanged)
   - B's exchange rate: 0.5 tokens/share

**Action:**
1. Validator A is slashed with 50% slash factor
2. `SlashRedelegation` executes:
   - Line 238-240: Calculates `slashAmount = 0.5 * 100 = 50` tokens (theoretical)
   - Line 243: Calculates `sharesToUnbond = 0.5 * 100 = 50` shares
   - Line 265: Calls `Unbond(50 shares)` which converts via `TokensFromShares`:
     - `50 shares * 0.5 rate = 25 tokens` (actual)
   - Line 295: Returns `totalSlashAmount = 50` tokens (theoretical)
3. Main `Slash` function (line 101): Reduces `remainingSlashAmount` by 50 tokens
4. Only 25 tokens actually burned from redelegation

**Result:**
- Expected total slash: 50 tokens from redelegation + remaining from validator
- Actual: 25 tokens from redelegation + remaining from validator
- Net under-slash: 25 tokens (50% of intended redelegation slash lost)

**Verification:** The bonded pool balance decrease will be less than the intended slash amount by the difference between theoretical and actual redelegation burns.

## Notes

The vulnerability stems from storing `SharesDst` as a fixed value at redelegation time, then using it for slash calculations when the exchange rate may have changed. While `InitialBalance` correctly captures the original token value, the actual burning uses share-based calculations with a potentially stale exchange rate relationship. The existing test `TestSlashRedelegation` only validates the happy path with stable 1:1 exchange rates and doesn't cover exchange rate deterioration scenarios. [11](#0-10)

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

**File:** x/staking/keeper/delegation.go (L498-515)
```go
// addresses. It creates the unbonding delegation if it does not exist.
func (k Keeper) SetRedelegationEntry(ctx sdk.Context,
	delegatorAddr sdk.AccAddress, validatorSrcAddr,
	validatorDstAddr sdk.ValAddress, creationHeight int64,
	minTime time.Time, balance sdk.Int,
	sharesSrc, sharesDst sdk.Dec,
) types.Redelegation {
	red, found := k.GetRedelegation(ctx, delegatorAddr, validatorSrcAddr, validatorDstAddr)
	if found {
		red.AddEntry(creationHeight, minTime, balance, sharesDst)
	} else {
		red = types.NewRedelegation(delegatorAddr, validatorSrcAddr,
			validatorDstAddr, creationHeight, minTime, balance, sharesDst)
	}

	k.SetRedelegation(ctx, red)

	return red
```

**File:** x/staking/keeper/delegation.go (L787-787)
```go
	validator, amount = k.RemoveValidatorTokensAndShares(ctx, validator, shares)
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

**File:** x/staking/types/validator.go (L304-306)
```go
func (v Validator) TokensFromShares(shares sdk.Dec) sdk.Dec {
	return (shares.MulInt(v.Tokens)).Quo(v.DelegatorShares)
}
```

**File:** x/staking/keeper/slash_test.go (L119-183)
```go
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
