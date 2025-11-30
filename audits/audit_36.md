# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function contains an accounting vulnerability where it calculates the theoretical slash amount based on the original token balance (`InitialBalance`) but returns this theoretical amount instead of the actual tokens burned. When the destination validator's exchange rate deteriorates between redelegation and slashing, fewer tokens are actually burned than calculated, causing the source validator to be systematically under-slashed.

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296) and main `Slash` function (lines 93-101) [1](#0-0) 

**Intended logic:** When slashing a validator with active redelegations, the protocol should burn exactly `slashFactor * InitialBalance` tokens from each redelegation entry. The `remainingSlashAmount` should be reduced by the actual tokens burned to ensure the total slashed equals `slashFactor * power_at_infraction`.

**Actual logic:** The function performs:
1. Calculates `slashAmount = slashFactor * entry.InitialBalance` (line 238-240)
2. Adds this to `totalSlashAmount` (line 240)
3. Calculates `sharesToUnbond = slashFactor * entry.SharesDst` using shares stored at redelegation time (line 243)
4. Calls `k.Unbond(sharesToUnbond)` which converts shares to tokens at the destination validator's **current** exchange rate (line 265) [2](#0-1) 

The `Unbond` function calls `RemoveValidatorTokensAndShares` which uses `TokensFromShares` to convert shares at the current exchange rate: [3](#0-2) [4](#0-3) 

5. The actual `tokensToBurn` (potentially less than `slashAmount`) is accumulated and burned (lines 279-293)
6. Returns `totalSlashAmount` instead of the sum of actual `tokensToBurn` values (line 295)

The main `Slash` function then reduces `remainingSlashAmount` by the returned theoretical amount: [5](#0-4) 

**Exploitation path:**
1. Validator A commits an infraction at height H
2. User redelegates from A to Validator B using standard redelegation: [6](#0-5) 

3. RedelegationEntry is created with `InitialBalance` (original tokens) and `SharesDst` (shares at B's current rate): [7](#0-6) 

4. Validator B's exchange rate deteriorates (e.g., B gets slashed independently for 50%)
5. Evidence of A's infraction is submitted and `Slash` is called
6. `SlashRedelegation` calculates `slashAmount = 50` tokens but only burns 25 tokens (due to B's 0.5:1 rate)
7. `remainingSlashAmount` reduced by 50, but only 25 actually burned
8. Validator A is under-slashed by 25 tokens

**Security guarantee broken:** The protocol's slashing invariant `total_tokens_burned = slashFactor * power_at_infraction` is violated. The actual penalty becomes dependent on the destination validator's health rather than solely on infraction severity.

## Impact Explanation

This vulnerability systematically undermines the Proof-of-Stake network's economic security model:

1. **Systematic Under-Slashing:** Whenever destination validators have deteriorating exchange rates (common due to slashing, validator operations, or rounding), actual slashing is less than intended. With a 50% exchange rate deterioration, up to 50% of the slashing penalty can be avoided.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced actual penalties weaken this deterrent mechanism, potentially encouraging infractions since the expected cost is lower than designed.

3. **Accounting Invariant Violation:** The protocol's fundamental assumption that slashing removes a deterministic amount based on infraction severity is broken. Instead, the actual penalty varies based on factors unrelated to the infraction.

4. **Potential Gaming:** While the issue occurs naturally, sophisticated actors could deliberately redelegate to validators with declining exchange rates to minimize slashing exposure.

This matches the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**High likelihood:**

1. **Common triggers:** Validator infractions occur regularly in PoS networks
2. **Natural exchange rate fluctuations:** Exchange rates change frequently due to slashing events, validator operations, or precision losses
3. **Wide redelegation usage:** Redelegation is a core feature widely used by delegators
4. **Extended vulnerability window:** The unbonding period (typically 21 days) provides ample time for exchange rate changes

**No special requirements:**
- Any delegator can perform redelegations (no special privileges)
- The bug causes systematic under-slashing even without intentional exploitation
- Occurs through normal protocol operations

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

Ensure the return value matches actual tokens burned, not theoretical amounts.

## Proof of Concept

**Setup:**
1. Create validators A (source) and B (destination) with 1:1 exchange rates
2. User delegates 100 tokens to A
3. User redelegates 100 tokens from A to B, creating `RedelegationEntry` with `InitialBalance=100`, `SharesDst=100`
4. Validator B gets independently slashed by 50%, reducing exchange rate to 0.5:1

**Action:**
1. Validator A is slashed for an infraction with 50% slash factor
2. `SlashRedelegation` executes:
   - Calculates: `slashAmount = 0.5 * 100 = 50` tokens (line 238-240)
   - Calculates: `sharesToUnbond = 0.5 * 100 = 50` shares (line 243)
   - Unbonds 50 shares: `50 * 0.5 = 25` tokens via `TokensFromShares` (line 265)
   - Returns `totalSlashAmount = 50` tokens (line 295)

**Result:**
- `remainingSlashAmount` reduced by 50 tokens
- Only 25 tokens actually burned
- Validator A under-slashed by 25 tokens (50% of intended redelegation slash)

**Verification:** Monitor bonded pool balance decrease vs reported slash amounts to confirm actual burned < theoretical slashed.

## Notes

The vulnerability stems from storing `SharesDst` as a fixed value at redelegation time, then using it for slash calculations when the exchange rate may have changed. The `InitialBalance` correctly captures original tokens, but the actual burning uses share-based calculations with a potentially stale exchange rate relationship, creating systematic accounting mismatch whenever destination validator exchange rates deteriorate.

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

**File:** x/staking/keeper/delegation.go (L734-794)
```go
// Unbond unbonds a particular delegation and perform associated store operations.
func (k Keeper) Unbond(
	ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, shares sdk.Dec,
) (amount sdk.Int, err error) {
	// check if a delegation object exists in the store
	delegation, found := k.GetDelegation(ctx, delAddr, valAddr)
	if !found {
		return amount, types.ErrNoDelegatorForAddress
	}

	// call the before-delegation-modified hook
	k.BeforeDelegationSharesModified(ctx, delAddr, valAddr)

	// ensure that we have enough shares to remove
	if delegation.Shares.LT(shares) {
		return amount, sdkerrors.Wrap(types.ErrNotEnoughDelegationShares, delegation.Shares.String())
	}

	// get validator
	validator, found := k.GetValidator(ctx, valAddr)
	if !found {
		return amount, types.ErrNoValidatorFound
	}

	// subtract shares from delegation
	delegation.Shares = delegation.Shares.Sub(shares)

	delegatorAddress, err := sdk.AccAddressFromBech32(delegation.DelegatorAddress)
	if err != nil {
		return amount, err
	}

	isValidatorOperator := delegatorAddress.Equals(validator.GetOperator())

	// If the delegation is the operator of the validator and undelegating will decrease the validator's
	// self-delegation below their minimum, we jail the validator.
	if isValidatorOperator && !validator.Jailed &&
		validator.TokensFromShares(delegation.Shares).TruncateInt().LT(validator.MinSelfDelegation) {
		k.jailValidator(ctx, validator)
		validator = k.mustGetValidator(ctx, validator.GetOperator())
	}

	// remove the delegation
	if delegation.Shares.IsZero() {
		k.RemoveDelegation(ctx, delegation)
	} else {
		k.SetDelegation(ctx, delegation)
		// call the after delegation modification hook
		k.AfterDelegationModified(ctx, delegatorAddress, delegation.GetValidatorAddr())
	}

	// remove the shares and coins from the validator
	// NOTE that the amount is later (in keeper.Delegation) moved between staking module pools
	validator, amount = k.RemoveValidatorTokensAndShares(ctx, validator, shares)

	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}

	return amount, nil
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

**File:** x/staking/types/validator.go (L410-430)
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
```

**File:** proto/cosmos/staking/v1beta1/staking.proto (L231-250)
```text
// RedelegationEntry defines a redelegation object with relevant metadata.
message RedelegationEntry {
  option (gogoproto.equal)            = true;
  option (gogoproto.goproto_stringer) = false;

  // creation_height  defines the height which the redelegation took place.
  int64 creation_height = 1 [(gogoproto.moretags) = "yaml:\"creation_height\""];
  // completion_time defines the unix time for redelegation completion.
  google.protobuf.Timestamp completion_time = 2
      [(gogoproto.nullable) = false, (gogoproto.stdtime) = true, (gogoproto.moretags) = "yaml:\"completion_time\""];
  // initial_balance defines the initial balance when redelegation started.
  string initial_balance = 3 [
    (gogoproto.customtype) = "github.com/cosmos/cosmos-sdk/types.Int",
    (gogoproto.nullable)   = false,
    (gogoproto.moretags)   = "yaml:\"initial_balance\""
  ];
  // shares_dst is the amount of destination-validator shares created by redelegation.
  string shares_dst = 4
      [(gogoproto.customtype) = "github.com/cosmos/cosmos-sdk/types.Dec", (gogoproto.nullable) = false];
}
```
