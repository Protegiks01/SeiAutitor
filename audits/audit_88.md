# Audit Report

## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function contains an accounting vulnerability where it reports slashing `totalSlashAmount` (based on original token balance) but actually burns fewer tokens when calculated through the destination validator's current exchange rate. This creates a systematic under-slashing scenario that violates the protocol's slashing invariant. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296), with the critical accounting mismatch between lines 238-240 and 265.

**Intended logic:** When a validator commits an infraction and has active redelegations, the protocol should slash exactly `slashFactor * InitialBalance` tokens from each redelegation entry, where `InitialBalance` represents the tokens at stake during the infraction. The total amount slashed should equal `slashFactor * power_at_infraction`.

**Actual logic:** The function calculates `totalSlashAmount = slashFactor * entry.InitialBalance` at line 238-240, but then:
1. Calculates `sharesToUnbond = slashFactor * entry.SharesDst` at line 243
2. Converts these shares to tokens via `k.Unbond()` at line 265, which uses the destination validator's **current** exchange rate
3. Returns `totalSlashAmount` (not the actual burned amount) at line 295 [2](#0-1) [3](#0-2) 

The conversion uses the validator's current exchange rate formula: `TokensFromShares(shares) = shares * Tokens / DelegatorShares` [4](#0-3) 

When the destination validator's exchange rate decreases (e.g., due to independent slashing), the actual tokens burned (`tokensToBurn`) become less than `totalSlashAmount`. However, the main `Slash` function reduces `remainingSlashAmount` by the full `totalSlashAmount`: [5](#0-4) 

**Exploitation path:**
1. Validator A commits an infraction at height H (evidence not yet submitted)
2. User redelegates from A to Validator B (which has or develops a poor exchange rate)
3. The `RedelegationEntry` is created with fixed `InitialBalance` and `SharesDst` values [6](#0-5) 

4. Validator B's exchange rate deteriorates between redelegation and slashing
5. Evidence of A's infraction is submitted and slashing executes
6. `totalSlashAmount` is calculated as `slashFactor * InitialBalance`
7. But actual tokens burned = `sharesToUnbond * current_exchange_rate < totalSlashAmount`
8. The discrepancy means the protocol burns fewer tokens than intended

**Security guarantee broken:** The slashing invariant that `total_tokens_burned = slashFactor * power_at_infraction` is violated. The protocol fails to properly enforce slashing penalties, allowing validators/delegators to retain tokens they should lose.

## Impact Explanation

This vulnerability undermines the economic security model of the Proof-of-Stake network:

1. **Systematic Under-Slashing:** Whenever destination validators have deteriorating exchange rates, actual slashing is less than intended. With a 50% exchange rate deterioration, users could avoid up to 50% of their slashing penalty.

2. **Economic Security Weakening:** Slashing serves as the primary deterrent against validator misbehavior. Reduced penalties weaken this deterrent, potentially encouraging infractions.

3. **Accounting Invariant Violation:** The protocol's fundamental accounting assumption—that slashing removes a deterministic amount based on infraction severity—is broken. The actual penalty becomes dependent on destination validator health rather than infraction severity.

4. **Potential Gaming:** Sophisticated actors monitoring validator infractions could redelegate to validators with poor exchange rates to minimize slashing exposure, creating "slashing havens."

While this doesn't constitute direct fund theft between users, it represents a failure of the protocol's core security mechanism, fitting the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**High likelihood of occurrence:**

1. **Common triggers:** Validator infractions (downtime, double-signing) occur regularly in any PoS network
2. **Natural exchange rate fluctuations:** Exchange rates change frequently due to slashing events, validator operations, or precision losses
3. **Wide redelegation usage:** Redelegation is a core feature allowing instant validator switching, widely used by delegators
4. **Extended vulnerability window:** The unbonding period (typically 21 days) provides a long window for exchange rate changes

**Exploitation requirements:**

- **No special privileges:** Any delegator can perform redelegations
- **No malicious intent needed:** The bug causes systematic under-slashing even without intentional exploitation whenever exchange rates naturally fluctuate
- **Intentional exploitation:** While sophisticated actors could monitor infractions and deliberately redelegate to validators with declining rates, even unintentional cases cause the accounting mismatch

The vulnerability is triggered through normal protocol operations and affects the fundamental slashing mechanism that underpins network security.

## Recommendation

Modify `SlashRedelegation` to ensure the actual tokens burned match the intended slash amount:

```go
// Calculate target tokens to burn based on original stake
slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
tokensToBurn := slashAmountDec.TruncateInt()
totalSlashAmount = totalSlashAmount.Add(tokensToBurn)

// Convert target token amount to shares at CURRENT exchange rate
dstValidator, found := k.GetValidator(ctx, valDstAddr)
if !found {
    panic("destination validator not found")
}

sharesToUnbond, err := dstValidator.SharesFromTokens(tokensToBurn)
if err != nil {
    // Handle edge case where validator has no tokens
    continue
}

// Cap at available delegation shares if necessary
delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
if !found {
    continue
}
if sharesToUnbond.GT(delegation.Shares) {
    sharesToUnbond = delegation.Shares
    // Recalculate actual tokens that can be burned
    tokensToBurn = dstValidator.TokensFromShares(sharesToUnbond).TruncateInt()
}

// Unbond and verify
actualTokens, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
// actualTokens should approximately equal tokensToBurn
```

The key principle: Calculate the token amount to burn first (based on `InitialBalance`), then convert to shares at the current rate, rather than calculating shares first and converting to tokens.

## Proof of Concept

**Test scenario:** `TestSlashRedelegationWithExchangeRateChange`

**Setup:**
1. Create validators A (source) and B (destination)
2. Delegate tokens to both validators
3. Validator B gets slashed, reducing its exchange rate from 1:1 to 0.5:1 (100 tokens → 50 tokens, but shares remain 100)
4. User redelegates 50 tokens from A to B at this poor exchange rate
   - Receives ~100 shares for 50 tokens
   - `RedelegationEntry` stores: `InitialBalance=50`, `SharesDst=100`

**Action:**
1. Validator A is slashed for an infraction at 50% slash factor
2. `SlashRedelegation` is called for the redelegation entry
3. Calculates: `totalSlashAmount = 0.5 * 50 = 25` tokens
4. Calculates: `sharesToUnbond = 0.5 * 100 = 50` shares  
5. Unbonds 50 shares at current exchange rate: `50 shares * 0.5 = 25` tokens

**Result if B's exchange rate deteriorates further before slashing:**
1. If B's rate becomes 0.33:1 (33 tokens for 100 shares)
2. Unbonding 50 shares yields: `50 * 0.33 = 16.5` tokens
3. But `totalSlashAmount` still reports 25 tokens
4. `remainingSlashAmount` is reduced by 25, but only 16.5 tokens burned
5. Total slashing is 8.5 tokens less than intended (34% under-slash)

**Verification:**
- Check bonded pool balance decreases by less than reported `totalSlashAmount`
- Verify `remainingSlashAmount` reduction exceeds actual tokens burned
- Confirm total slashed < `slashFactor * power_at_infraction`

This demonstrates the accounting mismatch that violates the protocol's slashing invariant.

## Notes

The vulnerability is rooted in storing `SharesDst` as a fixed value in `RedelegationEntry` at redelegation time, then using it for slashing calculations later when the exchange rate may have changed. The `InitialBalance` field correctly captures the original token amount, but the actual burning uses share-based calculations with a potentially stale exchange rate relationship.

While intentional exploitation requires knowledge of infractions before evidence submission, the more concerning aspect is systematic under-slashing that occurs naturally whenever exchange rates fluctuate—which is common in PoS networks due to slashing events, validator operations, and rounding effects.

### Citations

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

**File:** x/staking/types/validator.go (L303-306)
```go
// calculate the token worth of provided shares
func (v Validator) TokensFromShares(shares sdk.Dec) sdk.Dec {
	return (shares.MulInt(v.Tokens)).Quo(v.DelegatorShares)
}
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
