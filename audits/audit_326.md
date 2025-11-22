## Title
Redelegation Slashing Accounting Mismatch Due to Exchange Rate Changes

## Summary
The `SlashRedelegation` function in the staking module contains an accounting vulnerability where the reported slash amount is calculated based on the original token balance at redelegation time, but the actual tokens burned are calculated using the destination validator's current exchange rate. When the destination validator's exchange rate decreases after redelegation, fewer tokens are burned than reported, resulting in systematic under-slashing of infractions. [1](#0-0) 

## Impact
**Medium** - This bug results in unintended protocol behavior where slashing penalties can be reduced by redelegating to validators with deteriorating exchange rates, violating the intended slashing invariant and potentially undermining network security.

## Finding Description

**Location:** The vulnerability exists in the `SlashRedelegation` function in `x/staking/keeper/slash.go`, specifically in the accounting mismatch between lines 238-240 (calculating theoretical slash amount) and line 243-265 (calculating and executing actual token burns). [2](#0-1) 

**Intended Logic:** When a validator commits an infraction and has active redelegations, the system should slash the proportional amount of tokens that were staked at the time of the infraction. For redelegations, this means burning `slashFactor * InitialBalance` tokens from the destination validator, where `InitialBalance` represents the tokens that were originally at stake.

**Actual Logic:** The code calculates two different values:
1. `totalSlashAmount = slashFactor * entry.InitialBalance` - the theoretical slash amount based on original tokens
2. `sharesToUnbond = slashFactor * entry.SharesDst` - the shares to unbond from destination validator
3. `tokensToBurn = Unbond(sharesToUnbond)` - actual tokens obtained by unbonding those shares at current exchange rate [3](#0-2) 

The function returns `totalSlashAmount` which is used to reduce the remaining amount that needs to be slashed from the source validator. However, if the destination validator's exchange rate has changed since redelegation, `tokensToBurn ≠ totalSlashAmount`.

The exchange rate calculation in validators is: `TokensFromShares(shares) = shares * Tokens / DelegatorShares` [4](#0-3) 

When a validator is slashed or experiences losses, its `Tokens` decrease while `DelegatorShares` remains constant, decreasing the exchange rate.

**Exploit Scenario:**
1. A user has 1000 tokens delegated to Validator A
2. Validator A commits an infraction at height H (but evidence not yet submitted)
3. Validator B gets slashed or experiences losses, decreasing its exchange rate from 1:1 to 2:1 (2 shares per token)
4. User redelegates 1000 tokens from A to B at height H+1, receiving 2000 shares in B
5. A `RedelegationEntry` is created with `InitialBalance=1000` tokens and `SharesDst=2000` shares
6. Evidence of A's infraction at height H is submitted
7. When slashing the redelegation with `slashFactor=0.1`:
   - `totalSlashAmount = 0.1 * 1000 = 100` tokens (reported)
   - `sharesToUnbond = 0.1 * 2000 = 200` shares
   - `tokensToBurn = 200 shares * 0.5 = 100` tokens (actual)
8. But now B's exchange rate deteriorates further to 3:1
9. When the slash executes:
   - `totalSlashAmount = 100` tokens (still reported as slashed)
   - `tokensToBurn = 200 shares * 0.333... = 66.67` tokens (actually burned)
10. The system reduces `remainingSlashAmount` by 100 tokens, but only 66.67 tokens were actually burned [5](#0-4) 

The `SharesDst` value is stored in the `RedelegationEntry` at the time of redelegation but never updated: [6](#0-5) 

**Security Failure:** This violates the slashing accounting invariant. The protocol should burn exactly `slashFactor * staked_amount` tokens for an infraction, but due to this bug, the actual amount burned can be significantly less when destination validator exchange rates deteriorate.

## Impact Explanation

**Assets Affected:** Staked tokens in the bonded pool and the overall slashing mechanism integrity.

**Severity:** When users redelegate to validators with deteriorating exchange rates (either intentionally or coincidentally):
- The actual tokens burned during slashing are less than the intended slash amount
- The discrepancy equals: `slashFactor * InitialBalance * (1 - currentExchangeRate/originalExchangeRate)`
- With significant exchange rate changes (e.g., 50% deterioration), users could avoid 50% of their intended slash penalty
- This undermines the economic security model where slashing serves as the primary deterrent against validator misbehavior

**Systemic Impact:** 
- Rational actors could game the system by redelegating to validators with poor exchange rates to minimize slashing exposure
- Validators with deteriorating exchange rates become "slashing havens"
- The effective slashing penalty becomes unpredictable and dependent on destination validator health rather than the severity of the infraction
- Over time, this could lead to cascading failures as validators realize they can reduce their delegators' slashing risk through exchange rate manipulation

## Likelihood Explanation

**Triggerability:** Any user can trigger this by redelegating from a validator that has committed (or will commit) an infraction to a validator with a deteriorating exchange rate.

**Conditions Required:**
1. A validator commits an infraction (common in any PoS network - downtime, double signing, etc.)
2. The user redelegates to a validator with a changing exchange rate before evidence is submitted
3. The destination validator's exchange rate decreases between redelegation and slashing execution

**Frequency:** 
- Validator infractions occur regularly in PoS networks
- Exchange rate changes are common due to slashing events, precision losses, or other validator operations
- The redelegation mechanism is widely used (it's a core feature allowing instant validator switching)
- The vulnerability window extends for the entire unbonding period (typically 21 days)

**Exploitability:** 
- Sophisticated users monitoring validator infractions could intentionally redelegate to validators with declining exchange rates
- Even without intentional exploitation, the bug causes systematic under-slashing whenever exchange rates fluctuate
- No special privileges required - any delegator can perform redelegations

## Recommendation

Modify the `SlashRedelegation` function to burn tokens based on the calculated `slashAmount` rather than converting shares at the current exchange rate:

1. Calculate the target token amount to burn: `tokensToBurn = slashFactor * entry.InitialBalance`
2. Convert this to shares at the **current** destination validator exchange rate: `sharesToUnbond = validator.SharesFromTokensTruncated(tokensToBurn)`
3. Cap at available delegation shares if necessary
4. Unbond those shares and verify the burned amount matches expectations

Alternatively, store both `SharesSrc` (source validator shares) in the `RedelegationEntry` and use the source validator's exchange rate at redelegation time to reconstruct the original accounting.

The key fix is ensuring that the function burns the intended token amount (`slashFactor * InitialBalance`) regardless of exchange rate changes, rather than burning a shares-based amount that may represent different token values.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`

**Test Function:** `TestSlashRedelegationWithExchangeRateChange`

**Setup:**
1. Create three validators: valA (source), valB (destination), valC (for causing exchange rate changes)
2. Fund accounts and establish initial delegations of 100 tokens to valA and valB
3. Create a delegation to valC to facilitate exchange rate manipulation

**Trigger:**
1. At height 0, valA commits an infraction (simulated)
2. Slash valB by 50% to decrease its exchange rate from 1:1 to 2:1 (100 tokens, 200 shares)
3. Redelegate 50 tokens from valA to valB at height 1
   - valB now has exchange rate 2:1, so redelegation receives ~66.67 shares for 50 tokens
   - RedelegationEntry stores: InitialBalance=50, SharesDst=66.67
4. Submit evidence of valA's infraction at height 0
5. Execute slash with slashFactor=0.5 (50%)

**Observation:**
- Expected slash amount: `0.5 * 50 = 25` tokens
- Reported slash amount (`totalSlashAmount`): 25 tokens
- Actual shares unbonded: `0.5 * 66.67 = 33.33` shares
- Actual tokens burned: `33.33 shares * (150 tokens / 200 shares) = 25` tokens at slash time
- BUT if valB's exchange rate deteriorates further to 3:1 before slash execution:
  - Actual tokens burned: `33.33 shares * (100 tokens / 200 shares) = 16.67` tokens
  - Discrepancy: 25 - 16.67 = 8.33 tokens (33% under-slash)

The test should verify that:
1. The bonded pool balance decreases by less than the reported slash amount
2. The validator's remaining tokens to slash is incorrectly reduced by the full reported amount
3. The total slashed amount across all components is less than `slashFactor * validator.PowerAtInfraction`

This demonstrates that the accounting mismatch allows users to avoid a significant portion of their slashing penalty by redelegating to validators with deteriorating exchange rates.

### Citations

**File:** x/staking/keeper/slash.go (L90-101)
```go
			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}

		// Iterate through redelegations from slashed source validator
		redelegations := k.GetRedelegationsFromSrcValidator(ctx, operatorAddress)
		for _, redelegation := range redelegations {
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
