# Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function contains an accounting bug where it returns a theoretical slash amount calculated from `entry.InitialBalance` but only burns tokens based on available `delegation.Shares`. When users unbond from the destination validator after redelegating, the main `Slash` function subtracts more from `remainingSlashAmount` than was actually burned, resulting in systematic validator under-slashing. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, lines 219-296, function `SlashRedelegation`

**Intended logic:** When a validator is slashed, `SlashRedelegation` should return the actual amount of tokens burned from redelegations. The main `Slash` function uses this value to calculate how much additional slashing is needed from the validator's bonded tokens, ensuring the total slashed matches the calculated penalty. [2](#0-1) 

**Actual logic:** The function calculates a theoretical slash amount from `entry.InitialBalance` and accumulates it in `totalSlashAmount`. However, when users have previously unbonded from the destination validator, `delegation.Shares` is less than `entry.SharesDst`. The function caps the unbonding to available shares, calls `Unbond()` which returns fewer `tokensToBurn`, but returns the uncapped `totalSlashAmount`. [3](#0-2) 

**Exploitation path:**
1. User delegates X tokens to Validator A
2. User redelegates X tokens from A to B (creates `RedelegationEntry` with `InitialBalance=X`, `SharesDst=X`)
3. User unbonds Y tokens from Validator B via normal `Undelegate` (reduces `delegation.Shares` to X-Y, but `RedelegationEntry` remains unchanged)
4. Validator A is slashed for infraction during redelegation period
5. `SlashRedelegation` calculates `slashAmount = slashFactor * X` from `InitialBalance`
6. Function caps unbonding to available shares (X-Y)
7. `Unbond()` returns `tokensToBurn ≈ slashFactor * (X-Y)` (actual burned)
8. Function returns `totalSlashAmount = slashFactor * X` (theoretical)
9. Main `Slash` function subtracts theoretical amount from `remainingSlashAmount`
10. Validator under-slashed by approximately `slashFactor * Y` tokens [4](#0-3) 

**Security guarantee broken:** The slashing mechanism's fundamental invariant that validators are penalized by the full calculated slash amount based on their power at infraction time is violated. The specification states "Each amount slashed from redelegations and unbonding delegations is subtracted from the total slash amount," indicating actual amounts should be used, not theoretical.

The root cause is structural: `RedelegationEntry` only tracks `InitialBalance` and `SharesDst` without a current balance field. When users unbond from the destination validator, only delegation shares are reduced; redelegation entries remain unchanged. [5](#0-4) [6](#0-5) 

## Impact Explanation

This vulnerability causes systematic under-slashing of misbehaving validators:

- **Economic Security Degradation**: Tokens that should be burned remain with validators, reducing the economic deterrent effect
- **Protocol Mechanism Failure**: The slashing invariant is violated, undermining consensus security assumptions
- **Cumulative Effect**: Occurs automatically across all affected slashing events without requiring intentional exploitation

This qualifies as "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity). While no user funds are directly stolen or frozen, the slashing mechanism systematically fails to apply intended penalties.

## Likelihood Explanation

**Triggering Conditions:**
- A redelegation exists from a validator later slashed for an infraction during the redelegation period
- The delegator unbonded some tokens from the destination validator after redelegating but before slashing
- All are normal, permissionless user operations

**Who Can Trigger:** Any user through standard staking operations (delegating, redelegating, unbonding). The bug triggers automatically when these conditions align during validator slashing.

**Frequency:** Users commonly redelegate to optimize yields and may subsequently unbond for liquidity. Combined with periodic validator infractions, these conditions occur naturally.

**Likelihood:** Medium - While requiring a specific sequence, all are normal behaviors in PoS networks. The issue triggers automatically without intentional exploitation.

## Recommendation

Modify `SlashRedelegation` to track and return the actual amount of tokens burned:

After line 265 where `tokensToBurn` is obtained from `Unbond()`, accumulate the actual burned amount instead of the theoretical `slashAmount`. Maintain a separate accumulator for actual burned tokens and return that at line 295.

This ensures `SlashRedelegation` returns a value accurately reflecting tokens actually removed from circulation, enabling correct accounting in the main `Slash` function's `remainingSlashAmount` calculation.

## Proof of Concept

**Setup:**
- Bootstrap 3 validators with 10 consensus power each
- User delegates 6 tokens to Validator A
- User redelegates 6 tokens from A to B (creates `RedelegationEntry` with `InitialBalance=6`, `SharesDst=6`)
- User unbonds 4 tokens from B (reduces `delegation.Shares` to 2, `RedelegationEntry` remains at `InitialBalance=6`)

**Action:**
- Slash Validator A at 50% for infraction during redelegation period

**Expected Behavior:**
- Should slash ~1 token from redelegation (50% of 2 available shares)
- Should compensate by slashing more from validator's bonded tokens

**Actual Behavior:**
- `SlashRedelegation` calculates theoretical slash: 0.5 * 6 = 3 tokens
- Function caps to available shares, burns ~1 token
- Returns 3 tokens (theoretical)
- Main `Slash` function subtracts 3 from `remainingSlashAmount`
- Validator under-slashed by ~2 tokens [7](#0-6) 

## Notes

The comment at lines 214-217 explicitly states the function returns "the amount that would have been slashed," but this creates an accounting mismatch with how the main `Slash` function uses this return value. The specification clearly indicates the actual slashed amount should be used for correct accounting, not the theoretical amount. Existing tests do not cover the scenario where a user unbonds from the destination validator after redelegating but before slashing occurs.

### Citations

**File:** x/staking/keeper/slash.go (L96-106)
```go
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}
	}

	// cannot decrease balance below zero
	tokensToBurn := sdk.MinInt(remainingSlashAmount, validator.Tokens)
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

**File:** x/staking/spec/02_state_transitions.md (L133-138)
```markdown
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```

**File:** proto/cosmos/staking/v1beta1/staking.proto (L211-229)
```text
// UnbondingDelegationEntry defines an unbonding object with relevant metadata.
message UnbondingDelegationEntry {
  option (gogoproto.equal)            = true;
  option (gogoproto.goproto_stringer) = false;

  // creation_height is the height which the unbonding took place.
  int64 creation_height = 1 [(gogoproto.moretags) = "yaml:\"creation_height\""];
  // completion_time is the unix time for unbonding completion.
  google.protobuf.Timestamp completion_time = 2
      [(gogoproto.nullable) = false, (gogoproto.stdtime) = true, (gogoproto.moretags) = "yaml:\"completion_time\""];
  // initial_balance defines the tokens initially scheduled to receive at completion.
  string initial_balance = 3 [
    (gogoproto.customtype) = "github.com/cosmos/cosmos-sdk/types.Int",
    (gogoproto.nullable)   = false,
    (gogoproto.moretags)   = "yaml:\"initial_balance\""
  ];
  // balance defines the tokens to receive at completion.
  string balance = 4 [(gogoproto.customtype) = "github.com/cosmos/cosmos-sdk/types.Int", (gogoproto.nullable) = false];
}
```

**File:** proto/cosmos/staking/v1beta1/staking.proto (L232-250)
```text
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
