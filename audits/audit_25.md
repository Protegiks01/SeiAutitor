# Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function in `x/staking/keeper/slash.go` contains an accounting bug where it returns a theoretical slash amount calculated from `entry.InitialBalance` but only burns tokens based on capped `delegation.Shares`. When users unbond from the destination validator after redelegating, the redelegation entry remains unchanged while delegation shares decrease, causing the main `Slash` function to reduce `remainingSlashAmount` by more than was actually burned, resulting in systematic validator under-slashing. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/slash.go`, lines 219-296, function `SlashRedelegation`

**Intended logic:** When a validator is slashed for an infraction, the `SlashRedelegation` function should slash all eligible redelegations and return the actual amount of tokens burned. The main `Slash` function uses this returned value to calculate how much additional slashing is needed from the validator's bonded tokens, ensuring the total slashed amount matches the calculated penalty based on validator power at infraction time. [2](#0-1) 

**Actual logic:** The function calculates a theoretical slash amount from `entry.InitialBalance` at lines 238-240 and accumulates it in `totalSlashAmount`. However, when users have previously unbonded from the destination validator, `delegation.Shares` is less than `entry.SharesDst`. The function caps the unbonding to available shares (lines 261-263), calls `Unbond()` which returns fewer `tokensToBurn` than the theoretical amount, but then returns the uncapped `totalSlashAmount` at line 295. This causes `remainingSlashAmount` in the main `Slash` function to be reduced by more than was actually burned.

**Exploitation path:**
1. User delegates X tokens to Validator A
2. User redelegates X tokens from A to B, creating `RedelegationEntry` with `InitialBalance=X` and `SharesDst=X`
3. User performs normal unbonding of Y tokens from Validator B, reducing `delegation.Shares` to (X-Y) but leaving `RedelegationEntry` unchanged
4. Validator A commits an infraction during the redelegation period and is slashed
5. `SlashRedelegation` calculates `slashAmount = slashFactor * X` from `InitialBalance`
6. Function attempts to unbond `slashFactor * X` shares but is capped to available `delegation.Shares = (X-Y)`
7. `Unbond()` returns `tokensToBurn ≈ slashFactor * (X-Y)` tokens (actual burned amount)
8. Function returns `totalSlashAmount = slashFactor * X` (theoretical amount)
9. Main `Slash` function subtracts inflated theoretical amount from `remainingSlashAmount`
10. Validator is under-slashed by approximately `slashFactor * Y` tokens

**Security guarantee broken:** The slashing mechanism's fundamental invariant that validators are penalized by the full calculated slash amount based on their power at infraction time is violated. Validators systematically retain tokens that should have been burned as punishment.

The root cause is structural: `RedelegationEntry` only tracks `InitialBalance` and `SharesDst` without a current balance field like `UnbondingDelegationEntry` has. When users unbond from the destination validator through normal operations, only delegation shares are reduced; redelegation entries remain unchanged. [3](#0-2) [4](#0-3) 

## Impact Explanation

This vulnerability represents a breakdown in the slashing mechanism, a core security primitive of proof-of-stake networks:

- **Systematic Under-Slashing**: Every slashing event involving redelegations where delegators have reduced their destination delegation through normal unbonding results in validators being under-penalized by the difference between theoretical and actual burned amounts
- **Economic Security Degradation**: Tokens that should be burned (removed from circulation) as punishment remain with misbehaving validators, reducing the economic deterrent effect that slashing is designed to provide
- **Protocol Mechanism Failure**: The slashing invariant—that the full calculated penalty is applied—is violated, undermining consensus security assumptions
- **Cumulative Effect**: This occurs automatically across all affected slashing events without requiring intentional exploitation, potentially accumulating significant under-slashing over time

According to the provided impact categories, this qualifies as **"A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"** (Medium severity). While no user funds are directly at risk of theft or freezing, the slashing mechanism systematically fails to apply the intended penalties, which is unintended behavior in critical network code. [5](#0-4) 

## Likelihood Explanation

**Triggering Conditions:**
- A redelegation must exist from a validator that is later slashed for an infraction during the redelegation period
- The delegator must have unbonded some tokens from the destination validator after the redelegation but before the slashing event
- These are all normal, permissionless user operations

**Who Can Trigger:** Any user through standard staking operations—delegating, redelegating, and unbonding—with no special permissions required. The bug triggers automatically when the conditions are met during validator slashing.

**Frequency:** Users commonly redelegate to optimize yields or move away from underperforming validators, and may subsequently unbond for liquidity needs. When combined with validator infractions (which occur periodically in PoS networks), these conditions occur naturally.

**Likelihood Assessment:** Medium - While requiring the specific sequence of operations, all are normal user behaviors in proof-of-stake networks. The issue triggers automatically without intentional exploitation whenever the conditions align.

## Recommendation

Modify `SlashRedelegation` to track and return the actual amount of tokens burned rather than the theoretical amount:

**Preferred Solution:** After line 265 where `tokensToBurn` is obtained from `Unbond()`, accumulate the actual burned amount instead of the theoretical `slashAmount` calculated from `InitialBalance` at line 240. Maintain a separate accumulator for actual burned tokens and return that total at line 295.

```
// After line 240, instead of:
totalSlashAmount = totalSlashAmount.Add(slashAmount)

// Use:
// (keep theoretical slashAmount for potential logging/events)
// After line 265-268 where tokensToBurn is obtained:
totalActualBurned = totalActualBurned.Add(tokensToBurn)

// At line 295, return:
return totalActualBurned  // instead of totalSlashAmount
```

**Alternative Solution:** Track both theoretical and actual amounts with separate accumulators. After obtaining `tokensToBurn` from `Unbond()`, accumulate `min(slashAmount, tokensToBurn)` to ensure the returned value never exceeds actual burned tokens.

The fix ensures that `SlashRedelegation` returns a value that accurately reflects tokens actually removed from circulation, enabling correct accounting in the main `Slash` function's `remainingSlashAmount` calculation.

## Proof of Concept

**Test Scenario:**

Setup:
- Bootstrap 3 validators with 10 consensus power each
- User delegates 6 tokens to Validator A  
- User redelegates 6 tokens from A to B (creates `RedelegationEntry` with `InitialBalance=6`, `SharesDst=6`)
- User unbonds 4 tokens from B via normal `Undelegate` (reduces `delegation.Shares` to 2, but `RedelegationEntry` remains at `InitialBalance=6`, `SharesDst=6`)

Action:
- Slash Validator A at 50% (slashFactor=0.5) for infraction at height during the redelegation period

Expected Behavior:
- Total intended slash: 50% of validator's power at infraction time
- Should slash from redelegation based on actual available shares (50% of 2 = 1 token)
- Should compensate by slashing more from validator's bonded tokens to reach total intended penalty

Actual Behavior:
- `SlashRedelegation` calculates theoretical slash: 0.5 * 6 = 3 tokens from `InitialBalance`
- Function caps unbonding to available shares: min(0.5 * 6, 2) = 2 shares
- `Unbond()` returns ~1 token burned (50% of 2 shares)
- Function returns 3 tokens (theoretical) instead of ~1 token (actual)
- Main `Slash` function subtracts 3 from `remainingSlashAmount`
- Validator under-slashed by ~2 tokens (3 theoretical - 1 actual)

This demonstrates the accounting discrepancy causes measurable under-slashing, violating the slashing mechanism's security invariant. [6](#0-5) 

## Notes

The comment at lines 214-217 indicates the function intentionally returns "the amount that would have been slashed assuming the unbonding delegation had enough stake to slash," but this creates an accounting mismatch with how the main `Slash` function uses this return value. The specification at `x/staking/spec/02_state_transitions.md` lines 133-138 states "Each amount slashed from redelegations and unbonding delegations is subtracted from the total slash amount," which suggests the actual slashed amount should be used for correct accounting, not the theoretical amount.

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

**File:** x/staking/keeper/slash.go (L237-268)
```go
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

**File:** x/staking/spec/02_state_transitions.md (L133-138)
```markdown
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```
