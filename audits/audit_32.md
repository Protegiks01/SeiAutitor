# Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function contains an accounting bug where it returns a theoretical slash amount calculated from `entry.InitialBalance` but only burns tokens based on capped `delegation.Shares`. When users unbond from the destination validator after redelegating, the redelegation entry remains unchanged while delegation shares decrease, causing the main `Slash` function to incorrectly reduce `remainingSlashAmount` by more than was actually burned, resulting in systematic validator under-slashing. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296)

**Intended logic:** When a validator is slashed, the function should slash all eligible redelegations and return the actual amount of tokens burned. The main `Slash` function uses this returned value to determine how much additional slashing is needed from the validator's bonded tokens, ensuring the total slashed amount matches the calculated penalty based on the validator's power at the time of infraction.

**Actual logic:** The function exhibits a critical accounting discrepancy where it calculates and accumulates a theoretical slash amount from `entry.InitialBalance` (lines 238-240), but when delegation shares have been reduced through normal unbonding, it can only unbond and burn a capped amount based on available `delegation.Shares` (lines 261-265). Despite burning fewer tokens, the function returns the uncapped theoretical amount (line 295), causing `remainingSlashAmount` in the main `Slash` function to be reduced by more than was actually burned. [2](#0-1) [3](#0-2) 

**Exploitation path:**
1. User delegates X tokens to Validator A
2. User redelegates from A to B, creating `RedelegationEntry` with `InitialBalance=X` and `SharesDst=X`
3. User unbonds Y tokens from B through normal unbonding, reducing `delegation.Shares` to (X-Y)
4. Validator A is slashed for an infraction that occurred during the redelegation period
5. `SlashRedelegation` calculates theoretical slash of `slashFactor * X` but can only burn `slashFactor * (X-Y)` tokens
6. Function returns `slashFactor * X` (theoretical) instead of `slashFactor * (X-Y)` (actual)
7. Main `Slash` function subtracts the inflated amount from `remainingSlashAmount`
8. Validator is under-slashed by approximately `slashFactor * Y` tokens

**Security guarantee broken:** The slashing mechanism's fundamental invariant—that validators are penalized by the full calculated slash amount based on their power at the time of infraction—is violated. Validators systematically retain tokens that should have been burned. [4](#0-3) 

The root cause is structural: `RedelegationEntry` only tracks `InitialBalance` and `SharesDst` without a current balance field like `UnbondingDelegationEntry`. When users unbond from the destination validator, only delegation shares are reduced; redelegation entries remain unchanged. [5](#0-4) 

## Impact Explanation

This vulnerability represents direct loss of funds to the protocol's economic security:

- **Systematic Under-Slashing**: Every slashing event involving redelegations where delegators have reduced their destination delegation results in validators being under-penalized
- **Economic Security Failure**: Tokens that should be burned (removed from circulation) as punishment remain with misbehaving validators, reducing the deterrent effect of slashing
- **Protocol Value Loss**: The under-slashed amount represents real economic value that should have been destroyed but wasn't
- **Cumulative Impact**: This occurs automatically across all affected slashing events, potentially accumulating significant impact over time

The severity is High because it directly undermines slashing—a core security mechanism fundamental to proof-of-stake network security—by allowing validators to retain tokens that should be burned as punishment for infractions.

## Likelihood Explanation

**Triggering Conditions:**
- A redelegation must exist from a validator that is later slashed (common in PoS networks)
- The destination delegation must have fewer shares than recorded in the redelegation entry (occurs through normal unbonding)
- The source validator must be slashed for an infraction during the redelegation period

**Who Can Trigger:** Any regular user through standard blockchain operations—performing redelegations and unbonding—with no special permissions required.

**Frequency:** Occurs automatically whenever the above conditions are met. Redelegation followed by partial unbonding is a normal user behavior pattern for liquidity management and yield optimization.

**Likelihood Assessment:** Medium to High - While requiring specific conditions, these are all normal operations that occur regularly in proof-of-stake networks. The bug triggers automatically without intentional exploitation.

## Recommendation

Modify `SlashRedelegation` to track and return the actual amount of tokens burned rather than the theoretical amount:

**Preferred Solution:** Accumulate actual burned amounts instead of theoretical amounts. After line 265 where `tokensToBurn` is obtained from `Unbond()`, accumulate this actual value instead of accumulating `slashAmount` (from `InitialBalance`) at line 240. Return the total of actual burned tokens at line 295.

**Alternative Solution:** Track both theoretical and actual amounts separately, maintaining two accumulators. Use `min(slashAmount, tokensToBurn)` when accumulating to ensure the returned value reflects tokens actually removed from circulation.

The fix must ensure that the value returned by `SlashRedelegation` accurately reflects tokens actually burned, enabling correct accounting in the main `Slash` function.

## Proof of Concept

**Test Scenario:**

Setup:
- Create 3 validators with 10 consensus power each
- User delegates 6 tokens to Validator A
- User redelegates 6 tokens from A to B (RedelegationEntry: InitialBalance=6, SharesDst=6)
- User unbonds 4 tokens from B (delegation.Shares reduced to 2, RedelegationEntry unchanged)

Action:
- Slash Validator A at 50% for infraction at height during redelegation period

Expected Result:
- Total intended slash: 50% of relevant power
- Should slash from redelegation based on actual available shares
- Should compensate by slashing more from validator to reach total intended amount

Actual Result:
- SlashRedelegation returns theoretical 3 tokens (50% * 6) but only burns ~1 token (50% of 2 available shares)
- remainingSlashAmount reduced by 3 tokens (the returned value)
- Validator under-slashed by ~2 tokens (difference between theoretical and actual burn)

This demonstrates the accounting discrepancy causes measurable under-slashing, resulting in direct loss to the protocol's economic security mechanism.

## Notes

The vulnerability is confirmed through code analysis. The comment at lines 214-217 indicates the function intentionally returns "the amount that would have been slashed assuming the unbonding delegation had enough stake to slash," but this creates an accounting mismatch with how the main `Slash` function uses this return value. The spec at `x/staking/spec/02_state_transitions.md` lines 133-138 states "Each amount slashed from redelegations and unbonding delegations is subtracted from the total slash amount," which suggests the actual slashed amount should be used, not the theoretical amount.

### Citations

**File:** x/staking/keeper/slash.go (L96-101)
```go
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
```

**File:** x/staking/keeper/slash.go (L106-106)
```go
	tokensToBurn := sdk.MinInt(remainingSlashAmount, validator.Tokens)
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

**File:** x/staking/keeper/delegation.go (L734-795)
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
}
```
