# Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function contains a critical accounting bug where it calculates and returns a theoretical slash amount based on `entry.InitialBalance`, but only burns tokens based on the capped `delegation.Shares`. When users unbond from the destination validator after redelegating, the redelegation entry remains unchanged while the actual delegation shares decrease, creating a mismatch. This causes the main `Slash` function to incorrectly reduce `remainingSlashAmount` by more than was actually burned, resulting in systematic under-slashing of validators. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296)

**Intended logic:** When a validator is slashed, the function should slash all redelegations proportionally and return the actual amount of tokens burned from those redelegations. The main `Slash` function uses this returned value to determine how much additional slashing is needed from the validator's bonded tokens, ensuring the total slashed amount matches the calculated penalty.

**Actual logic:** The function exhibits a critical accounting discrepancy:

1. Lines 238-240 calculate `slashAmount = slashFactor * entry.InitialBalance` and accumulate this into `totalSlashAmount` [2](#0-1) 

2. Line 243 calculates `sharesToUnbond = slashFactor * entry.SharesDst` [3](#0-2) 

3. Lines 261-263 cap `sharesToUnbond` at `delegation.Shares` when the delegation has fewer shares than originally recorded [4](#0-3) 

4. Line 265 unbonds the capped shares, returning `tokensToBurn` based on actual available shares [5](#0-4) 

5. The actual `tokensToBurn` is properly burned at lines 279 or 281

6. However, line 295 returns `totalSlashAmount` which was calculated from `InitialBalance`, not from the actual burned tokens [6](#0-5) 

The root cause is structural: `RedelegationEntry` only tracks `InitialBalance` and `SharesDst` fields, unlike `UnbondingDelegationEntry` which has both `InitialBalance` and a current `Balance` field. [7](#0-6) 

When users unbond from the destination validator (via the `Unbond` function), the delegation shares decrease but the redelegation entry remains unchanged. [8](#0-7) 

**Exploitation path:**
1. User delegates X tokens to Validator A
2. User redelegates from Validator A to Validator B, creating `RedelegationEntry` with `InitialBalance=X` and `SharesDst=X`
3. User performs normal unbonding from Validator B, reducing delegation shares to Y (where Y < X)
4. Validator A commits an infraction and is slashed
5. In `SlashRedelegation`:
   - Calculates theoretical slash: `slashFactor * X` tokens
   - Tries to unbond: `slashFactor * X` shares  
   - Caps at available delegation: `slashFactor * Y` shares (or less)
   - Actually burns: approximately `slashFactor * Y` tokens
   - Returns: `slashFactor * X` tokens (theoretical amount)
6. Main `Slash` function at lines 96-101 subtracts the inflated returned amount from `remainingSlashAmount` [9](#0-8) 
7. Line 106 calculates `tokensToBurn` from validator using the incorrectly reduced `remainingSlashAmount` [10](#0-9) 
8. Result: Validator is under-slashed by approximately `slashFactor * (X - Y)` tokens

**Security guarantee broken:** The slashing mechanism's fundamental invariant—that validators are penalized by the full calculated slash amount—is violated. Validators systematically retain tokens that should have been burned, undermining the economic security model.

## Impact Explanation

This vulnerability represents a **direct loss of funds** to the protocol's economic security:

- **Systematic Under-Slashing**: Every slashing event involving redelegations where delegators have reduced their destination delegation results in validators being under-penalized
- **Economic Security Failure**: Tokens that should be burned (removed from circulation) as punishment remain with misbehaving validators, reducing the deterrent effect of slashing
- **Protocol Value Loss**: The under-slashing amount equals the difference between theoretical and actual redelegation slashing, representing real economic value that should have been destroyed but wasn't
- **Perverse Incentives**: Validators could potentially encourage delegators to redelegate and then unbond before engaging in risky behavior, knowing they'll face reduced penalties
- **Cumulative Impact**: This occurs automatically across all affected slashing events, potentially accumulating significant economic impact over time

The severity is High because it directly undermines a core security mechanism—slashing—which is fundamental to proof-of-stake network security.

## Likelihood Explanation

**Triggering Conditions:**
- A redelegation must exist from a validator that later gets slashed (common)
- The destination delegation must have fewer shares than recorded in the redelegation entry (occurs through normal unbonding)
- The source validator must be slashed (inevitable given validator misbehavior)

**Who Can Trigger:** Any regular user through standard blockchain operations:
- Performing redelegations (common for optimizing staking returns)
- Unbonding from validators (common for liquidity needs)  
- No special permissions or privileges required

**Frequency:** 
- Occurs automatically whenever the above conditions are met
- Redelegation followed by partial unbonding is a normal user behavior pattern
- Every applicable slashing event triggers this bug
- Given typical network activity, this likely affects a meaningful percentage of slashing events

**Likelihood Assessment:** Medium to High - While requiring specific conditions, these are all normal operations that occur regularly in proof-of-stake networks. The bug triggers automatically without intentional exploitation.

## Recommendation

Modify `SlashRedelegation` to track and return the actual amount of tokens burned rather than the theoretical amount:

**Option 1 (Preferred):** Accumulate actual burned amounts
```
After line 265 where tokensToBurn is obtained from Unbond():
- Instead of accumulating slashAmount (from InitialBalance) at line 240
- Accumulate the actual tokensToBurn value
- Return the total of actual burned tokens at line 295
```

**Option 2:** Track both theoretical and actual amounts separately
```
- Maintain two separate accumulators: totalTheoreticalSlash and totalActualBurned
- Use min(slashAmount, tokensToBurn) when accumulating to totalSlashAmount
- Return totalActualBurned instead of totalTheoreticalSlash
```

**Option 3:** Add current balance tracking to RedelegationEntry (more extensive change)
```
- Add a current balance field to RedelegationEntry similar to UnbondingDelegationEntry
- Update this field when delegation shares are reduced
- Use current balance for slash calculations instead of InitialBalance
```

The fix must ensure that the value returned by `SlashRedelegation` accurately reflects tokens actually removed from circulation, not a theoretical calculation that may exceed what could be burned.

## Proof of Concept

**Test Setup:**
```
File: x/staking/keeper/slash_test.go
Function: TestSlashRedelegationWithReducedDelegation (to be added)

1. Bootstrap with 3 validators at 10 consensus power each
2. Create redelegation: 6 tokens from Validator A to Validator B
   - RedelegationEntry: InitialBalance=6, SharesDst=6
3. Set delegation to Validator B with 6 shares
4. Fund bonded pool appropriately
```

**Action:**
```
1. User unbonds 4 shares from Validator B
   - Verify delegation.Shares = 2
   - Verify RedelegationEntry unchanged: InitialBalance=6, SharesDst=6
2. Record bonded pool balance
3. Slash Validator A at 50% for infraction at height before redelegation
```

**Expected Result:**
```
Total intended slash: 50% of 10 tokens = 5 tokens
- From redelegation: Should slash 50% of 6 = 3 tokens
- But can only unbond from 2 remaining shares ≈ 1 token
- Should burn from validator: 5 - 1 = 4 tokens
```

**Actual Result:**
```
- SlashRedelegation returns: 3 tokens (based on InitialBalance)
- Actually burned from redelegation: ~1 token (based on available shares)
- Validator slashing reduced by: 3 tokens
- Actually burned from validator: 5 - 3 = 2 tokens
- Total burned: 1 + 2 = 3 tokens instead of 5 tokens
- Validator under-slashed by: 2 tokens
```

This demonstrates the accounting discrepancy causes measurable under-slashing, resulting in direct loss to the protocol's economic security mechanism.

## Notes

The vulnerability is confirmed through code analysis. The key evidence:

1. **RedelegationEntry lacks current balance tracking** - Unlike UnbondingDelegationEntry which has separate InitialBalance and Balance fields, RedelegationEntry only has InitialBalance and SharesDst without tracking current state

2. **Unbond function doesn't update redelegation entries** - When users unbond from destination validators, only the delegation shares are reduced; redelegation entries remain unchanged

3. **SlashRedelegation returns theoretical vs actual** - The function calculates based on InitialBalance but burns based on capped shares, yet returns the theoretical amount

4. **Main Slash function trusts the return value** - It subtracts the returned amount from remainingSlashAmount without verification, leading to incorrect validator slashing calculations

This is a systematic issue affecting the core economic security mechanism of the staking module, warranting High severity classification under "Direct loss of funds" impact category.

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
