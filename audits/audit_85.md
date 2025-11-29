# Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function in `x/staking/keeper/slash.go` contains an accounting bug where it returns a theoretical slash amount based on `entry.InitialBalance` but only burns tokens based on the capped `delegation.Shares`. When a user unbonds from the destination validator after a redelegation, the function reports slashing more tokens than it actually burned, causing the main `Slash` function to under-slash the validator's bonded tokens. [1](#0-0) [2](#0-1) [3](#0-2) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296)

**Intended logic:** When a validator is slashed, all redelegations from that validator should be slashed proportionally. The function should return the actual amount of tokens that were slashed and burned from redelegations, which the main `Slash` function uses to calculate how much additional slashing is needed from the validator's bonded tokens.

**Actual logic:** The function has a critical discrepancy between the calculated `totalSlashAmount` and the actual tokens burned:

1. At lines 238-240, it calculates `slashAmount = slashFactor * entry.InitialBalance` and accumulates this into `totalSlashAmount`
2. At line 243, it calculates `sharesToUnbond = slashFactor * entry.SharesDst`  
3. At lines 261-263, when `sharesToUnbond > delegation.Shares`, it correctly caps at `delegation.Shares`
4. At line 265, it unbonds the capped shares, which returns `tokensToBurn` based on the actual shares available
5. The actual `tokensToBurn` is burned at lines 279 or 281
6. However, at line 295, it returns `totalSlashAmount` which was calculated from `InitialBalance`, not from the actual burned tokens [4](#0-3) [5](#0-4) 

Unlike `UnbondingDelegationEntry` which has both `InitialBalance` and `Balance` fields (where `Balance` tracks the current amount), `RedelegationEntry` only has `InitialBalance` and `SharesDst` fields. When a user unbonds from the destination validator after a redelegation, the delegation shares decrease but the redelegation entry remains unchanged. This creates an accounting mismatch. [6](#0-5) 

**Exploitation path:**
1. User delegates tokens to Validator A
2. User redelegates from Validator A to Validator B, creating a `RedelegationEntry` with `InitialBalance=X` and `SharesDst=X`
3. User performs normal unbonding from Validator B, reducing the delegation shares to Y (where Y < X)
4. Validator A misbehaves and is slashed
5. `SlashRedelegation` is called:
   - Calculates theoretical slash: `slashFactor * X` tokens
   - Tries to unbond: `slashFactor * X` shares
   - Caps at available delegation: `Y` shares  
   - Actually burns: approximately `slashFactor * Y` tokens
   - Returns: `slashFactor * X` tokens (the theoretical amount)
6. Main `Slash` function subtracts the returned amount from `remainingSlashAmount`
7. Result: Validator's bonded tokens are slashed by less than they should be, equal to `slashFactor * (X - Y)` tokens [7](#0-6) [8](#0-7) 

**Security guarantee broken:** The slashing mechanism's invariant that validators are penalized for the full calculated slash amount is violated. Validators retain tokens that should have been burned, reducing the economic penalty for misbehavior.

## Impact Explanation

**Direct loss of funds:** Tokens that should be burned (removed from circulation) as punishment for validator misbehavior are instead retained. This represents a direct loss to the protocol's economic security model.

**Severity:**
- Validators are systematically under-slashed when they commit infractions
- The under-slashing amount equals the difference between what should have been slashed from redelegations and what could actually be burned due to prior unbonding by users
- This undermines the entire slashing mechanism's deterrent effect, which is fundamental to proof-of-stake security
- The protocol effectively subsidizes validator misbehavior by not enforcing full penalties
- This could incentivize validators to encourage their delegators to redelegate and then unbond before the validator engages in risky behavior

## Likelihood Explanation

**Who can trigger:** Any regular user through normal blockchain operations:
- Performing a redelegation (common operation for optimizing staking returns)
- Later unbonding part of their delegation (common operation for liquidity needs)
- Waiting for a validator to be slashed (inevitable given validator misbehavior)

**Conditions required:**
- A redelegation exists from a validator that later gets slashed
- The destination delegation has fewer shares than originally recorded in the redelegation entry
- This occurs through normal unbonding operations, not edge cases

**Frequency:** 
- Happens automatically whenever these common conditions are met
- Redelegations and subsequent unbonding are normal user behavior patterns
- Every slashing event involving redelegations where delegators have partially unbonded will trigger this bug
- Could result in systematic under-slashing across the network over time

## Recommendation

Modify `SlashRedelegation` to track and return the actual amount of tokens burned rather than the theoretical amount based on `InitialBalance`:

1. After line 265 where `tokensToBurn` is obtained from `Unbond()`, use this actual value when accumulating the total
2. Replace the unconditional addition at line 240 with logic that adds `min(slashAmount, actualTokensBurned)` to `totalSlashAmount`

Alternatively, track both the intended slash amount and actual burned amount separately throughout the function, and only return the actual burned amount. This ensures the main `Slash` function's accounting accurately reflects tokens that were actually removed from circulation.

The fix must ensure that `totalSlashAmount` returned reflects actual tokens burned from the redelegation, not a theoretical calculation.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`

**Test Function:** `TestSlashRedelegationWithReducedDelegation` (to be added)

**Setup:**
- Bootstrap test with 3 validators at 10 consensus power each
- Create a redelegation with 6 tokens from Validator A to Validator B
- Set up corresponding delegation to Validator B with 6 shares
- Fund the bonded pool appropriately

**Action:**
- User unbonds 4 shares from Validator B (reducing delegation to 2 shares)
- Verify delegation now has only 2 shares while redelegation entry still records SharesDst=6
- Record bonded pool balance before slashing
- Slash Validator A at 50% slash factor for infraction at earlier height

**Result:**
- Expected total burn: 50% of 10 tokens = 5 tokens (based on validator power at infraction)
- Redelegation should contribute: 50% of 6 tokens = 3 tokens
- But can only burn: 50% of 2 remaining shares ≈ 1 token from redelegation  
- Should burn remaining: 5 - 1 = 4 tokens from validator bonded tokens
- Actually burns from validator: 5 - 3 = 2 tokens (because SlashRedelegation returned 3)
- **Total actually burned: 1 + 2 = 3 tokens instead of 5 tokens**
- **Validator is under-slashed by 2 tokens**

This demonstrates that the accounting discrepancy causes validators to be under-slashed whenever delegations are reduced after redelegations, resulting in direct loss of funds to the protocol's economic security mechanism.

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

**File:** x/staking/keeper/slash.go (L238-240)
```go
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)
```

**File:** x/staking/keeper/slash.go (L243-243)
```go
		sharesToUnbond := slashFactor.Mul(entry.SharesDst)
```

**File:** x/staking/keeper/slash.go (L261-263)
```go
		if sharesToUnbond.GT(delegation.Shares) {
			sharesToUnbond = delegation.Shares
		}
```

**File:** x/staking/keeper/slash.go (L265-268)
```go
		tokensToBurn, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
		if err != nil {
			panic(fmt.Errorf("error unbonding delegator: %v", err))
		}
```

**File:** x/staking/keeper/slash.go (L295-295)
```go
	return totalSlashAmount
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
