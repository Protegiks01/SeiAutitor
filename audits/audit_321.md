## Audit Report

## Title
Accounting Discrepancy in SlashRedelegation Leading to Validator Under-Slashing

## Summary
The `SlashRedelegation` function in `x/staking/keeper/slash.go` contains an accounting bug where it caps `sharesToUnbond` at `delegation.Shares` (lines 261-263) but calculates the returned `totalSlashAmount` based on `entry.InitialBalance` without accounting for this capping. This causes the main `Slash` function to believe more tokens were slashed than actually were, resulting in validators being under-slashed when they misbehave. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** `x/staking/keeper/slash.go`, function `SlashRedelegation` (lines 219-296)

**Intended Logic:** When a validator is slashed, all redelegations from that validator should be slashed proportionally. The function should return the total amount that was intended to be slashed (based on `InitialBalance`), which the main `Slash` function uses to track how much has been slashed from unbondings/redelegations, and then slash the remaining amount from the validator's bonded tokens.

**Actual Logic:** The function has a discrepancy between:
1. The calculated `slashAmount` (line 238-240): computed as `slashFactor * entry.InitialBalance` and accumulated into `totalSlashAmount`
2. The actual tokens burned: computed by unbonding the (potentially capped) `sharesToUnbond` [2](#0-1) 

When `sharesToUnbond` (calculated as `slashFactor * entry.SharesDst` on line 243) exceeds `delegation.Shares`, the code correctly caps it at line 261-263. However, the actual tokens burned are based on this capped value, while `totalSlashAmount` uses the uncapped calculation from `InitialBalance`. [3](#0-2) [4](#0-3) 

This capped amount is then unbonded and burned (lines 265-284), but the function returns the larger `totalSlashAmount` at line 295. [5](#0-4) 

In the main `Slash` function, this returned value reduces `remainingSlashAmount` (line 101), which determines how much to slash from the validator's bonded tokens (line 106). [6](#0-5) [7](#0-6) 

**Exploit Scenario:**
1. User delegates 100 tokens to Validator A (gets 100 shares)
2. User redelegates 100 tokens from Validator A to Validator B
   - Creates RedelegationEntry with `InitialBalance=100` tokens, `SharesDst=100` shares
   - User now has 100 shares in Validator B
3. User unbonds 60 shares from Validator B through normal unbonding
   - User's delegation to Validator B: 40 shares remaining
   - The RedelegationEntry still records `SharesDst=100`, `InitialBalance=100`
4. Validator A misbehaves and is slashed with `slashFactor=0.5` (50%)
5. `SlashRedelegation` is called:
   - Line 238-240: `slashAmount = 0.5 * 100 = 50` tokens, added to `totalSlashAmount`
   - Line 243: `sharesToUnbond = 0.5 * 100 = 50` shares
   - Line 255: Delegation found with only 40 shares
   - Lines 261-263: Since `50 > 40`, `sharesToUnbond` capped to 40 shares
   - Line 265: Unbond 40 shares → approximately 40 tokens burned (assuming ~1:1 ratio)
   - Lines 279/281: Only 40 tokens actually burned
   - Line 295: Returns `totalSlashAmount = 50` tokens
6. Main `Slash` function (line 101): `remainingSlashAmount -= 50` tokens
7. But only 40 tokens were actually burned from the redelegation
8. Line 106: Validator's bonded tokens slashed by `remainingSlashAmount - 50` instead of `remainingSlashAmount - 40`
9. Result: Validator is under-slashed by 10 tokens

**Security Failure:** This breaks the accounting invariant that ensures validators are slashed for the full calculated penalty. Validators who misbehave retain more tokens than they should, reducing the economic security of the network and creating unfair advantages for misbehaving validators.

## Impact Explanation

**Affected Assets:** Protocol tokens that should have been slashed from validators are retained instead.

**Severity of Damage:** 
- Validators are under-slashed when they commit infractions
- The amount of under-slashing equals the difference between what should have been slashed from the redelegation and what could actually be burned due to prior unbonding
- This can be substantial if users frequently unbond after redelegating, which is normal user behavior
- The protocol loses tokens that should have been burned, effectively subsidizing validator misbehavior
- This undermines the entire slashing mechanism's deterrent effect

**Why This Matters:** 
- Slashing is a critical security mechanism that enforces validator good behavior
- Under-slashing reduces the economic penalties for misbehavior, weakening network security
- Validators can potentially exploit this by encouraging delegators to redelegate and then partially unbond before the validator misbehaves
- This violates the fundamental economic security model of proof-of-stake networks

## Likelihood Explanation

**Who Can Trigger:** Any regular user through normal operations (no special privileges required):
- User performs a redelegation (common operation)
- User later unbonds part of their delegation (common operation)
- Validator misbehaves and gets slashed (expected to be rare but inevitable)

**Conditions Required:**
- A redelegation must exist from a validator that later gets slashed
- The destination delegation must have fewer shares than recorded in the redelegation entry (happens when user unbonds)
- This is a normal sequence of operations, not a rare edge case

**Frequency:** 
- Happens whenever the above conditions are met
- Given the commonality of redelegations and unbondings, this could affect many slashing events
- Every slashing event involving redelegations where delegators have partially unbonded will trigger this bug
- Could result in systematic under-slashing across the network

## Recommendation

Modify `SlashRedelegation` to calculate `totalSlashAmount` based on the actual tokens burned rather than the uncapped `InitialBalance` calculation. Specifically:

1. After line 265 where `tokensToBurn` is calculated from `Unbond`, use this actual amount instead of the pre-calculated `slashAmount` when accumulating the total
2. Replace line 240's unconditional addition with conditional logic that uses the minimum of `slashAmount` and the actual `tokensToBurn`

Alternative approach: Track both the intended slash amount and actual burned amount separately, and adjust the accounting in the main `Slash` function accordingly.

The fix should ensure that `totalSlashAmount` reflects the actual tokens that were burned from the redelegation, not the theoretical amount based on `InitialBalance`.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`

**Test Function:** Add new test `TestSlashRedelegationWithReducedDelegation`

**Setup:**
```
// Initialize 3 validators with 10 consensus power each
app, ctx, addrDels, addrVals := bootstrapSlashTest(t, 10)
fraction := sdk.NewDecWithPrec(5, 1) // 50% slash

// Fund bonded pool for redelegation
rdTokens := app.StakingKeeper.TokensFromConsensusPower(ctx, 6)
bondedPool := app.StakingKeeper.GetBondedPool(ctx)
rdCoins := sdk.NewCoins(sdk.NewCoin(app.StakingKeeper.BondDenom(ctx), rdTokens))
require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, bondedPool.GetName(), rdCoins))
app.AccountKeeper.SetModuleAccount(ctx, bondedPool)

// Create redelegation with 6 tokens/shares
rd := types.NewRedelegation(addrDels[0], addrVals[0], addrVals[1], 11, time.Unix(0, 0), rdTokens, rdTokens.ToDec())
app.StakingKeeper.SetRedelegation(ctx, rd)

// Create delegation to destination validator with 6 shares
del := types.NewDelegation(addrDels[0], addrVals[1], rdTokens.ToDec())
app.StakingKeeper.SetDelegation(ctx, del)
```

**Trigger:**
```
// Partially unbond to reduce delegation shares to 2 (less than the 6 in redelegation entry)
sharesToUnbond := sdk.NewDec(4)
_, err := app.StakingKeeper.Unbond(ctx, addrDels[0], addrVals[1], sharesToUnbond)
require.NoError(t, err)

// Verify delegation now has only 2 shares
del, found := app.StakingKeeper.GetDelegation(ctx, addrDels[0], addrVals[1])
require.True(t, found)
require.Equal(t, sdk.NewDec(2), del.Shares)

// Record bonded pool balance before slashing
oldBonded := app.BankKeeper.GetBalance(ctx, bondedPool.GetAddress(), app.StakingKeeper.BondDenom(ctx)).Amount

// Slash validator A at 50%
ctx = ctx.WithBlockHeight(12)
consAddr := sdk.ConsAddress(PKs[0].Address())
validator, found := app.StakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
require.True(t, found)
app.StakingKeeper.Slash(ctx, consAddr, 10, 10, fraction)
```

**Observation:**
```
// Calculate expected burn: 50% of 10 tokens = 5 tokens
// But only 2 shares remain in delegation (2 tokens at 1:1)
// So only 2 tokens can be burned from redelegation
// Remaining 3 tokens should be burned from validator bonded tokens
expectedTotalBurn := app.StakingKeeper.TokensFromConsensusPower(ctx, 5)

// Check actual burned amount
newBonded := app.BankKeeper.GetBalance(ctx, bondedPool.GetAddress(), app.StakingKeeper.BondDenom(ctx)).Amount
actualBurned := oldBonded.Sub(newBonded)

// BUG: actualBurned will be less than expectedTotalBurn
// Because SlashRedelegation returned 3 tokens as slashed (50% of 6)
// But only 2 tokens were actually burned from the redelegation
// So only 2 tokens were burned from validator instead of 3
// Total burned = 2 (redelegation) + 2 (validator) = 4 tokens
// Expected = 5 tokens
// Under-slashed by 1 token

require.True(t, actualBurned.LT(expectedTotalBurn), 
    "Validator was under-slashed: burned %s but should have burned %s", 
    actualBurned, expectedTotalBurn)
```

This test demonstrates that when a delegation has fewer shares than the redelegation entry records, the validator is under-slashed because `SlashRedelegation` reports slashing more tokens than it actually burned.

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
