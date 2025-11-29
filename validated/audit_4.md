# Audit Report

## Title
Off-by-One Error in Double-Sign Slashing Causes Incorrect Slashing of Unbonding Delegations

## Summary
The evidence handler incorrectly calculates which unbonding delegations should be slashed when processing double-sign evidence. Unbonding delegations that were initiated at the exact block height where the validator set was determined (`distributionHeight`) are incorrectly slashed, even though their stake had already been removed from the validator's power before the infraction occurred. This violates the "follow the usei" principle and causes direct loss of funds for affected delegators.

## Impact
Medium

## Finding Description

**Location:**
- Primary: [1](#0-0) 
- Secondary: [2](#0-1) 

**Intended Logic:**
The slashing system should follow the "follow the usei" principle as documented in the evidence specification [3](#0-2)  - only stake that actively contributed to a validator's voting power at the time of an infraction should be slashed.

When a delegator unbonds at block H-1:
1. The unbonding transaction is processed during DeliverTx of block H-1
2. The `Undelegate` function sets `CreationHeight = ctx.BlockHeight() = H-1` [4](#0-3) 
3. The validator's tokens are immediately reduced during DeliverTx [5](#0-4) 
4. At EndBlock(H-1), the validator set for block H is calculated with the reduced power
5. At block H, the validator signs with reduced power (the unbonded stake is NOT part of the validator's power)

**Actual Logic:**
The evidence handler calculates `distributionHeight = infractionHeight - ValidatorUpdateDelay` (where `ValidatorUpdateDelay = 1` [6](#0-5) ) and passes this as the `infractionHeight` parameter to the Slash function. For a double-sign at block H, this becomes H-1.

The slashing check uses `entry.CreationHeight < infractionHeight` to determine which delegations to skip. For an unbonding with CreationHeight = H-1:
- Check evaluates: `H-1 < H-1` → false
- The entry is NOT skipped, so it IS slashed

**Exploitation Path:**
1. Delegator submits unbonding transaction at block H-1 (normal operation, no special privileges)
2. Transaction is processed in DeliverTx with CreationHeight = H-1
3. Validator's power is reduced immediately via token transfer [7](#0-6) 
4. EndBlock(H-1) calculates validator set for block H with reduced power
5. Validator double-signs at block H (with the reduced power)
6. Evidence handler processes the evidence and calculates distributionHeight = H-1 [8](#0-7) 
7. Slash function incorrectly slashes the unbonding delegation because `H-1 < H-1` evaluates to false
8. Delegator loses SlashFractionDoubleSign (typically 5%) of their unbonding amount

**Security Guarantee Broken:**
This violates the documented "follow the usei" invariant that only stake contributing to an infraction should be penalized. It causes direct financial loss to delegators whose stake was not part of the validator's power during the misbehavior.

## Impact Explanation

Delegators who unbond from a validator at block height `distributionHeight` (H-1) suffer direct loss of funds when that validator subsequently double-signs at block H. The typical SlashFractionDoubleSign is 5%, representing a permanent loss of the delegators' unbonding funds.

While the time window is narrow (single block height), this affects any delegator who unbonds at the specific height in normal operation. The impact directly violates the core security principle that penalties should only apply to stake that actively contributed to the misbehavior, undermining trust in the slashing system's fairness.

## Likelihood Explanation

This issue occurs whenever:
1. A delegator unbonds from a validator at block height H-1 (common operation)
2. The same validator commits a double-sign infraction at block height H (rare but significant event)

While double-sign events are relatively rare, unbonding is a routine operation in any active Proof-of-Stake network. When a double-sign does occur, any delegators who happened to unbond at the distributionHeight will be incorrectly slashed. This is not a theoretical issue - it will occur in normal network operation without requiring any special conditions, malicious intent, or privileged access.

## Recommendation

Modify the value passed to the staking keeper's Slash function in the evidence handler to be `distributionHeight + 1` instead of `distributionHeight`. This ensures unbonding delegations created at block `distributionHeight` are correctly excluded from slashing since their stake was removed before the validator set for the infraction block was finalized.

In [9](#0-8) , change the last parameter from `distributionHeight` to `distributionHeight + 1`:

```go
k.slashingKeeper.Slash(
    ctx,
    consAddr,
    k.slashingKeeper.SlashFractionDoubleSign(ctx),
    evidence.GetValidatorPower(), distributionHeight + 1,
)
```

This shifts the threshold by one block, ensuring that only unbonding delegations created AFTER the validator set was finalized are slashed.

## Proof of Concept

**Setup:**
1. Initialize a validator with delegated stake at block 100
2. Execute EndBlock(100) to finalize validator set for block 101

**Action:**
1. At block 101 during DeliverTx:
   - Delegator submits unbonding transaction
   - `Undelegate` function is called [10](#0-9) 
   - CreationHeight is set to 101 via `ctx.BlockHeight()`
   - Validator's tokens are immediately reduced
2. At EndBlock(101):
   - Validator set for block 102 is calculated with reduced power
3. At block 102:
   - Validator double-signs using the reduced power
4. Evidence processing:
   - `distributionHeight = 102 - 1 = 101`
   - `SlashUnbondingDelegation` is called with `infractionHeight = 101`
5. Slashing check:
   - Check evaluates: `CreationHeight < infractionHeight` → `101 < 101` → false
   - Unbonding delegation IS slashed

**Result:**
- Expected: Slash amount should be 0 (stake didn't contribute to infraction)
- Actual: Slash amount is positive (5% of unbonding amount)
- This demonstrates that stake which did not contribute to the validator's power at the time of the infraction is incorrectly slashed

## Notes

The existing test at [11](#0-10)  correctly tests that unbonding delegations created BEFORE the infraction height are not slashed (CreationHeight = 0, infractionHeight = 1), but does not test the boundary case where CreationHeight equals distributionHeight. This boundary case is where the off-by-one error occurs.

### Citations

**File:** x/evidence/keeper/infraction.go (L101-112)
```go
	distributionHeight := infractionHeight - sdk.ValidatorUpdateDelay

	// Slash validator. The `power` is the int64 power of the validator as provided
	// to/by Tendermint. This value is validator.Tokens as sent to Tendermint via
	// ABCI, and now received as evidence. The fraction is passed in to separately
	// to slash unbonding and rebonding delegations.
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)
```

**File:** x/staking/keeper/slash.go (L174-177)
```go
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}
```

**File:** x/evidence/spec/06_begin_block.md (L40-44)
```markdown
If valid `Equivocation` evidence is included in a block, the validator's stake is
reduced (slashed) by `SlashFractionDoubleSign` as defined by the `x/slashing` module
of what their stake was when the infraction occurred, rather than when the evidence was discovered.
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
```

**File:** x/staking/keeper/delegation.go (L830-856)
```go
func (k Keeper) Undelegate(
	ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, sharesAmount sdk.Dec,
) (time.Time, error) {
	validator, found := k.GetValidator(ctx, valAddr)
	if !found {
		return time.Time{}, types.ErrNoDelegatorForAddress
	}

	if k.HasMaxUnbondingDelegationEntries(ctx, delAddr, valAddr) {
		return time.Time{}, types.ErrMaxUnbondingDelegationEntries
	}

	returnAmount, err := k.Unbond(ctx, delAddr, valAddr, sharesAmount)
	if err != nil {
		return time.Time{}, err
	}

	// transfer the validator tokens to the not bonded pool
	if validator.IsBonded() {
		k.bondedTokensToNotBonded(ctx, returnAmount)
	}

	completionTime := ctx.BlockHeader().Time.Add(k.UnbondingTime(ctx))
	ubd := k.SetUnbondingDelegationEntry(ctx, delAddr, valAddr, ctx.BlockHeight(), completionTime, returnAmount)
	k.InsertUBDQueue(ctx, ubd, completionTime)

	return completionTime, nil
```

**File:** types/staking.go (L26-26)
```go
	ValidatorUpdateDelay int64 = 1
```

**File:** x/staking/keeper/slash_test.go (L75-89)
```go
func TestSlashUnbondingDelegation(t *testing.T) {
	app, ctx, addrDels, addrVals := bootstrapSlashTest(t, 10)

	fraction := sdk.NewDecWithPrec(5, 1)

	// set an unbonding delegation with expiration timestamp (beyond which the
	// unbonding delegation shouldn't be slashed)
	ubd := types.NewUnbondingDelegation(addrDels[0], addrVals[0], 0,
		time.Unix(5, 0), sdk.NewInt(10))

	app.StakingKeeper.SetUnbondingDelegation(ctx, ubd)

	// unbonding started prior to the infraction height, stakw didn't contribute
	slashAmount := app.StakingKeeper.SlashUnbondingDelegation(ctx, ubd, 1, fraction)
	require.True(t, slashAmount.Equal(sdk.NewInt(0)))
```
