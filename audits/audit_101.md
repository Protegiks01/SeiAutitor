# Audit Report

## Title
Off-by-One Error in Double-Sign Slashing Causes Incorrect Slashing of Unbonding Delegations

## Summary
The slashing mechanism for double-sign evidence incorrectly slashes unbonding delegations that were initiated at the exact block height where the validator set was calculated (`distributionHeight`). When a validator double-signs at block H, the code calculates `distributionHeight = H - 1` and uses this to determine which unbonding delegations to slash. However, unbonding transactions processed during block H-1 occur in DeliverTx before the validator set calculation at EndBlock, meaning these delegations have already reduced the validator's power and should not be slashed. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/evidence/keeper/infraction.go` lines 101-112
- Secondary: `x/staking/keeper/slash.go` lines 174-177

**Intended Logic:**
The slashing system should follow the "follow the usei" principle documented in the evidence specification - only stake that actively contributed to a validator's voting power at the time of an infraction should be slashed. [2](#0-1) 

When unbonding occurs during block H-1:
1. The unbonding transaction is processed in DeliverTx, setting CreationHeight = H-1
2. The validator's tokens are immediately reduced via `RemoveValidatorTokensAndShares`
3. At EndBlock of H-1, the validator set for block H is calculated with the reduced power
4. Therefore, at block H, the unbonded stake is NOT contributing to the validator's power [3](#0-2) 

**Actual Logic:**
The code calculates `distributionHeight = infractionHeight - ValidatorUpdateDelay` and passes this value as the `infractionHeight` parameter to the Slash function. For a double-sign at block H, this becomes H - 1. The slashing check uses `entry.CreationHeight < infractionHeight` to exclude delegations, meaning delegations with `CreationHeight >= H - 1` are slashed. [4](#0-3) 

For an unbonding at block H-1 with CreationHeight = H-1:
- Check evaluates: `H-1 < H-1` → false
- Unbonding IS slashed despite its stake not contributing to the validator's power at block H

**Exploitation Path:**
1. Delegator submits unbonding transaction at block H-1
2. Transaction is processed in DeliverTx with CreationHeight = H-1
3. Validator's power is reduced immediately
4. EndBlock of H-1 calculates validator set for block H with reduced power
5. Validator double-signs at block H with the reduced power
6. Evidence handler calculates distributionHeight = H - 1
7. Slash function incorrectly slashes the unbonding delegation
8. Delegator loses SlashFractionDoubleSign (typically 5%) of their unbonding amount

**Security Guarantee Broken:**
This violates the documented "follow the usei" invariant that only stake contributing to an infraction should be penalized. It causes financial loss to delegators whose stake was not part of the validator's power during the misbehavior.

## Impact Explanation

Delegators who unbond from a validator at block height `distributionHeight` (H-1) lose a percentage of their unbonding funds when that validator subsequently double-signs at block H. The typical SlashFractionDoubleSign is 5%, representing direct and permanent loss of funds for affected delegators.

While the time window is narrow (single block height), this can affect multiple delegators per double-sign incident in networks with active delegation activity. The impact undermines trust in the slashing system's fairness and violates the core principle that penalties should only apply to stake that actively contributed to the misbehavior.

## Likelihood Explanation

This issue occurs whenever:
1. A delegator unbonds from a validator at block height H-1
2. The same validator commits a double-sign infraction at block height H

While double-sign events are relatively rare, unbonding is a common operation. When a double-sign does occur, any delegators who happened to unbond at the specific block height (H-1) will be incorrectly slashed. The probability is non-zero in any network with active delegation activity, making this a realistic scenario that occurs in normal operations without requiring any special privileges or malicious intent.

## Recommendation

Modify the value passed to the staking keeper's Slash function to be `distributionHeight + 1` instead of `distributionHeight`. This ensures unbonding delegations created at block `distributionHeight` are correctly excluded from slashing since they occurred before the validator set calculation.

In `x/evidence/keeper/infraction.go` line 107-112, change:
```go
k.slashingKeeper.Slash(
    ctx,
    consAddr,
    k.slashingKeeper.SlashFractionDoubleSign(ctx),
    evidence.GetValidatorPower(), distributionHeight,
)
```
To:
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
1. Create a validator with delegated stake at block 100
2. Execute EndBlock to finalize validator set for block 101

**Action:**
1. At block 101: Delegator submits unbonding transaction
   - CreationHeight is set to 101
   - Validator's tokens are reduced via `RemoveValidatorTokensAndShares`
2. Execute EndBlock(101): Validator set for block 102 is calculated with reduced power
3. At block 102: Validator double-signs
4. Process evidence: distributionHeight = 102 - 1 = 101
5. Call `SlashUnbondingDelegation` with infractionHeight = 101

**Result:**
- The check `CreationHeight < infractionHeight` evaluates to `101 < 101` → false
- Unbonding delegation IS slashed
- Expected: Slash amount should be 0 (stake didn't contribute)
- Actual: Slash amount is positive (5% of unbonding amount)

This demonstrates that stake which did not contribute to the validator's power at the time of the infraction is incorrectly slashed, violating the "follow the usei" principle.

## Notes

The existing test at `x/staking/keeper/slash_test.go` lines 75-89 shows the correct behavior for unbonding delegations that started BEFORE the infraction height, but does not test the boundary case where unbonding occurs at exactly `distributionHeight`. [5](#0-4)

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

**File:** x/staking/keeper/slash.go (L174-177)
```go
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}
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
