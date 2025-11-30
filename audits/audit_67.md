# Audit Report

## Title
Off-by-One Error in Double-Sign Slashing Causes Incorrect Slashing of Unbonding Delegations

## Summary
The evidence handler passes an incorrect infraction height parameter to the slashing function when processing double-sign evidence, causing unbonding delegations that were initiated at the exact block height where the validator set was finalized to be incorrectly slashed, even though their stake did not contribute to the validator's voting power during the infraction.

## Impact
Medium

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Secondary: [2](#0-1) 

**Intended Logic:**
According to the staking specification [3](#0-2) , only unbonding delegations where "the infraction occurred before the unbonding began" should be slashed. The system should follow the "follow the usei" principle [4](#0-3) , meaning only stake that actively contributed to a validator's voting power at the time of an infraction should be slashed.

When a delegator unbonds at block H-1:
1. During DeliverTx of block H-1, the `Undelegate` function sets `CreationHeight = ctx.BlockHeight() = H-1` [5](#0-4) 
2. Validator tokens are immediately reduced [6](#0-5) 
3. At EndBlock(H-1), the validator set for block H is calculated with the reduced power
4. At block H, the validator signs with reduced power (unbonded stake is NOT part of voting power)

**Actual Logic:**
The evidence handler calculates `distributionHeight = infractionHeight - ValidatorUpdateDelay` (where `ValidatorUpdateDelay = 1` [7](#0-6) ) and passes `distributionHeight` as the infraction height parameter to the Slash function. For a double-sign at block H, this becomes H-1.

The slashing check uses `entry.CreationHeight < infractionHeight` to determine which delegations to skip. For an unbonding with CreationHeight = H-1 and infractionHeight parameter = H-1:
- Check evaluates: `H-1 < H-1` → false  
- The entry is NOT skipped, so it IS slashed (incorrectly)

**Exploitation Path:**
1. Delegator submits unbonding transaction at block H-1 (normal operation)
2. Transaction is processed with CreationHeight = H-1
3. Validator's power is reduced immediately
4. EndBlock(H-1) calculates validator set for block H with reduced power
5. Validator double-signs at block H (with reduced power that doesn't include unbonded stake)
6. Evidence handler calculates distributionHeight = H-1 and passes it as infraction height
7. Slash function incorrectly slashes the unbonding because `H-1 < H-1` evaluates to false
8. Delegator loses SlashFractionDoubleSign (typically 5%) of their unbonding amount

**Security Guarantee Broken:**
This violates the documented invariant that only stake contributing to an infraction should be penalized. The unbonded stake was removed from the validator's power before the validator set for block H was finalized, so it did not contribute to the validator's voting power when the double-sign occurred at block H.

## Impact Explanation

Delegators who unbond from a validator at the exact block height where the validator set is finalized (distributionHeight) suffer direct loss of funds when that validator subsequently double-signs at the next block. The typical SlashFractionDoubleSign is 5%, representing a permanent loss of the delegators' unbonding funds. This directly violates the core security principle that penalties should only apply to stake that actively contributed to the misbehavior.

## Likelihood Explanation

This issue occurs when:
1. A delegator unbonds from a validator at block height H-1 (routine operation)
2. The same validator commits a double-sign infraction at block height H (rare but significant event)

While double-sign events are relatively rare, unbonding is a routine operation in any active Proof-of-Stake network. When a double-sign does occur, any delegators who happened to unbond at the specific height (distributionHeight) will be incorrectly slashed. This occurs in normal network operation without requiring any special conditions or privileged access.

## Recommendation

Modify the evidence handler to pass `distributionHeight + 1` instead of `distributionHeight` to the Slash function:

```go
k.slashingKeeper.Slash(
    ctx,
    consAddr,
    k.slashingKeeper.SlashFractionDoubleSign(ctx),
    evidence.GetValidatorPower(), 
    distributionHeight + 1,  // Changed from distributionHeight
)
```

This ensures the infraction height parameter correctly represents the actual block where the infraction occurred (H), not where the validator set was determined (H-1). The slashing check will then correctly evaluate to `H-1 < H` → true, skipping unbonding delegations whose stake was removed before the validator set for the infraction block was finalized.

## Proof of Concept

**Setup:**
1. Initialize a validator with delegated stake at block 100
2. Execute EndBlock(100) to finalize validator set for block 101

**Action:**
1. At block 101 during DeliverTx:
   - Delegator submits unbonding transaction
   - `Undelegate` function sets CreationHeight = 101 via `ctx.BlockHeight()`
   - Validator's tokens are immediately reduced via `bondedTokensToNotBonded`
2. At EndBlock(101):
   - Validator set for block 102 is calculated with reduced power
3. At block 102:
   - Validator double-signs using the reduced power
4. Evidence processing:
   - `distributionHeight = 102 - 1 = 101`
   - `SlashUnbondingDelegation` is called with `infractionHeight = 101`
5. Slashing check:
   - Check evaluates: `101 < 101` → false
   - Unbonding delegation IS slashed

**Result:**
- Expected: Slash amount = 0 (stake didn't contribute to infraction)
- Actual: Slash amount = 5% of unbonding amount
- This demonstrates stake that did not contribute to the validator's power at the infraction is incorrectly slashed

**Note:** The existing test [8](#0-7)  tests the case where CreationHeight = 0 and infractionHeight = 1 (clearly before), but does not test the boundary case where CreationHeight equals distributionHeight, which is where the off-by-one error manifests.

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

**File:** x/staking/spec/02_state_transitions.md (L133-134)
```markdown
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
```

**File:** x/evidence/spec/06_begin_block.md (L40-44)
```markdown
If valid `Equivocation` evidence is included in a block, the validator's stake is
reduced (slashed) by `SlashFractionDoubleSign` as defined by the `x/slashing` module
of what their stake was when the infraction occurred, rather than when the evidence was discovered.
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
```

**File:** x/staking/keeper/delegation.go (L848-850)
```go
	if validator.IsBonded() {
		k.bondedTokensToNotBonded(ctx, returnAmount)
	}
```

**File:** x/staking/keeper/delegation.go (L853-853)
```go
	ubd := k.SetUnbondingDelegationEntry(ctx, delAddr, valAddr, ctx.BlockHeight(), completionTime, returnAmount)
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
