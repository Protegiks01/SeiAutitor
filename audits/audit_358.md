# Audit Report

## Title
Off-by-One Error in Double-Sign Slashing Causes Incorrect Slashing of Unbonding Delegations

## Summary
The slashing mechanism for double-sign evidence incorrectly slashes unbonding delegations that started unbonding at the exact block height where the validator set was calculated (`distributionHeight`). This occurs because the `distributionHeight` value is passed directly as the `infractionHeight` parameter without accounting for the fact that unbonding transactions processed during block `distributionHeight` are completed before the validator set calculation at EndBlock, meaning those delegations do not contribute to the validator's power at the time of the infraction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

## Impact
**Medium** - Direct loss of funds for affected delegators, but limited to a narrow time window.

## Finding Description

**Location:** 
- Primary: `x/evidence/keeper/infraction.go` lines 101-112 (distributionHeight calculation and Slash call)
- Secondary: `x/staking/keeper/slash.go` lines 174-177 (unbonding delegation slashing logic)

**Intended Logic:**
The slashing system should follow the "follow the usei" principle - only stake that actively contributed to a validator's voting power at the time of an infraction should be slashed. When a validator double-signs at block height H, the system should:
1. Calculate which validator set was active: the set determined at EndBlock of height H-1
2. Slash only the delegations that were part of that validator set
3. Exclude delegations that had already unbonded before the validator set calculation

**Actual Logic:**
The code calculates `distributionHeight = infractionHeight - ValidatorUpdateDelay` (e.g., H - 1 for infraction at H), then passes this directly as the `infractionHeight` parameter to the staking keeper's Slash function. The SlashUnbondingDelegation function uses the condition `entry.CreationHeight < infractionHeight` to exclude delegations from slashing. This means:
- Delegations with `CreationHeight >= distributionHeight` are slashed
- Delegations that unbonded at exactly `distributionHeight` are slashed
- However, these delegations unbonded DURING block `distributionHeight` (in DeliverTx), which happens BEFORE the validator set calculation (in EndBlock)
- Therefore, their stake was NOT included in the validator's power at the time of the double-sign

**Exploit Scenario:**
1. A validator is part of the active validator set at block H
2. During block H-1, a delegator submits an unbonding transaction from this validator
3. The transaction is processed in DeliverTx of block H-1, setting `CreationHeight = H-1`
4. At EndBlock of block H-1, the validator set is recalculated WITHOUT this delegation
5. At block H, the validator double-signs
6. When the double-sign evidence is processed, `distributionHeight = H - 1` is calculated
7. The slashing logic checks `CreationHeight >= H - 1`, which evaluates to `H - 1 >= H - 1` (true)
8. The innocent delegator's unbonding delegation is slashed, despite their stake not contributing to the validator's power at the time of the infraction [5](#0-4) 

**Security Failure:**
This breaks the accounting invariant that only stake contributing to an infraction should be penalized. It results in unfair financial loss to delegators who legitimately unbonded before the infraction occurred (in terms of when the validator set was finalized).

## Impact Explanation

**Assets Affected:** Delegator funds in unbonding delegations

**Severity of Damage:**
- Delegators who unbond at the exact block height `distributionHeight` lose a percentage of their unbonding funds (determined by `SlashFractionDoubleSign`, typically 5%)
- This affects the specific subset of delegators who happened to unbond during the critical block
- While each individual case is limited, this violates the core principle that validators and their delegators should only be penalized for stake that was actively contributing to the misbehavior

**Why This Matters:**
- Undermines trust in the slashing system's fairness
- Creates an unpredictable penalty for delegators who unbond at specific times
- Violates the documented "follow the usei" principle that stake penalties should match stake contribution to infractions
- Could discourage delegators from unbonding when they legitimately want to, if they're aware of this risk [6](#0-5) 

## Likelihood Explanation

**Who Can Trigger:** Any delegator who unbonds from a validator that subsequently commits a double-sign infraction.

**Required Conditions:**
1. A delegator must unbond from a validator at block height `H - 1`
2. The same validator must commit a double-sign infraction at block height `H`
3. The timing window is narrow (single block height) but occurs in normal operations

**Frequency:**
- Occurs whenever a double-sign happens and there are unbonding delegations from that exact block
- Given that double-signs are relatively rare but unbonding is common, this could affect multiple delegators per double-sign incident
- The impact is probabilistic but non-zero in any network with active delegation activity

## Recommendation

Modify the `distributionHeight` passed to the staking keeper's Slash function to be `distributionHeight + 1` instead of `distributionHeight`. This ensures that unbonding delegations created at block `distributionHeight` (which are processed before the validator set calculation at EndBlock) are correctly excluded from slashing.

**Specific Fix:**
In `x/evidence/keeper/infraction.go`, change:
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

**File:** `x/staking/keeper/slash_test.go`

**Test Function:** `TestSlashUnbondingDelegationOffByOne`

**Setup:**
```go
// Create a validator with initial delegation
app, ctx := setupApp()
ctx = ctx.WithBlockHeight(10)
validator := createValidator(power=100)
delegator := createDelegator()
delegate(delegator, validator, amount=100)

// Process through block 10 EndBlock to finalize validator set
endBlock(ctx)
```

**Trigger:**
```go
// Block 11: Delegator unbonds
ctx = ctx.WithBlockHeight(11)
undelegate(delegator, validator, amount=100) // CreationHeight = 11

// Block 11 EndBlock: Validator set recalculated WITHOUT this delegation
endBlock(ctx)

// Block 12: Validator double-signs with power that does NOT include the unbonding delegation
ctx = ctx.WithBlockHeight(12)

// Process double-sign evidence
distributionHeight = 12 - 1 = 11  // Per current implementation
slashUnbondingDelegation(unbondingDelegation, infractionHeight=11, slashFactor=0.05)
```

**Observation:**
The test should verify that:
1. The unbonding delegation with `CreationHeight = 11` is slashed (due to `11 >= 11`)
2. This is incorrect because the delegation unbonded at block 11, before the validator set for block 12 was finalized
3. The validator's power at block 12 did NOT include this delegation
4. Therefore, the slash amount should be 0, but instead it's positive

The test demonstrates that stake which did not contribute to the validator's power at the time of the infraction is still being slashed, violating the "follow the usei" principle. [7](#0-6)

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

**File:** x/slashing/keeper/keeper.go (L68-79)
```go
func (k Keeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, fraction sdk.Dec, power, distributionHeight int64) {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSlash,
			sdk.NewAttribute(types.AttributeKeyAddress, consAddr.String()),
			sdk.NewAttribute(types.AttributeKeyPower, fmt.Sprintf("%d", power)),
			sdk.NewAttribute(types.AttributeKeyReason, types.AttributeValueDoubleSign),
		),
	)
	telemetry.IncrValidatorSlashedCounter(consAddr.String(), types.AttributeValueDoubleSign)
	k.sk.Slash(ctx, consAddr, distributionHeight, power, fraction)
}
```

**File:** x/staking/keeper/slash.go (L24-24)
```go
func (k Keeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdk.Dec) {
```

**File:** x/staking/keeper/slash.go (L174-177)
```go
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}
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

**File:** x/evidence/spec/06_begin_block.md (L40-44)
```markdown
If valid `Equivocation` evidence is included in a block, the validator's stake is
reduced (slashed) by `SlashFractionDoubleSign` as defined by the `x/slashing` module
of what their stake was when the infraction occurred, rather than when the evidence was discovered.
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
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
