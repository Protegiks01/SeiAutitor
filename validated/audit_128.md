# Audit Report

## Title
Future-Height Evidence Bypasses Validation and Causes Network Halt via Panic in Slash Function

## Summary
The evidence module fails to validate that evidence height is not from the future before processing. When evidence with `infractionHeight > currentHeight` enters through BeginBlock, a logic flaw in the age validation allows it to pass, ultimately causing the staking module's Slash function to panic and halt the entire network.

## Impact
High

## Finding Description

**Location:**
- `x/evidence/keeper/infraction.go` lines 43-64 (flawed age validation logic) [1](#0-0) 

- `x/evidence/keeper/infraction.go` lines 95-112 (distribution height calculation leading to slash call) [2](#0-1) 

- `x/staking/keeper/slash.go` lines 67-71 (panic on future infraction height) [3](#0-2) 

**Intended Logic:**
The evidence module should validate and reject evidence from future block heights before processing. The staking module explicitly documents this requirement via CONTRACT at lines 14-23 of slash.go, stating: "Infraction was committed at the current height or at a past height, not at a height in the future". [4](#0-3) 

The application is designed to defensively handle potentially malformed input from Tendermint, as documented in the code comment at lines 29-40 of infraction.go. [5](#0-4) 

**Actual Logic:**
When `infractionHeight > currentHeight`, the calculation `ageBlocks := ctx.BlockHeader().Height - infractionHeight` produces a negative value. The validation uses AND logic: `ageDuration > MaxAgeDuration && ageBlocks > MaxAgeNumBlocks`. Since a negative `ageBlocks` can never be greater than a positive `MaxAgeNumBlocks`, the condition evaluates to false and the evidence incorrectly passes validation.

**Exploitation Path:**
1. Evidence with future height enters via BeginBlocker from Tendermint's ByzantineValidators [6](#0-5) 

2. Evidence is converted without height validation via FromABCIEvidence [7](#0-6) 

3. Age validation fails to reject due to negative ageBlocks never exceeding positive MaxAgeNumBlocks

4. distributionHeight is calculated as `infractionHeight - sdk.ValidatorUpdateDelay` (where ValidatorUpdateDelay = 1) [8](#0-7) 

5. If infractionHeight is future, distributionHeight remains future (e.g., 200 - 1 = 199)

6. The slashing keeper passes distributionHeight as infractionHeight to the staking keeper [9](#0-8) 

7. The staking keeper's Slash function panics when `infractionHeight > ctx.BlockHeight()`

8. Panic propagates through BeginBlock, crashing all nodes simultaneously

**Security Guarantee Broken:**
This violates the explicit CONTRACT requirement that infractions must be from current or past heights, and breaks the defensive validation design principle documented in the codebase. The panic during BeginBlock causes unrecoverable network failure.

## Impact Explanation

When future-height evidence is processed during BeginBlock, all network nodes executing that block will panic simultaneously, resulting in:
- **Complete network shutdown** - no new blocks can be produced
- All nodes crash during consensus execution
- Requires emergency intervention to restore operation
- No transactions can be confirmed during the outage
- Consensus is completely halted

This matches the specified High severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

While this requires evidence with future height to enter via Tendermint's consensus layer, the codebase explicitly demonstrates that defensive validation of Tendermint inputs is an expected design pattern. The application layer is designed to handle potentially malformed evidence from Tendermint and the simulator, as documented in the code comments.

**Triggering Conditions:**
- A bug in Tendermint's evidence detection/reporting logic
- Edge cases in evidence propagation through consensus
- Simulator-generated evidence (as mentioned in comments)

**Frequency:** While unlikely under normal operation, if triggered, the impact is immediate and affects 100% of network nodes. The existing test `TestSlashAtFutureHeight` confirms the panic behavior is enforced, demonstrating this is a real failure mode.

## Recommendation

Add explicit validation to reject future-height evidence before processing in `x/evidence/keeper/infraction.go`:

```go
// After line 44, add:
if infractionHeight > ctx.BlockHeader().Height {
    logger.Info(
        "ignored equivocation; evidence from future height",
        "validator", consAddr,
        "infraction_height", infractionHeight,
        "current_height", ctx.BlockHeader().Height,
    )
    return
}
```

Additionally, fix the age validation logic to properly handle negative values:

```go
// Replace line 53 with:
if ageBlocks < 0 || (ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks) {
```

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Setup:**
1. Initialize context at block height 100
2. Create validator with signing info
3. Set standard consensus parameters (MaxAgeNumBlocks = 100000, MaxAgeDuration = 172800s)

**Action:**
Create evidence with `Height = 200` (future) and `Time` in the past (to bypass time-based check), then call `HandleEquivocationEvidence`

**Result:**
The function panics with message: "impossible attempt to slash future infraction at height 199 but we are at height 100"

The scenario confirms:
- `ageBlocks = 100 - 200 = -100` (negative)
- Validation check `ageBlocks > MaxAgeNumBlocks` evaluates to `-100 > 100000` = false
- Evidence incorrectly proceeds to slashing logic
- `distributionHeight = 200 - 1 = 199` (still future)
- Slash function panics as evidenced by existing test `TestSlashAtFutureHeight`

## Notes

This vulnerability represents a defense-in-depth failure where the application layer must validate all external inputs from the consensus layer but fails to do so for future-height evidence. The codebase's own comments and CONTRACT specifications indicate this validation is required but missing. The severity is High because exploitation results in total network shutdown affecting all nodes simultaneously.

### Citations

**File:** x/evidence/keeper/infraction.go (L29-40)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
	}
```

**File:** x/evidence/keeper/infraction.go (L43-64)
```go
	infractionHeight := evidence.GetHeight()
	infractionTime := evidence.GetTime()
	ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
	ageBlocks := ctx.BlockHeader().Height - infractionHeight

	// Reject evidence if the double-sign is too old. Evidence is considered stale
	// if the difference in time and number of blocks is greater than the allowed
	// parameters defined.
	cp := ctx.ConsensusParams()
	if cp != nil && cp.Evidence != nil {
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
			logger.Info(
				"ignored equivocation; evidence too old",
				"validator", consAddr,
				"infraction_height", infractionHeight,
				"max_age_num_blocks", cp.Evidence.MaxAgeNumBlocks,
				"infraction_time", infractionTime,
				"max_age_duration", cp.Evidence.MaxAgeDuration,
			)
			return
		}
	}
```

**File:** x/evidence/keeper/infraction.go (L95-112)
```go
	// We need to retrieve the stake distribution which signed the block, so we
	// subtract ValidatorUpdateDelay from the evidence height.
	// Note, that this *can* result in a negative "distributionHeight", up to
	// -ValidatorUpdateDelay, i.e. at the end of the
	// pre-genesis block (none) = at the beginning of the genesis block.
	// That's fine since this is just used to filter unbonding delegations & redelegations.
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

**File:** x/staking/keeper/slash.go (L14-23)
```go
// CONTRACT:
//    slashFactor is non-negative
// CONTRACT:
//    Infraction was committed equal to or less than an unbonding period in the past,
//    so all unbonding delegations and redelegations from that height are stored
// CONTRACT:
//    Slash will not slash unbonded validators (for the above reason)
// CONTRACT:
//    Infraction was committed at the current height or at a past height,
//    not at a height in the future
```

**File:** x/staking/keeper/slash.go (L67-71)
```go
	case infractionHeight > ctx.BlockHeight():
		// Can't slash infractions in the future
		panic(fmt.Sprintf(
			"impossible attempt to slash future infraction at height %d but we are at height %d",
			infractionHeight, ctx.BlockHeight()))
```

**File:** x/evidence/abci.go (L16-30)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	for _, tmEvidence := range req.ByzantineValidators {
		switch tmEvidence.Type {
		// It's still ongoing discussion how should we treat and slash attacks with
		// premeditation. So for now we agree to treat them in the same way.
		case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
			evidence := types.FromABCIEvidence(tmEvidence)
			k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))

		default:
			k.Logger(ctx).Error(fmt.Sprintf("ignored unknown evidence type: %s", tmEvidence.Type))
		}
	}
```

**File:** x/evidence/types/evidence.go (L91-104)
```go
func FromABCIEvidence(e abci.Evidence) exported.Evidence {
	bech32PrefixConsAddr := sdk.GetConfig().GetBech32ConsensusAddrPrefix()
	consAddr, err := sdk.Bech32ifyAddressBytes(bech32PrefixConsAddr, e.Validator.Address)
	if err != nil {
		panic(err)
	}

	return &Equivocation{
		Height:           e.Height,
		Power:            e.Validator.Power,
		ConsensusAddress: consAddr,
		Time:             e.Time,
	}
}
```

**File:** types/staking.go (L17-26)
```go
	// Delay, in blocks, between when validator updates are returned to the
	// consensus-engine and when they are applied. For example, if
	// ValidatorUpdateDelay is set to X, and if a validator set update is
	// returned with new validators at the end of block 10, then the new
	// validators are expected to sign blocks beginning at block 11+X.
	//
	// This value is constant as this should not change without a hard fork.
	// For Tendermint this should be set to 1 block, for more details see:
	// https://tendermint.com/docs/spec/abci/apps.html#endblock
	ValidatorUpdateDelay int64 = 1
```

**File:** x/slashing/keeper/keeper.go (L66-79)
```go
// Slash attempts to slash a validator. The slash is delegated to the staking
// module to make the necessary validator changes.
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
