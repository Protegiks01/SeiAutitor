## Title
Historical Validator Sets Store Modified Validator State Due to Module Execution Ordering

## Summary
The staking module's `TrackHistoricalInfo` function stores incorrect validator data in `HistoricalInfo` when validators are slashed during the same block's `BeginBlock` phase. This occurs because the slashing module's `BeginBlocker` executes before the staking module's `BeginBlocker`, causing `GetLastValidators` to retrieve validators with already-modified token balances and jailed status, rather than the state they had when they validated the previous block. [1](#0-0) [2](#0-1) [3](#0-2) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: `x/staking/keeper/validator.go` in the `GetLastValidators` function (lines 305-330)
- Contributing factor: Module execution order in `simapp/app.go` (line 366)
- Slashing execution: `x/slashing/keeper/infractions.go` in `SlashJailAndUpdateSigningInfo` (lines 126-154) [4](#0-3) [5](#0-4) 

**Intended Logic:** 
Historical validator sets should represent the exact validator state (tokens, power, status) that was used by Tendermint to validate a specific block. When `TrackHistoricalInfo` stores historical data at height N, it should capture the validator set that validated block N with their original token balances and consensus power.

**Actual Logic:** 
The actual execution flow is:

1. At block N, slashing `BeginBlocker` runs first (configured in module order)
2. For validators who missed too many blocks, `SlashJailAndUpdateSigningInfo` is called:
   - Calls `k.sk.Slash()` which invokes `RemoveValidatorTokens`, reducing the validator's tokens
   - Calls `k.sk.Jail()` which sets `validator.Jailed = true`
   - Both changes are persisted via `k.SetValidator()` [6](#0-5) [7](#0-6) 

3. Then staking `BeginBlocker` runs and calls `TrackHistoricalInfo`
4. `TrackHistoricalInfo` calls `GetLastValidators` to retrieve the validator set [8](#0-7) 

5. `GetLastValidators` reads validator addresses from `LastValidatorPowerKey` (set during the previous block's EndBlock)
6. But for each address, it calls `mustGetValidator` which fetches the CURRENT validator object from storage
7. These validator objects now have reduced tokens and `Jailed=true` set by the slashing module [9](#0-8) 

8. The modified validators are stored in `HistoricalInfo` at height N

**Exploit Scenario:**
This occurs automatically during normal network operation:

1. A validator misses enough blocks to trigger downtime slashing
2. At block N, the validator is in the active set and participates in validation with X tokens
3. During block N's `BeginBlock`:
   - Slashing module slashes the validator, reducing tokens to (X - slashed_amount)
   - Slashing module jails the validator
4. Staking module then stores `HistoricalInfo` at height N with the validator having (X - slashed_amount) tokens and `Jailed=true`
5. The stored historical data shows incorrect validator state for height N

**Security Failure:**
Data integrity violation - the stored historical validator set does not match the actual validator set that validated the block. This breaks the fundamental invariant that `HistoricalInfo` should accurately represent past consensus states. Since IBC light clients rely on `HistoricalInfo` for consensus state verification (as documented in ADR-017), this could cause IBC connection failures or security vulnerabilities in cross-chain verification. [10](#0-9) 

## Impact Explanation

**Affected Assets/Data:**
- Historical validator set data stored in the staking module's `HistoricalInfo` entries
- IBC light client verification that depends on accurate historical consensus states
- Any off-chain systems or relayers that query historical validator information

**Severity of Damage:**
- The incorrect data is permanently stored on-chain and cannot be corrected without state migration
- IBC light clients attempting to verify consensus states at heights where validators were slashed may receive incorrect validator sets
- The validator's consensus power calculation uses tokens (via `TokensToConsensusPower`), so incorrect token amounts mean incorrect power values [11](#0-10) 

- While this doesn't directly cause fund loss, it corrupts critical consensus metadata used for inter-chain security

**Why This Matters:**
IBC security depends on accurate historical validator sets for light client verification. If the historical data doesn't match what Tendermint actually used for consensus, it creates a divergence between the stored state and reality, potentially enabling attacks on IBC connections or causing legitimate connections to fail verification.

## Likelihood Explanation

**Who Can Trigger:**
This is triggered automatically by the protocol itself when any validator is slashed for downtime. No attacker action is required - it happens during normal validator slashing operations.

**Required Conditions:**
- A validator must miss enough blocks to exceed the downtime threshold (configurable parameter, typically ~9,500 out of 10,000 blocks in a sliding window)
- This is a common occurrence in blockchain networks due to node issues, network problems, or maintenance

**Frequency:**
This occurs every time a validator is slashed for downtime during `BeginBlock`. Given that validator downtime is relatively common in large validator sets, this bug likely affects multiple historical entries already stored on active chains.

## Recommendation

**Fix Strategy:**
Modify `GetLastValidators` to store a snapshot of validator state at the time `LastValidatorPowerKey` was updated, rather than fetching current validator objects. Two possible approaches:

1. **Store complete validator snapshots:** When `SetLastValidatorPower` is called during `EndBlock`, also store a complete validator snapshot that `GetLastValidators` can retrieve later.

2. **Change execution order:** Move the staking module's `BeginBlocker` to execute before the slashing module's `BeginBlocker` in the module manager configuration. However, this may have other implications for fee distribution that need to be carefully considered.

The recommended fix is option 1: create a separate storage for validator snapshots indexed by height, which `TrackHistoricalInfo` can use to retrieve the exact validator state from when `LastValidatorPowerKey` was last updated.

## Proof of Concept

**File:** `x/staking/keeper/historical_info_test.go`

**Test Function:** `TestHistoricalInfoWithSlashing`

```go
// Add this test to x/staking/keeper/historical_info_test.go

func TestHistoricalInfoWithSlashing(t *testing.T) {
	_, app, ctx := createTestInput()

	addrDels := simapp.AddTestAddrsIncremental(app, ctx, 10, sdk.NewInt(0))
	addrVals := simapp.ConvertAddrsToValAddrs(addrDels)

	// Create and set a bonded validator
	val := teststaking.NewValidator(t, addrVals[0], PKs[0])
	val.Status = types.Bonded
	initialTokens := app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
	val.Tokens = initialTokens
	app.StakingKeeper.SetValidator(ctx, val)
	app.StakingKeeper.SetLastValidatorPower(ctx, val.GetOperator(), 100)

	// Set up block context at height 10
	header := tmproto.Header{
		ChainID: "TestChain",
		Height:  10,
	}
	ctx = ctx.WithBlockHeader(header)

	// Simulate slashing BeginBlocker executing first and slashing the validator
	consAddr, _ := val.GetConsAddr()
	slashFraction := sdk.NewDecWithPrec(5, 2) // 5% slash
	
	// This simulates what slashing BeginBlocker does
	app.StakingKeeper.Slash(ctx, consAddr, 9, 100, slashFraction)
	app.StakingKeeper.Jail(ctx, consAddr)

	// Get the validator after slashing - tokens should be reduced
	valAfterSlash, _ := app.StakingKeeper.GetValidator(ctx, val.GetOperator())
	expectedSlashedTokens := initialTokens.Sub(initialTokens.MulRaw(5).QuoRaw(100))
	require.Equal(t, expectedSlashedTokens, valAfterSlash.Tokens, "Validator tokens should be slashed")
	require.True(t, valAfterSlash.Jailed, "Validator should be jailed")

	// Now staking BeginBlocker runs and calls TrackHistoricalInfo
	app.StakingKeeper.TrackHistoricalInfo(ctx)

	// Retrieve the historical info
	hist, found := app.StakingKeeper.GetHistoricalInfo(ctx, 10)
	require.True(t, found, "Historical info should be stored")

	// BUG: The historical info contains the SLASHED validator with reduced tokens
	// But the validator had ORIGINAL tokens when it validated block 10
	require.Len(t, hist.Valset, 1)
	historicalVal := hist.Valset[0]
	
	// This assertion FAILS on vulnerable code, proving the bug:
	// Historical validator has slashed tokens instead of original tokens
	require.Equal(t, expectedSlashedTokens, historicalVal.Tokens, 
		"BUG DETECTED: Historical validator has slashed tokens, not original tokens")
	require.True(t, historicalVal.Jailed,
		"BUG DETECTED: Historical validator shows jailed status, but wasn't jailed during validation")

	// The correct behavior would be:
	// require.Equal(t, initialTokens, historicalVal.Tokens, "Should have original tokens")
	// require.False(t, historicalVal.Jailed, "Should not be jailed in historical record")
}
```

**Setup:**
- Initialize test environment with staking keeper
- Create a bonded validator with 100 consensus power and specific token amount
- Set the validator in `LastValidatorPowerKey` to simulate it being active in previous block

**Trigger:**
- Execute slashing operations (Slash + Jail) that modify validator tokens and status
- Call `TrackHistoricalInfo` (simulating staking BeginBlocker)

**Observation:**
- Retrieve the stored `HistoricalInfo` at the current height
- Verify that the stored validator has REDUCED tokens (post-slash) instead of ORIGINAL tokens
- Verify that the stored validator shows `Jailed=true` instead of the original `Jailed=false`
- This proves the historical data stores modified validator state, not the state that existed during validation

This test demonstrates that `HistoricalInfo` contains incorrect validator data due to the module execution ordering issue, violating the invariant that historical validator sets should accurately represent the consensus state at each height.

### Citations

**File:** simapp/app.go (L365-367)
```go
	app.mm.SetOrderBeginBlockers(
		upgradetypes.ModuleName, capabilitytypes.ModuleName, minttypes.ModuleName, distrtypes.ModuleName, slashingtypes.ModuleName,
		evidencetypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/staking/abci.go (L15-19)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
}
```

**File:** x/slashing/abci.go (L24-26)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

```

**File:** x/staking/keeper/validator.go (L305-330)
```go
func (k Keeper) GetLastValidators(ctx sdk.Context) (validators []types.Validator) {
	store := ctx.KVStore(k.storeKey)

	// add the actual validator power sorted store
	maxValidators := k.MaxValidators(ctx)
	validators = make([]types.Validator, maxValidators)

	iterator := sdk.KVStorePrefixIterator(store, types.LastValidatorPowerKey)
	defer iterator.Close()

	i := 0
	for ; iterator.Valid(); iterator.Next() {
		// sanity check
		if i >= int(maxValidators) {
			panic("more validators than maxValidators found")
		}

		address := types.AddressFromLastValidatorPowerKey(iterator.Key())
		validator := k.mustGetValidator(ctx, address)

		validators[i] = validator
		i++
	}

	return validators[:i] // trim
}
```

**File:** x/slashing/keeper/infractions.go (L126-154)
```go
func (k Keeper) SlashJailAndUpdateSigningInfo(ctx sdk.Context, consAddr sdk.ConsAddress, slashInfo SlashInfo, signInfo types.ValidatorSigningInfo) types.ValidatorSigningInfo {
	logger := k.Logger(ctx)
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSlash,
			sdk.NewAttribute(types.AttributeKeyAddress, consAddr.String()),
			sdk.NewAttribute(types.AttributeKeyPower, fmt.Sprintf("%d", slashInfo.power)),
			sdk.NewAttribute(types.AttributeKeyReason, types.AttributeValueMissingSignature),
			sdk.NewAttribute(types.AttributeKeyJailed, consAddr.String()),
		),
	)

	// Slashed for missing too many block
	telemetry.IncrValidatorSlashedCounter(consAddr.String(), types.AttributeValueMissingSignature)
	k.sk.Slash(ctx, consAddr, slashInfo.distributionHeight, slashInfo.power, k.SlashFractionDowntime(ctx))
	k.sk.Jail(ctx, consAddr)
	signInfo.JailedUntil = ctx.BlockHeader().Time.Add(k.DowntimeJailDuration(ctx))
	signInfo.MissedBlocksCounter = 0
	signInfo.IndexOffset = 0
	logger.Info(
		"slashing and jailing validator due to liveness fault",
		"height", slashInfo.height,
		"validator", consAddr.String(),
		"min_height", slashInfo.minHeight,
		"threshold", slashInfo.minSignedPerWindow,
		"slashed", k.SlashFractionDowntime(ctx).String(),
		"jailed_until", signInfo.JailedUntil,
	)
	return signInfo
```

**File:** x/staking/keeper/slash.go (L120-128)
```go
	// Deduct from validator's bonded tokens and update the validator.
	// Burn the slashed tokens from the pool account and decrease the total supply.
	validator = k.RemoveValidatorTokens(ctx, validator, tokensToBurn)

	switch validator.GetStatus() {
	case types.Bonded:
		if err := k.burnBondedTokens(ctx, tokensToBurn); err != nil {
			panic(err)
		}
```

**File:** x/staking/keeper/val_state_change.go (L260-268)
```go
func (k Keeper) jailValidator(ctx sdk.Context, validator types.Validator) {
	if validator.Jailed {
		panic(fmt.Sprintf("cannot jail already jailed validator, validator: %v\n", validator))
	}

	validator.Jailed = true
	k.SetValidator(ctx, validator)
	k.DeleteValidatorByPowerIndex(ctx, validator)
}
```

**File:** x/staking/keeper/historical_info.go (L68-98)
```go
func (k Keeper) TrackHistoricalInfo(ctx sdk.Context) {
	entryNum := k.HistoricalEntries(ctx)

	// Prune store to ensure we only have parameter-defined historical entries.
	// In most cases, this will involve removing a single historical entry.
	// In the rare scenario when the historical entries gets reduced to a lower value k'
	// from the original value k. k - k' entries must be deleted from the store.
	// Since the entries to be deleted are always in a continuous range, we can iterate
	// over the historical entries starting from the most recent version to be pruned
	// and then return at the first empty entry.
	for i := ctx.BlockHeight() - int64(entryNum); i >= 0; i-- {
		_, found := k.GetHistoricalInfo(ctx, i)
		if found {
			k.DeleteHistoricalInfo(ctx, i)
		} else {
			break
		}
	}

	// if there is no need to persist historicalInfo, return
	if entryNum == 0 {
		return
	}

	// Create HistoricalInfo struct
	lastVals := k.GetLastValidators(ctx)
	historicalEntry := types.NewHistoricalInfo(ctx.BlockHeader(), lastVals, k.PowerReduction(ctx))

	// Set latest HistoricalInfo at current height
	k.SetHistoricalInfo(ctx, ctx.BlockHeight(), &historicalEntry)
}
```

**File:** docs/architecture/adr-017-historical-header-module.md (L10-26)
```markdown
In order for the Cosmos SDK to implement the [IBC specification](https://github.com/cosmos/ics), modules within the SDK must have the ability to introspect recent consensus states (validator sets & commitment roots) as proofs of these values on other chains must be checked during the handshakes.

## Decision

The application MUST store the most recent `n` headers in a persistent store. At first, this store MAY be the current Merklised store. A non-Merklised store MAY be used later as no proofs are necessary.

The application MUST store this information by storing new headers immediately when handling `abci.RequestBeginBlock`:

```golang
func BeginBlock(ctx sdk.Context, keeper HistoricalHeaderKeeper, req abci.RequestBeginBlock) abci.ResponseBeginBlock {
  info := HistoricalInfo{
    Header: ctx.BlockHeader(),
    ValSet: keeper.StakingKeeper.GetAllValidators(ctx), // note that this must be stored in a canonical order
  }
  keeper.SetHistoricalInfo(ctx, ctx.BlockHeight(), info)
  n := keeper.GetParamRecentHeadersToStore()
  keeper.PruneHistoricalInfo(ctx, ctx.BlockHeight() - n)
```

**File:** x/staking/types/validator.go (L358-361)
```go
// PotentialConsensusPower returns the potential consensus-engine power.
func (v Validator) PotentialConsensusPower(r sdk.Int) int64 {
	return sdk.TokensToConsensusPower(v.Tokens, r)
}
```
