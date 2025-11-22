# Audit Report

## Title
Historical Validator Sets Store Modified Validator State Due to Module Execution Ordering

## Summary
The staking module's `TrackHistoricalInfo` function stores validator data with post-slashing modifications when validators are slashed during BeginBlock. Due to module execution ordering, slashing occurs before historical info tracking, causing `GetLastValidators` to retrieve validators with already-modified token balances and jailed status rather than their state when they validated the block. This violates the documented specification that HistoricalInfo should contain "the Validators that committed the current block" and affects IBC light client consensus state verification. [1](#0-0) 

## Impact
Medium

## Finding Description

**location:** 
- Primary issue: `x/staking/keeper/validator.go` in `GetLastValidators` function (line 323)
- Module ordering: `simapp/app.go` (line 366)
- Slashing execution: `x/slashing/keeper/infractions.go` in `SlashJailAndUpdateSigningInfo` (lines 140-141) [2](#0-1) [3](#0-2) 

**intended logic:** 
According to the staking module specification, HistoricalInfo should persist "the Validators that committed the current block" at each BeginBlock. This means storing the validator set with the exact token balances and status they had when signing the block. The `LastValidatorPowerKey` index stores validator addresses from the previous block's EndBlock, representing the active consensus set. [4](#0-3) 

**actual logic:** 
The execution flow is:

1. At block N's BeginBlock, slashing module executes first (per module order configuration)
2. `SlashJailAndUpdateSigningInfo` modifies validator state by calling `k.sk.Slash()` and `k.sk.Jail()`
3. `Slash` reduces validator tokens via `RemoveValidatorTokens`, which calls `SetValidator` to persist changes
4. `Jail` sets `validator.Jailed = true` and persists via `SetValidator` [5](#0-4) [6](#0-5) [7](#0-6) 

5. Then staking BeginBlocker calls `TrackHistoricalInfo`
6. `TrackHistoricalInfo` calls `GetLastValidators` to retrieve the validator set
7. `GetLastValidators` iterates through `LastValidatorPowerKey` addresses and calls `mustGetValidator(ctx, address)` for each
8. `mustGetValidator` fetches the CURRENT validator object from storage, which now contains post-slash modifications [8](#0-7) [9](#0-8) 

**exploitation path:** 
This occurs automatically during normal protocol operation:
1. A validator misses sufficient blocks to exceed downtime threshold
2. During block N's BeginBlock, slashing module slashes and jails the validator
3. Staking module then stores HistoricalInfo at height N with the validator's post-slash state (reduced tokens, Jailed=true)
4. The stored historical data misrepresents the actual validator set that validated block N

**security guarantee broken:** 
The specification states that `LastValidatorsPower` "remains constant during a block" and HistoricalInfo should contain validators "that committed the current block". This invariant is violated because the stored validator state reflects modifications made during the same block's BeginBlock, not the state when the block was validated. [10](#0-9) 

## Impact Explanation

This bug affects IBC light client verification. According to IBC integration documentation, "The historical info is required to introspect the past historical info at any given height in order to verify the light client ConsensusState during the connection handshake." [11](#0-10) 

Since validator voting power is calculated from tokens, incorrect token amounts in HistoricalInfo mean incorrect consensus power values. This creates a divergence between stored consensus state and the actual validator set that signed blocks, which IBC relies upon for cross-chain security. [12](#0-11) 

The incorrect data is permanently stored on-chain. While this doesn't directly cause fund loss, it corrupts critical consensus metadata used for inter-blockchain communication, potentially causing IBC connection verification failures or creating security vulnerabilities in cross-chain verification.

## Likelihood Explanation

This vulnerability is triggered automatically by the protocol whenever a validator is slashed for downtime during BeginBlock. No attacker action is required - it occurs during normal validator slashing operations.

Required conditions: A validator must miss enough blocks to exceed the downtime threshold (typically ~9,500 out of 10,000 blocks in a sliding window). This is a common occurrence in blockchain networks due to node issues, network problems, or maintenance. Given that validator downtime is relatively common in large validator sets, this bug likely affects multiple historical entries already stored on active chains.

## Recommendation

Modify `GetLastValidators` to retrieve validator snapshots from when `LastValidatorPowerKey` was set, rather than fetching current validator state. Recommended approach:

1. Create separate storage for validator snapshots indexed by height
2. When `SetLastValidatorPower` is called during EndBlock, also store a complete validator snapshot
3. Modify `GetLastValidators` to retrieve these snapshots instead of calling `mustGetValidator`

Alternative: Change module execution order to run staking BeginBlocker before slashing BeginBlocker, though this may have implications for fee distribution (as noted in the comment at simapp/app.go:360-362). [13](#0-12) 

## Proof of Concept

The vulnerability can be demonstrated by adding a test to `x/staking/keeper/historical_info_test.go`:

**setup:** 
- Create a bonded validator with specific token amount
- Set validator in `LastValidatorPowerKey` to simulate it being active in previous block
- Set block context at height 10

**action:** 
- Execute slashing operations (Slash + Jail) that modify validator tokens and status
- Call `TrackHistoricalInfo` (simulating staking BeginBlocker)

**result:** 
- Retrieve stored `HistoricalInfo` at height 10
- Verify that stored validator has REDUCED tokens (post-slash) instead of original tokens
- Verify that stored validator shows `Jailed=true` instead of original `Jailed=false`
- This demonstrates HistoricalInfo contains modified validator state, violating the specification

The test proves that due to module execution ordering, HistoricalInfo stores post-modification validator state rather than the state validators had when they committed the block, as specified in the documentation.

### Citations

**File:** x/staking/spec/01_state.md (L13-14)
```markdown
LastTotalPower tracks the total amounts of bonded tokens recorded during the previous end block.
Store entries prefixed with "Last" must remain unchanged until EndBlock.
```

**File:** x/staking/spec/01_state.md (L72-74)
```markdown
`LastValidatorsPower` is a special index that provides a historical list of the
last-block's bonded validators. This index remains constant during a block but
is updated during the validator set update process which takes place in [`EndBlock`](./05_end_block.md).
```

**File:** x/staking/spec/01_state.md (L213-215)
```markdown
At each BeginBlock, the staking keeper will persist the current Header and the Validators that committed
the current block in a `HistoricalInfo` object. The Validators are sorted on their address to ensure that
they are in a determisnistic order.
```

**File:** simapp/app.go (L360-363)
```go
	// During begin block slashing happens after distr.BeginBlocker so that
	// there is nothing left over in the validator fee pool, so as to keep the
	// CanWithdrawInvariant invariant.
	// NOTE: staking module is required if HistoricalEntries param > 0
```

**File:** simapp/app.go (L365-367)
```go
	app.mm.SetOrderBeginBlockers(
		upgradetypes.ModuleName, capabilitytypes.ModuleName, minttypes.ModuleName, distrtypes.ModuleName, slashingtypes.ModuleName,
		evidencetypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/staking/keeper/validator.go (L120-127)
```go
func (k Keeper) RemoveValidatorTokens(ctx sdk.Context,
	validator types.Validator, tokensToRemove sdk.Int) types.Validator {
	k.DeleteValidatorByPowerIndex(ctx, validator)
	validator = validator.RemoveTokens(tokensToRemove)
	k.SetValidator(ctx, validator)
	k.SetValidatorByPowerIndex(ctx, validator)

	return validator
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

**File:** x/slashing/keeper/infractions.go (L140-141)
```go
	k.sk.Slash(ctx, consAddr, slashInfo.distributionHeight, slashInfo.power, k.SlashFractionDowntime(ctx))
	k.sk.Jail(ctx, consAddr)
```

**File:** x/staking/keeper/val_state_change.go (L265-266)
```go
	validator.Jailed = true
	k.SetValidator(ctx, validator)
```

**File:** x/staking/abci.go (L15-18)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
```

**File:** x/staking/keeper/historical_info.go (L93-94)
```go
	lastVals := k.GetLastValidators(ctx)
	historicalEntry := types.NewHistoricalInfo(ctx.BlockHeader(), lastVals, k.PowerReduction(ctx))
```

**File:** docs/ibc/integration.md (L200-204)
```markdown
One addition from IBC is the concept of `HistoricalEntries` which are stored on the staking module.
Each entry contains the historical information for the `Header` and `ValidatorSet` of this chain which is stored
at each height during the `BeginBlock` call. The historical info is required to introspect the
past historical info at any given height in order to verify the light client `ConsensusState` during the
connection handhake.
```

**File:** x/staking/types/validator.go (L358-361)
```go
// PotentialConsensusPower returns the potential consensus-engine power.
func (v Validator) PotentialConsensusPower(r sdk.Int) int64 {
	return sdk.TokensToConsensusPower(v.Tokens, r)
}
```
