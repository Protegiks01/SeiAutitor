# Audit Report

## Title
Historical Validator Sets Store Modified Validator State Due to Module Execution Ordering

## Summary
The staking module's `TrackHistoricalInfo` function stores validator data with post-slashing modifications when validators are slashed during BeginBlock. Due to module execution ordering where slashing executes before staking, `GetLastValidators` retrieves validators with already-modified token balances and jailed status rather than their state when they validated the block, violating the specification and corrupting IBC light client verification data.

## Impact
Medium

## Finding Description

**location:**
- Primary issue: `x/staking/keeper/validator.go` in `GetLastValidators` function [1](#0-0) 

- Module execution ordering: `simapp/app.go` [2](#0-1) 

- Slashing execution: `x/slashing/keeper/infractions.go` and `x/slashing/abci.go` [3](#0-2) [4](#0-3) 

**intended logic:**
According to the staking module specification, HistoricalInfo should persist "the Validators that committed the current block" at each BeginBlock with their exact token balances and status when signing the block: [5](#0-4) 

The specification also states that `LastValidatorsPower` "remains constant during a block": [6](#0-5) 

The `LastValidatorPowerKey` is set during EndBlock via `ApplyAndReturnValidatorSetUpdates`: [7](#0-6) 

**actual logic:**
The execution flow violates this specification:

1. Block N-1's EndBlock sets `LastValidatorPowerKey` entries for active validators via `SetLastValidatorPower`

2. Block N's BeginBlock executes modules in configured order, with slashing before staking: [8](#0-7) 

3. Slashing BeginBlocker calls `SlashJailAndUpdateSigningInfo` which modifies validator state:
   - `Slash()` reduces tokens via `RemoveValidatorTokens` → `SetValidator`: [9](#0-8) [10](#0-9) 
   
   - `Jail()` sets `validator.Jailed = true` via `SetValidator`: [11](#0-10) [12](#0-11) 

4. Staking BeginBlocker then calls `TrackHistoricalInfo`: [13](#0-12) 

5. `TrackHistoricalInfo` calls `GetLastValidators`: [14](#0-13) 

6. `GetLastValidators` iterates `LastValidatorPowerKey` addresses and calls `mustGetValidator(ctx, address)` for each, which fetches the CURRENT validator object from storage: [15](#0-14) [16](#0-15) 

7. The fetched validators now contain post-slash modifications (reduced tokens, Jailed=true)

**exploitation path:**
This occurs automatically during normal protocol operation:
1. A validator misses sufficient blocks to exceed the downtime threshold
2. During block N's BeginBlock, slashing module executes first and slashes/jails the validator
3. Validator state is modified in storage (reduced tokens, Jailed=true)
4. Staking module then executes and stores HistoricalInfo at height N
5. The stored HistoricalInfo contains the validator's post-slash state, not their state when they validated block N

**security guarantee broken:**
The specification guarantees that HistoricalInfo contains "the Validators that committed the current block" with state that "remains constant during a block". This invariant is violated because stored validator state reflects BeginBlock modifications rather than the actual state when the block was validated.

## Impact Explanation

This bug corrupts critical consensus metadata used for IBC light client verification. According to IBC integration documentation: [17](#0-16) 

Since validator voting power is calculated from token amounts: [18](#0-17) 

Incorrect token amounts in HistoricalInfo mean incorrect consensus power values. This creates a divergence between the stored consensus state and the actual validator set that signed blocks, which IBC relies upon for cross-chain security verification during connection handshakes.

The incorrect data is permanently stored on-chain. While this doesn't directly cause fund loss, it corrupts critical consensus metadata used for inter-blockchain communication, potentially causing IBC connection verification failures or creating security vulnerabilities in cross-chain verification processes.

## Likelihood Explanation

This vulnerability is triggered automatically by the protocol whenever a validator is slashed for downtime during BeginBlock. No attacker action is required - it occurs during normal validator slashing operations.

Required conditions: A validator must miss enough blocks to exceed the downtime threshold (typically ~9,500 out of 10,000 blocks in a sliding window). This is a common occurrence in blockchain networks due to node issues, network problems, or maintenance activities. Given that validator downtime is relatively common in large validator sets, this bug likely affects multiple historical entries already stored on active chains running this codebase.

## Recommendation

Modify `GetLastValidators` to retrieve validator snapshots from when `LastValidatorPowerKey` was set, rather than fetching current validator state. Recommended approach:

1. Create separate storage for validator snapshots indexed by height
2. When `SetLastValidatorPower` is called during EndBlock, also store a complete validator snapshot at that moment
3. Modify `GetLastValidators` to retrieve these immutable snapshots instead of calling `mustGetValidator` which fetches mutable current state

Alternative approach: Change module execution order to run staking BeginBlocker before slashing BeginBlocker, though this may have implications for the fee distribution invariant as noted in the code comments.

## Proof of Concept

The vulnerability can be demonstrated by adding a test to `x/staking/keeper/historical_info_test.go`:

**setup:**
- Create a bonded validator with specific token amount (e.g., 1000 tokens)
- Call `SetValidator` to persist the validator
- Call `SetLastValidatorPower` to simulate it being active in the previous block
- Set block context at height 10

**action:**
- Call `Slash` to reduce validator tokens (e.g., by 10%)
- Call `Jail` to set validator.Jailed = true
- Call `TrackHistoricalInfo` (simulating staking BeginBlocker execution)

**result:**
- Retrieve stored `HistoricalInfo` at height 10 using `GetHistoricalInfo`
- Assert that the stored validator has REDUCED tokens (e.g., 900 instead of 1000)
- Assert that the stored validator shows `Jailed=true` instead of `Jailed=false`
- This demonstrates that HistoricalInfo contains post-modification validator state, violating the specification that it should contain the state of validators "that committed the current block"

The test proves that due to module execution ordering and the implementation of `GetLastValidators` fetching current state, HistoricalInfo stores post-slashing validator state rather than the original state validators had when they validated the block.

## Notes

This is a Medium severity vulnerability according to the category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." The bug exists in core Cosmos SDK code (layer 0/1), produces unintended behavior (corrupted HistoricalInfo), and while there are no direct funds at immediate risk, it compromises IBC light client verification which is a critical cross-chain security mechanism.

### Citations

**File:** x/staking/keeper/validator.go (L14-24)
```go
func (k Keeper) GetValidator(ctx sdk.Context, addr sdk.ValAddress) (validator types.Validator, found bool) {
	store := ctx.KVStore(k.storeKey)

	value := store.Get(types.GetValidatorKey(addr))
	if value == nil {
		return validator, false
	}

	validator = types.MustUnmarshalValidator(k.cdc, value)
	return validator, true
}
```

**File:** x/staking/keeper/validator.go (L26-32)
```go
func (k Keeper) mustGetValidator(ctx sdk.Context, addr sdk.ValAddress) types.Validator {
	validator, found := k.GetValidator(ctx, addr)
	if !found {
		panic(fmt.Sprintf("validator record not found for address: %X\n", addr))
	}

	return validator
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

**File:** simapp/app.go (L360-367)
```go
	// During begin block slashing happens after distr.BeginBlocker so that
	// there is nothing left over in the validator fee pool, so as to keep the
	// CanWithdrawInvariant invariant.
	// NOTE: staking module is required if HistoricalEntries param > 0
	// NOTE: capability module's beginblocker must come before any modules using capabilities (e.g. IBC)
	app.mm.SetOrderBeginBlockers(
		upgradetypes.ModuleName, capabilitytypes.ModuleName, minttypes.ModuleName, distrtypes.ModuleName, slashingtypes.ModuleName,
		evidencetypes.ModuleName, stakingtypes.ModuleName,
```

**File:** x/slashing/keeper/infractions.go (L140-141)
```go
	k.sk.Slash(ctx, consAddr, slashInfo.distributionHeight, slashInfo.power, k.SlashFractionDowntime(ctx))
	k.sk.Jail(ctx, consAddr)
```

**File:** x/slashing/abci.go (L58-61)
```go
		if writeInfo.ShouldSlash {
			k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
			writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
		} else {
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

**File:** x/staking/keeper/val_state_change.go (L176-176)
```go
			k.SetLastValidatorPower(ctx, valAddr, newPower)
```

**File:** x/staking/keeper/val_state_change.go (L265-266)
```go
	validator.Jailed = true
	k.SetValidator(ctx, validator)
```

**File:** x/staking/keeper/slash.go (L122-122)
```go
	validator = k.RemoveValidatorTokens(ctx, validator, tokensToBurn)
```

**File:** x/staking/keeper/slash.go (L146-148)
```go
func (k Keeper) Jail(ctx sdk.Context, consAddr sdk.ConsAddress) {
	validator := k.mustGetValidatorByConsAddr(ctx, consAddr)
	k.jailValidator(ctx, validator)
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
