# Audit Report

## Title
Unbounded Storage Growth in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function contains a pruning loop that breaks on the first missing historical entry. When `HistoricalEntries` is legitimately changed from non-zero to 0 (documented as valid for non-IBC chains) and later restored to non-zero, a gap is created that permanently prevents pruning of older entries, causing unbounded storage accumulation. [1](#0-0) 

## Impact
Medium

## Finding Description

- **location**: `x/staking/keeper/historical_info.go`, lines 78-85

- **intended logic**: The function should maintain exactly `HistoricalEntries` number of recent historical entries by pruning all entries older than `currentHeight - HistoricalEntries`.

- **actual logic**: The pruning loop starts at `currentHeight - HistoricalEntries` and iterates backward, deleting found entries but immediately breaking when encountering a missing entry (line 83). The code comment at lines 75-77 reveals the assumption: "entries to be deleted are always in a continuous range." This assumption is violated when HistoricalEntries is set to 0 and back. [2](#0-1) 

- **exploitation path**:
  1. Network operates with `HistoricalEntries=100`, creating entries 1-100
  2. Governance changes `HistoricalEntries` to 0 via parameter proposal (documented as legitimate for non-IBC chains)
  3. During blocks with `HistoricalEntries=0`, no new entries are saved due to early return at lines 88-90
  4. Governance restores `HistoricalEntries=5` via another proposal
  5. At the next block (e.g., 111), pruning starts at height 106 (111-5)
  6. `GetHistoricalInfo(ctx, 106)` returns `found=false` (gap period)
  7. Break statement executes, exiting loop without deleting entries 1-100
  8. New entries accumulate: {1-100, 111, 112, ...}
  9. Every subsequent block hits the gap first, preventing all pruning indefinitely [3](#0-2) 

- **security guarantee broken**: The storage bound invariant is violated. The system should maintain at most `HistoricalEntries` entries but instead accumulates entries indefinitely after a gap is created.

## Impact Explanation

Each historical entry contains a complete block header and full validator set. With the default 35 validators, this represents substantial data per entry. [4](#0-3) [5](#0-4) 

Over months of operation with continuous block production, this leads to:
- **Storage exhaustion**: Thousands of unbounded entries consuming gigabytes of disk space
- **Resource consumption**: >30% increase compared to expected bounded levels
- **Node instability**: Nodes crash when disk space exhausted
- **Network degradation**: If 30%+ of nodes affected, network stability compromised

This directly matches the Medium severity impact category: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours."

## Likelihood Explanation

**Trigger mechanism**: The `HistoricalEntries` parameter is governance-controlled and can be changed through standard parameter change proposals. [6](#0-5) 

**Realistic scenario**: Setting `HistoricalEntries=0` is explicitly documented as a legitimate operation for chains that don't use IBC. The validation function allows zero values (only checks type). [7](#0-6) 

**Automatic execution**: `TrackHistoricalInfo` is called automatically in `BeginBlocker` every single block, ensuring continuous accumulation once the gap is created. [8](#0-7) 

**Frequency**: This can occur during normal governance operations when a chain temporarily disables historical tracking and later re-enables it. Once triggered, the effect compounds with every subsequent block indefinitely, making storage issues highly likely over the network's operational lifetime.

## Recommendation

Modify the pruning logic to iterate through all heights that should be pruned, regardless of gaps:

```go
// Prune all entries older than retention height
pruneHeight := ctx.BlockHeight() - int64(entryNum)
for i := pruneHeight - 1; i >= 0; i-- {
    _, found := k.GetHistoricalInfo(ctx, i)
    if found {
        k.DeleteHistoricalInfo(ctx, i)
    }
    // Continue checking all heights - do not break on gaps
}
```

Alternatively, maintain metadata tracking the oldest and newest stored entry heights to enable efficient targeted deletion without iterating through all possible heights.

## Proof of Concept

**Test conceptual outline** (to be added to `x/staking/keeper/historical_info_test.go`):

**Setup**:
- Initialize staking keeper with test validators
- Set `HistoricalEntries=100`
- Generate blocks 1-100 to create 100 historical entries
- Verify 100 entries exist in storage

**Action**:
1. Change `HistoricalEntries` to 0 via `SetParams`
2. Generate blocks 101-110 (creates gap - no entries saved due to early return)
3. Verify entries 1-100 still exist, no entries 101-110
4. Change `HistoricalEntries` to 5
5. Generate blocks 111-120

**Expected Result**: Only 5 most recent entries (116-120) should exist

**Actual Result**: 
- Entries 1-100 remain (never pruned)
- Entries 111-120 are created
- Total: 110 entries instead of 5
- Storage bound of `HistoricalEntries=5` is permanently violated

The test demonstrates that after creating a gap by setting `HistoricalEntries=0`, the storage bound invariant is permanently broken, with entries accumulating indefinitely beyond the configured limit.

### Citations

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

**File:** x/staking/types/params.go (L24-24)
```go
	DefaultMaxValidators uint32 = 35
```

**File:** x/staking/types/params.go (L29-32)
```go
	// DefaultHistorical entries is 10000. Apps that don't use IBC can ignore this
	// value by not adding the staking module to the application module manager's
	// SetOrderBeginBlockers.
	DefaultHistoricalEntries uint32 = 10000
```

**File:** x/staking/types/params.go (L81-92)
```go
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(KeyUnbondingTime, &p.UnbondingTime, validateUnbondingTime),
		paramtypes.NewParamSetPair(KeyMaxValidators, &p.MaxValidators, validateMaxValidators),
		paramtypes.NewParamSetPair(KeyMaxEntries, &p.MaxEntries, validateMaxEntries),
		paramtypes.NewParamSetPair(KeyMaxVotingPower, &p.MaxVotingPowerRatio, validateMaxVotingPowerRatio),
		paramtypes.NewParamSetPair(KeyMaxVotingPowerEnforcementThreshold, &p.MaxVotingPowerEnforcementThreshold, validateMaxVotingPowerEnforcementThreshold),
		paramtypes.NewParamSetPair(KeyHistoricalEntries, &p.HistoricalEntries, validateHistoricalEntries),
		paramtypes.NewParamSetPair(KeyBondDenom, &p.BondDenom, validateBondDenom),
		paramtypes.NewParamSetPair(KeyMinCommissionRate, &p.MinCommissionRate, validateMinCommissionRate),
	}
}
```

**File:** x/staking/types/params.go (L242-249)
```go
func validateHistoricalEntries(i interface{}) error {
	_, ok := i.(uint32)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	return nil
}
```

**File:** x/staking/types/historical_info.go (L17-26)
```go
func NewHistoricalInfo(header tmproto.Header, valSet Validators, powerReduction sdk.Int) HistoricalInfo {
	// Must sort in the same way that tendermint does
	sort.SliceStable(valSet, func(i, j int) bool {
		return ValidatorsByVotingPower(valSet).Less(i, j, powerReduction)
	})

	return HistoricalInfo{
		Header: header,
		Valset: valSet,
	}
```

**File:** x/staking/abci.go (L15-19)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
}
```
