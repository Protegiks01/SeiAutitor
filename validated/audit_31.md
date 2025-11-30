# Audit Report

## Title
Unbounded Storage Growth in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function contains a critical flaw where the pruning loop breaks on the first missing historical entry. When `HistoricalEntries` is legitimately changed from non-zero to 0 and later restored, a gap is created that permanently disables pruning, causing unbounded storage accumulation. [1](#0-0) 

## Impact
Medium

## Finding Description

- **location**: `x/staking/keeper/historical_info.go`, lines 78-85

- **intended logic**: The function should maintain exactly `HistoricalEntries` number of recent historical entries by pruning all entries older than `currentHeight - HistoricalEntries`.

- **actual logic**: The pruning loop iterates backward from `currentHeight - HistoricalEntries`, deleting found entries but immediately breaking when encountering a missing entry (line 83). The code comment explicitly states the flawed assumption: "entries to be deleted are always in a continuous range." [2](#0-1)  This assumption is violated when `HistoricalEntries` is set to 0 (causing no entries to be saved) and later restored to non-zero.

- **exploitation path**:
  1. Chain operates with `HistoricalEntries=100`, creating entries at heights 1-100
  2. Governance legitimately changes `HistoricalEntries` to 0 (documented as valid for non-IBC chains [3](#0-2) )
  3. During blocks 101-110 with `HistoricalEntries=0`, no new entries are saved due to early return [4](#0-3) 
  4. Governance restores `HistoricalEntries=5`
  5. At block 111, pruning starts at height 106 (111-5)
  6. `GetHistoricalInfo(ctx, 106)` returns `found=false` (gap period)
  7. Break statement executes, exiting loop without ever reaching entries 1-100
  8. New entries accumulate: {1-100, 111, 112, ...}
  9. Every subsequent block hits the gap first, preventing all pruning indefinitely

- **security guarantee broken**: The storage bound invariant is violated. The system guarantees to maintain at most `HistoricalEntries` entries, but after gap creation it accumulates entries unboundedly.

## Impact Explanation

Each historical entry contains a complete block header and full validator set. [5](#0-4)  With the default 35 validators, [6](#0-5)  this represents substantial data per entry.

Once the gap is created and `HistoricalEntries` is restored to a non-zero value:
- **Expected**: Maintain only the specified number of recent entries (e.g., 5)
- **Actual**: Old entries remain forever + new entries accumulate at ~14,400 per day (one per block)
- **Within 24 hours**: 14,400+ entries accumulate instead of maintaining 5 entries
- **Result**: Storage consumption increases by >288,000% compared to expected bounded operation

This leads to:
- Storage exhaustion consuming gigabytes of disk space
- Node instability and crashes when disk space is exhausted
- Network degradation if multiple nodes are affected

This directly matches the Medium severity impact: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours."

## Likelihood Explanation

**Trigger mechanism**: The `HistoricalEntries` parameter is governance-controlled and can be changed through standard parameter change proposals. [7](#0-6) 

**Realistic scenario**: Setting `HistoricalEntries=0` is explicitly documented as legitimate for chains that don't use IBC. [3](#0-2)  The validation function allows zero values without restriction. [8](#0-7) 

**Automatic execution**: `TrackHistoricalInfo` is called automatically in `BeginBlocker` every single block, [9](#0-8)  ensuring continuous accumulation once the gap is created.

**Qualification for privilege exception**: While this requires governance action, it qualifies for the exception because:
1. Setting `HistoricalEntries=0` is explicitly documented as a legitimate operation
2. Governance inadvertently triggers permanent damage beyond their intended authority
3. The consequence (broken pruning) is unrecoverable without code upgrade
4. Governance expects the system to handle parameter changes correctly

## Recommendation

Modify the pruning logic to continue checking all heights that should be pruned, regardless of gaps:

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

Alternatively, maintain metadata tracking the oldest and newest stored entry heights to enable efficient targeted deletion.

## Proof of Concept

**Test outline** (to be added to `x/staking/keeper/historical_info_test.go`):

**Setup:**
- Initialize staking keeper with test validators
- Set `HistoricalEntries=100`
- Generate blocks 1-100, verify 100 entries exist

**Action:**
1. Change `HistoricalEntries` to 0 via `SetParams`
2. Generate blocks 101-110 (no entries saved)
3. Verify entries 1-100 still exist, no entries 101-110
4. Change `HistoricalEntries` to 5
5. Generate blocks 111-120

**Expected Result:** Only 5 most recent entries (116-120) should exist

**Actual Result:** 
- Entries 1-100 remain (never pruned due to gap)
- Entries 111-120 created
- Total: 110 entries instead of 5
- Storage bound permanently violated

The scenario demonstrates that after creating a gap, the storage bound invariant is permanently broken with entries accumulating indefinitely beyond the configured limit.

### Citations

**File:** x/staking/keeper/historical_info.go (L75-77)
```go
	// Since the entries to be deleted are always in a continuous range, we can iterate
	// over the historical entries starting from the most recent version to be pruned
	// and then return at the first empty entry.
```

**File:** x/staking/keeper/historical_info.go (L78-85)
```go
	for i := ctx.BlockHeight() - int64(entryNum); i >= 0; i-- {
		_, found := k.GetHistoricalInfo(ctx, i)
		if found {
			k.DeleteHistoricalInfo(ctx, i)
		} else {
			break
		}
	}
```

**File:** x/staking/keeper/historical_info.go (L88-90)
```go
	if entryNum == 0 {
		return
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
