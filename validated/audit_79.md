# Audit Report

## Title
Unbounded Storage Growth in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function in the staking module contains a critical logic flaw in its pruning mechanism. The function uses a break statement that exits the pruning loop upon encountering the first missing historical entry, violating the storage bound invariant when gaps exist in the historical entry sequence. [1](#0-0) 

## Impact
Medium

## Finding Description

- **Location**: `x/staking/keeper/historical_info.go`, lines 78-85 in the `TrackHistoricalInfo` function, specifically the pruning loop with the break condition

- **Intended Logic**: The function should maintain exactly `HistoricalEntries` number of recent historical info entries by pruning all entries older than `currentHeight - HistoricalEntries`. The storage should be bounded to prevent resource exhaustion.

- **Actual Logic**: The pruning loop iterates downward from `currentHeight - HistoricalEntries` and breaks immediately upon encountering the first missing entry (line 83). [1](#0-0)  The code comment incorrectly assumes "the entries to be deleted are always in a continuous range" (line 75), but this assumption is violated when `HistoricalEntries` is changed from non-zero to 0 and back. [2](#0-1) 

- **Exploitation Path**:
  1. Network operates normally with `HistoricalEntries=100`, accumulating 100 historical entries (blocks 1-100)
  2. Through governance proposal, `HistoricalEntries` is changed to 0 for blocks 101-110
  3. During this period, no new entries are saved (early return when `entryNum == 0` at line 88), but existing entries 1-100 remain in storage [3](#0-2) 
  4. Through another governance proposal, `HistoricalEntries` is changed to 5 at block 111
  5. The pruning loop starts at height 106 (111-5), finds no entry (gap period), immediately breaks
  6. Old entries 1-100 are never deleted, new entry 111 is saved
  7. Each subsequent block adds a new entry without deleting old ones
  8. Storage grows unboundedly: {1-100, 111, 112, 113, ...}

- **Security Guarantee Broken**: The storage bound invariant is violated. The system should maintain exactly `HistoricalEntries` entries, but instead accumulates entries without bound, causing resource exhaustion.

## Impact Explanation

Each `HistoricalInfo` entry contains a complete block header and full validator set. [4](#0-3)  With the default 35 validators [5](#0-4) , each entry represents substantial data (multiple kilobytes).

After the vulnerability is triggered:
- Expected storage with `HistoricalEntries=5`: ~5 entries
- Actual storage: 100 old entries + continuously growing new entries (8,640+ per day assuming 10-second blocks)
- Within 24 hours: increases from 100 to 8,740+ entries = 87x increase (8,640% increase)
- This clearly exceeds the 30% threshold for Medium severity resource consumption impact

Over time, this leads to:
- **Storage exhaustion**: Thousands of entries accumulate, consuming gigabytes of disk space
- **Node crashes**: When disk space is exhausted, nodes fail to write new blocks
- **Network degradation**: If sufficient nodes run out of storage, network stability is compromised

## Likelihood Explanation

**Who can trigger**: Any network participant through the standard governance process. The `HistoricalEntries` parameter is governance-controlled and can be modified via parameter change proposals. [6](#0-5) 

**Conditions required**:
1. A governance proposal changes `HistoricalEntries` from non-zero to 0
2. After several blocks, another proposal changes it back to a non-zero value

**Why realistic**:
- The validation function explicitly allows `HistoricalEntries=0` as valid (only checks type, not value) [7](#0-6) 
- The simulation code confirms 0 is an intended valid value [8](#0-7) 
- Non-IBC chains may legitimately set `HistoricalEntries=0` to save resources, as noted in the default value comment [9](#0-8) 
- This is not a malicious attack but a legitimate governance operation that triggers a code bug

**Frequency**: Once triggered through normal governance operations, the effect compounds with every subsequent block. The storage grows continuously at a rate of 1 entry per block, making it inevitable that storage issues will occur over the network's lifetime.

## Recommendation

Modify the pruning logic to delete all entries older than the retention threshold, regardless of gaps. Remove the break condition and iterate through all possible heights:

```go
// Prune all entries older than retention height, regardless of gaps
pruneHeight := ctx.BlockHeight() - int64(entryNum)
for i := pruneHeight; i >= 0; i-- {
    _, found := k.GetHistoricalInfo(ctx, i)
    if found {
        k.DeleteHistoricalInfo(ctx, i)
    }
    // Remove the break statement - continue checking all heights
}
```

Alternatively, track the oldest and newest entry heights in state to enable efficient range-based deletion without relying on the "continuous range" assumption.

## Proof of Concept

**File**: `x/staking/keeper/historical_info_test.go`

**Test Function**: `TestTrackHistoricalInfoUnboundedGrowth`

**Setup**:
- Initialize staking keeper with validators
- Set `HistoricalEntries=100`
- Generate 100 blocks, creating 100 historical entries

**Action**:
1. Change `HistoricalEntries` to 0
2. Generate 10 blocks (101-110), creating a gap
3. Change `HistoricalEntries` to 5
4. Generate block 111
5. Continue generating blocks 112-120

**Result**:
- Expected after block 111: 5 entries (107-111)
- Actual after block 111: 101 entries (1-100 + 111)
- Expected after block 120: 5 entries (116-120)
- Actual after block 120: 110 entries (1-100 + 111-120)

The test assertions will fail, proving that old entries are never pruned when a gap exists, leading to unbounded storage growth that violates the intended `HistoricalEntries` bound.

**Notes**

This vulnerability is called every block through `BeginBlocker` [10](#0-9) , making it a production-critical issue. The flaw stems from an incorrect assumption documented in the code comments that entries form a "continuous range," which is violated by legitimate governance operations that temporarily set `HistoricalEntries=0`.

### Citations

**File:** x/staking/keeper/historical_info.go (L71-77)
```go
	// Prune store to ensure we only have parameter-defined historical entries.
	// In most cases, this will involve removing a single historical entry.
	// In the rare scenario when the historical entries gets reduced to a lower value k'
	// from the original value k. k - k' entries must be deleted from the store.
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

**File:** x/staking/keeper/historical_info.go (L87-90)
```go
	// if there is no need to persist historicalInfo, return
	if entryNum == 0 {
		return
	}
```

**File:** x/staking/types/historical_info.go (L15-27)
```go
// NewHistoricalInfo will create a historical information struct from header and valset
// it will first sort valset before inclusion into historical info
func NewHistoricalInfo(header tmproto.Header, valSet Validators, powerReduction sdk.Int) HistoricalInfo {
	// Must sort in the same way that tendermint does
	sort.SliceStable(valSet, func(i, j int) bool {
		return ValidatorsByVotingPower(valSet).Less(i, j, powerReduction)
	})

	return HistoricalInfo{
		Header: header,
		Valset: valSet,
	}
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

**File:** x/staking/keeper/params.go (L82-84)
```go
// set the params
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) {
	k.paramstore.SetParamSet(ctx, &params)
```

**File:** x/staking/simulation/genesis.go (L34-37)
```go
// getHistEntries returns randomized HistoricalEntries between 0-100.
func getHistEntries(r *rand.Rand) uint32 {
	return uint32(r.Intn(int(types.DefaultHistoricalEntries + 1)))
}
```

**File:** x/staking/abci.go (L15-18)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
```
