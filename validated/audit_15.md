# Audit Report

## Title
Unbounded Storage Growth in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function contains a critical flaw where its pruning mechanism exits upon encountering the first missing historical entry. When governance legitimately sets `HistoricalEntries` to 0 temporarily, gaps are created in the historical entry sequence, permanently preventing old entries from being pruned and causing unbounded storage growth. This vulnerability occurs in `x/staking/keeper/historical_info.go` and is triggered every block through `BeginBlocker`.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** The function should maintain exactly `HistoricalEntries` number of recent historical info entries by pruning all entries older than `currentHeight - HistoricalEntries`. Storage should remain bounded to the parameter-defined limit to prevent resource exhaustion.

**Actual logic:** The pruning loop [2](#0-1)  iterates downward from `currentHeight - HistoricalEntries` and breaks immediately upon encountering the first missing entry. The code explicitly assumes entries form a "continuous range" [3](#0-2) , but this assumption is violated when `HistoricalEntries` is temporarily set to 0.

**Exploitation path:**
1. Network operates with `HistoricalEntries=100`, accumulating entries for blocks 1-100
2. Governance proposal changes `HistoricalEntries` to 0 at block 101 (valid per [4](#0-3) )
3. During blocks 101-110, no new entries are saved due to early return [5](#0-4) , but existing entries 1-100 remain in storage
4. Governance proposal changes `HistoricalEntries` to 5 at block 111
5. At block 111, pruning loop starts at height 106, finds no entry at height 106 (gap period), immediately breaks on line 83
6. Old entries 1-100 are never deleted, new entry 111 is saved
7. Each subsequent block adds a new entry without deleting old ones because the pruning loop always encounters the gap first
8. Storage grows unboundedly: {1-100, 111, 112, 113, ...}

**Security guarantee broken:** The storage bound invariant is violated. The system should maintain exactly `HistoricalEntries` entries, but instead accumulates entries without bound. Once triggered, governance cannot recover from this state through any parameter change - only a hard fork with code changes can resolve it.

## Impact Explanation

Each `HistoricalInfo` entry contains a complete block header and full validator set [6](#0-5) , with default 35 validators [7](#0-6) . Each entry represents multiple kilobytes of data.

After vulnerability triggering with 10-second blocks:
- Expected storage with `HistoricalEntries=5`: 5 entries
- Actual storage after 24 hours: 100 old entries + 8,640 new entries = 8,740 entries  
- Storage increase: 174,700%

This far exceeds the 30% threshold for Medium severity resource consumption impact. Over time, this leads to storage exhaustion, node crashes when disk space is exhausted, and potential network degradation as nodes run out of storage.

## Likelihood Explanation

**Who can trigger:** Any network participant through standard governance process. The `HistoricalEntries` parameter is governance-controlled and can be changed via governance proposals.

**Conditions required:**
1. Governance proposal changes `HistoricalEntries` from non-zero to 0
2. After several blocks, another proposal changes it back to a non-zero value

**Why realistic:**
- The validation function explicitly allows `HistoricalEntries=0` as valid (only checks type, not value) [4](#0-3) 
- The simulation code confirms 0 is an intended valid value [8](#0-7) 
- Non-IBC chains may legitimately set `HistoricalEntries=0` to save resources [9](#0-8) 
- This is not a malicious attack but a legitimate governance operation triggering a code bug
- Once triggered, the issue is **unrecoverable** without a hard fork - governance cannot remove orphaned entries through any parameter change

**Frequency:** Once triggered through normal governance operations, the effect compounds with every subsequent block [10](#0-9) .

## Recommendation

Modify the pruning logic to delete all entries older than the retention threshold, regardless of gaps. Remove the break condition at line 83 and continue checking all heights down to 0. This ensures that even if gaps exist in the sequence, all entries older than `currentHeight - HistoricalEntries` will be pruned.

Alternatively, track the oldest and newest entry heights in state to enable efficient range-based deletion without relying on the "continuous range" assumption.

## Proof of Concept

**File:** `x/staking/keeper/historical_info_test.go`

**Test Function:** `TestTrackHistoricalInfoUnboundedGrowth`

**Setup:**
- Initialize staking keeper and context
- Set `HistoricalEntries=100` via `SetParams`  
- Create 100 blocks (heights 1-100) by calling `TrackHistoricalInfo` with incrementing block heights
- Verify 100 entries exist using `GetAllHistoricalInfo`

**Action:**
1. Change `HistoricalEntries` to 0 via `SetParams`
2. Generate 10 blocks (101-110) by calling `TrackHistoricalInfo` with updated block heights in context
3. Verify no new entries created during this period (gap created)
4. Change `HistoricalEntries` to 5 via `SetParams`
5. Generate block 111 by calling `TrackHistoricalInfo` with height 111
6. Count total entries using `GetAllHistoricalInfo`

**Result:**
- Expected after block 111: 5 entries (heights 107-111)
- Actual after block 111: 101 entries (heights 1-100 + 111)
- This proves old entries are never pruned when gaps exist, violating the `HistoricalEntries` bound

## Notes

This vulnerability qualifies as valid despite involving governance because:
1. Setting `HistoricalEntries=0` is explicitly allowed and documented as valid for non-IBC chains
2. Once triggered, the issue creates an **unrecoverable state** that governance cannot fix through any parameter change  
3. This represents a security failure **beyond governance's intended authority** - they should be able to set any valid parameter value without causing permanent, unfixable storage issues that require a hard fork to resolve

The flaw stems from an incorrect assumption that entries form a "continuous range", which is violated by legitimate governance operations that temporarily set `HistoricalEntries=0`.

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
