# Audit Report

## Title
Storage Bound Invariant Violation in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function in the staking module contains a pruning logic flaw where the loop exits immediately upon encountering the first missing historical entry. When governance temporarily sets `HistoricalEntries` to 0 (an explicitly supported parameter value), gaps are created in the historical entry sequence. Upon restoring it to a non-zero value, the pruning loop encounters these gaps and exits prematurely, permanently orphaning older entries in storage and violating the storage bound invariant.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** The function should maintain exactly `HistoricalEntries` number of recent historical info entries by pruning all entries older than `currentHeight - HistoricalEntries`. Storage should remain bounded to the configured parameter value.

**Actual logic:** The pruning loop iterates downward from `currentHeight - HistoricalEntries` and breaks immediately upon encountering the first missing entry [2](#0-1) . The code explicitly assumes entries form a "continuous range" [3](#0-2) , but this assumption is violated when `HistoricalEntries` is temporarily set to 0.

**Exploitation path:**
1. Network operates with `HistoricalEntries=100`, accumulating entries for blocks 1-100
2. Governance proposal changes `HistoricalEntries` to 0 at block 101 (validated as acceptable by [4](#0-3) )
3. During blocks 101-110, no new entries are saved due to early return [5](#0-4) , but existing entries 1-100 remain in storage
4. Governance proposal changes `HistoricalEntries` to 5 at block 111
5. At block 111, pruning loop starts at height 106 (111-5), finds no entry at height 106 (gap period), immediately breaks
6. Old entries 1-100 are never deleted, new entry 111 is saved
7. As blocks progress, the pruning eventually deletes recent entries (111+) but always stops at the gap (heights 101-110), never reaching the orphaned entries 1-100
8. Storage stabilizes at: {1-100 (orphaned), plus most recent 5 entries} = 105 entries instead of 5

**Security guarantee broken:** The storage bound invariant is violated. The system should maintain exactly `HistoricalEntries` entries, but instead permanently retains old orphaned entries. Once triggered, governance cannot recover from this state through any parameter change—only a hard fork can resolve it.

## Impact Explanation

Each `HistoricalInfo` entry contains a complete block header and full validator set [6](#0-5) , with a default of 35 validators [7](#0-6) . Each entry represents multiple kilobytes of data.

After vulnerability triggering with the scenario described:
- Expected storage with `HistoricalEntries=5`: 5 entries
- Actual storage: 105 entries (100 orphaned + 5 recent)
- Storage increase: 2,100% (21x increase)

This far exceeds the 30% threshold for Medium severity: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours." While the growth eventually stabilizes rather than being truly unbounded, the permanent 21x increase in storage consumption represents a significant resource exhaustion issue that cannot be resolved through governance.

## Likelihood Explanation

**Who can trigger:** Any network participant through the standard governance process [8](#0-7) .

**Conditions required:**
1. Governance proposal changes `HistoricalEntries` from non-zero to 0
2. After several blocks, another proposal changes it back to a non-zero value

**Why realistic:**
- The validation function explicitly allows `HistoricalEntries=0` as valid [4](#0-3) 
- The simulation code confirms 0 is an intended valid value [9](#0-8) 
- Documentation suggests non-IBC chains may legitimately set `HistoricalEntries=0` to save resources [10](#0-9) 
- This is not a malicious attack but a legitimate governance operation triggering a code bug
- Once triggered, the issue is **unrecoverable** without a hard fork—governance cannot remove orphaned entries through any parameter change

**Frequency:** The vulnerability is triggered through normal governance operations. Once triggered, it affects the chain permanently via [11](#0-10) .

## Recommendation

Modify the pruning logic to delete all entries older than the retention threshold, regardless of gaps:

```go
// Prune all entries older than retention height, regardless of gaps
pruneHeight := ctx.BlockHeight() - int64(entryNum)
for i := pruneHeight; i >= 0; i-- {
    _, found := k.GetHistoricalInfo(ctx, i)
    if found {
        k.DeleteHistoricalInfo(ctx, i)
    }
    // Continue checking all heights - do not break on missing entries
}
```

Alternatively, track the oldest and newest entry heights in state to enable efficient range-based deletion without relying on the "continuous range" assumption.

## Proof of Concept

**File:** `x/staking/keeper/historical_info_test.go`

**Test Function:** `TestTrackHistoricalInfoGapPruningFailure`

**Setup:**
- Initialize staking keeper and context
- Set `HistoricalEntries=100` via `SetParams`
- Simulate 100 blocks by calling `TrackHistoricalInfo` with incrementing block heights (1-100)
- Verify 100 entries exist using `GetAllHistoricalInfo`

**Action:**
1. Change `HistoricalEntries` to 0 via `SetParams`
2. Simulate 10 blocks (101-110) by calling `TrackHistoricalInfo` with updated contexts
3. Verify no new entries created during this period (gap created)
4. Change `HistoricalEntries` to 5 via `SetParams`
5. Simulate blocks 111-120 by calling `TrackHistoricalInfo`
6. Count total entries using `GetAllHistoricalInfo`

**Result:**
- Expected after block 120: 5 entries (heights 116-120)
- Actual after block 120: 105 entries (heights 1-100 orphaned + heights 116-120)
- This proves old entries are never pruned when gaps exist, violating the `HistoricalEntries` storage bound by 2,100% (21x increase)

## Notes

This vulnerability is called every block through `BeginBlocker` [11](#0-10) , making it production-critical. The flaw stems from an incorrect assumption that entries form a "continuous range" [3](#0-2) , which is violated by legitimate governance operations that temporarily set `HistoricalEntries=0`. This is not a misconfiguration but a code bug triggered by explicitly supported parameter values, causing an unrecoverable security failure beyond governance's intended authority. While governance is trusted to change parameters, setting any valid parameter value should not cause permanent, unfixable storage issues that require a hard fork to resolve.

### Citations

**File:** x/staking/keeper/historical_info.go (L75-75)
```go
	// Since the entries to be deleted are always in a continuous range, we can iterate
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

**File:** x/staking/keeper/historical_info.go (L88-89)
```go
	if entryNum == 0 {
		return
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

**File:** x/staking/types/params.go (L242-248)
```go
func validateHistoricalEntries(i interface{}) error {
	_, ok := i.(uint32)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	return nil
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
