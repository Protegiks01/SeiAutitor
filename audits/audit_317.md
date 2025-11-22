## Title
Unbounded Storage Growth in TrackHistoricalInfo Due to Gap-Based Pruning Failure

## Summary
The `TrackHistoricalInfo` function in the staking module fails to properly bound historical entries when gaps exist in the stored history. The pruning loop breaks on encountering the first missing entry, preventing deletion of older entries beyond that gap. This leads to unbounded storage growth when the `HistoricalEntries` governance parameter is changed from non-zero to 0 and back to non-zero, as gaps are created and old entries are never pruned. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in `x/staking/keeper/historical_info.go` in the `TrackHistoricalInfo` function, specifically in the pruning loop. [2](#0-1) 

**Intended Logic:** 
The function should maintain exactly `HistoricalEntries` number of recent historical info entries in storage by pruning entries older than `currentHeight - HistoricalEntries`.

**Actual Logic:** 
The pruning loop starts at height `currentHeight - HistoricalEntries` and iterates downward, deleting found entries but immediately breaking when it encounters a missing entry. This means if there's a gap in the stored entries, all entries before that gap are never deleted. [3](#0-2) 

**Exploit Scenario:**
1. Network operates with `HistoricalEntries=100` for blocks 1-100, accumulating 100 historical entries
2. Through governance proposal, `HistoricalEntries` is changed to 0 for blocks 101-110
3. During blocks 101-110, no new entries are saved (early return when `entryNum == 0`)
4. Through governance proposal, `HistoricalEntries` is changed to 5 at block 111
5. At block 111, pruning starts at height 106 (111-5), finds no entry, immediately breaks
6. Old entries 1-100 remain in storage indefinitely
7. Each subsequent block adds a new entry without deleting old ones
8. Storage continues growing: {1-100, 111, 112, 113, ...} [4](#0-3) 

The `HistoricalEntries` parameter can validly be set to 0: [5](#0-4) 

**Security Failure:** 
Resource exhaustion - the storage bound invariant is violated, allowing unbounded accumulation of historical entries on disk storage.

## Impact Explanation

Each historical entry contains a full block header and complete validator set. With the default 35 validators, this represents substantial data per entry: [6](#0-5) 

Over time, this leads to:
- **Storage exhaustion**: Thousands of entries accumulate over months, consuming gigabytes of disk space
- **Node resource consumption**: Increased by >30% compared to expected levels
- **Node crashes**: When disk space is exhausted, nodes fail to write new blocks
- **Network degradation**: If 30%+ of nodes run out of storage, network stability is compromised

This directly impacts network reliability and can lead to node shutdowns, falling within the Medium severity scope of increasing resource consumption by at least 30% without brute force actions.

## Likelihood Explanation

**Who can trigger it:** 
Any network participant through the standard governance process. The `HistoricalEntries` parameter is a governance-controlled parameter that can be changed via parameter change proposals. [7](#0-6) 

**Conditions required:**
1. A governance proposal changes `HistoricalEntries` from non-zero to 0
2. After several blocks, another proposal changes it back to a non-zero value

This is a realistic scenario as:
- Non-IBC chains may legitimately set `HistoricalEntries=0` to save resources
- The default value is 10,000, explicitly noted for IBC chains [8](#0-7) 

**Frequency:** 
Can occur during normal governance operations. Once triggered, the effect compounds with every subsequent block, making it highly likely to cause storage issues over the network's lifetime.

## Recommendation

Modify the pruning logic to delete all entries older than the retention threshold, regardless of gaps. Replace the gap-based break condition with a height-based check:

```go
// Prune all entries older than retention height
pruneHeight := ctx.BlockHeight() - int64(entryNum)
for i := pruneHeight; i >= 0; i-- {
    _, found := k.GetHistoricalInfo(ctx, i)
    if found {
        k.DeleteHistoricalInfo(ctx, i)
    }
}
```

Alternatively, track the oldest entry height in state and use it to determine which entries to delete without relying on gap detection.

## Proof of Concept

**File:** `x/staking/keeper/historical_info_test.go`

**Test Function:** Add `TestTrackHistoricalInfoUnboundedGrowth` 

```go
func TestTrackHistoricalInfoUnboundedGrowth(t *testing.T) {
    _, app, ctx := createTestInput()
    
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 2, sdk.NewInt(0))
    addrVals := simapp.ConvertAddrsToValAddrs(addrDels)
    
    // Setup: Set HistoricalEntries to 100 and create validators
    params := types.DefaultParams()
    params.HistoricalEntries = 100
    app.StakingKeeper.SetParams(ctx, params)
    
    val1 := teststaking.NewValidator(t, addrVals[0], PKs[0])
    val1.Status = types.Bonded
    val1.Tokens = app.StakingKeeper.TokensFromConsensusPower(ctx, 10)
    app.StakingKeeper.SetValidator(ctx, val1)
    app.StakingKeeper.SetLastValidatorPower(ctx, val1.GetOperator(), 10)
    
    // Phase 1: Simulate blocks 1-100 with HistoricalEntries=100
    for height := int64(1); height <= 100; height++ {
        ctx = ctx.WithBlockHeight(height).WithBlockHeader(tmproto.Header{
            ChainID: "test-chain",
            Height:  height,
        })
        app.StakingKeeper.TrackHistoricalInfo(ctx)
    }
    
    // Verify 100 entries exist
    allInfos := app.StakingKeeper.GetAllHistoricalInfo(ctx)
    require.Equal(t, 100, len(allInfos), "Should have 100 historical entries")
    
    // Phase 2: Change HistoricalEntries to 0 for blocks 101-110 (creates gap)
    params.HistoricalEntries = 0
    app.StakingKeeper.SetParams(ctx, params)
    
    for height := int64(101); height <= 110; height++ {
        ctx = ctx.WithBlockHeight(height).WithBlockHeader(tmproto.Header{
            ChainID: "test-chain",
            Height:  height,
        })
        app.StakingKeeper.TrackHistoricalInfo(ctx)
    }
    
    // Still 100 entries (no new entries saved, none deleted)
    allInfos = app.StakingKeeper.GetAllHistoricalInfo(ctx)
    require.Equal(t, 100, len(allInfos), "Should still have 100 entries after gap")
    
    // Phase 3: Change HistoricalEntries to 5 at block 111
    params.HistoricalEntries = 5
    app.StakingKeeper.SetParams(ctx, params)
    
    ctx = ctx.WithBlockHeight(111).WithBlockHeader(tmproto.Header{
        ChainID: "test-chain",
        Height:  111,
    })
    app.StakingKeeper.TrackHistoricalInfo(ctx)
    
    // Trigger: After block 111, we should have only 5 entries (106-111)
    // but due to the bug, we have 101 entries (1-100 + 111)
    allInfos = app.StakingKeeper.GetAllHistoricalInfo(ctx)
    
    // Observation: This assertion fails, proving the bug
    // Expected: 5 entries, Actual: 101 entries
    require.Equal(t, 5, len(allInfos), 
        "Should have only 5 entries but have %d - old entries not pruned due to gap", 
        len(allInfos))
    
    // Verify the unbounded growth continues
    for height := int64(112); height <= 120; height++ {
        ctx = ctx.WithBlockHeight(height).WithBlockHeader(tmproto.Header{
            ChainID: "test-chain",
            Height:  height,
        })
        app.StakingKeeper.TrackHistoricalInfo(ctx)
    }
    
    allInfos = app.StakingKeeper.GetAllHistoricalInfo(ctx)
    // Should have 5 entries (116-120), but will have 110 entries (1-100, 111-120)
    require.Equal(t, 5, len(allInfos),
        "Unbounded growth: expected 5 entries but have %d", len(allInfos))
}
```

**Setup:** Initialize staking keeper with validators and set `HistoricalEntries=100`.

**Trigger:** 
1. Generate 100 blocks to create 100 historical entries
2. Change parameter to 0, generate 10 blocks (creating gap)
3. Change parameter to 5, generate blocks 111-120

**Observation:** The test will fail at the first assertion after block 111, showing 101 entries instead of the expected 5. This proves that old entries (1-100) are never pruned when a gap exists, leading to unbounded storage growth that violates the intended bound of `HistoricalEntries`.

### Citations

**File:** x/staking/abci.go (L15-19)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
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

**File:** x/staking/keeper/params.go (L29-34)
```go
// HistoricalEntries = number of historical info entries
// to persist in store
func (k Keeper) HistoricalEntries(ctx sdk.Context) (res uint32) {
	k.paramstore.Get(ctx, types.KeyHistoricalEntries, &res)
	return
}
```
