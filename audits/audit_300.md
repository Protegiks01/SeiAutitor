# Audit Report

## Title
Historical Info Pruning Fails When HistoricalEntries is Set to Zero, Causing Permanent Storage Bloat

## Summary
The historical info pruning logic in `TrackHistoricalInfo` breaks on the first missing entry when iterating backward from `currentHeight - HistoricalEntries`. When `HistoricalEntries` is reduced to 0, the pruning loop starts at the current block height (which hasn't been saved yet), immediately encounters a missing entry, and breaks without deleting any existing historical entries. This causes all previously stored historical entries to remain in storage indefinitely, violating the intended behavior and causing permanent storage bloat.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When the `HistoricalEntries` parameter is set to 0, the system should delete all historical entries from storage to free up resources. The parameter controls how many recent historical block headers and validator sets are persisted. [2](#0-1) 

**Actual Logic:**
The pruning loop starts at `ctx.BlockHeight() - int64(entryNum)` and iterates backward, deleting entries until it finds a missing one, at which point it breaks. When `entryNum` is 0, the loop starts at the current block height. Since the current block's historical entry hasn't been saved yet (saving happens after pruning), the loop immediately encounters a missing entry at the current height and breaks without deleting any old entries. [3](#0-2) 

**Exploit Scenario:**
1. A blockchain operates with `HistoricalEntries = 100` for thousands of blocks, accumulating 100 historical entries at any given time
2. Through a governance proposal, `HistoricalEntries` is legitimately changed to 0 to reduce storage requirements (as suggested in the documentation for chains not using IBC)
3. At the next block after the parameter change, `TrackHistoricalInfo` is called in BeginBlocker [4](#0-3) 
4. The pruning loop calculates the starting height as `currentHeight - 0 = currentHeight`
5. It checks if an entry exists at `currentHeight`, finds none (because new entries are saved after pruning), and immediately breaks
6. All 100 previously stored historical entries remain in storage
7. This persists indefinitely as subsequent blocks also fail to prune (same logic applies)

**Security Failure:**
This breaks the resource management invariant that setting `HistoricalEntries = 0` will prevent historical info persistence. The storage bloat accumulates over time and can never be cleaned up through normal operation, only through manual state migration or hard fork.

## Impact Explanation

**Affected Resources:**
- Node storage: Historical entries contain block headers and complete validator sets, which for a network with many validators can be several KB per entry
- Memory and I/O: Nodes must maintain and potentially query this bloated state
- IBC functionality: Stale historical info could be queried and potentially used incorrectly

**Severity of Damage:**
- With 100 historical entries remaining from a network with 100 validators, approximately 10-50 MB of unnecessary data persists per node
- Over time, if the parameter is toggled multiple times or kept at non-zero values for extended periods, this could accumulate to hundreds of MB or more
- All network nodes are affected simultaneously, as this is deterministic state machine behavior
- The storage cannot be reclaimed without a hard fork or state migration

**System Reliability:**
This violates operator expectations when they reduce `HistoricalEntries` to save resources. Instead of freeing storage, the change has no effect, causing persistent resource consumption that operators cannot remediate through configuration alone.

## Likelihood Explanation

**Who Can Trigger:**
This vulnerability is triggered automatically by any governance proposal that sets `HistoricalEntries` to 0. While governance is a privileged operation, this is not malicious misuse—it's a legitimate operational decision that chains might make. The documentation explicitly mentions that "Apps that don't use IBC can ignore this value" by not including historical tracking. [2](#0-1) 

**Required Conditions:**
- The chain must have previously stored historical entries (HistoricalEntries > 0)
- A governance proposal must pass to set HistoricalEntries to 0
- This is a realistic scenario for chains wanting to reduce storage requirements

**Frequency:**
This occurs every time HistoricalEntries is reduced to 0 after having been positive. While governance changes are infrequent, the impact is permanent once triggered. Additionally, the same issue occurs (though less severely) when HistoricalEntries is reduced from a large value to a smaller non-zero value, if gaps exist in the historical entries from previous periods when HistoricalEntries was 0.

## Recommendation

Modify the pruning logic to handle the case where `entryNum == 0` separately by explicitly deleting all historical entries without relying on the break-on-gap behavior:

```go
func (k Keeper) TrackHistoricalInfo(ctx sdk.Context) {
    entryNum := k.HistoricalEntries(ctx)

    // Special case: if entryNum is 0, delete all historical entries
    if entryNum == 0 {
        // Iterate through all historical entries and delete them
        k.IterateHistoricalInfo(ctx, func(hi types.HistoricalInfo) bool {
            k.DeleteHistoricalInfo(ctx, hi.Header.Height)
            return false // continue iteration
        })
        return
    }

    // Normal pruning logic for entryNum > 0
    for i := ctx.BlockHeight() - int64(entryNum); i >= 0; i-- {
        _, found := k.GetHistoricalInfo(ctx, i)
        if found {
            k.DeleteHistoricalInfo(ctx, i)
        } else {
            break
        }
    }

    // Save new entry
    lastVals := k.GetLastValidators(ctx)
    historicalEntry := types.NewHistoricalInfo(ctx.BlockHeader(), lastVals, k.PowerReduction(ctx))
    k.SetHistoricalInfo(ctx, ctx.BlockHeight(), &historicalEntry)
}
```

Alternatively, change the pruning loop to not rely on the break-on-gap behavior by tracking which entries actually exist and deleting all entries older than the retention window.

## Proof of Concept

**File:** `x/staking/keeper/historical_info_test.go`

**Test Function:** `TestHistoricalInfoPruningWithZeroEntries`

**Setup:**
1. Initialize a test app with staking keeper
2. Set HistoricalEntries to 5
3. Create and store historical info at heights 10, 11, 12, 13, 14
4. Verify all 5 entries exist

**Trigger:**
1. Set HistoricalEntries to 0 via SetParams
2. Call TrackHistoricalInfo at height 15

**Observation:**
1. Check that entries at heights 10-14 still exist (bug manifestation)
2. The test should fail because these entries should have been deleted
3. The expected behavior is that all historical entries are removed when HistoricalEntries is set to 0

**Test Code:**

```go
func TestHistoricalInfoPruningWithZeroEntries(t *testing.T) {
    _, app, ctx := createTestInput()
    
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 50, sdk.NewInt(0))
    addrVals := simapp.ConvertAddrsToValAddrs(addrDels)
    
    // Set historical entries to 5
    params := types.DefaultParams()
    params.HistoricalEntries = 5
    app.StakingKeeper.SetParams(ctx, params)
    
    // Create validator set
    valSet := []types.Validator{
        teststaking.NewValidator(t, addrVals[0], PKs[0]),
        teststaking.NewValidator(t, addrVals[1], PKs[1]),
    }
    
    // Store historical info at heights 10-14
    for height := int64(10); height <= 14; height++ {
        header := tmproto.Header{
            ChainID: "TestChain",
            Height:  height,
        }
        hi := types.NewHistoricalInfo(header, valSet, app.StakingKeeper.PowerReduction(ctx))
        app.StakingKeeper.SetHistoricalInfo(ctx, height, &hi)
    }
    
    // Verify all entries exist
    for height := int64(10); height <= 14; height++ {
        _, found := app.StakingKeeper.GetHistoricalInfo(ctx, height)
        require.True(t, found, "Historical info should exist at height %d", height)
    }
    
    // Change HistoricalEntries to 0
    params.HistoricalEntries = 0
    app.StakingKeeper.SetParams(ctx, params)
    
    // Set context to height 15 and call TrackHistoricalInfo
    header := tmproto.Header{
        ChainID: "TestChain",
        Height:  15,
    }
    ctx = ctx.WithBlockHeader(header)
    
    // Set bonded validators for TrackHistoricalInfo
    val1 := teststaking.NewValidator(t, addrVals[0], PKs[0])
    val1.Status = types.Bonded
    val1.Tokens = app.StakingKeeper.TokensFromConsensusPower(ctx, 10)
    app.StakingKeeper.SetValidator(ctx, val1)
    app.StakingKeeper.SetLastValidatorPower(ctx, val1.GetOperator(), 10)
    
    app.StakingKeeper.TrackHistoricalInfo(ctx)
    
    // BUG: Old entries should be deleted but they remain
    // This assertion will FAIL, demonstrating the vulnerability
    for height := int64(10); height <= 14; height++ {
        _, found := app.StakingKeeper.GetHistoricalInfo(ctx, height)
        require.False(t, found, 
            "VULNERABILITY: Historical info at height %d should have been deleted when HistoricalEntries was set to 0, but it still exists", 
            height)
    }
}
```

This test demonstrates that when `HistoricalEntries` is set to 0, the existing historical entries are not deleted as intended, confirming the vulnerability.

### Citations

**File:** x/staking/keeper/historical_info.go (L68-85)
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
```

**File:** x/staking/types/params.go (L29-32)
```go
	// DefaultHistorical entries is 10000. Apps that don't use IBC can ignore this
	// value by not adding the staking module to the application module manager's
	// SetOrderBeginBlockers.
	DefaultHistoricalEntries uint32 = 10000
```

**File:** x/staking/abci.go (L15-18)
```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	k.TrackHistoricalInfo(ctx)
```
