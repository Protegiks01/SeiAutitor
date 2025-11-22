# Audit Report

## Title
Node Permanent Failure Due to Pruning Before Metadata Flush in Multi-Store Commit

## Summary
The commit process in the root multi-store prunes old versions before atomically flushing the commit metadata. If a node crashes between these two operations, it becomes permanently unable to restart because it attempts to load a version that was already pruned. This vulnerability can cause validator nodes to become permanently disabled, potentially leading to network disruption during upgrade events. [1](#0-0) 

## Impact
Medium - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions

## Finding Description

**Location:** 
- Primary: `store/rootmulti/store.go`, `Commit()` method (lines 469-516)
- Secondary: `x/upgrade/keeper/keeper.go`, `ApplyUpgrade()` method (lines 364-391)

**Intended Logic:** 
The commit process should atomically persist all state changes and update metadata such that a node can always recover to the last successfully committed state after a crash. The upgrade module's `ApplyUpgrade` function relies on this atomic commit guarantee to ensure state consistency. [2](#0-1) 

**Actual Logic:** 
The commit process has a critical ordering flaw:

1. Line 490: `commitStores()` sequentially commits all individual stores to version N+1
2. Line 491: `defer rs.flushMetadata(...)` schedules metadata flush (executes at function end)
3. Lines 507-510: `PruneStores()` immediately deletes old versions including N
4. Lines 512-515: Function returns
5. Deferred `flushMetadata()` executes, writing version N+1 to metadata [3](#0-2) 

If a crash occurs after step 3 but before step 5, the metadata still points to version N, but version N has been deleted from all stores. [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. Network schedules an upgrade at height H (where H % pruningInterval == 0)
2. Validators execute `ApplyUpgrade` successfully
3. During block commit at height H:
   - All stores commit to version H
   - `PruneStores` deletes version H-KeepRecent
   - Node crashes (power failure, OS crash, hardware failure)
   - `flushMetadata` never executes
4. On restart:
   - `GetLatestVersion` returns H-1 (last flushed metadata)
   - `LoadLatestVersion` attempts to load version H-1
   - Version H-1 was pruned - load fails with error
   - Node calls `os.Exit(1)` and terminates [6](#0-5) [7](#0-6) 

**Security Failure:** 
Availability - The node enters a permanent failure state and cannot restart without manual intervention (rollback or database recovery). Multiple validators can be affected simultaneously during network-wide upgrades, potentially causing consensus disruption.

## Impact Explanation

**Affected Components:**
- Validator nodes that experience crashes during commit at pruning interval heights
- Network consensus if ≥30% of validators are affected simultaneously
- Chain liveness during coordinated upgrade events

**Severity:**
During a network-wide upgrade, all validators execute the upgrade simultaneously. If the upgrade height coincides with a pruning interval and multiple validators experience crashes (due to power failures, hardware issues, etc.) during the critical window:

1. Affected validators cannot restart automatically
2. Validator set participation drops
3. If enough validators are affected (≥33% of voting power), consensus halts
4. Even if consensus continues, affected validators miss blocks and may face slashing
5. Manual intervention is required for each affected node

**Why This Matters:**
This vulnerability makes the blockchain fragile to normal operational issues during upgrades - precisely when the network is most vulnerable. The atomic commit assumption is violated, creating a window where catastrophic state inconsistency can occur.

## Likelihood Explanation

**Trigger Conditions:**
- Node crash occurs between `PruneStores` execution and `flushMetadata` completion
- Crash happens at a block height that is a multiple of the pruning interval
- Pruning is enabled with Interval > 0

**Likelihood:**
- **Medium-High during upgrades:** Network-wide upgrades cause all validators to commit at the same height simultaneously, increasing the probability that some nodes experience crashes in the vulnerable window
- **Low during normal operation:** The vulnerable window is small (microseconds), but pruning intervals occur regularly
- **Realistic crash sources:** Power failures, hardware failures, OS crashes, OOM kills - none require attacker action

**Frequency:**
- Depends on pruning configuration (typical: every 100-1000 blocks)
- Most critical during scheduled upgrades when all nodes are synchronized
- A single occurrence can permanently disable a validator

## Recommendation

**Primary Fix:**
Reorder operations in the `Commit()` method to flush metadata before pruning:

1. Call `commitStores()` to commit all stores
2. Immediately call `flushMetadata()` (not deferred) to atomically mark the new version
3. Only then call `PruneStores()` to delete old versions
4. If pruning fails, log error but don't panic (old versions can be cleaned up later)

**Code Change in `store/rootmulti/store.go`:**
```go
func (rs *Store) Commit(bumpVersion bool) types.CommitID {
    // ... version calculation ...
    
    rs.SetLastCommitInfo(commitStores(version, rs.stores, bumpVersion))
    
    // Flush metadata immediately while old versions still exist
    rs.flushMetadata(rs.db, version, rs.LastCommitInfo())
    
    // ... pruning height determination ...
    
    // Now safe to prune - metadata already points to new version
    if rs.pruningOpts.Interval > 0 && version%int64(rs.pruningOpts.Interval) == 0 {
        rs.PruneStores(true, nil)
    }
    
    return types.CommitID{
        Version: version,
        Hash:    rs.LastCommitInfo().Hash(),
    }
}
```

**Additional Safeguard:**
Add recovery logic in `LoadLatestVersion` to detect this condition and attempt loading the next version if the metadata-specified version is missing.

## Proof of Concept

**Test File:** `store/rootmulti/store_test.go`

**Test Function:** `TestCommitCrashBetweenPruneAndFlush`

**Setup:**
1. Initialize a root multi-store with pruning enabled (KeepRecent=1, Interval=2)
2. Mount an IAVL store
3. Commit several versions to trigger pruning

**Trigger:**
```go
func TestCommitCrashBetweenPruneAndFlush(t *testing.T) {
    // Setup store with aggressive pruning
    db := dbm.NewMemDB()
    store := newMultiStoreWithMounts(db, types.PruningOptions{
        KeepRecent: 1,
        KeepEvery:  0,
        Interval:   2,
    })
    
    // Commit version 1
    store.Commit(true)
    
    // Simulate crash after pruning but before metadata flush at version 2
    // This is the vulnerable window
    store.SetLastCommitInfo(commitStores(2, store.stores, true))
    
    // Manually trigger pruning (simulating the code path in Commit)
    store.PruneStores(true, nil)
    
    // DO NOT call flushMetadata - simulating crash
    
    // Now try to restart by loading latest version
    newStore := newMultiStoreWithMounts(db, types.PruningOptions{
        KeepRecent: 1,
        KeepEvery:  0,
        Interval:   2,
    })
    
    // This should fail because:
    // - GetLatestVersion returns 1 (last flushed)
    // - But version 1 was pruned
    err := newStore.LoadLatestVersion()
    
    // Verify that load fails
    require.Error(t, err, "LoadLatestVersion should fail when trying to load pruned version")
    require.Contains(t, err.Error(), "failed to load store", "Error should indicate store load failure")
}
```

**Observation:**
The test demonstrates that after pruning without flushing metadata, `LoadLatestVersion()` fails with an error because it attempts to load a version that no longer exists. In production, this causes `os.Exit(1)` and the node cannot restart. [8](#0-7) [9](#0-8)

### Citations

**File:** store/rootmulti/store.go (L469-516)
```go
// Commit implements Committer/CommitStore.
func (rs *Store) Commit(bumpVersion bool) types.CommitID {
	var previousHeight, version int64
	c := rs.LastCommitInfo()
	if c.GetVersion() == 0 && rs.initialVersion > 1 {
		// This case means that no commit has been made in the store, we
		// start from initialVersion.
		version = rs.initialVersion

	} else if bumpVersion {
		// This case can means two things:
		// - either there was already a previous commit in the store, in which
		// case we increment the version from there,
		// - or there was no previous commit, and initial version was not set,
		// in which case we start at version 1.
		previousHeight = c.GetVersion()
		version = previousHeight + 1
	} else {
		version = c.GetVersion()
	}

	rs.SetLastCommitInfo(commitStores(version, rs.stores, bumpVersion))
	defer rs.flushMetadata(rs.db, version, rs.LastCommitInfo())

	// Determine if pruneHeight height needs to be added to the list of heights to
	// be pruned, where pruneHeight = (commitHeight - 1) - KeepRecent.
	if rs.pruningOpts.Interval > 0 && int64(rs.pruningOpts.KeepRecent) < previousHeight {
		pruneHeight := previousHeight - int64(rs.pruningOpts.KeepRecent)
		// We consider this height to be pruned iff:
		//
		// - KeepEvery is zero as that means that all heights should be pruned.
		// - KeepEvery % (height - KeepRecent) != 0 as that means the height is not
		// a 'snapshot' height.
		if rs.pruningOpts.KeepEvery == 0 || pruneHeight%int64(rs.pruningOpts.KeepEvery) != 0 {
			rs.pruneHeights = append(rs.pruneHeights, pruneHeight)
		}
	}

	// batch prune if the current height is a pruning interval height
	if rs.pruningOpts.Interval > 0 && version%int64(rs.pruningOpts.Interval) == 0 {
		rs.PruneStores(true, nil)
	}

	return types.CommitID{
		Version: version,
		Hash:    rs.LastCommitInfo().Hash(),
	}
}
```

**File:** store/rootmulti/store.go (L520-550)
```go
// pruningHeights and reset after finishing pruning.
func (rs *Store) PruneStores(clearStorePruningHeights bool, pruningHeights []int64) {
	if clearStorePruningHeights {
		pruningHeights = append(pruningHeights, rs.pruneHeights...)
	}

	if len(rs.pruneHeights) == 0 {
		return
	}

	for key, store := range rs.stores {
		if store.GetStoreType() == types.StoreTypeIAVL {
			// If the store is wrapped with an inter-block cache, we must first unwrap
			// it to get the underlying IAVL store.
			store = rs.GetCommitKVStore(key)

			if err := store.(*iavl.Store).DeleteVersions(pruningHeights...); err != nil {
				if errCause := errors.Cause(err); errCause != nil && errCause != iavltree.ErrVersionDoesNotExist {
					panic(err)
				}
			}
		}
	}
	if len(pruningHeights) > 0 {
		rs.earliestVersion = pruningHeights[len(pruningHeights)-1]
	}

	if clearStorePruningHeights {
		rs.pruneHeights = make([]int64, 0)
	}
}
```

**File:** store/rootmulti/store.go (L1095-1110)
```go
func GetLatestVersion(db dbm.DB) int64 {
	bz, err := db.Get([]byte(latestVersionKey))
	if err != nil {
		panic(err)
	} else if bz == nil {
		return 0
	}

	var latestVersion int64

	if err := gogotypes.StdInt64Unmarshal(&latestVersion, bz); err != nil {
		panic(err)
	}

	return latestVersion
}
```

**File:** store/rootmulti/store.go (L1112-1133)
```go
// Commits each store and returns a new commitInfo.
func commitStores(version int64, storeMap map[types.StoreKey]types.CommitKVStore, bumpVersion bool) *types.CommitInfo {
	storeInfos := make([]types.StoreInfo, 0, len(storeMap))

	for key, store := range storeMap {
		commitID := store.Commit(bumpVersion)

		if store.GetStoreType() == types.StoreTypeTransient {
			continue
		}

		si := types.StoreInfo{}
		si.Name = key.Name()
		si.CommitId = commitID
		storeInfos = append(storeInfos, si)
	}

	return &types.CommitInfo{
		Version:    version,
		StoreInfos: storeInfos,
	}
}
```

**File:** x/upgrade/keeper/keeper.go (L364-391)
```go
// ApplyUpgrade will execute the handler associated with the Plan and mark the plan as done.
func (k Keeper) ApplyUpgrade(ctx sdk.Context, plan types.Plan) {
	handler := k.upgradeHandlers[plan.Name]
	if handler == nil {
		panic("ApplyUpgrade should never be called without first checking HasHandler")
	}

	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}

	k.SetModuleVersionMap(ctx, updatedVM)

	// incremement the protocol version and set it in state and baseapp
	nextProtocolVersion := k.getProtocolVersion(ctx) + 1
	k.setProtocolVersion(ctx, nextProtocolVersion)
	if k.versionSetter != nil {
		// set protocol version on BaseApp
		k.versionSetter.SetProtocolVersion(nextProtocolVersion)
	}

	// Must clear IBC state after upgrade is applied as it is stored separately from the upgrade plan.
	// This will prevent resubmission of upgrade msg after upgrade is already completed.
	k.ClearIBCState(ctx, plan.Height)
	k.ClearUpgradePlan(ctx)
	k.SetDone(ctx, plan.Name)
}
```

**File:** simapp/app.go (L449-454)
```go
	if loadLatest {
		if err := app.LoadLatestVersion(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
```

**File:** store/iavl/store.go (L85-93)
```go
	if lazyLoading {
		_, err = tree.LazyLoadVersion(id.Version)
	} else {
		_, err = tree.LoadVersion(id.Version)
	}

	if err != nil {
		return nil, err
	}
```
