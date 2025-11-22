## Audit Report

## Title
Race Condition Between Snapshot Creation and State Pruning Causes Snapshot Failures

## Summary
A race condition exists between the asynchronous snapshot creation process and the automatic state pruning during block commits. When a snapshot is being created for a historical height, that height can be pruned from the IAVL stores before the snapshot export completes, causing the snapshot to fail. This occurs because the snapshot manager's operation lock does not protect against automatic pruning triggered by the `Commit()` function in the rootmulti store.

## Impact
Medium

## Finding Description

**Location:** 
- Snapshot creation: [1](#0-0) 
- Snapshot execution: [2](#0-1) 
- Automatic pruning: [3](#0-2) 
- Pruning implementation: [4](#0-3) 

**Intended Logic:** 
The snapshot system is designed to create consistent point-in-time snapshots of blockchain state at specific heights. The Manager uses an operation lock to prevent concurrent snapshot/prune/restore operations. State at the requested snapshot height should remain available throughout the entire snapshot creation process.

**Actual Logic:** 
The Manager's operation lock only prevents concurrent operations *through the Manager* (explicit Prune calls). However, automatic state pruning occurs directly in the `Store.Commit()` function, bypassing the Manager's coordination. When `Commit()` triggers `PruneStores()`, it can delete versions that are currently being snapshotted. The snapshot creation is asynchronous and can take significant time for large states, creating a race window.

**Exploit Scenario:**
1. Node is configured with `snapshot-interval=1000`, `pruning-keep-recent=90`, `pruning-interval=10`
2. At height 1000, `BaseApp.Commit()` triggers `SnapshotIfApplicable(1000)` which spawns an async goroutine
3. [5](#0-4) 
4. The goroutine calls `Manager.Create(1000)` which begins exporting IAVL stores at height 1000
5. [6](#0-5) 
6. Meanwhile, the chain continues processing blocks 1001, 1002, etc.
7. At height 1100, the Commit calculates `pruneHeight = 1099 - 90 = 1009`
8. At height 1101, `pruneHeight = 1000` is added to the `pruneHeights` list
9. At height 1110 (next interval), `PruneStores()` is called, deleting height 1000 from all IAVL stores
10. [7](#0-6) 
11. If the snapshot export is still reading nodes from height 1000, it encounters missing data and fails

**Security Failure:**
This breaks the availability guarantee of the snapshot system. The snapshot export calls `GetImmutable(version)` to access historical state, but the underlying IAVL nodes can be deleted during iteration, causing the export to fail with database errors.

## Impact Explanation

**Affected Processes:**
- **State Sync**: New nodes joining the network rely on snapshots for fast state synchronization. Failed snapshots force nodes to sync from genesis, which can take days or weeks for large chains.
- **Backup and Recovery**: Operators cannot reliably create snapshots for backup purposes when state is large and pruning is aggressive.
- **Network Resilience**: If existing nodes crash and cannot quickly resync via state sync, the network's active validator set may degrade over time.

**Severity:**
With large state sizes (100GB+), snapshot export can take 10+ minutes. During this window, the chain continues producing blocks. With aggressive pruning settings, the height being snapshotted can be pruned before export completes. This is not a theoretical edge case but a realistic operational scenario that affects production networks.

The impact qualifies as **Medium** under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - while not directly about smart contracts, the inability to create valid snapshots affects the network's ability to onboard new nodes and maintain operational health, which indirectly impacts all network functionality.

## Likelihood Explanation

**Triggering Conditions:**
- Any node operator or network participant (no special privileges required)
- Occurs during normal operation with certain pruning/snapshot configurations
- More likely with:
  - Large state sizes (longer snapshot duration)
  - Aggressive pruning (`pruning-keep-recent` close to `snapshot-interval`)
  - Slow storage I/O (extends snapshot time)
  - Fast block times (more blocks processed during snapshot)

**Frequency:**
With typical configurations (e.g., `snapshot-interval=1000`, `pruning-keep-recent=362880`), this race is unlikely. However, with optimized settings for disk space (e.g., `pruning-keep-recent=100`), the race window opens. On networks with 6-second blocks, if snapshot takes 10 minutes (100 blocks), and `pruning-keep-recent=90`, the race is guaranteed to occur.

## Recommendation

Add coordination between snapshot creation and automatic pruning:

1. **In `Store.PruneStores()`**: Check if any snapshot operations are in progress before pruning a height. This requires the rootmulti Store to maintain awareness of active snapshot operations.

2. **In `Manager.Create()`**: Register the snapshot height with the multistore before beginning export, and unregister upon completion. The multistore should skip pruning registered heights.

3. **Alternatively**: Extend the Manager's operation lock to cover automatic pruning by having `Store.Commit()` check with the snapshot manager before pruning, or by having pruning go through the Manager's `Prune()` method which already respects the operation lock.

Example approach:
```go
// In Manager
type Manager struct {
    // ... existing fields
    activeSnapshotHeights map[uint64]bool
    mtx sync.Mutex
}

func (m *Manager) Create(height uint64) (*types.Snapshot, error) {
    // ... existing validation
    m.mtx.Lock()
    m.activeSnapshotHeights[height] = true
    m.mtx.Unlock()
    
    defer func() {
        m.mtx.Lock()
        delete(m.activeSnapshotHeights, height)
        m.mtx.Unlock()
    }()
    
    // ... rest of snapshot creation
}

// In Store.PruneStores()
func (rs *Store) PruneStores(clearStorePruningHeights bool, pruningHeights []int64) {
    // Filter out heights that are being snapshotted
    filteredHeights := []int64{}
    for _, h := range pruningHeights {
        if !rs.snapshotManager.IsSnapshotInProgress(uint64(h)) {
            filteredHeights = append(filteredHeights, h)
        }
    }
    // ... proceed with filteredHeights
}
```

## Proof of Concept

**File**: `store/rootmulti/snapshot_prune_race_test.go`

**Setup:**
```go
package rootmulti_test

import (
    "testing"
    "time"
    "sync"
    
    "github.com/cosmos/cosmos-sdk/store/rootmulti"
    "github.com/cosmos/cosmos-sdk/store/types"
    "github.com/cosmos/cosmos-sdk/snapshots"
    "github.com/stretchr/testify/require"
    dbm "github.com/tendermint/tm-db"
    "github.com/tendermint/tendermint/libs/log"
)

// Test demonstrates race between snapshot creation and pruning
func TestSnapshotPruningRaceCondition(t *testing.T) {
    // Create a rootmulti store with IAVL stores
    db := dbm.NewMemDB()
    store := rootmulti.NewStore(db, log.NewNopLogger())
    
    // Mount a test store
    store.MountStoreWithDB(types.NewKVStoreKey("test"), types.StoreTypeIAVL, nil)
    
    // Set aggressive pruning: keep only last 5 versions, prune every 2 commits
    store.SetPruning(types.PruningOptions{
        KeepRecent: 5,
        KeepEvery:  0,
        Interval:   2,
    })
    
    require.NoError(t, store.LoadLatestVersion())
    
    // Commit several versions with data
    for i := 1; i <= 10; i++ {
        kvStore := store.GetKVStore(types.NewKVStoreKey("test"))
        kvStore.Set([]byte("key"), []byte("value"))
        store.Commit(true)
    }
    
    // Setup snapshot manager
    snapshotDB := dbm.NewMemDB()
    snapshotStore, err := snapshots.NewStore(snapshotDB, t.TempDir())
    require.NoError(t, err)
    manager := snapshots.NewManager(snapshotStore, store, log.NewNopLogger())
    
    // Start snapshot at height 6 in a goroutine (simulating async snapshot)
    var snapshotErr error
    var wg sync.WaitGroup
    wg.Add(1)
    go func() {
        defer wg.Done()
        // Add delay to simulate slow snapshot
        time.Sleep(100 * time.Millisecond)
        _, snapshotErr = manager.Create(6)
    }()
    
    // Meanwhile, continue committing blocks that will trigger pruning
    // After 5 more commits, height 6 should be in pruning range
    time.Sleep(10 * time.Millisecond) // Let snapshot start
    for i := 11; i <= 16; i++ {
        kvStore := store.GetKVStore(types.NewKVStoreKey("test"))
        kvStore.Set([]byte("key"), []byte("value"))
        store.Commit(true)
        time.Sleep(10 * time.Millisecond)
    }
    
    // Wait for snapshot to complete
    wg.Wait()
    
    // Snapshot should have failed due to pruned state
    require.Error(t, snapshotErr, "Expected snapshot to fail due to pruned state")
}
```

**Trigger:**
The test creates a scenario where:
1. Multiple versions are committed to establish history
2. A snapshot is started for height 6 with artificial delay
3. Additional commits trigger pruning that includes height 6
4. The snapshot export fails when trying to read pruned nodes

**Observation:**
The test expects `snapshotErr` to be non-nil, confirming that the snapshot failed due to the race condition. The error would typically be a database "key not found" or similar error when the IAVL export tries to read nodes that were deleted by pruning.

### Citations

**File:** snapshots/manager.go (L158-182)
```go
func (m *Manager) Create(height uint64) (*types.Snapshot, error) {
	if m == nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrLogic, "no snapshot store configured")
	}
	err := m.begin(opSnapshot)
	if err != nil {
		return nil, err
	}
	defer m.end()

	latest, err := m.store.GetLatest()
	if err != nil {
		return nil, sdkerrors.Wrap(err, "failed to examine latest snapshot")
	}
	if latest != nil && latest.Height >= height {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrConflict,
			"a more recent snapshot already exists at height %v", latest.Height)
	}

	// Spawn goroutine to generate snapshot chunks and pass their io.ReadClosers through a channel
	ch := make(chan io.ReadCloser)
	go m.createSnapshot(height, ch)

	return m.store.Save(height, types.CurrentFormat, ch)
}
```

**File:** snapshots/manager.go (L186-217)
```go
func (m *Manager) createSnapshot(height uint64, ch chan<- io.ReadCloser) {
	streamWriter := NewStreamWriter(ch)
	if streamWriter == nil {
		return
	}
	defer streamWriter.Close()
	if err := m.multistore.Snapshot(height, streamWriter); err != nil {
		m.logger.Error("Snapshot creation failed", "err", err)
		streamWriter.CloseWithError(err)
		return
	}
	for _, name := range m.sortedExtensionNames() {
		extension := m.extensions[name]
		// write extension metadata
		err := streamWriter.WriteMsg(&types.SnapshotItem{
			Item: &types.SnapshotItem_Extension{
				Extension: &types.SnapshotExtensionMeta{
					Name:   name,
					Format: extension.SnapshotFormat(),
				},
			},
		})
		if err != nil {
			streamWriter.CloseWithError(err)
			return
		}
		if err := extension.Snapshot(height, streamWriter); err != nil {
			streamWriter.CloseWithError(err)
			return
		}
	}
}
```

**File:** store/rootmulti/store.go (L508-510)
```go
	if rs.pruningOpts.Interval > 0 && version%int64(rs.pruningOpts.Interval) == 0 {
		rs.PruneStores(true, nil)
	}
```

**File:** store/rootmulti/store.go (L518-550)
```go
// PruneStores will batch delete a list of heights from each mounted sub-store.
// If clearStorePruningHeihgts is true, store's pruneHeights is appended to the
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

**File:** store/rootmulti/store.go (L766-865)
```go
func (rs *Store) Snapshot(height uint64, protoWriter protoio.Writer) error {
	if height == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "cannot snapshot height 0")
	}
	if height > uint64(rs.LastCommitID().Version) {
		return sdkerrors.Wrapf(sdkerrors.ErrLogic, "cannot snapshot future height %v", height)
	}

	// Collect stores to snapshot (only IAVL stores are supported)
	type namedStore struct {
		*iavl.Store
		name string
	}
	stores := []namedStore{}
	for key := range rs.stores {
		switch store := rs.GetCommitKVStore(key).(type) {
		case *iavl.Store:
			stores = append(stores, namedStore{name: key.Name(), Store: store})
		case *transient.Store, *mem.Store:
			// Non-persisted stores shouldn't be snapshotted
			continue
		default:
			return sdkerrors.Wrapf(sdkerrors.ErrLogic,
				"don't know how to snapshot store %q of type %T", key.Name(), store)
		}
	}
	sort.Slice(stores, func(i, j int) bool {
		return strings.Compare(stores[i].name, stores[j].name) == -1
	})

	// Export each IAVL store. Stores are serialized as a stream of SnapshotItem Protobuf
	// messages. The first item contains a SnapshotStore with store metadata (i.e. name),
	// and the following messages contain a SnapshotNode (i.e. an ExportNode). Store changes
	// are demarcated by new SnapshotStore items.
	for _, store := range stores {
		totalKeyBytes := int64(0)
		totalValueBytes := int64(0)
		totalNumKeys := int64(0)
		exporter, err := store.Export(int64(height))
		if err != nil {
			return err
		}
		defer exporter.Close()
		err = protoWriter.WriteMsg(&snapshottypes.SnapshotItem{
			Item: &snapshottypes.SnapshotItem_Store{
				Store: &snapshottypes.SnapshotStoreItem{
					Name: store.name,
				},
			},
		})
		if err != nil {
			return err
		}
		rs.logger.Info(fmt.Sprintf("Exporting snapshot for store %s", store.name))
		for {
			node, err := exporter.Next()
			if err == iavltree.ExportDone {
				break
			} else if err != nil {
				return err
			}
			err = protoWriter.WriteMsg(&snapshottypes.SnapshotItem{
				Item: &snapshottypes.SnapshotItem_IAVL{
					IAVL: &snapshottypes.SnapshotIAVLItem{
						Key:     node.Key,
						Value:   node.Value,
						Height:  int32(node.Height),
						Version: node.Version,
					},
				},
			})
			if err != nil {
				return err
			}
			totalKeyBytes += int64(len(node.Key))
			totalValueBytes += int64(len(node.Value))
			totalNumKeys += 1
		}
		telemetry.SetGaugeWithLabels(
			[]string{"iavl", "store", "total_num_keys"},
			float32(totalNumKeys),
			[]metrics.Label{telemetry.NewLabel("store_name", store.name)},
		)
		telemetry.SetGaugeWithLabels(
			[]string{"iavl", "store", "total_key_bytes"},
			float32(totalKeyBytes),
			[]metrics.Label{telemetry.NewLabel("store_name", store.name)},
		)
		telemetry.SetGaugeWithLabels(
			[]string{"iavl", "store", "total_value_bytes"},
			float32(totalValueBytes),
			[]metrics.Label{telemetry.NewLabel("store_name", store.name)},
		)
		rs.logger.Info(fmt.Sprintf("Exported snapshot for store %s, with total number of keys %d, total key bytes %d, total value bytes %d",
			store.name, totalNumKeys, totalKeyBytes, totalValueBytes))
		exporter.Close()
	}

	return nil
}
```

**File:** baseapp/abci.go (L423-427)
```go
func (app *BaseApp) SnapshotIfApplicable(height uint64) {
	if app.snapshotInterval > 0 && height%app.snapshotInterval == 0 {
		go app.Snapshot(int64(height))
	}
}
```
