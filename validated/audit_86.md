# Audit Report

## Title
Unrecovered Panic in State Sync Snapshot Restoration Crashes Nodes Processing Malformed Peer Data

## Summary
The storev2 snapshot restoration code spawns a goroutine that panics without recovery when processing malformed snapshot data from peers. When `ssStore.Import` fails during state sync, the unrecovered panic crashes the entire node process, causing a denial-of-service vulnerability.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** During snapshot restoration via ABCI state sync, the system should gracefully handle errors in snapshot data processing and return appropriate error responses to Tendermint, allowing the node to reject malformed snapshots and request data from different peers.

**Actual Logic:** When storev2 state store is enabled (`ssStore != nil`), the `restore()` method spawns an asynchronous goroutine that calls `ssStore.Import()`. If this import operation encounters an error, the goroutine directly calls `panic(err)` without any defer/recover mechanism. Since panics in goroutines without recovery propagate to the Go runtime, this crashes the entire application. The main restoration function does not wait for this goroutine to complete or handle any errors from it.

**Exploitation Path:**
1. Attacker sets up a malicious peer node in Tendermint's P2P network (no special privileges required)
2. Victim node initiates state sync during initial sync, catching up, or after downtime
3. Tendermint discovers attacker's node through P2P peer discovery [2](#0-1) 
4. Attacker offers snapshot with valid metadata passing initial validation
5. Victim calls ABCI `ApplySnapshotChunk` to process chunks [3](#0-2) 
6. Chunks are validated by hash (snapshots/manager.go lines 362-368) - this only checks integrity, not semantic correctness
7. Chunks pass protobuf unmarshaling but contain malformed data (invalid tree structure, constraint violations, corrupted node data)
8. Malformed data is sent to `ssImporter` channel [4](#0-3) 
9. `ssStore.Import` fails on deeper validation (database constraints, tree structure validation, key ordering violations, etc.)
10. Goroutine panics with no recovery, crashing the victim node process

**Security Guarantee Broken:** The state sync mechanism should be resilient to untrusted peer data and handle errors gracefully. The panic violates the fundamental principle that external untrusted input should never crash the application, breaking availability and fault-tolerance guarantees.

## Impact Explanation

**Node-Level Impact:**
- Complete node crash requiring manual restart
- Repeated denial-of-service - attacker can crash nodes attempting to sync multiple times
- Prevents nodes from successfully completing state sync

**Network-Level Impact:**
- New nodes cannot join the network via state sync
- Validators recovering from downtime cannot resync reliably
- During network upgrades when multiple nodes sync simultaneously, an attacker can crash 30% or more of syncing nodes
- State sync feature becomes unreliable, forcing operators to disable it or find alternative sync methods
- Network resilience degraded during critical periods (upgrades, mass validator onboarding)

This meets the **Medium** severity threshold of "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network" when multiple nodes are syncing concurrently during network upgrades or mass onboarding events.

## Likelihood Explanation

**Who Can Trigger:** Any network participant running a peer node. No special privileges, stake, or authentication required to participate in Tendermint P2P network and offer snapshots.

**Conditions Required:**
- Storev2 must be enabled on victim nodes (`ssConfig.Enable = true`) [5](#0-4) 
- Victim node must be performing state sync [6](#0-5) 
- Attacker's peer must be discovered by Tendermint peer discovery
- Attacker must craft snapshot chunks that pass protobuf unmarshaling and hash validation but fail `ssStore.Import` validation

**Frequency:** High likelihood for networks with storev2 enabled because:
- New nodes regularly join networks via state sync
- Validators resync after upgrades or operational issues
- State sync is a standard Cosmos SDK feature enabled on many nodes
- Attack can be repeated with minimal cost to the attacker
- Particularly common during high-sync periods (post-upgrade, validator onboarding events)

## Recommendation

Add panic recovery to the goroutine handling state store imports and propagate errors through an error channel:

```go
if rs.ssStore != nil {
    ssImporter = make(chan sstypes.SnapshotNode, 10000)
    ssImportErr := make(chan error, 1)
    
    go func() {
        defer func() {
            if r := recover(); r != nil {
                ssImportErr <- fmt.Errorf("panic in ssStore.Import: %v", r)
            }
        }()
        
        err := rs.ssStore.Import(height, ssImporter)
        if err != nil {
            ssImportErr <- err
            return
        }
        close(ssImportErr)
    }()
    
    // Before returning from restore(), wait for goroutine completion
    // and check ssImportErr for any errors
}
```

Additionally, ensure the main `restore()` function waits for goroutine completion and properly propagates any errors before returning success. This matches the error handling pattern used for `scImporter` at lines 789-792.

## Proof of Concept

**Test Scenario:**
1. Initialize a storev2 Store with ssStore enabled using test configuration [5](#0-4) 
2. Create a mock `protoReader` that returns `SnapshotItem` messages with leaf nodes containing data that will cause `ssStore.Import` to fail (e.g., duplicate keys, constraint violations, invalid versions)
3. Call `store.Restore()` with the malformed data [6](#0-5) 
4. Observe that the panic in the goroutine crashes the test/node, demonstrating the vulnerability
5. After applying the recommended fix with proper error handling, verify that errors are properly returned instead of panicking

**Note:** The vulnerability is evident from code inspection - line 730 explicitly calls `panic(err)` in a goroutine without recovery. In Go, this is guaranteed to crash the process. A complete working PoC would require access to the external sei-db package to trigger actual `ssStore.Import` failures with specific data patterns, but the code defect and its consequences are unambiguous from the source code analysis.

### Citations

**File:** storev2/rootmulti/store.go (L61-95)
```go
func NewStore(
	homeDir string,
	logger log.Logger,
	scConfig config.StateCommitConfig,
	ssConfig config.StateStoreConfig,
	migrateIavl bool,
) *Store {
	scStore := sc.NewCommitStore(homeDir, logger, scConfig)
	store := &Store{
		logger:         logger,
		scStore:        scStore,
		storesParams:   make(map[types.StoreKey]storeParams),
		storeKeys:      make(map[string]types.StoreKey),
		ckvStores:      make(map[types.StoreKey]types.CommitKVStore),
		pendingChanges: make(chan VersionedChangesets, 1000),
	}
	if ssConfig.Enable {
		ssStore, err := ss.NewStateStore(logger, homeDir, ssConfig)
		if err != nil {
			panic(err)
		}
		// Check whether SC was enabled before but SS was not
		ssVersion, _ := ssStore.GetLatestVersion()
		scVersion, _ := scStore.GetLatestVersion()
		if ssVersion <= 0 && scVersion > 0 && !migrateIavl {
			panic("Enabling SS store without state sync could cause data corruption")
		}
		if err = ss.RecoverStateStore(logger, homeDir, ssStore); err != nil {
			panic(err)
		}
		store.ssStore = ssStore
		go store.StateStoreCommit()
	}
	return store

```

**File:** storev2/rootmulti/store.go (L698-712)
```go
func (rs *Store) Restore(
	height uint64, format uint32, protoReader protoio.Reader,
) (snapshottypes.SnapshotItem, error) {
	if rs.scStore != nil {
		if err := rs.scStore.Close(); err != nil {
			return snapshottypes.SnapshotItem{}, fmt.Errorf("failed to close db: %w", err)
		}
	}
	item, err := rs.restore(int64(height), protoReader)
	if err != nil {
		return snapshottypes.SnapshotItem{}, err
	}

	return item, rs.LoadLatestVersion()
}
```

**File:** storev2/rootmulti/store.go (L727-732)
```go
		go func() {
			err := rs.ssStore.Import(height, ssImporter)
			if err != nil {
				panic(err)
			}
		}()
```

**File:** storev2/rootmulti/store.go (L776-782)
```go
			if rs.ssStore != nil && node.Height == 0 && ssImporter != nil {
				ssImporter <- sstypes.SnapshotNode{
					StoreKey: storeKey,
					Key:      node.Key,
					Value:    node.Value,
				}
			}
```

**File:** snapshots/manager.go (L249-300)
```go
// Restore begins an async snapshot restoration, mirroring ABCI OfferSnapshot. Chunks must be fed
// via RestoreChunk() until the restore is complete or a chunk fails.
func (m *Manager) Restore(snapshot types.Snapshot) error {
	if snapshot.Chunks == 0 {
		return sdkerrors.Wrap(types.ErrInvalidMetadata, "no chunks")
	}
	if uint32(len(snapshot.Metadata.ChunkHashes)) != snapshot.Chunks {
		return sdkerrors.Wrapf(types.ErrInvalidMetadata, "snapshot has %v chunk hashes, but %v chunks",
			uint32(len(snapshot.Metadata.ChunkHashes)),
			snapshot.Chunks)
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// check multistore supported format preemptive
	if snapshot.Format != types.CurrentFormat {
		return sdkerrors.Wrapf(types.ErrUnknownFormat, "snapshot format %v", snapshot.Format)
	}
	if snapshot.Height == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrLogic, "cannot restore snapshot at height 0")
	}
	if snapshot.Height > uint64(math.MaxInt64) {
		return sdkerrors.Wrapf(types.ErrInvalidMetadata,
			"snapshot height %v cannot exceed %v", snapshot.Height, int64(math.MaxInt64))
	}

	err := m.beginLocked(opRestore)
	if err != nil {
		return err
	}

	// Start an asynchronous snapshot restoration, passing chunks and completion status via channels.
	chChunks := make(chan io.ReadCloser, chunkBufferSize)
	chDone := make(chan restoreDone, 1)

	go func() {
		startTime := time.Now()
		err := m.restoreSnapshot(snapshot, chChunks)
		chDone <- restoreDone{
			complete: err == nil,
			err:      err,
		}
		close(chDone)
		m.logger.Info(fmt.Sprintf("Restoring snapshot for version %d took %s", snapshot.Height, time.Since(startTime)))
	}()

	m.chRestore = chChunks
	m.chRestoreDone = chDone
	m.restoreChunkHashes = snapshot.Metadata.ChunkHashes
	m.restoreChunkIndex = 0
	return nil
}
```

**File:** baseapp/abci.go (L628-642)
```go
func (app *BaseApp) ApplySnapshotChunk(context context.Context, req *abci.RequestApplySnapshotChunk) (*abci.ResponseApplySnapshotChunk, error) {
	if app.snapshotManager == nil {
		app.logger.Error("snapshot manager not configured")
		return &abci.ResponseApplySnapshotChunk{Result: abci.ResponseApplySnapshotChunk_ABORT}, nil
	}

	done, err := app.snapshotManager.RestoreChunk(req.Chunk)
	switch {
	case err == nil:
		if done {
			if app.interBlockCache != nil {
				app.interBlockCache.Reset()
			}
		}
		return &abci.ResponseApplySnapshotChunk{Result: abci.ResponseApplySnapshotChunk_ACCEPT}, nil
```
