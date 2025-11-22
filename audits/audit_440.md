## Audit Report

## Title
Missing Validation for IAVL Items Before Store Items in StoreV2 Snapshot Restoration Causes Node Crash

## Summary
The StoreV2 snapshot restoration code in `storev2/rootmulti/store.go` lacks validation to ensure that `SnapshotItem_Store` items are received before `SnapshotItem_IAVL` items. This allows an attacker to craft malformed snapshot chunks that pass initial validation but trigger a panic during restoration, crashing the node.

## Impact
Medium - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
During snapshot restoration, the code is expected to receive `SnapshotItem_Store` items first to initialize each store tree via `AddTree()`, followed by `SnapshotItem_IAVL` items to populate that store with IAVL nodes. This ordering constraint ensures that the importer is properly initialized before nodes are added.

**Actual Logic:** 
The storev2 implementation does not validate that a `SnapshotItem_Store` was received before processing `SnapshotItem_IAVL` items. The `storeKey` variable is initialized to an empty string, and if an IAVL item arrives first:
- `scImporter.AddNode(node)` is called without a prior `AddTree()` call
- For nodes with ssStore enabled, a `SnapshotNode` with an empty `StoreKey` is sent to the ssStore import goroutine
- The ssStore.Import goroutine has an uncaught panic on error, which will crash the entire node process [2](#0-1) 

In contrast, the traditional store implementation has an explicit check: [3](#0-2) 

**Exploit Scenario:**
1. During state sync, a malicious peer offers a snapshot to syncing nodes
2. The attacker crafts snapshot chunks where `SnapshotItem_IAVL` items appear before any `SnapshotItem_Store` item
3. The chunks pass initial hash validation because they match the attacker's declared chunk hashes
4. When the node processes the chunks through `Manager.RestoreChunk()`, the malformed data is fed to the restore stream
5. The storev2 `restore()` function receives the IAVL item first
6. `scImporter.AddNode()` is called with no prior `AddTree()` call, violating the expected contract
7. If ssStore is enabled, the goroutine at line 727-732 receives a SnapshotNode with an empty StoreKey
8. `ssStore.Import()` fails on invalid data and triggers the panic on line 730
9. The uncaught panic in the goroutine crashes the entire node process

**Security Failure:** 
This is a denial-of-service vulnerability. An attacker can crash nodes running StoreV2 during state sync by providing malformed snapshots. The panic is not caught and propagates to crash the entire process.

## Impact Explanation

**Affected processes:** 
- Nodes using StoreV2 (sei-enhanced storage) attempting state sync
- The snapshot restoration process and node availability

**Severity of damage:**
- Nodes crash completely when attempting to sync from malicious snapshots
- Syncing nodes cannot complete state sync and join the network
- If 30% or more of the network is running StoreV2 and attempts to sync from the malicious peer, they will all crash
- The network's resilience is reduced as new nodes cannot sync properly

**Importance:**
State sync is a critical mechanism for new nodes to join the network quickly. If attackers can consistently crash syncing nodes, it prevents network growth and reduces network resilience. This is particularly severe for StoreV2 nodes which represent the enhanced storage architecture.

## Likelihood Explanation

**Who can trigger it:**
Any network participant can trigger this vulnerability by:
- Running a node and responding to snapshot discovery requests
- Offering malicious snapshots with IAVL items before Store items
- No special privileges or resources are required

**Conditions required:**
- Target nodes must be using StoreV2 (the enhanced storage)
- Target nodes must be performing state sync and requesting snapshots
- The malicious node must be selected as a snapshot provider

**Frequency:**
- Can be triggered during any state sync operation
- Attacker can repeatedly offer malicious snapshots to crash multiple syncing nodes
- Particularly effective when many nodes are syncing (e.g., after a network upgrade or during high growth periods)

## Recommendation

Add validation in the StoreV2 restore function to ensure a Store item has been received before processing IAVL items, matching the behavior of the traditional store implementation:

```go
case *snapshottypes.SnapshotItem_IAVL:
    if storeKey == "" {
        restoreErr = errors.Wrap(sdkerrors.ErrLogic, "received IAVL node item before store item")
        break loop
    }
    if item.IAVL.Height > math.MaxInt8 {
        restoreErr = errors.Wrapf(sdkerrors.ErrLogic, "node height %v cannot exceed %v",
            item.IAVL.Height, math.MaxInt8)
        break loop
    }
    // ... rest of processing
```

Additionally, consider adding a recover mechanism around the ssStore.Import goroutine to prevent uncaught panics from crashing the node, or propagate errors through a channel instead of panicking.

## Proof of Concept

**File:** `storev2/rootmulti/store_test.go`

**Test Function:** `TestRestoreSnapshotWithIAVLBeforeStore`

**Setup:**
1. Create a StoreV2 instance with ssStore enabled
2. Prepare a malformed snapshot stream that contains `SnapshotItem_IAVL` before any `SnapshotItem_Store`
3. Create the necessary channels and StreamReader

**Trigger:**
1. Call the `restore()` function with the malformed protobuf stream
2. The stream should contain at least one IAVL item without a preceding Store item

**Observation:**
The test should either:
- Detect that the restore function returns an error (if we add the fix)
- Or observe a panic/crash (demonstrating the vulnerability exists)
- Verify that with the traditional store implementation, this scenario is properly rejected with "received IAVL node item before store item" error

**Test Code Structure:**
```go
func TestRestoreSnapshotWithIAVLBeforeStore(t *testing.T) {
    // Setup: Create store with ssStore
    store := NewStore(t.TempDir(), log.NewNopLogger(), 
        config.StateCommitConfig{}, 
        config.StateStoreConfig{Enable: true}, 
        false)
    
    // Create malformed stream with IAVL before Store
    ch := make(chan io.ReadCloser, 1)
    go func() {
        // Write IAVL item without Store item first
        writer := createMalformedStream() // Helper to create bad stream
        ch <- writer
        close(ch)
    }()
    
    streamReader, _ := snapshots.NewStreamReader(ch)
    
    // Trigger: Attempt restore
    _, err := store.restore(1, streamReader)
    
    // Observation: Should error or panic
    require.Error(t, err) // After fix is applied
    require.Contains(t, err.Error(), "before store item")
}
```

The test demonstrates that StoreV2 lacks the validation present in the traditional store, allowing malformed snapshots to cause node crashes.

### Citations

**File:** storev2/rootmulti/store.go (L714-803)
```go
func (rs *Store) restore(height int64, protoReader protoio.Reader) (snapshottypes.SnapshotItem, error) {
	var (
		ssImporter   chan sstypes.SnapshotNode
		snapshotItem snapshottypes.SnapshotItem
		storeKey     string
		restoreErr   error
	)
	scImporter, err := rs.scStore.Importer(height)
	if err != nil {
		return snapshottypes.SnapshotItem{}, err
	}
	if rs.ssStore != nil {
		ssImporter = make(chan sstypes.SnapshotNode, 10000)
		go func() {
			err := rs.ssStore.Import(height, ssImporter)
			if err != nil {
				panic(err)
			}
		}()
	}
loop:
	for {
		snapshotItem = snapshottypes.SnapshotItem{}
		err = protoReader.ReadMsg(&snapshotItem)
		if err == io.EOF {
			break
		} else if err != nil {
			restoreErr = errors.Wrap(err, "invalid protobuf message")
			break loop
		}

		switch item := snapshotItem.Item.(type) {
		case *snapshottypes.SnapshotItem_Store:
			storeKey = item.Store.Name
			if err = scImporter.AddTree(storeKey); err != nil {
				restoreErr = err
				break loop
			}
			rs.logger.Info(fmt.Sprintf("Start restoring store: %s", storeKey))
		case *snapshottypes.SnapshotItem_IAVL:
			if item.IAVL.Height > math.MaxInt8 {
				restoreErr = errors.Wrapf(sdkerrors.ErrLogic, "node height %v cannot exceed %v",
					item.IAVL.Height, math.MaxInt8)
				break loop
			}
			node := &sctypes.SnapshotNode{
				Key:     item.IAVL.Key,
				Value:   item.IAVL.Value,
				Height:  int8(item.IAVL.Height),
				Version: item.IAVL.Version,
			}
			// Protobuf does not differentiate between []byte{} as nil, but fortunately IAVL does
			// not allow nil keys nor nil values for leaf nodes, so we can always set them to empty.
			if node.Key == nil {
				node.Key = []byte{}
			}
			if node.Height == 0 && node.Value == nil {
				node.Value = []byte{}
			}
			scImporter.AddNode(node)

			// Check if we should also import to SS store
			if rs.ssStore != nil && node.Height == 0 && ssImporter != nil {
				ssImporter <- sstypes.SnapshotNode{
					StoreKey: storeKey,
					Key:      node.Key,
					Value:    node.Value,
				}
			}
		default:
			// unknown element, could be an extension
			break loop
		}
	}

	if err = scImporter.Close(); err != nil {
		if restoreErr == nil {
			restoreErr = err
		}
	}
	if ssImporter != nil {
		close(ssImporter)
	}
	// initialize the earliest version for SS store
	if rs.ssStore != nil {
		rs.ssStore.SetEarliestVersion(height, false)
	}

	return snapshotItem, restoreErr
}
```

**File:** store/rootmulti/store.go (L906-909)
```go
		case *snapshottypes.SnapshotItem_IAVL:
			if importer == nil {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(sdkerrors.ErrLogic, "received IAVL node item before store item")
			}
```
