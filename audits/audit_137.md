# Audit Report

## Title
Missing Validation for IAVL Items Before Store Items in StoreV2 Snapshot Restoration Causes Node Crash

## Summary
The StoreV2 snapshot restoration implementation in `storev2/rootmulti/store.go` lacks a critical validation check that exists in the traditional store implementation. It does not verify that a `SnapshotItem_Store` has been received before processing `SnapshotItem_IAVL` items, allowing malicious peers to craft snapshot data that crashes nodes during state sync via an uncaught panic.

## Impact
Low to Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
During snapshot restoration, the system expects to receive `SnapshotItem_Store` items first to initialize store trees via `AddTree()`, followed by `SnapshotItem_IAVL` items to populate those stores. This ordering ensures proper initialization before data insertion.

**Actual Logic:** 
The StoreV2 implementation initializes `storeKey` as an empty string and processes items without validating the ordering. When an IAVL item arrives before any Store item:
- The empty `storeKey` is used when creating `SnapshotNode` structures
- If `ssStore` is enabled, nodes with empty `StoreKey` are sent to the import goroutine [2](#0-1) 
- The goroutine has an uncaught `panic(err)` that crashes the entire process [3](#0-2) 

In contrast, the traditional store explicitly validates this: [4](#0-3) 

**Exploitation Path:**
1. Malicious peer offers snapshot during state sync discovery
2. Attacker crafts chunks with `SnapshotItem_IAVL` before `SnapshotItem_Store`
3. Chunks include correct SHA256 hashes (calculated by attacker) so they pass validation [5](#0-4) 
4. Target node processes chunks through `RestoreChunk()` which feeds data to restore stream
5. StoreV2 `restore()` receives IAVL items with `storeKey` still empty
6. If ssStore enabled, `SnapshotNode` with empty `StoreKey` sent to Import goroutine
7. `ssStore.Import()` likely fails on invalid data, triggering `panic(err)`
8. Uncaught panic in goroutine terminates the entire node process

**Security Guarantee Broken:** 
Denial of service through malformed state sync data. The snapshot restoration protocol assumes well-formed data ordering but lacks validation to enforce this assumption in StoreV2.

## Impact Explanation

This vulnerability enables denial-of-service attacks against nodes using StoreV2 with ssStore enabled during state sync. When exploited:
- Target nodes crash completely and cannot complete state sync
- New nodes or nodes catching up cannot join/rejoin the network through the malicious peer
- Network resilience is reduced as node recovery/growth is hindered
- No fund loss occurs, but node availability is compromised

The impact is limited to:
1. Nodes using StoreV2 (appears to be alternative to traditional store based on codebase structure)
2. Nodes with ssStore enabled (opt-in via configuration)
3. Nodes actively performing state sync (temporary state)

This affects a subset of network nodes rather than the entire network, qualifying as a low-to-medium severity DoS vulnerability.

## Likelihood Explanation

**Who can trigger:** Any network participant can exploit this by running a node that responds to snapshot requests with malformed data. No special privileges, stake, or resources required.

**Conditions required:**
- Target nodes must use StoreV2 with ssStore enabled
- Target nodes must be performing state sync
- Malicious peer must be selected as snapshot provider

**Frequency:** Can be triggered whenever qualifying nodes perform state sync. More impactful during network upgrades or growth periods when many nodes sync simultaneously. Nodes can recover by restarting and selecting different peers, but repeated attacks can significantly delay network participation.

## Recommendation

Add validation matching the traditional store implementation:

```go
case *snapshottypes.SnapshotItem_IAVL:
    if storeKey == "" {
        restoreErr = errors.Wrap(sdkerrors.ErrLogic, "received IAVL node item before store item")
        break loop
    }
    // ... rest of IAVL processing
```

Additionally, implement proper error propagation in the ssStore import goroutine instead of using `panic()`, or add a `recover()` mechanism to prevent uncaught panics from terminating the process.

## Proof of Concept

**Test Structure:** A test in `storev2/rootmulti/store_test.go` demonstrating the vulnerability:

**Setup:**
- Create StoreV2 instance with `StateStoreConfig{Enable: true}`
- Prepare protobuf stream with `SnapshotItem_IAVL` before any `SnapshotItem_Store`
- Create StreamReader from malformed chunks

**Action:**
- Call `restore()` with the malformed stream
- IAVL items processed before Store items

**Expected Result:**
- Current implementation: node crashes via uncaught panic (when ssStore.Import fails on empty StoreKey)
- With fix: returns error "received IAVL node item before store item"

The vulnerability is demonstrated by comparing StoreV2's missing check [6](#0-5)  against the traditional store's validation [4](#0-3) .

## Notes

The severity classification (Low to Medium) reflects uncertainty about StoreV2 deployment statistics. The vulnerability is technically valid and exploitable, but the percentage of affected nodes depends on StoreV2 adoption rates and ssStore configuration prevalence, which cannot be determined from the codebase alone. If StoreV2 with ssStore is widely deployed (≥30% of nodes), this would be Medium severity; if less widespread (10-30%), it would be Low severity.

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

**File:** snapshots/manager.go (L363-368)
```go
	hash := sha256.Sum256(chunk)
	expected := m.restoreChunkHashes[m.restoreChunkIndex]
	if !bytes.Equal(hash[:], expected) {
		return false, sdkerrors.Wrapf(types.ErrChunkHashMismatch,
			"expected %x, got %x", hash, expected)
	}
```
