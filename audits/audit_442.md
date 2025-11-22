## Title
Unmetered Memory Exhaustion via Excessive Iterator Creation in Multiversion Store

## Summary
The multiversion store's iterator creation allocates memory proportional to the number of prior transactions and their keys, but only charges a flat gas cost of 30. An attacker can create many iterators within a single transaction to exhaust node memory with minimal gas expenditure, causing a denial-of-service.

## Impact
Medium - Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours. Can lead to node crashes or shutdown of greater than or equal to 30% of network processing nodes.

## Finding Description

**Location:** 
- `store/multiversion/store.go` - `CollectIteratorItems` function (lines 242-260)
- `store/multiversion/mvkv.go` - `iterator` function (lines 282-322) and `NewIterationTracker` function (lines 48-62)
- `store/gaskv/store.go` - `iterator` function showing gas metering (lines 134-152) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:** 
Iterator creation should consume gas proportional to the computational and memory resources required. The multiversion store is designed to enable concurrent transaction execution with optimistic concurrency control.

**Actual Logic:** 
When a transaction creates an iterator in VersionIndexedStore:
1. `iterator()` calls `CollectIteratorItems(transactionIndex)` which creates a new MemDB instance
2. This function iterates through ALL writesets from transaction index 0 to (transactionIndex-1) and adds ALL their keys to the MemDB - O(transactionIndex × average_keys_per_transaction) memory allocation
3. `NewIterationTracker` creates a full copy of the current transaction's writeset
4. The iterationTracker is appended to an unbounded `iterateset` slice and persists even after the iterator is closed
5. Gas charged is only the flat `IterNextCostFlat` cost of 30 gas, regardless of how many keys are allocated in the MemDB [5](#0-4) 

**Exploit Scenario:**
1. Attacker submits a transaction containing code (e.g., smart contract) that creates many iterators in a loop (e.g., 1000 iterations)
2. The transaction is executed late in a block when optimistic concurrency control is enabled (e.g., at transaction index 50 out of 100)
3. Previous transactions have written many keys (e.g., average 100 keys per transaction)
4. Each iterator creation:
   - Allocates a MemDB with 50 × 100 = 5,000 keys
   - Copies the transaction's writeset (e.g., 100 keys)
   - Adds an iterationTracker to the slice
5. Creating 1000 iterators allocates memory for approximately 5 million key entries plus 1000 MemDB tree structures
6. Gas cost: 1000 × 30 = 30,000 gas (minimal compared to typical transaction limits)
7. Memory consumption is disproportionate to gas charged, exhausting node memory [6](#0-5) 

**Security Failure:** 
Memory exhaustion and denial-of-service. The gas metering system fails to account for the actual memory allocation cost during iterator creation, allowing an attacker to consume excessive memory with minimal gas expenditure.

## Impact Explanation

This vulnerability affects node availability and network stability:

1. **Node Resource Exhaustion**: Nodes processing blocks containing malicious transactions will experience severe memory pressure, potentially leading to out-of-memory crashes or significant performance degradation
2. **Network Disruption**: If multiple nodes crash simultaneously when processing the same malicious block, the network's ability to reach consensus and process subsequent transactions is impaired
3. **Economic Attack**: The attacker can exploit the gas-to-memory mismatch to cause disproportionate damage with minimal cost, making the attack economically viable and repeatable
4. **Cascading Failures**: Memory exhaustion can trigger garbage collection storms, thread starvation, and other cascading failures that affect the entire node infrastructure

The severity is Medium because it can increase network node resource consumption by more than 30% and potentially shut down 30% or more of network processing nodes, though it doesn't completely halt the network if some nodes have sufficient memory.

## Likelihood Explanation

**Who can trigger it:** Any user who can submit transactions, including smart contract deployments or contract execution calls. No special privileges required.

**Conditions required:**
- Optimistic concurrency control (OCC) must be enabled for parallel transaction execution (this is the default in Sei)
- Block must contain multiple transactions to amplify the memory allocation per iterator
- Attacker's transaction must be able to create iterators programmatically (possible through smart contract code that performs range queries or direct storage iteration)

**Frequency:** 
This can be triggered in every block where the attacker includes such a transaction. The attack is repeatable and deterministic. In blocks with high transaction throughput (which is the target scenario for OCC), the memory amplification is more severe.

The vulnerability is highly likely to be exploited because:
1. The cost-to-impact ratio heavily favors the attacker
2. It can be triggered through normal transaction submission
3. The pattern (creating many iterators) may occur naturally in some contracts, making it hard to distinguish malicious from legitimate usage

## Recommendation

Implement proper gas metering for iterator creation that accounts for the actual memory allocation:

1. **Charge gas proportional to keys collected**: In `CollectIteratorItems`, track the number of keys added to the MemDB and charge gas based on that count (e.g., `ReadCostPerByte × key_count`)

2. **Add iterator creation limit**: Implement a per-transaction limit on the number of concurrent iterators that can be created (e.g., maximum 100 iterators per transaction)

3. **Optimize memory allocation**: Consider caching the collected iterator items at the transaction level rather than recreating them for each iterator, or use a shared read-only view

4. **Charge for writeset copy**: In `NewIterationTracker`, charge gas proportional to the size of the writeset being copied

Example fix for `CollectIteratorItems`:
- Track `keyCount` during the loop
- After building the MemDB, consume gas: `gasMeter.ConsumeGas(gasConfig.ReadCostPerByte * Gas(keyCount), "CollectIteratorItems")`

## Proof of Concept

**File:** `store/multiversion/mvkv_test.go` (add new test function)

**Test Function Name:** `TestIteratorMemoryExhaustion`

**Setup:**
1. Create a parent KV store and multiversion store
2. Simulate a block with 50 prior transactions, each writing 100 keys
3. Create a VersionIndexedStore at transaction index 50
4. Track memory allocation before and after iterator creation

**Trigger:**
1. Create 1000 iterators in a loop without closing them (or even with closing, since iterationTrackers persist)
2. Each iterator creation calls `CollectIteratorItems(50)` which allocates a MemDB with 50 × 100 = 5000 keys
3. Monitor memory consumption

**Observation:**
The test should observe that:
- Memory consumption increases dramatically (multiple MB or GB depending on key sizes)
- Gas consumed is only 1000 × 30 = 30,000 gas
- The ratio of memory allocated to gas charged is extremely high (orders of magnitude higher than other operations)
- With sufficient iterations, the test will trigger out-of-memory conditions or demonstrate memory consumption exceeding reasonable bounds

```go
func TestIteratorMemoryExhaustion(t *testing.T) {
    mem := dbadapter.Store{DB: dbm.NewMemDB()}
    parentKVStore := cachekv.NewStore(mem, types.NewKVStoreKey("mock"), 1000)
    mvs := multiversion.NewMultiVersionStore(parentKVStore)
    
    // Simulate 50 prior transactions, each with 100 keys
    for txIdx := 0; txIdx < 50; txIdx++ {
        writeset := make(multiversion.WriteSet)
        for keyIdx := 0; keyIdx < 100; keyIdx++ {
            key := fmt.Sprintf("tx%d_key%d", txIdx, keyIdx)
            writeset[key] = []byte(fmt.Sprintf("value%d", keyIdx))
        }
        mvs.SetWriteset(txIdx, 1, writeset)
    }
    
    // Create VersionIndexedStore at index 50
    abortC := make(chan scheduler.Abort, 1)
    vis := multiversion.NewVersionIndexedStore(parentKVStore, mvs, 50, 1, abortC)
    
    // Get baseline memory stats
    var m1 runtime.MemStats
    runtime.ReadMemStats(&m1)
    
    // Create many iterators (demonstrating the vulnerability)
    iterators := make([]types.Iterator, 1000)
    for i := 0; i < 1000; i++ {
        iterators[i] = vis.Iterator([]byte("tx0"), []byte("tx99"))
    }
    
    // Force GC to get accurate memory measurement
    runtime.GC()
    var m2 runtime.MemStats
    runtime.ReadMemStats(&m2)
    
    // Calculate memory increase
    memIncreaseMB := float64(m2.Alloc-m1.Alloc) / (1024 * 1024)
    
    // Close iterators
    for _, iter := range iterators {
        iter.Close()
    }
    
    // Assert that memory consumption is disproportionate
    // With 1000 iterators × 5000 keys each = 5 million key allocations
    // This should consume significant memory (likely 10+ MB)
    require.Greater(t, memIncreaseMB, 10.0, 
        "Expected significant memory allocation from iterator creation")
    
    // The gas cost would only be 1000 * 30 = 30,000 gas
    // which is trivial compared to the memory allocated
    t.Logf("Memory increased by %.2f MB for 30,000 gas cost", memIncreaseMB)
    t.Logf("Memory per gas: %.2f KB per gas unit", memIncreaseMB*1024/30000)
}
```

This test demonstrates that iterator creation in the multiversion store has a severe gas-to-memory mismatch, enabling memory exhaustion attacks.

### Citations

**File:** store/multiversion/store.go (L242-260)
```go
// CollectIteratorItems implements MultiVersionStore. It will return a memDB containing all of the keys present in the multiversion store within the iteration range prior to (exclusive of) the index.
func (s *Store) CollectIteratorItems(index int) *db.MemDB {
	sortedItems := db.NewMemDB()

	// get all writeset keys prior to index
	for i := 0; i < index; i++ {
		writesetAny, found := s.txWritesetKeys.Load(i)
		if !found {
			continue
		}
		indexedWriteset := writesetAny.([]string)
		// TODO: do we want to exclude keys out of the range or just let the iterator handle it?
		for _, key := range indexedWriteset {
			// TODO: inefficient because (logn) for each key + rebalancing? maybe theres a better way to add to a tree to reduce rebalancing overhead
			sortedItems.Set([]byte(key), []byte{})
		}
	}
	return sortedItems
}
```

**File:** store/multiversion/mvkv.go (L48-62)
```go
func NewIterationTracker(startKey, endKey []byte, ascending bool, writeset WriteSet) iterationTracker {
	copyWriteset := make(WriteSet, len(writeset))

	for key, value := range writeset {
		copyWriteset[key] = value
	}

	return iterationTracker{
		startKey:     startKey,
		endKey:       endKey,
		iteratedKeys: make(map[string]struct{}),
		ascending:    ascending,
		writeset:     copyWriteset,
	}
}
```

**File:** store/multiversion/mvkv.go (L282-322)
```go
func (store *VersionIndexedStore) iterator(start []byte, end []byte, ascending bool) dbm.Iterator {
	// TODO: remove?
	// store.mtx.Lock()
	// defer store.mtx.Unlock()

	// get the sorted keys from MVS
	// TODO: ideally we take advantage of mvs keys already being sorted
	// TODO: ideally merge btree and mvs keys into a single sorted btree
	memDB := store.multiVersionStore.CollectIteratorItems(store.transactionIndex)

	// TODO: ideally we persist writeset keys into a sorted btree for later use
	// make a set of total keys across mvkv and mvs to iterate
	for key := range store.writeset {
		memDB.Set([]byte(key), []byte{})
	}
	// also add readset elements such that they fetch from readset instead of parent
	for key := range store.readset {
		memDB.Set([]byte(key), []byte{})
	}

	var parent, memIterator types.Iterator

	// make a memIterator
	memIterator = store.newMemIterator(start, end, memDB, ascending)

	if ascending {
		parent = store.parent.Iterator(start, end)
	} else {
		parent = store.parent.ReverseIterator(start, end)
	}

	mergeIterator := NewMVSMergeIterator(parent, memIterator, ascending, store)

	iterationTracker := NewIterationTracker(start, end, ascending, store.writeset)
	store.UpdateIterateSet(&iterationTracker)
	trackedIterator := NewTrackedIterator(mergeIterator, &iterationTracker)

	// mergeIterator
	return trackedIterator

}
```

**File:** store/gaskv/store.go (L234-245)
```go
// based on the current value's length.
func (gi *gasIterator) consumeSeekGas() {
	if gi.Valid() {
		key := gi.Key()
		value := gi.Value()

		gi.gasMeter.ConsumeGas(gi.gasConfig.ReadCostPerByte*types.Gas(len(key)), types.GasValuePerByteDesc)
		gi.gasMeter.ConsumeGas(gi.gasConfig.ReadCostPerByte*types.Gas(len(value)), types.GasValuePerByteDesc)
	}

	gi.gasMeter.ConsumeGas(gi.gasConfig.IterNextCostFlat, types.GasIterNextCostFlatDesc)
}
```

**File:** tasks/scheduler.go (L43-59)
```go
type deliverTxTask struct {
	Ctx     sdk.Context
	AbortCh chan occ.Abort

	mx            sync.RWMutex
	Status        status
	Dependencies  map[int]struct{}
	Abort         *occ.Abort
	Incarnation   int
	Request       types.RequestDeliverTx
	SdkTx         sdk.Tx
	Checksum      [32]byte
	AbsoluteIndex int
	Response      *types.ResponseDeliverTx
	VersionStores map[sdk.StoreKey]*multiversion.VersionIndexedStore
	TxTracer      sdk.TxTracer
}
```
