# Audit Report

## Title
Data Race in cachekv.Store Concurrent Iterator Creation Leading to Node Crash

## Summary
The `cachekv.Store` implementation has a critical data race when multiple iterators are created concurrently on the same store instance. The shared `sortedCache` field (a `dbm.MemDB`) is accessed without proper synchronization after the lock is released, causing concurrent read/write access that can crash nodes during parallel transaction execution. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
The vulnerability exists in the `iterator()` method at [2](#0-1) , specifically in how it manages the `sortedCache` field defined at [3](#0-2) .

**Intended Logic:** 
The `cachekv.Store` is designed to support concurrent writes during iteration, as documented in the KVStore interface contract: [4](#0-3) . The mutex lock in `iterator()` is intended to protect the creation of iterators and the synchronization of cached data.

**Actual Logic:** 
The `iterator()` method acquires a lock, calls `dirtyItems()` to move entries from `unsortedCache` to `sortedCache`, creates a `memIterator` backed by `sortedCache`, then releases the lock and returns the iterator. The returned iterator continues to read from the shared `sortedCache` AFTER the lock is released [5](#0-4) . When another goroutine calls `iterator()`, it acquires the lock and modifies the same `sortedCache` via `clearUnsortedCacheSubset()` [6](#0-5) , creating concurrent read/write access to the underlying `dbm.MemDB`.

**Exploit Scenario:**
In the parallel transaction execution system, multiple `VersionIndexedStore` instances share the same parent `cachekv.Store` [7](#0-6) . When concurrent transactions create iterators, each transaction's `Iterator()` call delegates to the shared parent store [8](#0-7) . 

Attack sequence:
1. Transaction A (goroutine 1) calls `visA.Iterator()` which invokes `parent.Iterator()`
2. The parent cachekv.Store creates an iterator backed by `sortedCache` and returns it
3. Transaction A begins iterating (reading from `sortedCache` outside the lock)
4. Transaction B (goroutine 2) concurrently calls `visB.Iterator()` which also invokes `parent.Iterator()`
5. Transaction B's call acquires the lock and executes `dirtyItems()`, which writes to `sortedCache` via `sortedCache.Set()`
6. Now we have concurrent access: goroutine 1 reading from `sortedCache`, goroutine 2 writing to it
7. Since `dbm.MemDB` is not thread-safe, this triggers a Go runtime panic on concurrent map access

**Security Failure:** 
This violates memory safety by allowing concurrent unsynchronized access to a non-thread-safe data structure. The Go runtime detects concurrent map read/write and panics, crashing the node.

## Impact Explanation

**Affected Components:**
- All nodes running parallel transaction execution with the multiversion store
- Any transaction processing that creates multiple iterators on shared stores
- Network consensus and availability

**Severity:**
- **Node Crashes:** Nodes will panic with "concurrent map read and map write" errors during normal parallel transaction execution
- **Consensus Disruption:** If multiple validators crash simultaneously, it can halt block production
- **DOS Vector:** Attackers can craft transactions that trigger frequent iterator creation, increasing crash probability
- **Non-Deterministic Behavior:** Different nodes may crash at different times based on timing, leading to unpredictable network behavior

This matters because it undermines the fundamental reliability of the parallel execution system, which is critical for Sei's performance advantages. The vulnerability can be triggered during normal operation without requiring any special privileges.

## Likelihood Explanation

**Trigger Conditions:**
- Any user can trigger this by submitting transactions that cause modules to create iterators
- No special permissions or configuration required
- Occurs during normal parallel transaction execution when the scheduler runs multiple transactions concurrently

**Frequency:**
- High likelihood during normal operation with parallel execution enabled
- The race window exists every time iterators are created on the shared parent store
- As transaction throughput increases, the probability of concurrent iterator creation increases
- Common module operations (balance queries, iteration over accounts, etc.) create iterators

**Who Can Exploit:**
- Any network participant submitting transactions
- No privilege escalation needed
- Can be triggered accidentally during high load or intentionally by crafting transaction patterns

## Recommendation

**Immediate Fix:**
Create a snapshot of `sortedCache` for each iterator instead of sharing the same instance. Modify the `iterator()` method to:

1. Clone the `sortedCache` contents into a new temporary `dbm.MemDB` before creating the iterator
2. Pass this cloned instance to `newMemIterator()` instead of the shared `store.sortedCache`
3. This ensures each iterator operates on its own isolated data structure

**Alternative Approach:**
Extend the lock protection to cover the entire iterator lifetime by:
1. Having iterators hold a read lock on the store while they're active
2. Implement reference counting to track active iterators
3. Block `Write()` operations until all iterators are closed

The snapshot approach is preferred as it maintains the "safe to write during iteration" contract without requiring complex lifecycle management.

## Proof of Concept

**File:** `store/cachekv/store_test.go`

**Test Function:** `TestConcurrentIteratorDataRace`

**Setup:**
```go
// Create a shared cachekv.Store
mem := dbadapter.Store{DB: dbm.NewMemDB()}
parentStore := cachekv.NewStore(mem, types.NewKVStoreKey("TestStore"), 1000)

// Populate with keys to create unsortedCache entries
for i := 0; i < 100; i++ {
    parentStore.Set(keyFmt(i), valFmt(i))
}
```

**Trigger:**
```go
// Launch two goroutines that concurrently create and use iterators
var wg sync.WaitGroup
wg.Add(2)

// Goroutine 1: Create iterator and iterate slowly
go func() {
    defer wg.Done()
    for j := 0; j < 10; j++ {
        // Add more keys to populate unsortedCache
        for i := 100 + j*10; i < 100 + (j+1)*10; i++ {
            parentStore.Set(keyFmt(i), valFmt(i))
        }
        // Create iterator - this triggers dirtyItems() which modifies sortedCache
        iter := parentStore.Iterator(nil, nil)
        for ; iter.Valid(); iter.Next() {
            _ = iter.Key()
            _ = iter.Value()
        }
        iter.Close()
    }
}()

// Goroutine 2: Concurrently create iterators
go func() {
    defer wg.Done()
    for j := 0; j < 10; j++ {
        // Add more keys
        for i := 200 + j*10; i < 200 + (j+1)*10; i++ {
            parentStore.Set(keyFmt(i), valFmt(i))
        }
        // This will race with goroutine 1's iterator access
        iter := parentStore.Iterator(nil, nil)
        for ; iter.Valid(); iter.Next() {
            _ = iter.Key()
            _ = iter.Value()
        }
        iter.Close()
    }
}()

wg.Wait()
```

**Observation:**
When run with `go test -race`, the Go race detector will report concurrent read/write access to the `dbm.MemDB` backing `sortedCache`. Without `-race`, the test will eventually panic with "concurrent map iteration and map write" or similar concurrent map access errors. The panic occurs when:
- One goroutine's iterator is reading from `sortedCache` via the `dbm.MemDB` iterator
- Another goroutine's `dirtyItems()` call is writing to `sortedCache` via `sortedCache.Set()`

The test demonstrates that the shared `sortedCache` is accessed concurrently without proper synchronization, violating Go's memory safety guarantees and causing node crashes.

### Citations

**File:** store/cachekv/store.go (L19-30)
```go
// Store wraps an in-memory cache around an underlying types.KVStore.
type Store struct {
	mtx           sync.RWMutex
	cache         *sync.Map
	deleted       *sync.Map
	unsortedCache *sync.Map
	sortedCache   *dbm.MemDB // always ascending sorted
	parent        types.KVStore
	eventManager  *sdktypes.EventManager
	storeKey      types.StoreKey
	cacheSize     int
}
```

**File:** store/cachekv/store.go (L169-193)
```go
func (store *Store) iterator(start, end []byte, ascending bool) types.Iterator {
	store.mtx.Lock()
	defer store.mtx.Unlock()
	// TODO: (occ) Note that for iterators, we'll need to have special handling (discussed in RFC) to ensure proper validation

	var parent, cache types.Iterator

	if ascending {
		parent = store.parent.Iterator(start, end)
	} else {
		parent = store.parent.ReverseIterator(start, end)
	}
	defer func() {
		if err := recover(); err != nil {
			// close out parent iterator, then reraise panic
			if parent != nil {
				parent.Close()
			}
			panic(err)
		}
	}()
	store.dirtyItems(start, end)
	cache = newMemIterator(start, end, store.sortedCache, store.deleted, ascending, store.eventManager, store.storeKey)
	return NewCacheMergeIterator(parent, cache, ascending, store.storeKey)
}
```

**File:** store/cachekv/store.go (L320-333)
```go
	for _, item := range unsorted {
		if item.Value == nil {
			// deleted element, tracked by store.deleted
			// setting arbitrary value
			if err := store.sortedCache.Set(item.Key, []byte{}); err != nil {
				panic(err)
			}

			continue
		}
		if err := store.sortedCache.Set(item.Key, item.Value); err != nil {
			panic(err)
		}
	}
```

**File:** store/types/store.go (L252-253)
```go
	// CONTRACT: No writes may happen within a domain while an iterator exists over it.
	// Exceptionally allowed for cachekv.Store, safe to write in the modules.
```

**File:** store/cachekv/memiterator.go (L36-40)
```go
	if ascending {
		iter, err = items.Iterator(start, end)
	} else {
		iter, err = items.ReverseIterator(start, end)
	}
```

**File:** store/multiversion/mvkv.go (L102-114)
```go
func NewVersionIndexedStore(parent types.KVStore, multiVersionStore MultiVersionStore, transactionIndex, incarnation int, abortChannel chan scheduler.Abort) *VersionIndexedStore {
	return &VersionIndexedStore{
		readset:           make(map[string][][]byte),
		writeset:          make(map[string][]byte),
		iterateset:        []*iterationTracker{},
		sortedStore:       dbm.NewMemDB(),
		parent:            parent,
		multiVersionStore: multiVersionStore,
		transactionIndex:  transactionIndex,
		incarnation:       incarnation,
		abortChannel:      abortChannel,
	}
}
```

**File:** store/multiversion/mvkv.go (L307-311)
```go
	if ascending {
		parent = store.parent.Iterator(start, end)
	} else {
		parent = store.parent.ReverseIterator(start, end)
	}
```
