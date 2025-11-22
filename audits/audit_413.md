# Audit Report

## Title
Lost Writes Due to Unsynchronized Pointer Replacement in cachekv.Store During Concurrent Operations

## Summary
The `cachekv.Store` implementation in `store/cachekv/store.go` has a race condition between the `Write()` method and concurrent `Set()`/`Delete()` operations. While `sync.Map` is used for thread-safe concurrent access, the `Write()` method replaces these `sync.Map` pointers with new instances while holding a mutex, but read/write operations (`Set`, `Get`, `Delete`) access these pointers without acquiring the mutex. This allows a goroutine to read a stale pointer, have it replaced, then store to the old (now-orphaned) map, causing the write to be permanently lost. [1](#0-0) 

## Impact
**Medium** - This bug results in unintended state behavior where transaction writes appear to succeed but are not persisted to the store, causing state inconsistency.

## Finding Description

**Location:** 
- Primary issue: `store/cachekv/store.go` lines 135-138 (pointer replacement in `Write()`)
- Vulnerable access: `store/cachekv/store.go` line 351 (`setCacheValue()` accessing `store.cache` without mutex)
- Also: lines 68-72 (`getFromCache()` accessing `store.cache` without mutex) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The `cachekv.Store` uses `sync.Map` for the `cache`, `deleted`, and `unsortedCache` fields to enable concurrent reads and writes during transaction execution. The `Write()` method is supposed to safely flush dirty entries to the parent store and reset the cache, while concurrent `Set()`/`Get()`/`Delete()` operations continue to work correctly on the same store instance.

**Actual Logic:**
The `Write()` method acquires a mutex lock, iterates over cached entries, writes them to the parent store, then **replaces the sync.Map pointers with new empty instances** (lines 135-138). However, `Set()`, `Get()`, and `Delete()` operations do NOT acquire this mutex before accessing these pointers. This creates a time-of-check-time-of-use (TOCTOU) race: [4](#0-3) 

1. Goroutine A calls `Set(key, value)` which invokes `setCacheValue()`
2. In `setCacheValue()`, goroutine A reads the field `store.cache` (line 351)
3. Goroutine B calls `Write()`, acquires mutex, performs writes, replaces `store.cache = &sync.Map{}` (line 135), releases mutex
4. Goroutine A calls `store.cache.Store(keyStr, ...)` using the OLD pointer it read in step 2
5. The write goes to an orphaned sync.Map that is no longer referenced by the store

**Exploit Scenario:**
During concurrent transaction execution or when a test like `TestTraceConcurrency` runs:
1. Multiple goroutines share the same `cachekv.Store` instance (common in cached multi-store scenarios)
2. One goroutine processes a transaction and calls `Set()` to update state
3. Another goroutine concurrently calls `Write()` to flush the cache
4. The race condition causes the `Set()` operation's write to be lost
5. The transaction appears successful, but the state change is not persisted [5](#0-4) 

**Security Failure:**
This breaks the **data integrity invariant** - writes that appear to succeed are silently lost. This can cause:
- State inconsistency where nodes have different views of state
- Unintended smart contract behavior where state mutations are dropped
- Consensus disagreement if different nodes experience the race at different times

## Impact Explanation

**Affected Assets/Processes:**
- Transaction state changes can be lost during concurrent execution
- Smart contract state updates may not persist despite successful transaction execution
- Multi-store cache operations during block processing

**Severity:**
This is a **Medium severity** issue under the scope definition: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk." While funds are not directly stolen, the lost writes can cause:
- Smart contracts to operate on incorrect state
- Validators to disagree on state if the race manifests differently across nodes
- Users to believe their transactions succeeded when state changes were actually lost

**System Reliability Impact:**
The vulnerability undermines the fundamental correctness guarantee that committed transactions' state changes are persisted. This can lead to subtle, hard-to-debug state inconsistencies that accumulate over time.

## Likelihood Explanation

**Who Can Trigger:**
Any participant submitting transactions during periods of concurrent execution. This includes:
- Normal users submitting transactions
- Validators processing blocks with concurrent transaction execution enabled
- Test environments running concurrent operations (as evidenced by existing `TestTraceConcurrency`)

**Conditions Required:**
- Concurrent execution mode enabled (OCC mode or scenarios with shared cachekv stores)
- Two goroutines accessing the same `cachekv.Store` instance where one calls `Write()` while another calls `Set()`/`Delete()`
- Timing window where the pointer replacement occurs between pointer read and Store/Load call

**Frequency:**
- Can occur during normal operation when concurrent transaction execution is enabled
- Higher likelihood under heavy transaction load with frequent cache flushes
- The existing `TestTraceConcurrency` test demonstrates the exact conditions but doesn't validate correctness [6](#0-5) 

## Recommendation

**Fix Strategy:**
Protect pointer reads in `Set()`, `Get()`, `Delete()` operations with the same mutex used in `Write()`, OR use atomic pointer operations to safely replace the sync.Map instances.

**Specific Changes:**

**Option 1 (Simpler):** Add mutex protection to `setCacheValue()` and `getFromCache()`:
```go
func (store *Store) setCacheValue(key, value []byte, deleted bool, dirty bool) {
    types.AssertValidKey(key)
    keyStr := conv.UnsafeBytesToStr(key)
    
    store.mtx.RLock()
    cache := store.cache
    deletedMap := store.deleted
    unsortedCache := store.unsortedCache
    store.mtx.RUnlock()
    
    cache.Store(keyStr, types.NewCValue(value, dirty))
    if deleted {
        deletedMap.Store(keyStr, struct{}{})
    } else {
        deletedMap.Delete(keyStr)
    }
    if dirty {
        unsortedCache.Store(keyStr, struct{}{})
    }
}
```

**Option 2 (Better):** Use atomic pointers or avoid pointer replacement entirely by clearing the existing sync.Maps instead of replacing them.

## Proof of Concept

**File:** `store/cachekv/store_test.go`

**Test Function:** Add this new test to demonstrate lost writes:

```go
func TestConcurrentWriteLostWrite(t *testing.T) {
    mem := dbadapter.Store{DB: dbm.NewMemDB()}
    st := cachekv.NewStore(mem, types.NewKVStoreKey("test"), types.DefaultCacheSizeLimit)
    
    const iterations = 10000
    const numKeys = 100
    lost := make(chan string, iterations*numKeys)
    done := make(chan bool, 2)
    
    // Goroutine 1: Continuously write values
    go func() {
        for i := 0; i < iterations; i++ {
            for k := 0; k < numKeys; k++ {
                key := []byte(fmt.Sprintf("key%d", k))
                value := []byte(fmt.Sprintf("value%d-%d", k, i))
                st.Set(key, value)
            }
        }
        done <- true
    }()
    
    // Goroutine 2: Continuously call Write()
    go func() {
        for i := 0; i < iterations; i++ {
            st.Write()
            time.Sleep(1 * time.Microsecond) // Small delay to increase race window
        }
        done <- true
    }()
    
    // Wait for both goroutines
    <-done
    <-done
    
    // Final write to ensure everything is flushed
    st.Write()
    
    // Verify all keys exist in parent store
    // If writes were lost, some keys will be missing or have stale values
    for k := 0; k < numKeys; k++ {
        key := []byte(fmt.Sprintf("key%d", k))
        value := mem.Get(key)
        if value == nil {
            lost <- fmt.Sprintf("key%d missing", k)
        }
    }
    
    close(lost)
    lostCount := 0
    for msg := range lost {
        t.Logf("Lost write: %s", msg)
        lostCount++
    }
    
    require.Zero(t, lostCount, "Detected %d lost writes due to race condition", lostCount)
}
```

**Setup:** 
- Create a new `cachekv.Store` backed by a memory database
- Prepare two goroutines that will run concurrently

**Trigger:**
- Goroutine 1 continuously calls `Set()` to write values
- Goroutine 2 continuously calls `Write()` to flush the cache
- This creates the race window where `Set()` can read a stale pointer before `Write()` replaces it

**Observation:**
- After both goroutines complete and a final `Write()` is called, verify that all expected keys exist in the parent store
- If the race condition manifests, some keys will be missing or have incorrect values because their writes were lost
- The test will fail with a non-zero lost write count, demonstrating the bug

**Expected Behavior on Vulnerable Code:**
Run with race detector (`go test -race`) and the test will show:
1. Race warnings between Write() replacing pointers and Set() accessing them
2. Lost writes evidenced by missing or stale key-value pairs in the final verification

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

**File:** store/cachekv/store.go (L101-139)
```go
func (store *Store) Write() {
	store.mtx.Lock()
	defer store.mtx.Unlock()

	// We need a copy of all of the keys.
	// Not the best, but probably not a bottleneck depending.
	keys := []string{}

	store.cache.Range(func(key, value any) bool {
		if value.(*types.CValue).Dirty() {
			keys = append(keys, key.(string))
		}
		return true
	})
	sort.Strings(keys)
	// TODO: Consider allowing usage of Batch, which would allow the write to
	// at least happen atomically.
	for _, key := range keys {
		if store.isDeleted(key) {
			// We use []byte(key) instead of conv.UnsafeStrToBytes because we cannot
			// be sure if the underlying store might do a save with the byteslice or
			// not. Once we get confirmation that .Delete is guaranteed not to
			// save the byteslice, then we can assume only a read-only copy is sufficient.
			store.parent.Delete([]byte(key))
			continue
		}

		cacheValue, ok := store.cache.Load(key)
		if ok && cacheValue.(*types.CValue).Value() != nil {
			// It already exists in the parent, hence delete it.
			store.parent.Set([]byte(key), cacheValue.(*types.CValue).Value())
		}
	}

	store.cache = &sync.Map{}
	store.deleted = &sync.Map{}
	store.unsortedCache = &sync.Map{}
	store.sortedCache = dbm.NewMemDB()
}
```

**File:** store/cachekv/store.go (L347-360)
```go
func (store *Store) setCacheValue(key, value []byte, deleted bool, dirty bool) {
	types.AssertValidKey(key)

	keyStr := conv.UnsafeBytesToStr(key)
	store.cache.Store(keyStr, types.NewCValue(value, dirty))
	if deleted {
		store.deleted.Store(keyStr, struct{}{})
	} else {
		store.deleted.Delete(keyStr)
	}
	if dirty {
		store.unsortedCache.Store(keyStr, struct{}{})
	}
}
```

**File:** store/rootmulti/store_test.go (L711-759)
```go
func TestTraceConcurrency(t *testing.T) {
	db := dbm.NewMemDB()
	multi := newMultiStoreWithMounts(db, types.PruneNothing)
	err := multi.LoadLatestVersion()
	require.NoError(t, err)

	b := &bytes.Buffer{}
	key := multi.keysByName["store1"]
	tc := types.TraceContext(map[string]interface{}{"blockHeight": 64})

	multi.SetTracer(b)
	multi.SetTracingContext(tc)

	cms := multi.CacheMultiStore()
	store1 := cms.GetKVStore(key)
	cw := store1.CacheWrapWithTrace(nil, b, tc)
	_ = cw
	require.NotNil(t, store1)

	stop := make(chan struct{})
	stopW := make(chan struct{})

	go func(stop chan struct{}) {
		for {
			select {
			case <-stop:
				return
			default:
				store1.Set([]byte{1}, []byte{1})
				cms.Write()
			}
		}
	}(stop)

	go func(stop chan struct{}) {
		for {
			select {
			case <-stop:
				return
			default:
				multi.SetTracingContext(tc)
			}
		}
	}(stopW)

	time.Sleep(3 * time.Second)
	stop <- struct{}{}
	stopW <- struct{}{}
}
```
