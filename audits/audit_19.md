# Audit Report

## Title
Race Condition in CommitKVStoreCache Due to Improper Read Lock Usage During Cache Write Operations

## Summary
The `getAndWriteToCache` method uses `RLock()` (read lock) while performing write operations on a non-thread-safe LRU cache, allowing multiple goroutines to concurrently corrupt the cache during parallel transaction execution. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `store/cache/cache.go`, lines 113-119

**Intended Logic:**
The `CommitKVStoreCache` should safely handle concurrent access during transaction parallelization by using proper synchronization. When populating the cache with uncached keys, only one goroutine should modify the cache at a time. [2](#0-1) 

**Actual Logic:**
The `getAndWriteToCache` method acquires `RLock()` before calling `cache.Add()`. Since `RLock()` allows multiple goroutines to hold the read lock simultaneously, multiple threads can execute `cache.Add()` concurrently on the non-thread-safe `lru.TwoQueueCache` from hashicorp/golang-lru/v2. [3](#0-2) 

This contradicts the synchronization pattern used in other cache-modifying methods which correctly use exclusive `Lock()`: [4](#0-3) [5](#0-4) [6](#0-5) 

**Exploitation Path:**
1. The scheduler spawns worker goroutines for concurrent transaction execution [7](#0-6) 

2. Each transaction uses a `VersionIndexedStore` with a shared `CommitKVStoreCache` as parent [8](#0-7) 

3. When a key is not in the multiversion store, it reads from the parent store [9](#0-8) 

4. If the key is not cached, `getAndWriteToCache()` is called [10](#0-9) 

5. Multiple goroutines acquire `RLock` concurrently and call `cache.Add()` without mutual exclusion, corrupting the cache's internal data structures

**Security Guarantee Broken:**
This violates the thread-safety guarantee for concurrent access documented in the code. The hashicorp/golang-lru library requires external synchronization, which is not provided when using `RLock` for write operations.

## Impact Explanation

This vulnerability causes cache corruption during concurrent transaction processing, leading to:

1. **Node Instability**: Corrupted cache internal structures (linked lists, hash maps) cause panics from nil pointer dereferences or invalid memory access
2. **Non-Deterministic Behavior**: Corrupted cache state leads to unpredictable transaction execution results
3. **Network Degradation**: During high transaction throughput, multiple nodes experiencing this race condition can crash, impacting network availability

This qualifies as **Medium severity** under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Triggering Conditions:**
- Any network participant can trigger this by submitting normal transactions
- No special privileges required
- Concurrent transaction processing is the default operational mode
- Multiple transactions must access the same uncached keys simultaneously

**Frequency:**
The race occurs during:
- High transaction throughput periods
- After cache evictions or node restarts when cache is cold
- When accessing newly introduced keys

The vulnerability is more exploitable than typical race conditions because `RLock` allows unlimited concurrent access, maximizing collision probability. With sufficient transaction volume, the likelihood of triggering this race increases significantly.

## Recommendation

Change `getAndWriteToCache` to use an exclusive write lock:

```go
func (ckv *CommitKVStoreCache) getAndWriteToCache(key []byte) []byte {
    ckv.mtx.Lock()  // Changed from RLock
    defer ckv.mtx.Unlock()  // Changed from RUnlock
    value := ckv.CommitKVStore.Get(key)
    ckv.cache.Add(string(key), value)
    return value
}
```

This ensures only one goroutine can modify the cache at a time, matching the pattern in `Set()`, `Delete()`, and `Reset()` methods.

## Proof of Concept

**Setup:**
1. Create a `CommitKVStoreCache` with an underlying store
2. Populate the underlying store with keys not yet in the cache
3. Launch multiple goroutines (10+) simulating concurrent transaction execution

**Action:**
1. All goroutines concurrently call `Get()` on the same uncached keys
2. This triggers concurrent calls to `getAndWriteToCache()`
3. Multiple goroutines acquire `RLock` simultaneously and call `cache.Add()` concurrently

**Result:**
Running with Go's race detector (`go test -race`) would report data races in cache operations. Without the race detector, the test can observe panics from corrupted cache state during high concurrency. The race occurs because `RLock` allows multiple concurrent holders, enabling simultaneous execution of the write operation `cache.Add()` on the non-thread-safe LRU cache.

### Citations

**File:** store/cache/cache.go (L34-36)
```go
		// the same CommitKVStoreCache may be accessed concurrently by multiple
		// goroutines due to transaction parallelization
		mtx sync.RWMutex
```

**File:** store/cache/cache.go (L113-119)
```go
func (ckv *CommitKVStoreCache) getAndWriteToCache(key []byte) []byte {
	ckv.mtx.RLock()
	defer ckv.mtx.RUnlock()
	value := ckv.CommitKVStore.Get(key)
	ckv.cache.Add(string(key), value)
	return value
}
```

**File:** store/cache/cache.go (L124-133)
```go
func (ckv *CommitKVStoreCache) Get(key []byte) []byte {
	types.AssertValidKey(key)

	if value, ok := ckv.getFromCache(key); ok {
		return value
	}

	// if not found in the cache, query the underlying CommitKVStore and init cache value
	return ckv.getAndWriteToCache(key)
}
```

**File:** store/cache/cache.go (L137-146)
```go
func (ckv *CommitKVStoreCache) Set(key, value []byte) {
	ckv.mtx.Lock()
	defer ckv.mtx.Unlock()

	types.AssertValidKey(key)
	types.AssertValidValue(value)

	ckv.cache.Add(string(key), value)
	ckv.CommitKVStore.Set(key, value)
}
```

**File:** store/cache/cache.go (L150-156)
```go
func (ckv *CommitKVStoreCache) Delete(key []byte) {
	ckv.mtx.Lock()
	defer ckv.mtx.Unlock()

	ckv.cache.Remove(string(key))
	ckv.CommitKVStore.Delete(key)
}
```

**File:** store/cache/cache.go (L158-163)
```go
func (ckv *CommitKVStoreCache) Reset() {
	ckv.mtx.Lock()
	defer ckv.mtx.Unlock()

	ckv.cache.Purge()
}
```

**File:** go.mod (L28-28)
```text
	github.com/hashicorp/golang-lru/v2 v2.0.1
```

**File:** tasks/scheduler.go (L135-148)
```go
func start(ctx context.Context, ch chan func(), workers int) {
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case work := <-ch:
					work()
				}
			}
		}()
	}
}
```

**File:** tasks/scheduler.go (L217-227)
```go
func (s *scheduler) tryInitMultiVersionStore(ctx sdk.Context) {
	if s.multiVersionStores != nil {
		return
	}
	mvs := make(map[sdk.StoreKey]multiversion.MultiVersionStore)
	keys := ctx.MultiStore().StoreKeys()
	for _, sk := range keys {
		mvs[sk] = multiversion.NewMultiVersionStore(ctx.MultiStore().GetKVStore(sk))
	}
	s.multiVersionStores = mvs
}
```

**File:** store/multiversion/mvkv.go (L173-175)
```go
	parentValue := store.parent.Get(key)
	store.UpdateReadSet(key, parentValue)
	return parentValue
```
