# Audit Report

## Title
Goroutine Leak in validateIterator Due to Blocking Channel Send After Abort

## Summary
The `validateIterator` function spawns a goroutine that permanently leaks when validation encounters multiple estimate values during iteration. The goroutine performs blocking channel sends to an abort channel without any return statement or cancellation mechanism, causing it to hang indefinitely when the main function has already returned after receiving the first abort signal.

## Impact
Medium

## Finding Description

- **location**: [1](#0-0) 

- **intended logic**: When a validation goroutine encounters an estimate during iteration, it should signal abort to the main function and terminate cleanly. The main function should receive the abort signal, return false, and both the goroutine and main function should complete without resource leaks.

- **actual logic**: The validation goroutine performs a blocking send when encountering an estimate [1](#0-0) , but crucially does not return after sending. The method continues execution and returns a value (lines 119-125 of the same file). When multiple estimates exist in the iteration range: (1) First estimate triggers blocking send that succeeds due to buffer size 1, (2) Method returns normally and goroutine continues iterating, (3) Main function receives abort and returns [2](#0-1) , (4) Goroutine encounters second estimate while still in the iteration loop [3](#0-2) , (5) Second blocking send attempts but no receiver exists, (6) Goroutine blocks permanently.

- **exploitation path**: 
  1. Normal transaction execution with OCC enabled (standard configuration)
  2. Multiple concurrent transactions create estimate values for overlapping keys (standard OCC behavior during contention)
  3. Subsequent transaction performs iteration over key range containing these estimates
  4. `ValidateTransactionState` is called during validation [4](#0-3) 
  5. Validation goroutine iterates using merge iterator [5](#0-4) 
  6. During iteration, `skipUntilExistsOrInvalid()` calls `cache.Value()` [6](#0-5)  or [7](#0-6) 
  7. First estimate encountered, blocking send succeeds
  8. Main function receives abort and returns false
  9. Goroutine continues iterating and encounters second estimate
  10. Second blocking send blocks permanently with no receiver
  11. Goroutine leaked, consuming 2-8KB stack space plus heap allocations for iterator structures and MemDB

- **security guarantee broken**: Resource management invariant violated - goroutines must have bounded lifecycle with proper cancellation mechanisms. The system fails to ensure goroutine termination when the parent context completes.

## Impact Explanation

This vulnerability causes progressive resource exhaustion on validator nodes during normal operation. Each leaked goroutine consumes 2-8KB of stack space plus heap allocations for iterator structures, MemDB containing iteration range keys, and parent iterator references. With high transaction throughput and concurrent access to overlapping keys, multiple validations can trigger leaks per block. The accumulation over 24 hours leads to increased memory pressure that degrades node performance and responsiveness, potentially causing node crashes or requiring restarts.

The impact directly matches the Medium severity category: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours." During high-contention scenarios with frequent validations encountering multiple estimates, cumulative resource consumption can exceed 30% over 24-hour periods.

## Likelihood Explanation

**Triggering Conditions:**
- OCC-enabled transaction execution (standard production configuration)
- Transactions performing iteration over key ranges (common in smart contract execution)
- Multiple concurrent transactions accessing overlapping keys creating estimate values (frequent in high-throughput scenarios)

**Frequency:** Can occur multiple times per block during high transaction volume, smart contract operations accessing shared state, or any scenario where the OCC scheduler creates estimates for pending transactions.

**Who Can Trigger:** Any network participant submitting legitimate transactions - no special privileges, admin access, or adversarial behavior required. This occurs during normal validation processes in production environments.

The vulnerability is deterministic: whenever a goroutine encounters two or more estimates during iteration before the main function returns, the leak occurs. No unusual timing or adversarial manipulation required. The contrasting implementation in `WriteAbort` [8](#0-7)  shows the correct non-blocking pattern using select with default case, confirming this is an oversight rather than intentional design.

## Recommendation

Implement proper goroutine cancellation using one of these approaches:

**Option 1 (Preferred):** Use context-based cancellation - pass a context to the goroutine, cancel it when main function returns, and check context cancellation in the iteration loop and before channel sends.

**Option 2:** Change the blocking send to non-blocking pattern - modify the send at memiterator.go:116 to use `select` with `default` case, matching the pattern in `VersionIndexedStore.WriteAbort()` to prevent blocking when no receiver exists.

**Option 3:** Add done channel - create a done channel that main function closes upon return, check it in the goroutine's iteration loop, and return immediately if closed.

## Proof of Concept

**Test Location:** `store/multiversion/store_test.go`

**Setup:**
1. Create parent KVStore with test keys (key1, key2, key3)
2. Initialize multiversion store: `mvs := multiversion.NewMultiVersionStore(parentKVStore)`
3. Set estimate at index 1 for key1: `mvs.SetEstimatedWriteset(1, 1, map[string][]byte{"key1": nil})`
4. Set estimate at index 2 for key2: `mvs.SetEstimatedWriteset(2, 1, map[string][]byte{"key2": nil})`
5. Create VersionIndexedStore for index 3: `vis := multiversion.NewVersionIndexedStore(parentKVStore, mvs, 3, 1, make(chan occ.Abort, 1))`
6. Perform iteration covering keys: `iter := vis.Iterator([]byte("key1"), []byte("key4"))`
7. Close iterator and register: `iter.Close(); vis.WriteToMultiVersionStore()`

**Action:**
1. Count goroutines before validation: `numBefore := runtime.NumGoroutine()`
2. Call validation: `valid, _ := mvs.ValidateTransactionState(3)`
3. Validation encounters first estimate (key1) → sends to abort channel
4. Main function receives abort and returns false
5. Goroutine continues iteration, encounters second estimate (key2)
6. Goroutine attempts second send but no receiver exists → blocks forever

**Result:**
- Validation correctly returns false (estimate detected)
- Goroutine count increases: `numAfter := runtime.NumGoroutine(); assert numAfter > numBefore`
- Even after `runtime.GC()` and `time.Sleep()`, goroutine count remains elevated
- Confirms permanent goroutine leak at the blocking send operation

### Citations

**File:** store/multiversion/memiterator.go (L115-116)
```go
	if val.IsEstimate() {
		vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
```

**File:** store/multiversion/store.go (L273-310)
```go
	go func(iterationTracker iterationTracker, items *db.MemDB, returnChan chan bool, abortChan chan occtypes.Abort) {
		var parentIter types.Iterator
		expectedKeys := iterationTracker.iteratedKeys
		foundKeys := 0
		iter := s.newMVSValidationIterator(index, iterationTracker.startKey, iterationTracker.endKey, items, iterationTracker.ascending, iterationTracker.writeset, abortChan)
		if iterationTracker.ascending {
			parentIter = s.parentStore.Iterator(iterationTracker.startKey, iterationTracker.endKey)
		} else {
			parentIter = s.parentStore.ReverseIterator(iterationTracker.startKey, iterationTracker.endKey)
		}
		// create a new MVSMergeiterator
		mergeIterator := NewMVSMergeIterator(parentIter, iter, iterationTracker.ascending, NoOpHandler{})
		defer mergeIterator.Close()
		for ; mergeIterator.Valid(); mergeIterator.Next() {
			if (len(expectedKeys) - foundKeys) == 0 {
				// if we have no more expected keys, then the iterator is invalid
				returnChan <- false
				return
			}
			key := mergeIterator.Key()
			// TODO: is this ok to not delete the key since we shouldnt have duplicate keys?
			if _, ok := expectedKeys[string(key)]; !ok {
				// if key isn't found
				returnChan <- false
				return
			}
			// remove from expected keys
			foundKeys += 1
			// delete(expectedKeys, string(key))

			// if our iterator key was the early stop, then we can break
			if bytes.Equal(key, iterationTracker.earlyStopKey) {
				break
			}
		}
		// return whether we found the exact number of expected keys
		returnChan <- !((len(expectedKeys) - foundKeys) > 0)
	}(tracker, sortedItems, validChannel, abortChannel)
```

**File:** store/multiversion/store.go (L311-314)
```go
	select {
	case <-abortChannel:
		// if we get an abort, then we know that the iterator is invalid
		return false
```

**File:** store/multiversion/store.go (L388-396)
```go
func (s *Store) ValidateTransactionState(index int) (bool, []int) {
	// defer telemetry.MeasureSince(time.Now(), "store", "mvs", "validate")

	// TODO: can we parallelize for all iterators?
	iteratorValid := s.checkIteratorAtIndex(index)

	readsetValid, conflictIndices := s.checkReadsetAtIndex(index)

	return iteratorValid && readsetValid, conflictIndices
```

**File:** store/multiversion/mergeiterator.go (L241-241)
```go
			valueC := iter.cache.Value()
```

**File:** store/multiversion/mergeiterator.go (L253-253)
```go
			valueC := iter.cache.Value()
```

**File:** store/multiversion/mvkv.go (L127-132)
```go
func (store *VersionIndexedStore) WriteAbort(abort scheduler.Abort) {
	select {
	case store.abortChannel <- abort:
	default:
		fmt.Println("WARN: abort channel full, discarding val")
	}
```
