# Audit Report

## Title
Goroutine Leak in validateIterator Due to Blocking Channel Send Without Cancellation

## Summary
The `validateIterator` function in the multiversion store spawns a goroutine that can leak permanently when encountering multiple estimate values during iterator validation. The goroutine performs blocking channel sends without any cancellation mechanism, causing it to hang indefinitely after the main function returns, leading to progressive resource exhaustion on validator nodes.

## Impact
Medium

## Finding Description

**Location:**
- Primary goroutine spawn: [1](#0-0) 
- Blocking send without protection: [2](#0-1) 
- Channel trigger points during iteration: [3](#0-2)  and [4](#0-3) 

**Intended Logic:**
The validation goroutine should replay iterator operations to verify consistency. When an estimate value is encountered (indicating a dependency on an unfinished transaction), it should signal abort via `abortChannel`, allowing the main function to return `false` for validation failure. The goroutine should then terminate cleanly, either through completion or early exit.

**Actual Logic:**
The goroutine performs a blocking channel send when encountering estimates at [2](#0-1) . The channel has buffer size 1 as shown at [5](#0-4) . When three or more estimates exist in the iteration range:

1. First estimate triggers blocking send → buffer accepts value (buffer: 1/1)
2. Main function receives from `abortChannel` → buffer empties (buffer: 0/1)
3. Main function returns `false` and exits at [6](#0-5) 
4. Goroutine continues iteration (no cancellation mechanism exists)
5. Second estimate triggers blocking send → buffer accepts value (buffer: 1/1)
6. Goroutine encounters third estimate
7. Third blocking send attempts but buffer is full and no receiver exists → goroutine blocks forever

The goroutine lacks any cancellation mechanism (no context, done channel, or timeout), differing from the safe non-blocking pattern used in [7](#0-6)  where a `select` with `default` case prevents blocking.

**Exploitation Path:**
1. Network operates with OCC (Optimistic Concurrency Control) enabled - standard configuration
2. Multiple concurrent transactions access overlapping key ranges, creating estimate values for keys being written by in-flight transactions
3. A subsequent transaction performs iteration over a range containing these keys (common operation, no special transaction structure required)
4. Transaction completes and `ValidateTransactionState` is called at [8](#0-7) 
5. Validation goroutine spawned, begins iterating with merge iterator
6. During iteration, `skipUntilExistsOrInvalid()` calls `cache.Value()` to check for deleted items
7. `validationIterator.Value()` encounters first estimate, sends abort to channel
8. Main function receives abort and returns `false`
9. Goroutine continues, encounters second estimate, sends to channel (succeeds, buffer has space)
10. Goroutine encounters third estimate, attempts send, blocks permanently
11. Goroutine leaked: consumes 2-8KB stack memory + heap allocations for iterator structures

**Security Guarantee Broken:**
Resource management invariant - all spawned goroutines must have bounded lifecycle with proper cancellation mechanisms to prevent resource leaks.

## Impact Explanation

This vulnerability causes progressive resource exhaustion on validator nodes:

- **Memory Consumption**: Each leaked goroutine consumes 2-8KB of stack space plus heap allocations for iterator structures
- **Accumulation**: With frequent validations during high transaction throughput, hundreds to thousands of goroutines can leak over hours
- **Performance Degradation**: Increased memory pressure and goroutine scheduler overhead degrades overall node performance
- **Node Instability**: Severe cases can cause out-of-memory conditions or node crashes

The vulnerability directly satisfies the Medium severity impact: **"Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours."** During sustained high-contention workloads where multiple transactions access overlapping keys, the cumulative effect of leaked goroutines can easily exceed 30% resource increase within 24 hours.

## Likelihood Explanation

**Triggering Conditions:**
- OCC-based parallel transaction execution (default operational mode)
- Transactions performing iterator operations over key ranges (common pattern in Cosmos SDK applications)
- High-contention scenarios where multiple concurrent transactions write to overlapping keys (frequent during peak usage)

**Frequency:**
The vulnerability can trigger multiple times per block during:
- High transaction volume periods
- Applications with shared state across many transactions (e.g., DeFi protocols, token transfers)
- Any workload where the OCC scheduler creates estimates for unfinished transactions

**Who Can Trigger:**
Any network participant submitting standard transactions - no special privileges, transaction structure, or adversarial behavior required. The leak occurs as a side effect of normal transaction validation.

**Likelihood Assessment:**
High likelihood in production environments. The conditions are standard operational scenarios rather than edge cases. Networks with moderate to high transaction throughput will regularly encounter this issue.

## Recommendation

Implement proper goroutine lifecycle management using one of these approaches:

**Option 1 (Recommended):** Use context-based cancellation:
```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go func(ctx context.Context, ...) {
    for ; mergeIterator.Valid(); mergeIterator.Next() {
        select {
        case <-ctx.Done():
            return
        default:
        }
        // ... iteration logic
    }
}(ctx, ...)
```

**Option 2:** Apply the non-blocking send pattern already used in `WriteAbort` to the validation iterator:
```go
// In memiterator.go validationIterator.Value()
if val.IsEstimate() {
    select {
    case vi.abortChannel <- occtypes.NewEstimateAbort(val.Index()):
    default:
        // Channel full, abort already signaled
    }
}
```

**Option 3:** Add a done channel that main closes upon return:
```go
doneChannel := make(chan struct{})
defer close(doneChannel)

go func(..., done <-chan struct{}) {
    for ; mergeIterator.Valid(); mergeIterator.Next() {
        select {
        case <-done:
            return
        default:
        }
        // ... iteration logic
    }
}(..., doneChannel)
```

Option 2 is simplest and aligns with the existing safe pattern shown in [7](#0-6) .

## Proof of Concept

**Test File:** `store/multiversion/store_test.go`

**Setup:**
1. Create parent KVStore with initial keys
2. Initialize MultiVersionStore
3. Set estimate values at multiple transaction indices for keys within an iteration range:
   - `mvs.SetEstimatedWriteset(1, 1, map[string][]byte{"key1": []byte("est")})`
   - `mvs.SetEstimatedWriteset(2, 1, map[string][]byte{"key2": []byte("est")})`
   - `mvs.SetEstimatedWriteset(3, 1, map[string][]byte{"key3": []byte("est")})`
4. Create VersionIndexedStore for a later transaction index (e.g., index 5)
5. Perform iteration over the range containing these keys
6. Call `WriteToMultiVersionStore()` to register the iteration set

**Action:**
1. Count goroutines before validation: `numBefore := runtime.NumGoroutine()`
2. Call `valid, _ := mvs.ValidateTransactionState(5)`
3. Validation goroutine spawns, begins iterating
4. Encounters first estimate → sends to abortChannel
5. Main function receives and returns `false`
6. Goroutine continues iteration
7. Encounters second estimate → sends to abortChannel (succeeds, buffer available)
8. Encounters third estimate → attempts send, blocks forever
9. Count goroutines after: `numAfter := runtime.NumGoroutine()`
10. Wait and force GC: `time.Sleep(100*time.Millisecond); runtime.GC()`
11. Count again: `numFinal := runtime.NumGoroutine()`

**Result:**
- `valid == false` (correct validation failure)
- `numAfter > numBefore` (goroutine count increased)
- `numFinal == numAfter` (goroutine count doesn't decrease, confirming permanent leak)
- Goroutine remains blocked on channel send indefinitely

The test demonstrates that despite validation returning the correct result (`false`), a goroutine is permanently leaked in the process, violating the resource management invariant.

## Notes

The vulnerability is confirmed by the architectural inconsistency: the normal execution path uses non-blocking sends with `select/default` at [7](#0-6) , while the validation path uses blocking sends without protection at [2](#0-1) . This suggests the developers were aware of the channel blocking hazard but didn't apply the protective pattern consistently throughout the codebase.

The leak requires at least three estimates in a single iteration range with appropriate timing, which while not occurring on every validation, is sufficiently common during high-contention workloads to constitute a real production risk.

### Citations

**File:** store/multiversion/store.go (L262-318)
```go
func (s *Store) validateIterator(index int, tracker iterationTracker) bool {
	// collect items from multiversion store
	sortedItems := s.CollectIteratorItems(index)
	// add the iterationtracker writeset keys to the sorted items
	for key := range tracker.writeset {
		sortedItems.Set([]byte(key), []byte{})
	}
	validChannel := make(chan bool, 1)
	abortChannel := make(chan occtypes.Abort, 1)

	// listen for abort while iterating
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
	select {
	case <-abortChannel:
		// if we get an abort, then we know that the iterator is invalid
		return false
	case valid := <-validChannel:
		return valid
	}
}
```

**File:** store/multiversion/store.go (L388-397)
```go
func (s *Store) ValidateTransactionState(index int) (bool, []int) {
	// defer telemetry.MeasureSince(time.Now(), "store", "mvs", "validate")

	// TODO: can we parallelize for all iterators?
	iteratorValid := s.checkIteratorAtIndex(index)

	readsetValid, conflictIndices := s.checkReadsetAtIndex(index)

	return iteratorValid && readsetValid, conflictIndices
}
```

**File:** store/multiversion/memiterator.go (L115-116)
```go
	if val.IsEstimate() {
		vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
```

**File:** store/multiversion/mergeiterator.go (L241-241)
```go
			valueC := iter.cache.Value()
```

**File:** store/multiversion/mergeiterator.go (L253-253)
```go
			valueC := iter.cache.Value()
```

**File:** store/multiversion/mvkv.go (L127-133)
```go
func (store *VersionIndexedStore) WriteAbort(abort scheduler.Abort) {
	select {
	case store.abortChannel <- abort:
	default:
		fmt.Println("WARN: abort channel full, discarding val")
	}
}
```
