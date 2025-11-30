# Audit Report

## Title
Non-Deterministic Iterator Validation Due to Race Condition in Channel Selection

## Summary
The `validateIterator` function in the multi-version store contains a race condition where encountering an estimate value during iterator validation sends an abort signal to `abortChannel` but allows execution to continue, eventually sending a result to `validChannel`. When both buffered channels contain values, Go's `select` statement uses non-deterministic random selection, causing different validator nodes to reach different conclusions about transaction validity during consensus.

## Impact
High

## Finding Description

**Location:** 
- Primary issue: `store/multiversion/store.go` lines 262-318 (validateIterator function)
- Contributing code: `store/multiversion/memiterator.go` lines 114-117 (validationIterator.Value)
- Validation entry: `store/multiversion/store.go` lines 387-397 (ValidateTransactionState) [1](#0-0) [2](#0-1) 

**Intended logic:**
When validating an iterator during optimistic concurrency control, if an estimate value is encountered (indicating a dependency on an unfinished transaction), the validation should deterministically abort and consistently return `false` across all validator nodes, similar to how the normal execution path handles estimates by panicking. [3](#0-2) 

**Actual logic:**
When `validationIterator.Value()` encounters an estimate, it sends an abort to `abortChannel` but continues execution without returning or panicking. The method proceeds to check if the value is deleted, caches the result, and returns a value. Meanwhile, the validation goroutine continues iterating through all keys and eventually sends the final validation result to `validChannel` at line 309. Both channels are buffered with capacity 1, allowing both sends to complete without blocking. When the main goroutine reaches the `select` statement at line 311, both channels have values ready. According to Go's specification, when multiple cases in a `select` are ready, one is chosen via uniform pseudo-random selection. This introduces non-determinism where different validator nodes processing identical state can randomly choose different channels, returning different validation results. [4](#0-3) [5](#0-4) [6](#0-5) 

**Exploitation path:**
1. Block processing begins via `DeliverTxBatch` in baseapp
2. Scheduler processes transactions concurrently using optimistic concurrency control
3. During validation phase, `findConflicts` is called for each task
4. This invokes `ValidateTransactionState` on each multiversion store
5. `ValidateTransactionState` calls `checkIteratorAtIndex`
6. For each iterator, `validateIterator` is called
7. The validation goroutine iterates using a merge iterator
8. During iteration, `mergeIterator.Valid()` internally calls `skipUntilExistsOrInvalid()`
9. This calls `cache.Value()` which invokes `validationIterator.Value()`
10. If the multiversion store has an estimate value for a key, `validationIterator.Value()` sends to `abortChannel` but continues execution
11. The goroutine completes iteration and sends result to `validChannel`
12. Both channels now contain values
13. The `select` statement randomly chooses which channel to read
14. Different validator nodes make different random choices
15. Validators compute different validation results, leading to different transaction execution and state hashes
16. Consensus fails permanently [7](#0-6) [8](#0-7) [9](#0-8) 

**Security guarantee broken:**
This violates the fundamental determinism requirement for blockchain consensus. All validator nodes must reach identical conclusions about transaction validity when processing the same block with identical state. The non-deterministic channel selection breaks this invariant.

## Impact Explanation

When different validator nodes process the same block, they must compute identical state hashes to maintain consensus. This race condition causes validators to reach different conclusions about which transactions are valid. Some validators may read from `abortChannel` and mark the transaction invalid, while others read from `validChannel` and mark it valid (or return a different validation result). This leads to different transaction execution orders, different state transitions, and ultimately different application state hashes. When validators cannot agree on the canonical chain state, the network experiences a permanent split that cannot self-heal. This requires manual intervention through a hard fork to resolve, during which all transactions and state changes after the divergence point become uncertain, disrupting all economic activity on the chain.

## Likelihood Explanation

**Triggering conditions:**
- Concurrent transactions with overlapping key access (common in high-throughput blocks)
- Transactions using iterators for range queries, batch deletions, or state migrations
- Transaction re-execution creating estimate values (inherent to the optimistic concurrency control design)

**Who can trigger:**
Any user submitting normal transactions can inadvertently trigger this through natural system operation. No special privileges, malicious intent, or coordination required. The issue arises from the OCC system's normal handling of concurrent transaction dependencies.

**Frequency:**
The race condition window exists every time a validation iterator encounters an estimate value. On a busy network with parallel transaction execution, estimates are created frequently as transactions are speculatively executed and re-executed. The manifestation depends on Go runtime scheduling and the pseudo-random selection in the `select` statement, which varies across different processes. Given sufficient transaction volume and concurrent execution, consensus disagreement becomes inevitable.

## Recommendation

**Immediate fix:**
Modify `validationIterator.Value()` to immediately terminate execution after sending to `abortChannel`, consistent with how the normal execution path handles estimates:

```go
if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
    panic(occtypes.NewEstimateAbort(val.Index()))
}
```

**Alternative fix:**
Add abort checking in the validation goroutine loop before processing each key:

```go
for ; mergeIterator.Valid(); mergeIterator.Next() {
    select {
    case <-abortChan:
        returnChan <- false
        return
    default:
    }
    // ... rest of iteration logic
}
```

**Root cause fix:**
Redesign the validation flow to ensure estimate detection always takes precedence before any result is written to `validChannel`. Consider using a single result channel with a discriminated union type that can represent both abort and validation results, eliminating the race between two channels.

## Proof of Concept

The existing test demonstrates the expected behavior when an estimate is encountered: [10](#0-9) 

To demonstrate the race condition, extend this test to run validation repeatedly:

**Setup:**
1. Create parent store with initial keys "key2", "key3", "key4", "key5"
2. Transaction 1 writes writeset including "key2"
3. Transaction 5 creates an iterator over range ["key1", "key6")
4. Set transaction 2's writeset for "key2" as an estimate using `SetEstimatedWriteset(2, 2, writeset2)`

**Action:**
Run `mvs.ValidateTransactionState(5)` in a loop (e.g., 1000 times). Each validation creates new goroutines where the iterator encounters the estimate from transaction 2.

**Expected result:**
While a simple loop may not reliably demonstrate different outcomes due to test environment timing, the code structure definitively proves both channels can have values simultaneously. According to Go's language specification, when multiple cases in a `select` statement are ready, one is chosen via uniform pseudo-random selection. This non-determinism means different validator nodes processing the same state will make different random choices, causing consensus failure.

The vulnerability is proven by the code structure: `validationIterator.Value()` sends to `abortChannel` without stopping execution (unlike the normal execution path which panics), allowing both channels to receive values, triggering Go's non-deterministic selection behavior.

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

**File:** store/multiversion/memiterator.go (L99-126)
```go
func (vi *validationIterator) Value() []byte {
	key := vi.Iterator.Key()

	// try fetch from writeset - return if exists
	if val, ok := vi.writeset[string(key)]; ok {
		return val
	}
	// serve value from readcache (means it has previously been accessed by this iterator so we want consistent behavior here)
	if val, ok := vi.readCache[string(key)]; ok {
		return val
	}

	// get the value from the multiversion store
	val := vi.mvStore.GetLatestBeforeIndex(vi.index, key)

	// if we have an estimate, write to abort channel
	if val.IsEstimate() {
		vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
	}

	// if we have a deleted value, return nil
	if val.IsDeleted() {
		vi.readCache[string(key)] = nil
		return nil
	}
	vi.readCache[string(key)] = val.Value()
	return val.Value()
}
```

**File:** store/multiversion/mvkv.go (L163-166)
```go
		if mvsValue.IsEstimate() {
			abort := scheduler.NewEstimateAbort(mvsValue.Index())
			store.WriteAbort(abort)
			panic(abort)
```

**File:** baseapp/abci.go (L266-267)
```go
	scheduler := tasks.NewScheduler(app.concurrencyWorkers, app.TracingInfo, app.DeliverTx)
	txRes, err := scheduler.ProcessAll(ctx, req.TxEntries)
```

**File:** tasks/scheduler.go (L365-365)
```go
		if valid, conflicts := s.findConflicts(task); !valid {
```

**File:** store/multiversion/mergeiterator.go (L241-241)
```go
			valueC := iter.cache.Value()
```

**File:** store/multiversion/store_test.go (L375-407)
```go
func TestMVSIteratorValidationWithEstimate(t *testing.T) {
	parentKVStore := dbadapter.Store{DB: dbm.NewMemDB()}
	mvs := multiversion.NewMultiVersionStore(parentKVStore)
	vis := multiversion.NewVersionIndexedStore(parentKVStore, mvs, 5, 1, make(chan occ.Abort, 1))

	parentKVStore.Set([]byte("key2"), []byte("value0"))
	parentKVStore.Set([]byte("key3"), []byte("value3"))
	parentKVStore.Set([]byte("key4"), []byte("value4"))
	parentKVStore.Set([]byte("key5"), []byte("value5"))

	writeset := make(multiversion.WriteSet)
	writeset["key1"] = []byte("value1")
	writeset["key2"] = []byte("value2")
	writeset["key3"] = nil
	mvs.SetWriteset(1, 2, writeset)

	iter := vis.Iterator([]byte("key1"), []byte("key6"))
	for ; iter.Valid(); iter.Next() {
		// read value
		iter.Value()
	}
	iter.Close()
	vis.WriteToMultiVersionStore()

	writeset2 := make(multiversion.WriteSet)
	writeset2["key2"] = []byte("value2")
	mvs.SetEstimatedWriteset(2, 2, writeset2)

	// should be invalid
	valid, conflicts := mvs.ValidateTransactionState(5)
	require.False(t, valid)
	require.Equal(t, []int{2}, conflicts)
}
```
