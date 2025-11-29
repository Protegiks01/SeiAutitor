# Audit Report

## Title
Non-Deterministic Iterator Validation Due to Race Condition in Channel Selection

## Summary
The `validateIterator` function in the multi-version store contains a critical race condition where encountering an estimate value during iterator validation sends an abort signal to `abortChannel` but allows execution to continue, eventually sending a result to `validChannel`. When both buffered channels contain values, Go's `select` statement uses non-deterministic random selection, causing different validator nodes to reach different conclusions about transaction validity during consensus, leading to permanent chain splits.

## Impact
High

## Finding Description

**Location:**
- Primary issue: [1](#0-0) 
- Contributing code: [2](#0-1) 
- Call path: [3](#0-2) 

**Intended logic:**
When validating an iterator during optimistic concurrency control, if an estimate value is encountered (indicating a dependency on an unfinished transaction), the validation should deterministically abort and return `false` consistently across all validator nodes.

**Actual logic:**
When `validationIterator.Value()` encounters an estimate, it sends an abort to `abortChannel` but does not terminate execution. [4](#0-3)  The method continues executing and returns a value normally. [5](#0-4)  The validation goroutine continues iterating and eventually sends the final result to `validChannel`. [6](#0-5)  Both channels are buffered with capacity 1, [7](#0-6)  allowing both sends to succeed without blocking. The `select` statement randomly chooses between the two ready channels according to Go's specification, [8](#0-7)  introducing non-determinism.

**Exploitation path:**
1. Block execution begins via `DeliverTxBatch` [9](#0-8) 
2. Scheduler processes transactions and calls validation via `findConflicts` [10](#0-9) 
3. Validation calls `ValidateTransactionState` which invokes `checkIteratorAtIndex` [11](#0-10) 
4. This calls `validateIterator` for each iterator [12](#0-11) 
5. During validation, `mergeIterator.Valid()` is called [13](#0-12) 
6. This internally calls `skipUntilExistsOrInvalid()` which calls `cache.Value()` [14](#0-13) 
7. The `validationIterator.Value()` method retrieves a value that is an estimate
8. An abort is sent to `abortChannel` but execution continues
9. The goroutine completes iteration and sends the result to `validChannel`
10. Both channels now have values, and Go's `select` randomly chooses which to read
11. Different validator nodes get different results, causing consensus disagreement

**Security guarantee broken:**
This violates the fundamental determinism requirement for blockchain consensus. All validator nodes must reach identical conclusions about transaction validity when processing the same block with identical state.

## Impact Explanation

This race condition causes different validator nodes processing the same block to reach different conclusions about transaction validity. When validators disagree on which transactions are valid, they compute different application state hashes. This triggers a consensus failure where the network cannot reach agreement on the canonical chain state, resulting in a permanent network partition that requires a hard fork to resolve. All transactions and state changes after the divergence point become uncertain, compromising the finality guarantees of the blockchain and disrupting all economic activity on the chain.

## Likelihood Explanation

**Triggering conditions:**
- Concurrent transactions with overlapping key access (common in busy blocks)
- Transactions using iterators (range queries, deletions, migrations)
- Transaction re-execution creating estimate values (inherent to OCC design)

**Who can trigger:**
Any user submitting normal transactions can inadvertently trigger this through the natural operation of the optimistic concurrency control system. No special privileges or malicious intent required.

**Frequency:**
The race condition window exists every time a validation iterator encounters an estimate. On a busy network with parallel transaction execution, this occurs frequently. The actual manifestation depends on Go runtime scheduling variations across nodes. Given sufficient transaction volume, consensus disagreement is inevitable.

## Recommendation

**Immediate fix:**
Modify `validationIterator.Value()` to immediately terminate execution after sending to `abortChannel`:

```go
if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
    panic(occtypes.NewEstimateAbort(val.Index()))
}
```

**Alternative fix:**
Add abort checking in the validation goroutine loop:

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
Redesign the validation flow to ensure estimate detection always takes precedence before writing to `validChannel`, or use a single channel with a result type that includes abort information.

## Proof of Concept

**Test approach:**
Extend the existing test in `store/multiversion/store_test.go` [15](#0-14) 

**Setup:**
1. Create parent store with initial keys
2. Create writeset for transaction 2 including key "key2"
3. Have transaction 5 create an iterator that includes key "key2"
4. Call `SetEstimatedWriteset(2, 2, writeset2)` to mark transaction 2's writes as estimates

**Action:**
1. Call `ValidateTransactionState(5)` repeatedly (e.g., 1000 times in a loop)
2. During each validation, the iterator encounters the estimate from transaction 2
3. Both `abortChannel` and `validChannel` receive values
4. The `select` statement randomly chooses which to read

**Expected result:**
If the race condition exists, running validation multiple times will produce non-deterministic results - sometimes returning `true`, sometimes `false` for the same state. The code structure definitively proves both channels can have values simultaneously, enabling non-deterministic selection per Go's specification.

## Notes

This vulnerability qualifies as "Unintended permanent chain split requiring hard fork" (High severity impact). The race condition is inherent in the code structure where estimate handling sends to `abortChannel` without stopping goroutine execution, allowing both channels to receive values simultaneously and triggering Go's random selection in the `select` statement.

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

**File:** store/multiversion/store.go (L329-329)
```go
		iteratorValid := s.validateIterator(index, *iterationTracker)
```

**File:** store/multiversion/store.go (L392-392)
```go
	iteratorValid := s.checkIteratorAtIndex(index)
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

**File:** store/multiversion/mergeiterator.go (L218-263)
```go
func (iter *mvsMergeIterator) skipUntilExistsOrInvalid() bool {
	for {
		// If parent is invalid, fast-forward cache.
		if !iter.parent.Valid() {
			iter.skipCacheDeletes(nil)
			return iter.cache.Valid()
		}
		// Parent is valid.
		if !iter.cache.Valid() {
			return true
		}
		// Parent is valid, cache is valid.

		// Compare parent and cache.
		keyP := iter.parent.Key()
		keyC := iter.cache.Key()

		switch iter.compare(keyP, keyC) {
		case -1: // parent < cache.
			return true

		case 0: // parent == cache.
			// Skip over if cache item is a delete.
			valueC := iter.cache.Value()
			if valueC == nil {
				iter.parent.Next()
				iter.cache.Next()

				continue
			}
			// Cache is not a delete.

			return true // cache exists.
		case 1: // cache < parent
			// Skip over if cache item is a delete.
			valueC := iter.cache.Value()
			if valueC == nil {
				iter.skipCacheDeletes(keyP)
				continue
			}
			// Cache is not a delete.

			return true // cache exists.
		}
	}
}
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
