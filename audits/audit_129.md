# Audit Report

## Title
Non-Deterministic Iterator Validation Due to Race Condition in Channel Selection

## Summary
The `validateIterator` function contains a race condition where an estimate encountered during iterator validation sends an abort signal to `abortChannel` but continues execution, eventually also sending a result to `validChannel`. When both buffered channels have values, Go's `select` statement randomly chooses between them, causing non-deterministic validation results that can lead to consensus failures and permanent chain splits. [1](#0-0) [2](#0-1) 

## Impact
High

## Finding Description

**Location:** 
- Primary issue: `store/multiversion/store.go`, function `validateIterator`, lines 262-318, specifically the select statement at lines 311-317
- Contributing code: `store/multiversion/memiterator.go`, function `validationIterator.Value()`, lines 99-126, specifically lines 115-116

**Intended logic:** 
When validating an iterator during optimistic concurrency control, if an estimate value is encountered (indicating a dependency on an unfinished transaction), the validation should deterministically fail and return `false` consistently across all nodes.

**Actual logic:** 
When `validationIterator.Value()` encounters an estimate, it sends an abort to `abortChannel` but does not terminate execution. [3](#0-2)  The goroutine continues iterating through all keys and eventually writes the final validation result to `validChannel`. [4](#0-3)  Both channels are buffered with capacity 1, [5](#0-4)  allowing both sends to succeed without blocking. The `select` statement randomly chooses between the two ready channels according to Go's specification, introducing non-determinism. [6](#0-5) 

**Exploitation path:**
1. During validation, `mergeIterator.Valid()` is called which internally calls `skipUntilExistsOrInvalid()` [7](#0-6) 
2. This function calls `cache.Value()` on the validation iterator at lines 241 and 253 [8](#0-7) 
3. The `validationIterator.Value()` method retrieves a value that is an estimate
4. An abort is sent to `abortChannel` but execution continues
5. The goroutine completes iteration and sends the result to `validChannel`
6. Both channels now have values, and the `select` randomly chooses which to read
7. Different nodes may get different results, causing consensus disagreement

**Security guarantee broken:** 
This violates the fundamental determinism requirement for blockchain consensus. All validator nodes must reach identical conclusions about transaction validity when processing the same block with identical state.

## Impact Explanation

When this race condition manifests, different validator nodes processing the same block can reach different conclusions about which transactions are valid. This causes:

1. **Consensus Failure**: Nodes disagree on the canonical chain state
2. **Network Partition**: The network splits into incompatible forks  
3. **Permanent Chain Split**: Resolution requires a hard fork as automated recovery is impossible
4. **Transaction Finality Loss**: All transactions and state changes after the split point become uncertain
5. **Economic Disruption**: All applications and economic activity on the chain are compromised

This is a critical consensus-breaking vulnerability that undermines the core security guarantees of the blockchain, even though no funds are directly stolen.

## Likelihood Explanation

**Triggering conditions:**
- Multiple concurrent transactions with overlapping key access (common in busy blocks)
- Iterator usage by transactions (common for range queries, deletions, state migrations)  
- Transaction re-execution creating estimate values (inherent to the OCC design)

**Who can trigger:** 
Any user submitting normal transactions can inadvertently trigger this condition through the natural operation of the optimistic concurrency control system. No special privileges or malicious intent required.

**Frequency:**
The race condition window exists every time a validation iterator encounters an estimate. On a busy network with parallel transaction execution, this could occur multiple times per block. The actual manifestation depends on Go runtime scheduling and timing variations across nodes, making it unpredictable but inevitable over sufficient time and transaction volume.

## Recommendation

**Immediate Fix:**
Modify `validationIterator.Value()` to immediately terminate execution after sending to `abortChannel`:

```go
// In store/multiversion/memiterator.go, around line 115-117
if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
    panic(occtypes.NewEstimateAbort(val.Index()))
}
```

**Alternative Fix:**
Add abort checking in the validation goroutine loop:

```go
// In store/multiversion/store.go, in the validation goroutine
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

**Root Cause Fix:**
Redesign the validation flow to ensure estimate detection always takes precedence and is checked before writing to `validChannel`, or use a single channel with a result type that includes abort information.

## Proof of Concept

**Test Location:** `store/multiversion/store_test.go`

**Setup:**
1. Create parent store with initial keys
2. Create writeset for transaction 2 including key "key2"
3. Have transaction 5 create an iterator that includes key "key2"
4. Invalidate transaction 2's writeset to turn it into estimates

**Action:**
1. Call `ValidateTransactionState(5)` repeatedly (e.g., 1000 times)
2. During each validation, the iterator encounters the estimate from transaction 2
3. Both `abortChannel` and `validChannel` receive values
4. The `select` statement randomly chooses which to read

**Expected Result:**
If the race condition exists, running validation multiple times will produce non-deterministic results - sometimes returning `true`, sometimes `false` for the same state. Even if the race isn't observed in every test run due to timing, the code structure definitively proves both channels can have values simultaneously, allowing non-deterministic selection.

**Note:** The existing test `TestMVSIteratorValidationWithEstimate` (lines 375-407) only validates once and expects `false`, but doesn't test for non-determinism by running multiple iterations.

## Notes

The vulnerability is confirmed by analyzing the code structure:
- The estimate check sends to `abortChannel` without stopping execution [3](#0-2) 
- The goroutine continues and can send to `validChannel` [4](#0-3)   
- Both are buffered channels (capacity 1) that can hold values simultaneously [5](#0-4) 
- Go's `select` with multiple ready cases uses random selection per language specification [6](#0-5) 

This race condition directly violates blockchain determinism requirements and can cause permanent chain splits, qualifying as a High severity issue under "Unintended permanent chain split requiring hard fork."

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
