# Audit Report

## Title
Unmetered Storage Access Operations During Parallel Execution Validation Phase

## Summary
The parallel execution validation logic in the multiversion store performs storage read and iterator operations without gas metering. During transaction validation, `checkReadsetAtIndex` and `validateIterator` directly access the parent store, bypassing the gas metering layer that wraps normal transaction execution. This allows attackers to trigger expensive storage operations that are not accounted for in gas costs.

## Impact
Medium

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
All storage access operations should be gas metered to prevent resource exhaustion attacks. In normal execution, when a transaction accesses stores via `ctx.KVStore()`, the context wraps the store with `gaskv.NewStore()` which meters all Get, Set, Iterator, and other operations. [3](#0-2) 

**Actual Logic:** 
During parallel execution validation, the multiversion store's `ValidateTransactionState` method performs storage operations that bypass gas metering:

1. In `checkReadsetAtIndex`, line 355 directly calls `s.parentStore.Get([]byte(key))` without going through the gas metering wrapper
2. In `validateIterator`, lines 279-281 directly call `s.parentStore.Iterator()` or `s.parentStore.ReverseIterator()`, and then iterate through all keys (line 286) without gas charges

These validation operations happen outside the transaction's gas-metered context and directly access the underlying store.

**Exploit Scenario:**
1. Attacker crafts transactions that iterate over large key ranges (e.g., 10,000+ keys)
2. During execution, gas is charged normally for the iteration
3. Attacker submits multiple conflicting transactions to trigger re-executions
4. For each re-execution, validation runs and performs unmetered operations:
   - Creates iterators on the parent store
   - Iterates through all keys in the range
   - Performs Get operations on the parent store
5. With `maximumIterations = 10` [4](#0-3) , validation can happen up to 10 times per transaction
6. Attacker effectively performs 10x more storage operations than paid for

**Security Failure:** 
The gas accounting security property is broken. Validation performs computational work proportional to the readset/iterateset size, including expensive storage reads and iterations, without charging gas. This enables resource exhaustion beyond what the transaction's gas limit should allow.

## Impact Explanation

This vulnerability allows attackers to consume excessive node resources (CPU, I/O, memory) by forcing nodes to perform unmetered storage operations:

- **Resource Consumption:** Each validation iteration performs full storage reads and iterations that should cost gas but don't. With 10 potential validations per transaction, attackers can multiply their computational work 10x.
  
- **Network-wide Impact:** Multiple validators performing these unmetered operations concurrently can significantly increase block processing time and resource usage across the network.

- **Severity:** This qualifies as Medium impact under "Increasing network processing node resource consumption by at least 30% without brute force actions" because attackers can craft transactions with large iteratesets that force expensive unmetered validation work across multiple re-executions.

## Likelihood Explanation

**Triggering Conditions:**
- Any user can submit transactions with large read/iterate sets
- Conflicts are easily inducible by submitting transactions that access overlapping key ranges
- The scheduler automatically triggers validation for all executed transactions [5](#0-4) 

**Frequency:**
- Can occur during normal operation whenever parallel transactions conflict
- Attacker can deliberately maximize this by submitting batches of conflicting transactions
- Each block with parallel execution is vulnerable

**Accessibility:**
- Exploitable by any unprivileged user submitting transactions
- Requires no special permissions or configuration
- Works with the default parallel execution settings

## Recommendation

Add gas metering to validation operations by:

1. Pass the transaction's gas meter context to validation functions
2. Wrap parent store accesses during validation with gas metering
3. Charge validation operations against the transaction's original gas limit or a separate validation gas budget
4. Consider limiting the number of validation iterations per transaction more aggressively
5. Alternatively, bound the size of readsets/iteratesets to prevent excessive validation work

Example fix approach:
```
func (s *Store) checkReadsetAtIndex(index int, gasMeter types.GasMeter, gasConfig types.GasConfig) (bool, []int) {
    // ... existing code ...
    if latestValue == nil {
        gasMeter.ConsumeGas(gasConfig.ReadCostFlat, types.GasReadCostFlatDesc)
        parentVal := s.parentStore.Get([]byte(key))
        gasMeter.ConsumeGas(gasConfig.ReadCostPerByte*types.Gas(len(key)), types.GasReadPerByteDesc)
        // ... rest of logic ...
    }
}
```

## Proof of Concept

**File:** `tasks/scheduler_test.go`

**Test Function:** Add new test `TestUnmeteredValidationStorageAccess`

**Setup:**
1. Initialize context with a gas meter that tracks total consumption
2. Populate the base store with 1000 keys to create a large iteration range
3. Create transactions that iterate over these keys during execution

**Trigger:**
1. Transaction T1 iterates over all 1000 keys (gas is charged during execution)
2. Transaction T2 writes to a key in T1's iteration range, causing a conflict
3. Scheduler validates T1, which internally calls `validateIterator`
4. `validateIterator` creates a new iterator and iterates over all 1000 keys again
5. Track that the gas meter does NOT increase during this validation iteration

**Observation:**
The test demonstrates that:
- During execution, gas meter increases proportionally to the number of keys iterated
- During validation (triggered by conflict), the same iteration happens but gas meter does NOT increase
- The validation performs expensive parentStore.Iterator operations without gas charges
- With multiple conflicts, this unmetered work multiplies

The test would show that validation work (storage reads, iterations) happens outside gas accounting, confirming the vulnerability. A proper implementation should either charge gas during validation or bound validation work independently.

## Notes

The validation phase is designed to check consistency after parallel execution, but it performs potentially expensive storage operations that scale with the transaction's readset/iterateset size. Since this work is proportional to what the transaction did during execution (which WAS gas metered), an attacker who pays for large operations during execution gets the same operations repeated for free during validation. With up to 10 validation iterations possible via transaction conflicts, this represents a significant gas accounting bypass in parallel execution contexts.

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

**File:** store/multiversion/store.go (L335-385)
```go
func (s *Store) checkReadsetAtIndex(index int) (bool, []int) {
	conflictSet := make(map[int]struct{})
	valid := true

	readSetAny, found := s.txReadSets.Load(index)
	if !found {
		return true, []int{}
	}
	readset := readSetAny.(ReadSet)
	// iterate over readset and check if the value is the same as the latest value relateive to txIndex in the multiversion store
	for key, valueArr := range readset {
		if len(valueArr) != 1 {
			valid = false
			continue
		}
		value := valueArr[0]
		// get the latest value from the multiversion store
		latestValue := s.GetLatestBeforeIndex(index, []byte(key))
		if latestValue == nil {
			// this is possible if we previously read a value from a transaction write that was later reverted, so this time we read from parent store
			parentVal := s.parentStore.Get([]byte(key))
			if !bytes.Equal(parentVal, value) {
				valid = false
			}
		} else {
			// if estimate, mark as conflict index - but don't invalidate
			if latestValue.IsEstimate() {
				conflictSet[latestValue.Index()] = struct{}{}
			} else if latestValue.IsDeleted() {
				if value != nil {
					// conflict
					// TODO: would we want to return early?
					conflictSet[latestValue.Index()] = struct{}{}
					valid = false
				}
			} else if !bytes.Equal(latestValue.Value(), value) {
				conflictSet[latestValue.Index()] = struct{}{}
				valid = false
			}
		}
	}

	conflictIndices := make([]int, 0, len(conflictSet))
	for index := range conflictSet {
		conflictIndices = append(conflictIndices, index)
	}

	sort.Ints(conflictIndices)

	return valid, conflictIndices
}
```

**File:** types/context.go (L567-574)
```go
func (c Context) KVStore(key StoreKey) KVStore {
	if c.isTracing {
		if _, ok := c.nextStoreKeys[key.Name()]; ok {
			return gaskv.NewStore(c.nextMs.GetKVStore(key), c.GasMeter(), stypes.KVGasConfig(), key.Name(), c.StoreTracer())
		}
	}
	return gaskv.NewStore(c.MultiStore().GetKVStore(key), c.GasMeter(), stypes.KVGasConfig(), key.Name(), c.StoreTracer())
}
```

**File:** tasks/scheduler.go (L38-40)
```go
	statusWaiting status = "waiting"
	// maximumIterations before we revert to sequential (for high conflict rates)
	maximumIterations = 10
```

**File:** tasks/scheduler.go (L166-183)
```go
func (s *scheduler) findConflicts(task *deliverTxTask) (bool, []int) {
	var conflicts []int
	uniq := make(map[int]struct{})
	valid := true
	for _, mv := range s.multiVersionStores {
		ok, mvConflicts := mv.ValidateTransactionState(task.AbsoluteIndex)
		for _, c := range mvConflicts {
			if _, ok := uniq[c]; !ok {
				conflicts = append(conflicts, c)
				uniq[c] = struct{}{}
			}
		}
		// any non-ok value makes valid false
		valid = valid && ok
	}
	sort.Ints(conflicts)
	return valid, conflicts
}
```
