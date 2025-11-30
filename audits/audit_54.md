# Audit Report

## Title
Non-Deterministic Iterator Validation Causing Consensus Failures Due to Race Condition in Channel Selection

## Summary
The `validateIterator` function contains a critical race condition where both `abortChannel` and `validChannel` can simultaneously have ready values, causing Go's `select` statement to non-deterministically choose between them. This breaks consensus determinism as different validator nodes reach different validation decisions for identical transactions, leading to chain splits.

## Impact
High

## Finding Description

**Location:**
- Primary: [1](#0-0) 
- Contributing: [2](#0-1) 

**Intended logic:**
When validating an iterator during optimistic concurrency control, if an estimate value is encountered (indicating a dependency on an unfinished transaction), the validation should deterministically return `false` across all validator nodes to trigger re-execution.

**Actual logic:**
When the validation iterator's `Value()` method encounters an estimate, it sends an abort signal to `abortChannel` [3](#0-2)  but does not terminate execution. The method continues to execute [4](#0-3)  and returns the value, allowing the validation goroutine to continue iterating. The goroutine eventually completes and sends the final validation result to `validChannel` [5](#0-4) . Since both channels are buffered with capacity 1 [6](#0-5) , both sends succeed without blocking. The `select` statement [7](#0-6)  then receives from whichever channel the Go runtime pseudo-randomly selects when multiple cases are simultaneously ready.

**Exploitation path:**
1. Transaction A writes to keys and undergoes re-execution, creating estimate values in the multiversion store
2. Transaction B's validation performs iterator operations that encounter Transaction A's estimate values
3. During validation replay in the goroutine, `mergeIterator.Valid()` or `mergeIterator.Key()` internally calls `skipUntilExistsOrInvalid()` [8](#0-7) 
4. This triggers `iter.cache.Value()` calls which invoke the validation iterator's `Value()` method
5. The estimate detection sends to `abortChannel` but execution continues without stopping
6. The goroutine completes iteration and sends to `validChannel`
7. Both channels now have ready values simultaneously
8. Different validator nodes execute the `select` at different runtime scheduling states
9. Some validators' `select` reads from `abortChannel` (returns false, marks validation as failed, triggers re-execution)
10. Other validators' `select` reads from `validChannel` (may return true, marks validation as passed)
11. Validators diverge on transaction validation states
12. Different final block states emerge across validators
13. Consensus cannot be reached, causing network partition

**Security guarantee broken:**
Consensus determinism - the fundamental requirement that all honest validator nodes processing identical block inputs must reach identical state transitions and validation decisions.

## Impact Explanation

This vulnerability causes different validator nodes to produce divergent validation results for the same transaction within the same block. When some validators mark a transaction as invalid (triggering re-execution) while others validate it successfully (committing to final state), the nodes diverge on which transactions are included in the canonical state. This results in:

1. **Immediate consensus failure** - Validators cannot agree on the block's state root
2. **Permanent chain split** - The network partitions into incompatible forks following different validation paths  
3. **Requires hard fork to resolve** - No automatic recovery mechanism exists; manual network coordination and upgrade required
4. **Complete loss of transaction finality** - All transactions after the split point become uncertain across the network
5. **Network-wide impact** - Affects all users, applications, and services running on the blockchain

The vulnerability is invoked during block execution via the scheduler's optimistic concurrency control system [9](#0-8) , making it part of the consensus-critical path.

## Likelihood Explanation

**Triggering conditions:**
- Multiple concurrent transactions accessing overlapping key ranges (common in high-throughput blocks)
- Transaction usage of iterators for range queries, state migrations, or batch deletions (standard blockchain operations)
- Transaction re-execution creating estimate values (inherent to the OCC design pattern)
- No special privileges or adversarial behavior required

**Frequency:**
The race condition window opens whenever a validation iterator encounters an estimate value during replay. On networks with parallel transaction execution using optimistic concurrency control, this occurs regularly - potentially multiple times per block under load. The actual manifestation depends on Go runtime scheduling variability and is unpredictable but statistically inevitable over time.

**Who can trigger:**
Any user submitting normal transactions can inadvertently trigger this through routine system operation. This is not an attack vector requiring malicious intent, but rather a fundamental non-determinism in consensus-critical validation logic. The probability increases with:
- Higher transaction throughput
- More complex transactions using iterator operations
- Longer validation processing times
- Increased parallel execution depth

## Recommendation

**Immediate fix:**
Modify `validationIterator.Value()` to immediately terminate execution after detecting an estimate:

```go
// In store/multiversion/memiterator.go, line 115-117
if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
    panic(occtypes.NewEstimateAbort(val.Index())) // Immediately terminate goroutine
}
```

**Alternative fix:**
Add abort signal checking within the validation loop:

```go
// In store/multiversion/store.go, inside the validation goroutine loop
for ; mergeIterator.Valid(); mergeIterator.Next() {
    select {
    case <-abortChan:
        returnChan <- false
        return
    default:
    }
    // ... existing iteration logic
}
```

**Root cause fix:**
Redesign the validation flow to ensure estimate detection always takes precedence before any result reaches `validChannel`. Consider:
- Using a single channel with typed responses (success/abort)
- Implementing context-based cancellation on abort detection
- Adding explicit goroutine termination on estimate detection

## Proof of Concept

The existing test [10](#0-9)  demonstrates the scenario but expects deterministic behavior by running only once.

**Setup:**
1. Initialize multiversion store with parent keys (key2-key5)
2. Transaction 2 writes to key2 creating a writeset
3. Transaction 5 creates an iterator that includes key2
4. Invalidate transaction 2's writeset by setting it as an estimate

**Action:**
Call `mvs.ValidateTransactionState(5)` which triggers the vulnerable `validateIterator` code path

**Expected result (deterministic):**
Should consistently return `false` due to estimate detection

**Actual result (non-deterministic):**
The code structure proves both channels can have values simultaneously:
- Estimate detection sends to `abortChannel` (non-blocking, buffer capacity 1)
- Goroutine continues execution and completes
- Validation result is sent to `validChannel` (non-blocking, buffer capacity 1)
- Go's `select` statement chooses non-deterministically when both cases are ready

Running the validation multiple times across different validator nodes with different runtime scheduling would produce inconsistent results, demonstrating the non-deterministic behavior that causes consensus failures.

## Notes

This vulnerability is particularly critical because:
1. It affects the core consensus mechanism used during block execution
2. It can be triggered through normal operation without malicious intent
3. No existing safeguards prevent the non-deterministic behavior
4. The Go language specification explicitly defines `select` as non-deterministic when multiple cases are ready
5. Different validator nodes running at different times with different runtime scheduling will make different choices
6. The impact matches the high-severity category: "Unintended permanent chain split requiring hard fork"

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

**File:** store/multiversion/memiterator.go (L114-125)
```go
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

**File:** tasks/scheduler.go (L284-352)
```go
func (s *scheduler) ProcessAll(ctx sdk.Context, reqs []*sdk.DeliverTxEntry) ([]types.ResponseDeliverTx, error) {
	startTime := time.Now()
	var iterations int
	// initialize mutli-version stores if they haven't been initialized yet
	s.tryInitMultiVersionStore(ctx)
	// prefill estimates
	// This "optimization" path is being disabled because we don't have a strong reason to have it given that it
	// s.PrefillEstimates(reqs)
	tasks, tasksMap := toTasks(reqs)
	s.allTasks = tasks
	s.allTasksMap = tasksMap
	s.executeCh = make(chan func(), len(tasks))
	s.validateCh = make(chan func(), len(tasks))
	defer s.emitMetrics()

	// default to number of tasks if workers is negative or 0 by this point
	workers := s.workers
	if s.workers < 1 || len(tasks) < s.workers {
		workers = len(tasks)
	}

	workerCtx, cancel := context.WithCancel(ctx.Context())
	defer cancel()

	// execution tasks are limited by workers
	start(workerCtx, s.executeCh, workers)

	// validation tasks uses length of tasks to avoid blocking on validation
	start(workerCtx, s.validateCh, len(tasks))

	toExecute := tasks
	for !allValidated(tasks) {
		// if the max incarnation >= x, we should revert to synchronous
		if iterations >= maximumIterations {
			// process synchronously
			s.synchronous = true
			startIdx, anyLeft := s.findFirstNonValidated()
			if !anyLeft {
				break
			}
			toExecute = tasks[startIdx:]
		}

		// execute sets statuses of tasks to either executed or aborted
		if err := s.executeAll(ctx, toExecute); err != nil {
			return nil, err
		}

		// validate returns any that should be re-executed
		// note this processes ALL tasks, not just those recently executed
		var err error
		toExecute, err = s.validateAll(ctx, tasks)
		if err != nil {
			return nil, err
		}
		// these are retries which apply to metrics
		s.metrics.retries += len(toExecute)
		iterations++
	}

	for _, mv := range s.multiVersionStores {
		mv.WriteLatestToStore()
	}
	s.metrics.maxIncarnation = s.maxIncarnation

	ctx.Logger().Info("occ scheduler", "height", ctx.BlockHeight(), "txs", len(tasks), "latency_ms", time.Since(startTime).Milliseconds(), "retries", s.metrics.retries, "maxIncarnation", s.maxIncarnation, "iterations", iterations, "sync", s.synchronous, "workers", s.workers)

	return s.collectResponses(tasks), nil
}
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
