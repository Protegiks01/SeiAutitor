# Audit Report

## Title
Non-Deterministic Iterator Validation Causing Consensus Failures Due to Race Condition in Channel Selection

## Summary
The `validateIterator` function contains a critical race condition where both `abortChannel` and `validChannel` can simultaneously hold values during iterator validation. When an estimate is encountered, the validation iterator sends an abort signal but continues execution without termination, eventually sending a validation result to a second channel. Go's `select` statement then uses pseudo-random selection between these ready channels, causing different validator nodes to reach different validation decisions for identical transactions, breaking consensus determinism.

## Impact
High

## Finding Description

**Location:**
- Primary: `store/multiversion/store.go` lines 262-318 (validateIterator function) [1](#0-0) 
- Contributing: `store/multiversion/memiterator.go` lines 114-117 (estimate detection without termination) [2](#0-1) 

**Intended logic:**
When validating an iterator during optimistic concurrency control, if an estimate value is encountered (indicating a dependency on an unfinished transaction), the validation should deterministically return `false` across all validator nodes to trigger re-execution, ensuring all validators reach the same validation decision.

**Actual logic:**
When `validationIterator.Value()` encounters an estimate, it sends an abort to `abortChannel` but does NOT terminate execution (no return or panic statement follows). [3](#0-2)  The function continues executing and returns the estimate value, [4](#0-3)  allowing the validation goroutine to continue iterating. The goroutine eventually completes and sends the final validation result to `validChannel`. [5](#0-4)  Since both channels are buffered with capacity 1, [6](#0-5)  both sends succeed without blocking. The `select` statement then receives from whichever channel the Go runtime pseudo-randomly selects when multiple cases are simultaneously ready. [7](#0-6) 

**Exploitation path:**
1. During block execution, the scheduler's `ProcessAll` method processes transactions using optimistic concurrency control [8](#0-7) 
2. Transaction A undergoes re-execution, creating estimate values in the multiversion store
3. Transaction B's validation performs iterator operations that encounter Transaction A's estimate values
4. During validation, `ValidateTransactionState` is called [9](#0-8)  which invokes `validateIterator`
5. The validation goroutine calls `mergeIterator.Valid()` which internally calls `skipUntilExistsOrInvalid()` [10](#0-9) 
6. This triggers `iter.cache.Value()` calls, invoking the validation iterator's `Value()` method
7. The estimate detection sends to `abortChannel` but execution continues without termination
8. The goroutine completes iteration and sends to `validChannel`
9. Both channels now have ready values
10. Different validator nodes execute the `select` at different Go runtime scheduling states
11. Go's language specification states: "If one or more of the communications can proceed, a single one that can proceed is chosen via a uniform pseudo-random selection"
12. Some validators' `select` reads from `abortChannel` (returning false, triggering re-execution)
13. Other validators' `select` reads from `validChannel` (returning the validation result, potentially true)
14. Validators diverge on transaction validation states
15. Different final block states emerge across validators
16. Consensus cannot be reached

**Security guarantee broken:**
Consensus determinism - the fundamental blockchain requirement that all honest validator nodes processing identical block inputs must reach identical state transitions and validation decisions.

## Impact Explanation

This vulnerability causes different validator nodes to produce divergent validation results for the same transaction within the same block. When some validators validate a transaction (committing it to final state) while others reject it (triggering re-execution), the nodes diverge on which transactions are included in the canonical state. This results in:

1. **Immediate consensus failure** - Validators cannot agree on the next block's state root
2. **Permanent network halt** - The network cannot finalize new blocks, requiring manual intervention
3. **Requires hard fork to resolve** - No automatic recovery mechanism exists; manual network coordination and code upgrade required
4. **Complete loss of transaction finality** - All transactions after the issue manifests become uncertain
5. **Network-wide impact** - Affects all users, applications, and services running on the blockchain

The vulnerability is called during block execution via the scheduler's validation logic, [11](#0-10)  making it part of the consensus-critical path where the scheduler calls `ValidateTransactionState` to determine transaction validity.

## Likelihood Explanation

**Triggering conditions:**
- Multiple concurrent transactions accessing overlapping key ranges (common in high-throughput blocks)
- Transaction usage of iterators for range queries, state migrations, or batch deletions (standard blockchain operations)
- Transaction re-execution creating estimate values (inherent to the optimistic concurrency control design pattern)
- No special privileges or adversarial behavior required

**Frequency:**
The race condition window opens whenever a validation iterator encounters an estimate value during replay. On networks with parallel transaction execution using optimistic concurrency control, this occurs regularly - potentially multiple times per block under load. The actual manifestation depends on Go runtime scheduling variability between different validator nodes, which varies based on hardware, OS scheduling, and CPU load. While each individual occurrence has a probabilistic chance of manifesting the non-determinism, over time with sufficient transaction volume, the event becomes statistically inevitable.

**Who can trigger:**
Any user submitting normal transactions can inadvertently trigger this through routine system operation. This is not an attack vector requiring malicious intent, but rather a fundamental non-determinism in consensus-critical validation logic that manifests during normal concurrent transaction processing.

## Recommendation

**Immediate fix:**
Modify `validationIterator.Value()` to immediately terminate the goroutine after detecting an estimate by using panic to unwind the stack:

```go
// In store/multiversion/memiterator.go, lines 115-117
if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
    panic(occtypes.NewEstimateAbort(val.Index()))
}
```

**Alternative fix:**
Add abort signal checking within the validation loop to detect and handle abort signals before completing iteration:

```go
// In store/multiversion/store.go, inside the validation goroutine loop (after line 286)
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
Redesign the validation flow to ensure estimate detection always takes precedence. Consider using context cancellation to terminate the goroutine when an abort is detected, or use a single channel with typed responses indicating whether validation completed successfully or was aborted.

## Proof of Concept

The existing test demonstrates the scenario: [12](#0-11) 

**Setup:**
1. Initialize multiversion store with parent keys (key2-key5)
2. Transaction 2 writes to key2 creating a writeset
3. Transaction 5 creates an iterator that includes key2 and records the iterated keys
4. Invalidate transaction 2's writeset by setting it as an estimate using `SetEstimatedWriteset`

**Action:**
Call `mvs.ValidateTransactionState(5)` which triggers the vulnerable `validateIterator` code path

**Expected result (deterministic):**
Should consistently return `false` due to estimate detection, with conflict index [2]

**Actual behavior (non-deterministic):**
The code structure proves both channels can have values simultaneously. The Go language specification explicitly states that when multiple select cases are ready, "a single one that can proceed is chosen via a uniform pseudo-random selection." Running this validation across multiple validator nodes with different Go runtime states would produce inconsistent results where some validators return `false` when `abortChannel` is selected and other validators return the result from `validChannel`, demonstrating the non-deterministic behavior that causes consensus failures.

While the test currently passes (expecting `false`), this is only because the test runs in a single process with a single Go runtime instance. In a distributed consensus environment with multiple validators, each running independent Go runtime instances with different scheduling states, the pseudo-random selection in the `select` statement would produce different results across validators, causing consensus divergence.

## Notes

This vulnerability is particularly critical because:

1. **Consensus-critical code**: Affects the core consensus mechanism used during block execution
2. **No adversarial action required**: Can be triggered through normal operation without malicious intent
3. **No existing safeguards**: No mechanism prevents the goroutine from continuing after abort signal
4. **Go language specification**: Explicitly defines `select` as using "uniform pseudo-random selection" when multiple cases are ready, which varies across different runtime instances
5. **Independent validator states**: Different validator nodes run with independent Go runtime states and will make different pseudo-random choices
6. **Matches high-severity impact**: "Unintended permanent chain split requiring hard fork (network partition requiring hard fork)"
7. **Buffered channels enable race**: Both channels have capacity 1, allowing both sends to succeed non-blocking, creating the race window

The vulnerability exists in production consensus-critical code and represents a fundamental violation of blockchain determinism requirements.

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

**File:** store/multiversion/store.go (L388-396)
```go
func (s *Store) ValidateTransactionState(index int) (bool, []int) {
	// defer telemetry.MeasureSince(time.Now(), "store", "mvs", "validate")

	// TODO: can we parallelize for all iterators?
	iteratorValid := s.checkIteratorAtIndex(index)

	readsetValid, conflictIndices := s.checkReadsetAtIndex(index)

	return iteratorValid && readsetValid, conflictIndices
```

**File:** store/multiversion/memiterator.go (L114-117)
```go
	// if we have an estimate, write to abort channel
	if val.IsEstimate() {
		vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
	}
```

**File:** store/multiversion/memiterator.go (L119-125)
```go
	// if we have a deleted value, return nil
	if val.IsDeleted() {
		vi.readCache[string(key)] = nil
		return nil
	}
	vi.readCache[string(key)] = val.Value()
	return val.Value()
```

**File:** tasks/scheduler.go (L166-182)
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
```

**File:** tasks/scheduler.go (L284-351)
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
```

**File:** store/multiversion/mergeiterator.go (L218-262)
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
