# Audit Report

## Title
Nil Pointer Dereference in Iterator Validation Causing Node Crash During Concurrent Transaction Processing

## Summary
The `validationIterator.Value()` function in the multiversion store lacks a nil check before calling methods on the return value of `GetLatestBeforeIndex()`, causing a nil pointer dereference panic that crashes validator nodes during concurrent transaction processing.

## Impact
Medium

## Finding Description

**Location**: `store/multiversion/memiterator.go`, lines 112-125 [1](#0-0) 

**Intended logic**: The validation iterator should safely retrieve values from the multiversion store during transaction validation. When `GetLatestBeforeIndex()` returns nil (indicating a key doesn't exist before the given index), the function should check for nil before accessing interface methods, matching the defensive pattern used in `VersionIndexedStore.Get()`. [2](#0-1) 

**Actual logic**: The code calls `GetLatestBeforeIndex()` at line 112 and immediately invokes `.IsEstimate()` at line 115 without checking if the returned value is nil. In Go, calling a method on a nil interface value causes a panic with "invalid memory address or nil pointer dereference", which terminates the process immediately.

**Exploitation path**:
1. User submits concurrent transactions where one transaction creates an iterator over a key range
2. Another transaction writes keys within that range, capturing them in the multiversion store
3. The writing transaction undergoes re-execution due to conflicts, producing a different writeset
4. `removeOldWriteset()` removes keys no longer in the new writeset from the multiversion store [3](#0-2) 

5. During validation via `ValidateTransactionState()`, a validation iterator is created through the scheduler's `findConflicts()` method [4](#0-3) 

6. The validation process calls `validateIterator()` which creates a merge iterator combining the validation iterator with the parent store iterator
7. The merge iterator calls `Value()` on the validation iterator for a removed key
8. `GetLatestBeforeIndex()` returns nil for the removed key (documented behavior) [5](#0-4) 

9. Calling `.IsEstimate()` on nil at line 115 triggers a panic, crashing the validator node

**Security guarantee broken**: Memory safety and node availability. The code violates Go's requirement to check interface values for nil before dereferencing, causing unrecoverable panics that terminate validator processes during normal transaction processing.

## Impact Explanation

This vulnerability causes validator nodes to crash during block processing:

- **Node Crashes**: The panic causes immediate process termination without graceful shutdown or recovery in the validation path
- **Deterministic Failures**: All validators processing the same block execute identical validation logic and will crash simultaneously
- **Consensus Disruption**: If sufficient validators crash (≥30% of voting power), block finalization is delayed until nodes restart
- **Attack Vector**: Any user can craft transaction sequences to trigger this condition by submitting transactions that create iterators while concurrent transactions undergo re-execution

The vulnerability affects the core optimistic concurrency control mechanism used for parallel transaction execution in the Sei blockchain.

## Likelihood Explanation

**High likelihood**:

- **Who can trigger**: Any user submitting transactions to the network - no special privileges required
- **Conditions**: Requires transactions that create iterators while other transactions modify their writesets and undergo re-execution due to conflicts. This is normal operation in optimistic concurrency control systems during high load
- **Frequency**: Transaction conflicts and re-executions occur regularly under network load. An attacker can deliberately trigger these conditions by submitting carefully timed transaction batches

The codebase demonstrates awareness of this issue through proper nil checks in other locations [6](#0-5) , confirming that `GetLatestBeforeIndex()` returning nil is expected behavior that should be handled defensively. Tests explicitly verify nil returns are expected: [7](#0-6) 

## Recommendation

Add a nil check before calling methods on the value returned by `GetLatestBeforeIndex()`, matching the defensive programming pattern used in `VersionIndexedStore.Get()`:

```go
val := vi.mvStore.GetLatestBeforeIndex(vi.index, key)

// Check for nil before accessing methods
if val == nil {
    // Key doesn't exist in multiversion store before this index
    // Return nil to indicate the key should be fetched from parent store
    return nil
}

if val.IsEstimate() {
    vi.abortChannel <- occtypes.NewEstimateAbort(val.Index())
}

if val.IsDeleted() {
    vi.readCache[string(key)] = nil
    return nil
}
vi.readCache[string(key)] = val.Value()
return val.Value()
```

## Proof of Concept

**Setup**: The multiversion store's optimistic concurrency control system processes transactions in parallel with conflict detection and re-execution.

**Action**:
1. Transaction 0 writes keys {key1, key2, key3} with incarnation 1
2. Transaction 1 creates an iterator covering this key range - `CollectIteratorItems(1)` captures these keys
3. Transaction 0 re-executes with incarnation 2, writing only {key1, key3}
4. `removeOldWriteset(0, {key1, key3})` removes key2 from the multiversion store at index 0
5. Validation of Transaction 1 proceeds: `validateIterator()` creates a validation iterator with key2 in its memDB
6. The merge iterator calls `validationIterator.Value()` for key2
7. `GetLatestBeforeIndex(1, key2)` returns nil (no value before index 1 after removal)
8. Line 115 attempts to call `.IsEstimate()` on nil

**Result**: Panic with "runtime error: invalid memory address or nil pointer dereference", crashing the validator node process.

**Evidence**:
- `GetLatestBeforeIndex()` explicitly returns nil in documented cases [8](#0-7) 
- Tests confirm nil returns are expected behavior [9](#0-8) 
- Other code paths properly check for nil [10](#0-9) 
- The vulnerable code path lacks this essential check [11](#0-10) 

## Notes

This vulnerability matches the impact criteria: **"Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network"** (Medium severity). The issue is triggered through normal transaction submission without requiring administrative privileges or brute force attacks. The missing nil check is a clear programming error where the codebase demonstrates proper handling in other locations but fails to apply the same pattern in this critical validation path.

### Citations

**File:** store/multiversion/memiterator.go (L112-125)
```go
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
```

**File:** store/multiversion/mvkv.go (L161-176)
```go
	mvsValue := store.multiVersionStore.GetLatestBeforeIndex(store.transactionIndex, key)
	if mvsValue != nil {
		if mvsValue.IsEstimate() {
			abort := scheduler.NewEstimateAbort(mvsValue.Index())
			store.WriteAbort(abort)
			panic(abort)
		} else {
			// This handles both detecting readset conflicts and updating readset if applicable
			return store.parseValueAndUpdateReadset(strKey, mvsValue)
		}
	}
	// if we didn't find it in the multiversion store, then we want to check the parent store + add to readset
	parentValue := store.parent.Get(key)
	store.UpdateReadSet(key, parentValue)
	return parentValue
}
```

**File:** store/multiversion/mvkv.go (L211-230)
```go
		mvsValue := store.multiVersionStore.GetLatestBeforeIndex(store.transactionIndex, key)
		if mvsValue != nil {
			if mvsValue.IsEstimate() {
				// if we see an estimate, that means that we need to abort and rerun
				store.WriteAbort(scheduler.NewEstimateAbort(mvsValue.Index()))
				return false
			} else {
				if mvsValue.IsDeleted() {
					// check for `nil`
					if value != nil {
						return false
					}
				} else {
					// check for equality
					if string(value) != string(mvsValue.Value()) {
						return false
					}
				}
			}
			continue // value is valid, continue to next key
```

**File:** store/multiversion/store.go (L82-97)
```go
// GetLatestBeforeIndex implements MultiVersionStore.
func (s *Store) GetLatestBeforeIndex(index int, key []byte) (value MultiVersionValueItem) {
	keyString := string(key)
	mvVal, found := s.multiVersionMap.Load(keyString)
	// if the key doesn't exist in the overall map, return nil
	if !found {
		return nil
	}
	val, found := mvVal.(MultiVersionValue).GetLatestBeforeIndex(index)
	// otherwise, we may have found a value for that key, but its not written before the index passed in
	if !found {
		return nil
	}
	// found a value prior to the passed in index, return that value (could be estimate OR deleted, but it is a definitive value)
	return val
}
```

**File:** store/multiversion/store.go (L112-138)
```go
func (s *Store) removeOldWriteset(index int, newWriteSet WriteSet) {
	writeset := make(map[string][]byte)
	if newWriteSet != nil {
		// if non-nil writeset passed in, we can use that to optimize removals
		writeset = newWriteSet
	}
	// if there is already a writeset existing, we should remove that fully
	oldKeys, loaded := s.txWritesetKeys.LoadAndDelete(index)
	if loaded {
		keys := oldKeys.([]string)
		// we need to delete all of the keys in the writeset from the multiversion store
		for _, key := range keys {
			// small optimization to check if the new writeset is going to write this key, if so, we can leave it behind
			if _, ok := writeset[key]; ok {
				// we don't need to remove this key because it will be overwritten anyways - saves the operation of removing + rebalancing underlying btree
				continue
			}
			// remove from the appropriate item if present in multiVersionMap
			mvVal, found := s.multiVersionMap.Load(key)
			// if the key doesn't exist in the overall map, return nil
			if !found {
				continue
			}
			mvVal.(MultiVersionValue).Remove(index)
		}
	}
}
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

**File:** store/multiversion/store_test.go (L156-160)
```go
	mvs.SetWriteset(1, 2, writeset1_b)
	require.Equal(t, []byte("value4"), mvs.GetLatestBeforeIndex(2, []byte("key1")).Value())
	require.Nil(t, mvs.GetLatestBeforeIndex(2, []byte("key2")))
	// verify that GetLatest for key3 returns nil - because of removal from writeset
	require.Nil(t, mvs.GetLatest([]byte("key3")))
```
