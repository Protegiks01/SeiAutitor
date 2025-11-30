# Audit Report

## Title
Unmetered Storage Access Operations During Parallel Execution Validation Phase

## Summary
The multiversion store's validation logic in the optimistic concurrency control (OCC) parallel execution system performs storage read and iterator operations without gas metering. During validation, the `ValidateTransactionState` method directly accesses the parent store without the gas metering wrapper that protects normal transaction execution, allowing attackers to consume validator resources disproportionate to gas paid.

## Impact
Medium

## Finding Description

**Location:**
- `store/multiversion/store.go` lines 355 (checkReadsetAtIndex), 279-281 (validateIterator)
- `tasks/scheduler.go` line 171 (validation trigger), line 224 (parent store initialization)

**Intended Logic:**
All storage access operations should be gas-metered to prevent resource exhaustion attacks. The gas metering system charges for Get, Set, Iterator, and iteration operations to ensure users pay for computational resources consumed. [1](#0-0) [2](#0-1) [3](#0-2) 

**Actual Logic:**
During parallel execution validation, gas metering is bypassed:

1. The multiversion store's parent store is initialized using `ctx.MultiStore().GetKVStore(sk)` instead of `ctx.KVStore(sk)`, so it lacks the `gaskv.NewStore()` wrapper: [4](#0-3) 

2. In `checkReadsetAtIndex`, when the latest value is nil, the code directly accesses `s.parentStore.Get()` without gas metering: [5](#0-4) 

3. In `validateIterator`, the code creates parent store iterators and iterates through all keys without gas charges: [6](#0-5) 

**Exploitation Path:**
1. Attacker submits transaction T1 that iterates over large key ranges (e.g., 10,000+ keys)
2. During execution, T1 pays gas for iterations through the gas-metered store wrapper
3. T1's execution records its iterateset (all iterated keys)
4. Attacker submits transaction T2 that writes to keys within T1's iteration range
5. Scheduler detects conflict and triggers validation via `findConflicts` → `ValidateTransactionState`: [7](#0-6) 

6. During validation, `validateIterator` creates parent store iterator and iterates through all keys without consuming gas
7. With `maximumIterations = 10`, validation can occur up to 10 times per transaction: [8](#0-7) 

8. Attacker effectively forces validators to perform 10× more storage operations than paid for

**Security Guarantee Broken:**
The economic security property of gas metering is violated. The system should ensure users pay for all computational resources they consume. However, validation operations scale linearly with transaction complexity (readset/iterateset size) but are not accounted for in gas costs.

## Impact Explanation

This vulnerability enables resource exhaustion attacks against validator nodes:

- **Resource Consumption Multiplier**: Each validation iteration performs full storage reads and iterations proportional to the transaction's readset/iterateset size. With up to 10 potential validations per transaction, validators perform 2-11× more work than the gas payment covers.

- **Network-wide Impact**: All validators in the network must perform these unmetered validation operations when processing blocks, increasing CPU, I/O, and memory consumption across the entire network.

- **Economic Security Violation**: The gas system's fundamental guarantee—that resource consumption is proportional to payment—is broken. Attackers can pay for X work but force validators to perform 2X-11X work.

- **Severity Justification**: This qualifies as Medium severity under "Increasing network processing node resource consumption by at least 30% without brute force actions" because:
  - Attackers can craft transactions with large iteratesets (10,000+ keys)
  - Each validation doubles the work (100% increase minimum)
  - Multiple validations multiply this further (up to 1,000% increase)
  - A batch of such transactions easily increases network resource consumption by 30-300%

## Likelihood Explanation

**Triggering Conditions:**
- Any unprivileged user can submit transactions with large read/iterate sets
- Conflicts are easily inducible by submitting transactions that access overlapping key ranges
- The scheduler automatically triggers validation for all executed transactions
- No special permissions, configuration, or edge-case conditions required

**Frequency:**
- Occurs during normal parallel execution whenever transactions conflict
- Attacker can deliberately maximize this by submitting batches of conflicting transactions with large iteratesets
- Each block with parallel execution is potentially vulnerable

**Accessibility:**
- Exploitable by any user submitting normal transactions
- Requires no privileged access or system misconfiguration
- Works with default parallel execution settings
- Attack cost bounded only by transaction gas limits, but the resource consumption multiplier (2-11×) makes it economically viable

## Recommendation

Add gas metering to validation operations:

1. **Pass gas meter to validation functions**: Modify `ValidateTransactionState`, `checkReadsetAtIndex`, and `validateIterator` to accept a gas meter parameter from the transaction context

2. **Wrap parent store accesses**: When validation accesses the parent store, wrap it with `gaskv.NewStore()` to meter the operations, or charge gas directly before/after each operation using the gas meter

3. **Charge against transaction gas limit**: Validation gas should be charged against the original transaction's gas limit. If validation would exceed remaining gas, the transaction should fail validation

4. **Alternative mitigations**:
   - Impose hard limits on readset/iterateset sizes per transaction
   - Cap the number of validation iterations more aggressively (e.g., reduce from 10 to 3)
   - Implement a separate "validation gas budget" that scales with transaction gas used

5. **Implementation pattern**: Modify validation functions to accept and use a gas meter, consuming gas for parent store accesses similar to how `gaskv.Store` does: [9](#0-8) 

## Proof of Concept

**Conceptual Test**: `TestUnmeteredValidationStorageAccess` in `tasks/scheduler_test.go`

**Setup:**
1. Initialize test context with tracked gas meter
2. Create multiversion store with base store containing 1,000 pre-populated keys
3. Create two transactions:
   - T1: Iterates over all 1,000 keys (using Iterator)
   - T2: Writes to a key within T1's iteration range

**Action:**
1. Execute T1 through scheduler - record gas consumed (should be ~1,000 × IterNextCostFlat + ReadCostPerByte × sizes)
2. Execute T2 through scheduler - creates write conflict with T1
3. Scheduler validates T1 via `findConflicts` → `ValidateTransactionState` → `validateIterator`
4. Validation creates parent store iterator and iterates through 1,000 keys
5. Monitor gas meter during validation phase

**Expected Result:**
- During T1 execution: Gas meter increases by ~300,000+ gas (1,000 × 30 IterNextCostFlat + key/value read costs)
- During T1 validation: Gas meter does NOT increase despite performing same iteration operations
- Validation performs expensive `parentStore.Iterator()` and `iterator.Next()` calls without gas charges
- With multiple conflicts triggering multiple validations, unmetered work multiplies

**Observation:**
The test demonstrates that validation work (storage reads, iterator creation, key iteration) happens outside gas accounting, confirming attackers can force validators to perform significantly more work than gas payment covers.

## Notes

The validation phase is architecturally necessary for OCC parallel execution consistency. However, the current implementation performs validation operations that scale linearly with transaction complexity without accounting for their cost. Since validation work is proportional to execution work (both iterate through the same readsets/iteratesets), and validation can occur up to 10 times per transaction, this represents a significant bypass of the gas accounting mechanism that violates the economic security model.

### Citations

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

**File:** store/gaskv/store.go (L54-66)
```go
func (gs *Store) Get(key []byte) (value []byte) {
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostFlat, types.GasReadCostFlatDesc)
	value = gs.parent.Get(key)

	// TODO overflow-safe math?
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostPerByte*types.Gas(len(key)), types.GasReadPerByteDesc)
	gs.gasMeter.ConsumeGas(gs.gasConfig.ReadCostPerByte*types.Gas(len(value)), types.GasReadPerByteDesc)
	if gs.tracer != nil {
		gs.tracer.Get(key, value, gs.moduleName)
	}

	return value
}
```

**File:** store/gaskv/store.go (L107-153)
```go
func (gs *Store) Iterator(start, end []byte) types.Iterator {
	return gs.iterator(start, end, true)
}

// ReverseIterator implements the KVStore interface. It returns a reverse
// iterator which incurs a flat gas cost for seeking to the first key/value pair
// and a variable gas cost based on the current value's length if the iterator
// is valid.
func (gs *Store) ReverseIterator(start, end []byte) types.Iterator {
	return gs.iterator(start, end, false)
}

// Implements KVStore.
func (gs *Store) CacheWrap(_ types.StoreKey) types.CacheWrap {
	panic("cannot CacheWrap a GasKVStore")
}

// CacheWrapWithTrace implements the KVStore interface.
func (gs *Store) CacheWrapWithTrace(_ types.StoreKey, _ io.Writer, _ types.TraceContext) types.CacheWrap {
	panic("cannot CacheWrapWithTrace a GasKVStore")
}

// CacheWrapWithListeners implements the CacheWrapper interface.
func (gs *Store) CacheWrapWithListeners(_ types.StoreKey, _ []types.WriteListener) types.CacheWrap {
	panic("cannot CacheWrapWithListeners a GasKVStore")
}

func (gs *Store) iterator(start, end []byte, ascending bool) types.Iterator {
	var parent types.Iterator
	if ascending {
		parent = gs.parent.Iterator(start, end)
	} else {
		parent = gs.parent.ReverseIterator(start, end)
	}

	gi := newGasIterator(gs.gasMeter, gs.gasConfig, parent, gs.moduleName, gs.tracer)
	defer func() {
		if err := recover(); err != nil {
			// if there is a panic, we close the iterator then reraise
			gi.Close()
			panic(err)
		}
	}()
	gi.(*gasIterator).consumeSeekGas()

	return gi
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

**File:** store/multiversion/store.go (L278-307)
```go
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
```

**File:** store/multiversion/store.go (L352-358)
```go
		latestValue := s.GetLatestBeforeIndex(index, []byte(key))
		if latestValue == nil {
			// this is possible if we previously read a value from a transaction write that was later reverted, so this time we read from parent store
			parentVal := s.parentStore.Get([]byte(key))
			if !bytes.Equal(parentVal, value) {
				valid = false
			}
```

**File:** store/types/gas.go (L329-351)
```go
// GasConfig defines gas cost for each operation on KVStores
type GasConfig struct {
	HasCost          Gas
	DeleteCost       Gas
	ReadCostFlat     Gas
	ReadCostPerByte  Gas
	WriteCostFlat    Gas
	WriteCostPerByte Gas
	IterNextCostFlat Gas
}

// KVGasConfig returns a default gas config for KVStores.
func KVGasConfig() GasConfig {
	return GasConfig{
		HasCost:          1000,
		DeleteCost:       1000,
		ReadCostFlat:     1000,
		ReadCostPerByte:  3,
		WriteCostFlat:    2000,
		WriteCostPerByte: 30,
		IterNextCostFlat: 30,
	}
}
```
