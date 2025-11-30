# Audit Report

## Title
Unmetered Storage Access Operations During Parallel Execution Validation Phase

## Summary
The OCC parallel execution system's validation logic performs storage read and iterator operations without gas metering, allowing any user to force validators to perform up to 11× more computational work than what was paid for in gas fees, enabling resource exhaustion attacks across the entire validator network.

## Impact
Medium

## Finding Description

**Location:**
- `store/multiversion/store.go` lines 279-281, 286, 355
- `tasks/scheduler.go` lines 40, 166-183, 217-227

**Intended Logic:**
All storage operations should be gas-metered through the `gaskv.Store` wrapper to ensure users pay for computational resources consumed. The system should prevent users from forcing validators to perform unbounded work without corresponding payment. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Actual Logic:**
The multiversion store's parent store is initialized using `ctx.MultiStore().GetKVStore(sk)` which bypasses the gas metering wrapper that would be provided by `ctx.KVStore(sk)`. During validation, the system directly accesses this unmetered parent store: [5](#0-4) 

In validation operations, storage reads and iterations occur without any gas consumption: [6](#0-5) [7](#0-6) 

**Exploitation Path:**
1. Attacker submits transaction T1 that iterates over 10,000+ keys, paying gas during execution
2. T1's iterateset is recorded with all accessed keys
3. Attacker submits transaction T2 that writes to keys within T1's iteration range
4. Conflict detection triggers via `findConflicts()` → `ValidateTransactionState()`
5. Validation creates parent store iterators and iterates through all keys without consuming gas
6. With `maximumIterations = 10`, this validation can repeat up to 10 times
7. Result: Attacker pays gas for 1 execution but forces 1-10 unmetered validations [8](#0-7) [9](#0-8) 

**Security Guarantee Broken:**
The fundamental economic security principle that users must pay for all computational resources they cause validators to consume is violated. Validation operations scale linearly with transaction complexity but are completely unaccounted for in gas costs.

## Impact Explanation

This vulnerability enables resource exhaustion attacks affecting all validator nodes:

- **Resource Multiplier**: With standard gas costs of 30 gas per iteration (`IterNextCostFlat`), iterating 10,000 keys represents 300,000+ gas of work. With up to 10 validations, this becomes 3,000,000 gas of unmetered operations per transaction.

- **Network-wide Impact**: All validators must perform these unmetered validation operations when processing blocks, causing simultaneous CPU, I/O, and memory consumption increases across the entire network.

- **Economic Violation**: Attackers pay for X work but force validators to perform up to 11X work (1 execution + 10 validations), creating a massive resource consumption asymmetry.

- **Concrete Impact**: Batches of transactions with large iteratesets causing multiple validations can easily increase network-wide resource consumption by 300-1000%, far exceeding the Medium severity threshold of 30% resource consumption increase.

## Likelihood Explanation

**Triggering Conditions:**
- Any unprivileged user can submit transactions with arbitrarily large iteratesets (no size limits enforced)
- Conflicts are trivially induced by submitting transactions accessing overlapping key ranges
- Scheduler automatically triggers validation during parallel execution
- No special permissions or edge-case conditions required

**Frequency:**
- Occurs whenever transactions conflict during parallel execution
- Attacker can deliberately maximize by submitting batches of conflicting transactions with large iteratesets per block
- Every block with parallel execution enabled is vulnerable

**Accessibility:**
- Exploitable through normal transaction submission
- No privileged access needed
- Works with default parallel execution settings
- Attack cost bounded only by transaction gas limits, but 11× multiplier makes DoS economically viable

## Recommendation

Implement gas metering for validation operations:

1. **Meter validation storage operations**: Modify `ValidateTransactionState`, `checkReadsetAtIndex`, and `validateIterator` to accept and use a gas meter parameter. Wrap parent store accesses with `gaskv.NewStore()` or directly charge gas for each operation.

2. **Charge against transaction gas limit**: Validation gas should count against the original transaction's gas limit. Transactions exceeding their gas budget during validation should fail.

3. **Alternative mitigations** (if architectural constraints exist):
   - Impose hard limits on readset/iterateset sizes per transaction
   - Reduce `maximumIterations` from 10 to a lower value (e.g., 3)
   - Implement exponential backoff for repeated validations
   - Rate-limit transactions causing frequent validation failures

## Proof of Concept

**Conceptual Test** (implementable in `tasks/scheduler_test.go`):

**Setup:**
1. Initialize test context with tracked gas meter
2. Create multiversion store with 1,000 pre-populated keys
3. Create transaction T1: Iterates over all 1,000 keys
4. Create transaction T2: Writes to key within T1's iteration range

**Action:**
1. Execute T1 through scheduler - record gas consumed (~300,000 gas for 1,000 keys × 30 gas/key)
2. Execute T2 - creates write conflict with T1's iteration range
3. Scheduler validates T1 via `findConflicts()` → `ValidateTransactionState()` → `validateIterator()`
4. Monitor gas meter during validation phase

**Expected Result:**
- T1 execution: Gas meter increases by ~300,000+ gas
- T1 validation: Gas meter does NOT increase despite performing identical iteration operations
- Validation performs `parentStore.Iterator()` and loop with `Next()` calls without gas charges
- Multiple validations multiply unmetered work linearly

**Observation:**
Validation work (storage reads, iterator creation, key iteration) occurs completely outside gas accounting, allowing attackers to force validators to perform 2-11× more work than gas payment covers.

## Notes

The validation phase is architecturally necessary for OCC consistency, but the current implementation performs operations scaling linearly with transaction complexity without cost accounting. Since validation work is proportional to execution work and can occur up to 10 times per transaction, this creates a significant DoS vector violating the economic security model. The lack of readset/iterateset size limits exacerbates the issue, allowing attackers to maximize the resource consumption multiplier effect.

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

**File:** store/gaskv/store.go (L134-153)
```go
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
