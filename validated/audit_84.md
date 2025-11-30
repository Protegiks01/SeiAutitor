# Audit Report

## Title
Concurrent Capability Creation Race Condition Causes Non-Deterministic Consensus Failure

## Summary
The capability module's `NewCapability` function writes to a shared `capMap` without synchronization during concurrent transaction execution in the OCC scheduler. This creates a data race where different validators end up with different capability objects mapped to the same index, causing non-deterministic authentication results and consensus failure.

## Impact
High

## Finding Description

**Location**: `x/capability/keeper/keeper.go` line 260 in the `NewCapability` function [1](#0-0) 

**Intended Logic**: The capability module should provide deterministic capability creation and authentication across all validators. Each capability index should map to exactly one capability object, ensuring consistent authentication results across all nodes. The design assumes that when a transaction is aborted, all its state changes are rolled back, maintaining consistency.

**Actual Logic**: 
The sei-cosmos blockchain executes transactions concurrently using an OCC scheduler with 20 workers by default [2](#0-1) , spawning multiple worker goroutines [3](#0-2) .

All `ScopedKeeper` instances share the same `capMap` reference [4](#0-3) , which is defined as a plain Go map without synchronization [5](#0-4) .

When multiple transactions concurrently execute `NewCapability`, they perform unsynchronized writes to `capMap[index]` [1](#0-0) . The OCC scheduler only tracks KVStore operations via multiversion stores [6](#0-5) , not plain Go maps. When a transaction is aborted, its KVStore writes are rolled back, but the `capMap[index]` write persists.

**Exploitation Path**:
1. User submits IBC transactions that call `NewCapability` (e.g., channel creation, port binding)
2. Scheduler executes transactions concurrently in worker goroutines [7](#0-6) 
3. Two transactions (Tx1, Tx2) read the same index value from KVStore [8](#0-7) 
4. Both create different capability objects (`capA`, `capB`) with that index [9](#0-8) 
5. Both race on writing to `capMap[index]` without synchronization [1](#0-0) 
6. Both write to KVStore, creating a conflict [10](#0-9) 
7. OCC scheduler detects the conflict and aborts one transaction
8. The aborted transaction's KVStore and memStore writes are rolled back, but `capMap[index]` may contain either `capA` or `capB` depending on race timing
9. Different validators have different goroutine scheduling → different race outcomes → different `capMap` contents
10. Later `GetCapability` calls [11](#0-10)  return different capability objects on different validators
11. `AuthenticateCapability` uses `FwdCapabilityKey` which encodes the capability's memory address [12](#0-11) 
12. For the wrong capability object, authentication fails because the memStore key was rolled back
13. Different validators produce different authentication results → different transaction outcomes → different state roots → consensus failure

**Security Guarantee Broken**: Deterministic consensus - identical transaction sequences must produce identical state across all validators.

## Impact Explanation

This vulnerability affects the fundamental consensus mechanism of the blockchain:

- **Scope**: All capability-based operations (IBC channels, ports, module authorizations) become non-deterministic
- **Consequence**: Validators disagree on capability authentication results, computing different state roots for identical transaction sequences
- **Network Effect**: The blockchain will halt or permanently split when validators cannot reach consensus on block validity
- **Recovery**: Requires a hard fork to add synchronization to the capability module and resync the network

The codebase already acknowledges that `capMap` doesn't revert properly [13](#0-12) , but this TODO doesn't address the concurrent race condition scenario.

## Likelihood Explanation

**Triggering Actors**: Any user submitting transactions that create capabilities (IBC operations, module initialization)

**Required Conditions**:
- Concurrent transaction execution (enabled by default with 20 workers)
- At least two transactions in the same block calling `NewCapability`
- Transactions executing concurrently and reading the same capability index

**Frequency Assessment**:
- **High likelihood** during normal operations with IBC activity
- Default configuration uses 20 concurrent workers, maximizing the race window
- Probability increases with block size and transaction throughput
- The race is probabilistic but inevitable under sustained IBC traffic
- Once triggered, all subsequent authentications for that capability index are affected until a hard fork

## Recommendation

Replace the plain `map[uint64]*types.Capability` with thread-safe concurrent access patterns:

**Option 1**: Use `sync.Map` for built-in concurrency safety
**Option 2**: Add `sync.RWMutex` protection around all `capMap` access

All reads must use `RLock()`/`RUnlock()` and all writes must use `Lock()`/`Unlock()` to ensure atomicity during concurrent execution. The codebase already uses these patterns elsewhere [6](#0-5)  and [14](#0-13) , confirming their suitability for this scenario.

## Proof of Concept

While the report describes a test function `TestConcurrentCapabilityRaceCondition`, the actual test implementation is not provided in the codebase. However, the vulnerability is evident from code inspection:

**Setup**: Initialize capability keeper with concurrent transaction execution enabled (default configuration)

**Action**: 
1. Submit two transactions in the same block that call `NewCapability` with different names
2. Both transactions execute concurrently in the OCC scheduler
3. Both read the same index and create different capability objects
4. Both race on writing to `capMap[index]`
5. OCC detects KVStore conflict and aborts one transaction

**Expected Result**: Running with `go test -race` would detect a data race on `capMap[index]`. Different validators would observe different authentication outcomes depending on race timing, demonstrating non-deterministic consensus behavior.

## Notes

This vulnerability exists in production code and affects consensus determinism under the default concurrent execution configuration. The ADR-003 design document [15](#0-14)  explicitly describes the intended behavior of reverting capability creation on transaction failure, but this design assumes sequential execution or proper synchronization, which is broken by the concurrent OCC scheduler. The issue represents a critical mismatch between the capability module's sequential design and the concurrent execution model introduced by the OCC scheduler.

### Citations

**File:** x/capability/keeper/keeper.go (L33-33)
```go
		capMap        map[uint64]*types.Capability
```

**File:** x/capability/keeper/keeper.go (L83-89)
```go
	return ScopedKeeper{
		cdc:      k.cdc,
		storeKey: k.storeKey,
		memKey:   k.memKey,
		capMap:   k.capMap,
		module:   moduleName,
	}
```

**File:** x/capability/keeper/keeper.go (L236-236)
```go
	index := types.IndexFromKey(store.Get(types.KeyIndex))
```

**File:** x/capability/keeper/keeper.go (L237-237)
```go
	cap := types.NewCapability(index)
```

**File:** x/capability/keeper/keeper.go (L245-245)
```go
	store.Set(types.KeyIndex, types.IndexToKey(index+1))
```

**File:** x/capability/keeper/keeper.go (L260-260)
```go
	sk.capMap[index] = cap
```

**File:** x/capability/keeper/keeper.go (L361-388)
```go
func (sk ScopedKeeper) GetCapability(ctx sdk.Context, name string) (*types.Capability, bool) {
	if strings.TrimSpace(name) == "" {
		return nil, false
	}
	memStore := ctx.KVStore(sk.memKey)

	key := types.RevCapabilityKey(sk.module, name)
	indexBytes := memStore.Get(key)
	index := sdk.BigEndianToUint64(indexBytes)

	if len(indexBytes) == 0 {
		// If a tx failed and NewCapability got reverted, it is possible
		// to still have the capability in the go map since changes to
		// go map do not automatically get reverted on tx failure,
		// so we delete here to remove unnecessary values in map
		// TODO: Delete index correctly from capMap by storing some reverse lookup
		// in-memory map. Issue: https://github.com/cosmos/cosmos-sdk/issues/7805

		return nil, false
	}

	cap := sk.capMap[index]
	if cap == nil {
		panic("capability found in memstore is missing from map")
	}

	return cap, true
}
```

**File:** server/config/config.go (L25-26)
```go
	// DefaultConcurrencyWorkers defines the default workers to use for concurrent transactions
	DefaultConcurrencyWorkers = 20
```

**File:** tasks/scheduler.go (L47-47)
```go
	mx            sync.RWMutex
```

**File:** tasks/scheduler.go (L135-148)
```go
func start(ctx context.Context, ch chan func(), workers int) {
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case work := <-ch:
					work()
				}
			}
		}()
	}
}
```

**File:** store/multiversion/store.go (L40-50)
```go
type Store struct {
	// map that stores the key string -> MultiVersionValue mapping for accessing from a given key
	multiVersionMap *sync.Map
	// TODO: do we need to support iterators as well similar to how cachekv does it - yes

	txWritesetKeys *sync.Map // map of tx index -> writeset keys []string
	txReadSets     *sync.Map // map of tx index -> readset ReadSet
	txIterateSets  *sync.Map // map of tx index -> iterateset Iterateset

	parentStore types.KVStore
}
```

**File:** baseapp/abci.go (L266-266)
```go
	scheduler := tasks.NewScheduler(app.concurrencyWorkers, app.TracingInfo, app.DeliverTx)
```

**File:** x/capability/types/keys.go (L41-50)
```go
func FwdCapabilityKey(module string, cap *Capability) []byte {
	// encode the key to a fixed length to avoid breaking consensus state machine
	// it's a hacky backport of https://github.com/cosmos/cosmos-sdk/pull/11737
	// the length 10 is picked so it's backward compatible on common architectures.
	key := fmt.Sprintf("%#010p", cap)
	if len(key) > 10 {
		key = key[len(key)-10:]
	}
	return []byte(fmt.Sprintf("%s/fwd/0x%s", module, key))
}
```

**File:** docs/architecture/adr-003-dynamic-capability-store.md (L329-330)
```markdown
- Dynamic capability support.
- Allows CapabilityKeeper to return same capability pointer from go-map while reverting any writes to the persistent `KVStore` and in-memory `MemoryStore` on tx failure.
```
