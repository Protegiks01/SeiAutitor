# Audit Report

## Title
Concurrent Capability Creation Race Condition Causes Non-Deterministic Consensus Failure

## Summary
The capability module's `NewCapability` function writes to a shared `capMap` without synchronization during concurrent transaction execution via the OCC scheduler. This creates a data race where different validators may end up with different capability objects mapped to the same index, causing non-deterministic authentication results and consensus failure. [1](#0-0) 

## Impact
High

## Finding Description

**Location**: `x/capability/keeper/keeper.go` line 260 in the `NewCapability` function

**Intended Logic**: The capability module should provide deterministic capability creation and authentication across all validators. Each capability index should map to exactly one capability object, ensuring consistent authentication results across all nodes and deterministic consensus.

**Actual Logic**: 
The sei-cosmos blockchain uses an OCC (Optimistic Concurrency Control) scheduler that executes transactions concurrently in multiple goroutines (default 20 workers). [2](#0-1) [3](#0-2) 

All `ScopedKeeper` instances share the same `capMap` reference from the parent `Keeper`: [4](#0-3) 

The critical flaw is that `capMap` is a plain Go map accessed without any synchronization (no mutexes, no sync.Map), while the OCC scheduler only tracks reads/writes to the KVStore via multiversion stores. The `capMap` exists outside the KVStore and its modifications cannot be tracked or rolled back by OCC.

When multiple transactions concurrently execute `NewCapability`:
1. Both read the same index from the persistent store (optimistic read allowed by OCC)
2. Both create different capability objects with the same index
3. Both write to `capMap[index]` concurrently **without synchronization** - this is a data race
4. OCC detects the KVStore conflict (both wrote to `KeyIndex`) and aborts one transaction
5. The aborted transaction's KVStore writes (memStore entries) are properly rolled back
6. **However**, the `capMap[index]` write from the aborted transaction may persist due to the race condition

**Exploitation Path**:
1. User submits IBC transactions that create capabilities (e.g., port bindings, channel creations)
2. Two transactions in the same block both call `NewCapability` 
3. OCC scheduler executes them concurrently in separate goroutines
4. Both read `index=1`, create different capability objects (`capA` and `capB`), and race on `capMap[1]` write
5. OCC validation succeeds for one transaction (A), aborts the other (B)
6. Due to the race, `capMap[1]` may contain either `capA` (correct) or `capB` (wrong - from aborted tx)
7. Different validators have different goroutine scheduling, resulting in different race outcomes
8. Later transactions call `GetCapability` which reads from `capMap[1]` [5](#0-4) 
9. Validators with `capMap[1] = capA` return the correct capability; those with `capMap[1] = capB` return the wrong one
10. When `AuthenticateCapability` is called, it uses `FwdCapabilityKey` which encodes the capability's memory address [6](#0-5) 
11. For the wrong capability object, `memStore.Get(FwdCapabilityKey(module, wrongCap))` returns empty (the key was rolled back), causing authentication to fail
12. Different validators produce different authentication results → different transaction outcomes → different state roots → **consensus failure**

**Security Guarantee Broken**: Deterministic consensus - the same sequence of transactions must produce identical state across all validators.

## Impact Explanation

This vulnerability affects the fundamental consensus mechanism:

- **Scope**: All IBC channels, ports, and capability-based authorizations become non-deterministic
- **Consequence**: Validators disagree on capability authentication results within the same block, computing different state roots for identical transaction sequences
- **Network Effect**: The blockchain will halt or permanently split when validators cannot reach consensus on block validity
- **Recovery**: Requires a hard fork to fix the race condition and resync the network

The issue is particularly severe because:
1. It occurs during normal IBC operations (not an attack vector)
2. The non-determinism is probabilistic and scheduler-dependent (timing-based)
3. IBC is a critical component for cross-chain communication
4. There's existing acknowledgment in the code that `capMap` doesn't revert properly [7](#0-6) 

## Likelihood Explanation

**Triggering Actors**: Any user or protocol submitting transactions that create capabilities (IBC port bindings, channel openings, etc.)

**Required Conditions**:
- Concurrent transaction execution enabled (OCC scheduler with >1 worker)
- At least two transactions in the same block calling `NewCapability`
- Transactions executing concurrently and reading the same capability index

**Frequency Assessment**:
- **High likelihood**: IBC operations are frequent in production chains
- The default configuration uses 20 concurrent workers, maximizing the race window [2](#0-1) 
- Probability increases linearly with block size and transaction throughput
- The race is probabilistic but inevitable under sustained IBC traffic
- Once triggered, all subsequent authentications for that capability index are affected

## Recommendation

Replace the plain `map[uint64]*types.Capability` with `sync.Map` for thread-safe concurrent access:

```go
// In Keeper and ScopedKeeper structs
capMap sync.Map

// In NewCapability
sk.capMap.Store(index, cap)

// In GetCapability  
capInterface, ok := sk.capMap.Load(index)
if !ok {
    panic("capability found in memstore is missing from map")
}
cap := capInterface.(*types.Capability)

// In InitializeCapability
k.capMap.Store(index, cap)

// In ReleaseCapability
sk.capMap.Delete(cap.GetIndex())
```

Alternatively, protect all `capMap` access with a `sync.RWMutex` to ensure atomicity during concurrent execution. This would require:
- Adding `var capMapMu sync.RWMutex` to the Keeper struct
- Wrapping all `capMap` reads with `capMapMu.RLock()`/`capMapMu.RUnlock()`
- Wrapping all `capMap` writes with `capMapMu.Lock()`/`capMapMu.Unlock()`

## Proof of Concept

**File**: `x/capability/keeper/keeper_test.go`

**Test Function**: `TestConcurrentCapabilityRaceCondition`

**Setup**:
1. Initialize a capability keeper with two scoped modules ("ibc" and "transfer")
2. Initialize the keeper's memory store via `keeper.InitMemStore(ctx)`
3. Create a context that simulates concurrent OCC execution environment
4. Set up channels to coordinate goroutine execution timing

**Action**:
1. Launch two goroutines that simultaneously call `NewCapability` with different capability names
2. Use barriers/channels to ensure both goroutines read the same index before either commits
3. Both create capabilities with index=1 and race on `capMap[1]` write
4. Allow one transaction to complete successfully, simulate OCC aborting the other
5. Attempt to retrieve the capability via `GetCapability` and authenticate it via `AuthenticateCapability`

**Result**:
1. The test should detect (via `go test -race`) a data race on `capMap[index]`
2. Multiple test runs produce different authentication outcomes depending on race timing
3. Specifically, when `capMap[1]` contains the wrong capability object:
   - `GetCapability` returns a capability object
   - `AuthenticateCapability` returns `false` because `GetCapabilityName` returns empty string
   - The memStore has the correct forward key, but `capMap[1]` points to a different object
4. This demonstrates non-deterministic behavior: identical transaction sequences produce different results

Running with `go test -race` should detect the unsynchronized concurrent access to `capMap[index]`.

## Notes

The code already contains a comment acknowledging that "changes to go map do not automatically get reverted on tx failure" and references issue #7805. However, the current mitigation only handles the case where no capability exists in memStore, not the race condition where concurrent writes leave the wrong capability object in the map. This vulnerability requires immediate attention as it affects consensus determinism under the default concurrent execution configuration.

### Citations

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

**File:** tasks/scheduler.go (L449-472)
```go
func (s *scheduler) executeAll(ctx sdk.Context, tasks []*deliverTxTask) error {
	if len(tasks) == 0 {
		return nil
	}
	ctx, span := s.traceSpan(ctx, "SchedulerExecuteAll", nil)
	span.SetAttributes(attribute.Bool("synchronous", s.synchronous))
	defer span.End()

	// validationWg waits for all validations to complete
	// validations happen in separate goroutines in order to wait on previous index
	wg := &sync.WaitGroup{}
	wg.Add(len(tasks))

	for _, task := range tasks {
		t := task
		s.DoExecute(func() {
			s.prepareAndRunTask(wg, ctx, t)
		})
	}

	wg.Wait()

	return nil
}
```

**File:** x/capability/types/keys.go (L39-50)
```go
// FwdCapabilityKey returns a forward lookup key for a given module and capability
// reference.
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
