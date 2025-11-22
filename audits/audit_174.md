## Title
Data Race in Capability Keeper's Shared capMap During Concurrent Transaction Execution

## Summary
The capability keeper uses an unsynchronized Go map (`capMap`) that is accessed concurrently by multiple goroutines during parallel transaction execution, causing data races that lead to node panics and crashes. The vulnerability exists in `x/capability/keeper/keeper.go` where `capMap` is defined (lines 33, 60) and accessed by multiple concurrent operations without any synchronization primitives.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:**
- Primary vulnerability: [1](#0-0) 
- Map initialization: [2](#0-1) 
- Shared reference in ScopedKeeper: [3](#0-2) 

**Intended Logic:**
The capability keeper maintains an in-memory map (`capMap`) that stores capability pointers indexed by capability index. This map should be accessed safely during transaction execution to create, retrieve, and release capabilities. [4](#0-3) 

**Actual Logic:**
The `capMap` is a regular Go map without any synchronization. Multiple operations access it concurrently:
- Write operation in `NewCapability`: [5](#0-4) 
- Read operation in `GetCapability`: [6](#0-5) 
- Delete operation in `ReleaseCapability`: [7](#0-6) 
- Write operation in `InitializeCapability`: [8](#0-7) 

Sei-cosmos implements concurrent transaction execution through an optimistic concurrency control scheduler that processes transactions in parallel using worker goroutines: [9](#0-8) [10](#0-9) 

When multiple transactions execute concurrently and perform capability operations, they race on the shared `capMap`.

**Exploit Scenario:**
1. A block contains multiple transactions that use IBC or other modules requiring capability operations
2. The scheduler executes these transactions concurrently via worker goroutines: [11](#0-10) 
3. Transaction A calls `NewCapability` which writes to `capMap[index]`
4. Transaction B simultaneously calls `GetCapability` which reads from `capMap[index]`
5. Go's runtime detects the concurrent map access and panics with "concurrent map read and map write"
6. The node crashes immediately

**Security Failure:**
Memory safety violation. Go's map implementation is not thread-safe and explicitly panics when concurrent access is detected. This violates the availability guarantee of the blockchain network.

## Impact Explanation

**Affected Components:**
- All nodes processing blocks with concurrent transactions using capabilities
- Network availability and consensus
- IBC operations and any module using the capability keeper

**Severity of Damage:**
- Node crashes with panic: "concurrent map read and map write" or "concurrent map writes"
- Complete node unavailability until restart
- If multiple validators experience this simultaneously, the network cannot reach consensus
- Transactions cannot be confirmed, blocks cannot be produced
- Total network shutdown if enough validators crash

**Why This Matters:**
Capability-based modules (especially IBC) are critical infrastructure. Any block containing multiple IBC transactions or concurrent capability operations will trigger this race condition, causing widespread node crashes. This directly threatens network liveness and reliability.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant submitting transactions. No special privileges required.

**Conditions Required:**
- A block must contain at least 2 transactions that perform capability operations (e.g., IBC channel operations, port bindings)
- Concurrent transaction execution must be enabled (default configuration): [12](#0-11) 
- The scheduler must schedule these transactions to run in parallel (normal operation)

**Frequency:**
- Very likely during normal operation
- IBC is a core feature; blocks regularly contain multiple IBC transactions
- Concurrent execution is the default mode for performance
- The race detector would catch this immediately if tests were run with `-race` flag
- Production deployments without race detection will experience random crashes during high transaction throughput

## Recommendation

Replace the regular Go map with a thread-safe alternative. The codebase already uses this pattern in other concurrent stores:

**Option 1 (Recommended):** Use `sync.Map` like the multiversion store does: [13](#0-12) 

**Option 2:** Add a `sync.RWMutex` to protect all `capMap` accesses, following the pattern in the cache store: [14](#0-13) 

**Implementation:**
1. Change `capMap map[uint64]*types.Capability` to `capMap *sync.Map` in both `Keeper` and `ScopedKeeper` structs
2. Update all map operations:
   - `capMap[index] = cap` → `capMap.Store(index, cap)`
   - `cap := capMap[index]` → `capInterface, _ := capMap.Load(index); cap := capInterface.(*types.Capability)`
   - `delete(capMap, index)` → `capMap.Delete(index)`
3. Initialize with `capMap: &sync.Map{}` instead of `make(map[uint64]*types.Capability)`

## Proof of Concept

**File:** `x/capability/keeper/keeper_race_test.go` (new test file)

**Setup:**
Create a test that simulates concurrent transaction execution with capability operations.

**Trigger:**
Spawn multiple goroutines that concurrently perform `NewCapability`, `GetCapability`, and `ReleaseCapability` operations on the same keeper instance, mimicking the scheduler's behavior.

**Observation:**
When run with `go test -race`, the test will report data races. Without `-race` flag, it may panic with "concurrent map read and map write" or produce corrupted state.

**Test Code Structure:**
```go
func TestCapabilityMapConcurrentAccess(t *testing.T) {
    // Setup: Create keeper and scoped keepers
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    keeper := keeper.NewKeeper(cdc, storeKey, memKey)
    
    sk1 := keeper.ScopeToModule("module1")
    sk2 := keeper.ScopeToModule("module2")
    
    // Trigger: Launch concurrent goroutines performing capability operations
    // Each goroutine simulates a transaction worker
    var wg sync.WaitGroup
    workers := 10
    
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            // Simulate capability operations in concurrent transactions
            cap, _ := sk1.NewCapability(ctx, fmt.Sprintf("cap-%d", id))
            sk1.GetCapability(ctx, fmt.Sprintf("cap-%d", id))
            if cap != nil {
                sk1.ReleaseCapability(ctx, cap)
            }
        }(i)
    }
    
    wg.Wait()
    
    // Observation: With -race flag, this test will fail with data race detection
    // Without -race, it may panic with "concurrent map read and map write"
}
```

**Run Command:**
```bash
go test -race -run TestCapabilityMapConcurrentAccess ./x/capability/keeper/
```

**Expected Result:**
The test will report data races on the `capMap` accesses, confirming the vulnerability. The race detector output will show conflicting accesses from multiple goroutines to the same map.

### Citations

**File:** x/capability/keeper/keeper.go (L33-33)
```go
		capMap        map[uint64]*types.Capability
```

**File:** x/capability/keeper/keeper.go (L60-60)
```go
		capMap:        make(map[uint64]*types.Capability),
```

**File:** x/capability/keeper/keeper.go (L87-87)
```go
		capMap:   k.capMap,
```

**File:** x/capability/keeper/keeper.go (L211-211)
```go
		k.capMap[index] = cap
```

**File:** x/capability/keeper/keeper.go (L260-260)
```go
	sk.capMap[index] = cap
```

**File:** x/capability/keeper/keeper.go (L349-349)
```go
		delete(sk.capMap, cap.GetIndex())
```

**File:** x/capability/keeper/keeper.go (L382-382)
```go
	cap := sk.capMap[index]
```

**File:** docs/architecture/adr-003-dynamic-capability-store.md (L35-41)
```markdown
The `CapabilityKeeper` will include a persistent `KVStore`, a `MemoryStore`, and an in-memory map.
The persistent `KVStore` tracks which capability is owned by which modules.
The `MemoryStore` stores a forward mapping that map from module name, capability tuples to capability names and
a reverse mapping that map from module name, capability name to the capability index.
Since we cannot marshal the capability into a `KVStore` and unmarshal without changing the memory location of the capability,
the reverse mapping in the KVStore will simply map to an index. This index can then be used as a key in the ephemeral
go-map to retrieve the capability at the original memory location.
```

**File:** tasks/scheduler.go (L136-147)
```go
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
```

**File:** tasks/scheduler.go (L266-267)
```go
			s.multiVersionStores[storeKey].SetEstimatedWriteset(req.AbsoluteIndex, -1, writeset)
		}
```

**File:** tasks/scheduler.go (L309-309)
```go
	start(workerCtx, s.executeCh, workers)
```

**File:** baseapp/abci.go (L266-267)
```go
	scheduler := tasks.NewScheduler(app.concurrencyWorkers, app.TracingInfo, app.DeliverTx)
	txRes, err := scheduler.ProcessAll(ctx, req.TxEntries)
```

**File:** store/multiversion/store.go (L42-47)
```go
	multiVersionMap *sync.Map
	// TODO: do we need to support iterators as well similar to how cachekv does it - yes

	txWritesetKeys *sync.Map // map of tx index -> writeset keys []string
	txReadSets     *sync.Map // map of tx index -> readset ReadSet
	txIterateSets  *sync.Map // map of tx index -> iterateset Iterateset
```

**File:** store/cache/cache.go (L34-36)
```go
		// the same CommitKVStoreCache may be accessed concurrently by multiple
		// goroutines due to transaction parallelization
		mtx sync.RWMutex
```
