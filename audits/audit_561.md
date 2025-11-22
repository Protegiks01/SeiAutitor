## Audit Report

## Title
Race Condition in Export State Access via Unlocked checkState Read

## Summary
The export functionality accesses application state through the `NewContext` method which directly reads `app.checkState.ms` without acquiring any locks, creating a data race with concurrent block processing operations that modify `checkState` through `setCheckState()` during commit operations. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- Primary vulnerability: `baseapp/test_helpers.go`, lines 57-64, in the `NewContext()` method
- Exploited by: `simapp/export.go`, line 22, calling `app.NewContext(true, tmproto.Header{Height: app.LastBlockHeight()})`
- Concurrent writer: `baseapp/abci.go`, line 393, calling `app.setCheckState(header)` during `Commit()`

**Intended Logic:**
The `NewContext` method should safely provide a context for operations by reading from the application's checkState or deliverState. The `state` struct provides thread-safe accessor methods (`MultiStore()`, `Context()`) that use internal read-write mutexes to protect concurrent access. [2](#0-1) 

The BaseApp also maintains a `checkTxStateLock` to coordinate access to checkState during modifications. [3](#0-2) 

**Actual Logic:**
The `NewContext` method directly accesses `app.checkState.ms` (line 59) and `app.deliverState.ms` (line 63) without acquiring `checkTxStateLock` or using the thread-safe `MultiStore()` accessor method. This creates an unsynchronized read that can race with concurrent writes during `setCheckState()` which properly acquires locks before modifying the state. [1](#0-0) 

**Exploit Scenario:**
1. A node operator initiates an export operation while the node continues processing blocks
2. Export calls `ExportAppStateAndValidators()` which invokes `app.NewContext(true, ...)` [4](#0-3) 

3. Simultaneously, block processing reaches the Commit phase and calls `app.setCheckState(header)` [5](#0-4) 

4. The export's `NewContext()` reads `app.checkState.ms` without any lock
5. The commit's `setCheckState()` writes to `app.checkState` while holding `checkTxStateLock`
6. This creates a classic data race: unsynchronized read concurrent with synchronized write

**Security Failure:**
Memory safety is violated through a data race. The export operation can read partially updated or inconsistent checkState, potentially leading to corrupted genesis data, export failures, or crashes.

## Impact Explanation

This vulnerability affects the state export functionality, which is critical for:
- Chain upgrades and migrations
- Creating genesis files for new chains
- Disaster recovery and state verification

The concurrent access issue can result in:
1. **Corrupted export data**: Reading inconsistent state during concurrent modification produces invalid genesis files
2. **Export operation failures**: Panic or crash when accessing partially updated state structures
3. **Operational disruptions**: Failed exports during critical upgrade windows could delay chain migrations

This qualifies as **Medium** severity under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the corrupted export could lead to incorrect state initialization if used for chain restarts or forks.

## Likelihood Explanation

**Triggering conditions:**
- Any node operator or validator running the export command while the node is actively processing blocks
- No special privileges required beyond node operator access
- The export command is documented for use during chain upgrades and state snapshots

**Frequency:**
- Moderate likelihood during normal operations
- High likelihood during chain upgrades when operators commonly export state from running nodes
- The race window occurs during every commit operation (each block), providing frequent opportunities

**Who can trigger:**
- Node operators with access to the CLI
- Automated scripts performing periodic state exports
- Validators preparing for chain upgrades

## Recommendation

Modify the `NewContext` method to acquire proper locks before accessing checkState:

```go
func (app *BaseApp) NewContext(isCheckTx bool, header tmproto.Header) sdk.Context {
    if isCheckTx {
        app.checkTxStateLock.RLock()
        defer app.checkTxStateLock.RUnlock()
        return sdk.NewContext(app.checkState.MultiStore(), header, true, app.logger).
            WithMinGasPrices(app.minGasPrices)
    }
    
    return sdk.NewContext(app.deliverState.MultiStore(), header, false, app.logger)
}
```

Alternatively, use the existing `GetCheckCtx()` method which already implements proper locking: [6](#0-5) 

## Proof of Concept

**Test File:** `baseapp/export_race_test.go`

**Setup:**
1. Create a BaseApp instance with checkState initialized
2. Start a goroutine that continuously commits blocks (calling setCheckState)
3. Start another goroutine that continuously calls NewContext (simulating export)
4. Run with Go race detector: `go test -race`

**Test Code:**
```go
func TestExportRaceCondition(t *testing.T) {
    app := setupBaseApp(t)
    
    // Initialize checkState
    header := tmproto.Header{Height: 1, ChainID: "test"}
    app.setCheckState(header)
    
    var wg sync.WaitGroup
    stopCh := make(chan struct{})
    
    // Goroutine 1: Simulate commit operations
    wg.Add(1)
    go func() {
        defer wg.Done()
        for i := 0; i < 1000; i++ {
            select {
            case <-stopCh:
                return
            default:
                header := tmproto.Header{Height: int64(i + 2)}
                app.setCheckState(header) // Writer with lock
            }
        }
    }()
    
    // Goroutine 2: Simulate export operations
    wg.Add(1)
    go func() {
        defer wg.Done()
        for i := 0; i < 1000; i++ {
            select {
            case <-stopCh:
                return
            default:
                _ = app.NewContext(true, tmproto.Header{}) // Reader without lock
            }
        }
    }()
    
    wg.Wait()
}
```

**Observation:**
Running this test with the race detector (`go test -race`) will report a data race between the write in `setCheckState()` and the read in `NewContext()`, confirming the vulnerability.

### Citations

**File:** baseapp/test_helpers.go (L57-64)
```go
func (app *BaseApp) NewContext(isCheckTx bool, header tmproto.Header) sdk.Context {
	if isCheckTx {
		return sdk.NewContext(app.checkState.ms, header, true, app.logger).
			WithMinGasPrices(app.minGasPrices)
	}

	return sdk.NewContext(app.deliverState.ms, header, false, app.logger)
}
```

**File:** baseapp/state.go (L9-27)
```go
type state struct {
	ms  sdk.CacheMultiStore
	ctx sdk.Context
	mtx *sync.RWMutex
}

// CacheMultiStore calls and returns a CacheMultiStore on the state's underling
// CacheMultiStore.
func (st *state) CacheMultiStore() sdk.CacheMultiStore {
	st.mtx.RLock()
	defer st.mtx.RUnlock()
	return st.ms.CacheMultiStore()
}

func (st *state) MultiStore() sdk.CacheMultiStore {
	st.mtx.RLock()
	defer st.mtx.RUnlock()
	return st.ms
}
```

**File:** baseapp/baseapp.go (L558-574)
```go
// on Commit.
func (app *BaseApp) setCheckState(header tmproto.Header) {
	ms := app.cms.CacheMultiStore()
	ctx := sdk.NewContext(ms, header, true, app.logger).WithMinGasPrices(app.minGasPrices)
	app.checkTxStateLock.Lock()
	defer app.checkTxStateLock.Unlock()
	if app.checkState == nil {
		app.checkState = &state{
			ms:  ms,
			ctx: ctx,
			mtx: &sync.RWMutex{},
		}
		return
	}
	app.checkState.SetMultiStore(ms)
	app.checkState.SetContext(ctx)
}
```

**File:** baseapp/baseapp.go (L1249-1253)
```go
func (app *BaseApp) GetCheckCtx() sdk.Context {
	app.checkTxStateLock.RLock()
	defer app.checkTxStateLock.RUnlock()
	return app.checkState.ctx
}
```

**File:** simapp/export.go (L18-22)
```go
func (app *SimApp) ExportAppStateAndValidators(
	forZeroHeight bool, jailAllowedAddrs []string,
) (servertypes.ExportedApp, error) {
	// as if they could withdraw from the start of the next block
	ctx := app.NewContext(true, tmproto.Header{Height: app.LastBlockHeight()})
```

**File:** baseapp/abci.go (L389-393)
```go
	// Reset the Check state to the latest committed.
	//
	// NOTE: This is safe because Tendermint holds a lock on the mempool for
	// Commit. Use the header from this latest block.
	app.setCheckState(header)
```
