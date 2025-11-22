## Audit Report

## Title
Silent Failure on Pruned Height Queries Returns Empty Data Instead of Error

## Summary
The `CreateQueryContext` function in `baseapp/abci.go` fails to properly validate whether a requested height has been pruned from storage. When querying a pruned height, instead of returning an error, it silently returns a query context with empty stores, causing queries to return incorrect empty results that are indistinguishable from legitimately empty state. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: `store/iavl/store.go`, function `GetImmutable()` (lines 123-143)
- Secondary issue: `baseapp/abci.go`, function `CreateQueryContext()` (lines 712-762) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
When a user queries a historical height through `CreateQueryContext`, the system should:
1. Validate the height is within available range
2. Return an error if the height has been pruned
3. Only return a valid context if the actual state data exists

**Actual Logic:**
The `GetImmutable()` function returns an empty IAVL tree with **no error** when `VersionExists(version)` returns false (indicating a pruned version): [4](#0-3) 

This empty tree propagates through `CacheMultiStoreWithVersion()` in `store/rootmulti/store.go`: [5](#0-4) 

Since no error is returned, the error check at lines 747-753 in `baseapp/abci.go` does not trigger, and a context with empty stores is created successfully.

**Exploit Scenario:**
1. A blockchain node runs with pruning enabled (e.g., `KeepRecent: 100` blocks)
2. Current block height is 1000
3. A user queries account balance at height 50 (which has been pruned)
4. `CreateQueryContext(50, false)` validates: height > 0 ✓, height < 1000 ✓
5. `CacheMultiStoreWithVersion(50)` calls `GetImmutable(50)` for each IAVL store
6. `VersionExists(50)` returns false (pruned)
7. `GetImmutable` returns empty tree with no error
8. Query executes on empty stores and returns balance = 0
9. User receives incorrect data: "balance was 0 at height 50" when actual balance was 1000 tokens

**Security Failure:**
Data integrity violation. The system returns incorrect empty data instead of an error, breaking the invariant that queries must either return accurate historical state or explicitly fail. This causes unintended behavior in applications relying on historical queries.

## Impact Explanation

**Affected Components:**
- Historical state queries via RPC/gRPC
- Applications/smart contracts querying past state
- Indexers and block explorers relying on historical data
- Any service using `CreateQueryContext` for historical queries

**Severity:**
This bug results in unintended behavior with no direct funds at risk, but affects data integrity:
- Applications receive incorrect empty results for pruned heights
- Cannot distinguish between "data doesn't exist" vs "height unavailable"
- May cause incorrect business logic decisions based on false "empty state"
- Affects governance queries, staking queries, balance queries at historical heights
- Violates user expectations that unavailable data returns an error

This matches the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"

## Likelihood Explanation

**Who can trigger it:**
Any user or application making historical queries through RPC endpoints

**Conditions required:**
- Node has pruning enabled (common in production for disk space management)
- Query targets a height that has been pruned
- Query does not request proofs (proof queries have partial mitigation but still succeed with empty proofs)

**Frequency:**
This occurs regularly in production:
- Most validator nodes run with pruning enabled
- Historical queries are common for analytics, block explorers, and dApps
- Users frequently query heights beyond the retention window
- The issue is systematic and affects all pruned height queries

The vulnerability triggers during normal operation whenever pruned heights are queried, making it highly likely to occur in practice.

## Recommendation

Add explicit version existence validation in `GetImmutable()` or `CreateQueryContext()`:

**Option 1 - Fix in `GetImmutable()`:**
Change `store/iavl/store.go` lines 127-132 to return an error instead of empty tree:
```go
if !st.VersionExists(version) {
    return nil, fmt.Errorf("version %d does not exist or has been pruned", version)
}
```

**Option 2 - Add validation in `CreateQueryContext()`:**
After line 745 in `baseapp/abci.go`, add version existence check:
```go
// Validate that the requested height still exists (not pruned)
for key, store := range app.cms.GetStores() {
    if store.GetStoreType() == types.StoreTypeIAVL {
        s := app.cms.GetCommitKVStore(key)
        if iavlStore, ok := s.(*iavl.Store); ok {
            if !iavlStore.VersionExists(height) {
                return sdk.Context{}, sdkerrors.Wrapf(
                    sdkerrors.ErrInvalidRequest,
                    "height %d has been pruned; earliest available height: %d",
                    height, app.cms.(*rootmulti.Store).GetEarliestVersion(),
                )
            }
        }
    }
}
```

**Recommendation:** Implement Option 1 for cleaner separation of concerns and consistent behavior across all uses of `GetImmutable()`.

## Proof of Concept

**File:** `baseapp/baseapp_test.go`
**Test Function:** `TestCreateQueryContextPrunedHeight` (new test to add)

**Setup:**
```go
func TestCreateQueryContextPrunedHeight(t *testing.T) {
    logger := log.NewNopLogger()
    db := dbm.NewMemDB()
    name := t.Name()
    
    // Create app with aggressive pruning: keep only last 3 blocks
    pruningOpt := SetPruning(store.PruningOptions{
        KeepRecent: 3,
        KeepEvery:  0,  // Don't keep any snapshots
        Interval:   1,  // Prune every block
    })
    
    app := NewBaseApp(name, logger, db, nil, nil, &testutil.TestAppOpts{}, pruningOpt)
    capKey := sdk.NewKVStoreKey("teststore")
    app.MountStores(capKey)
    require.NoError(t, app.LoadLatestVersion())
    
    // Commit 10 blocks with data
    for i := int64(1); i <= 10; i++ {
        ctx := app.NewContext(true, tmproto.Header{Height: i})
        store := ctx.KVStore(capKey)
        store.Set([]byte("key"), []byte(fmt.Sprintf("value_at_height_%d", i)))
        
        app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{Height: i})
        app.SetDeliverStateToCommit()
        app.Commit(context.Background())
    }
    
    // At this point, heights 1-6 should be pruned (only keeping 7, 8, 9, 10)
    // Verify current state
    require.Equal(t, int64(10), app.LastBlockHeight())
}
```

**Trigger:**
```go
    // Query a pruned height (height 5 should be pruned)
    prunedHeight := int64(5)
    ctx, err := app.CreateQueryContext(prunedHeight, false)
```

**Observation:**
```go
    // BUG: This should return an error but doesn't
    require.NoError(t, err, "Expected error for pruned height, but got none")
    
    // Query returns empty data instead of error
    store := ctx.KVStore(capKey)
    value := store.Get([]byte("key"))
    
    // BUG: Returns empty instead of the actual value "value_at_height_5"
    // User cannot distinguish between "key doesn't exist" vs "height is pruned"
    require.Nil(t, value, "Expected nil for pruned height (BUG: should have errored instead)")
    
    // For comparison, query an available height
    availableHeight := int64(9)
    ctx2, err2 := app.CreateQueryContext(availableHeight, false)
    require.NoError(t, err2)
    store2 := ctx2.KVStore(capKey)
    value2 := store2.Get([]byte("key"))
    require.NotNil(t, value2)
    require.Equal(t, []byte("value_at_height_9"), value2)
```

The test demonstrates that querying pruned height 5 succeeds (no error) but returns empty data, which is incorrect behavior. The expected behavior is to return an error indicating the height is unavailable/pruned.

### Citations

**File:** baseapp/abci.go (L712-762)
```go
func (app *BaseApp) CreateQueryContext(height int64, prove bool) (sdk.Context, error) {
	err := checkNegativeHeight(height)
	if err != nil {
		return sdk.Context{}, err
	}

	lastBlockHeight := app.LastBlockHeight()
	if height > lastBlockHeight {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidHeight,
				"cannot query with height in the future; please provide a valid height",
			)
	}

	// when a client did not provide a query height, manually inject the latest
	if height == 0 {
		height = lastBlockHeight
	}

	if height <= 1 && prove {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidRequest,
				"cannot query with proof when height <= 1; please provide a valid height",
			)
	}

	var cacheMS types.CacheMultiStore
	if height < app.migrationHeight && app.qms != nil {
		cacheMS, err = app.qms.CacheMultiStoreWithVersion(height)
	} else {
		cacheMS, err = app.cms.CacheMultiStoreWithVersion(height)
	}

	if err != nil {
		return sdk.Context{},
			sdkerrors.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"failed to load state at height %d; %s (latest height: %d)", height, err, lastBlockHeight,
			)
	}

	checkStateCtx := app.checkState.Context()
	// branch the commit-multistore for safety
	ctx := sdk.NewContext(
		cacheMS, checkStateCtx.BlockHeader(), true, app.logger,
	).WithMinGasPrices(app.minGasPrices).WithBlockHeight(height)

	return ctx, nil
}
```

**File:** store/iavl/store.go (L123-143)
```go
func (st *Store) GetImmutable(version int64) (*Store, error) {
	st.treeMtx.RLock()
	defer st.treeMtx.RUnlock()

	if !st.VersionExists(version) {
		return &Store{
			tree:    &immutableTree{&iavl.ImmutableTree{}},
			treeMtx: &sync.RWMutex{},
		}, nil
	}

	iTree, err := st.tree.GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &Store{
		tree:    &immutableTree{iTree},
		treeMtx: &sync.RWMutex{},
	}, nil
}
```

**File:** store/rootmulti/store.go (L581-605)
```go
func (rs *Store) CacheMultiStoreWithVersion(version int64) (types.CacheMultiStore, error) {
	cachedStores := make(map[types.StoreKey]types.CacheWrapper)
	for key, store := range rs.stores {
		switch store.GetStoreType() {
		case types.StoreTypeIAVL:
			// If the store is wrapped with an inter-block cache, we must first unwrap
			// it to get the underlying IAVL store.
			store = rs.GetCommitKVStore(key)

			// Attempt to lazy-load an already saved IAVL store version. If the
			// version does not exist or is pruned, an error should be returned.
			iavlStore, err := store.(*iavl.Store).GetImmutable(version)
			if err != nil {
				return nil, err
			}

			cachedStores[key] = iavlStore

		default:
			cachedStores[key] = store
		}
	}

	return cachemulti.NewStore(rs.db, cachedStores, rs.keysByName, rs.traceWriter, rs.getTracingContext(), rs.listeners), nil
}
```
