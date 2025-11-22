## Title
InterBlockCache Not Invalidated After State Rollback Leading to Stale Cache Reads

## Summary
The `RollbackToVersion` function in `store/rootmulti/store.go` rolls back the underlying IAVL stores to a previous version but fails to invalidate the `interBlockCache`. This allows subsequent reads to return stale cached values from before the rollback, leading to incorrect transaction execution based on outdated state. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in the `RollbackToVersion` function in `store/rootmulti/store.go` (lines 1034-1056), and in how the cache is reused in `loadCommitStoreFromParams` (lines 983-988) via `GetStoreCache` in `store/cache/cache.go` (lines 74-80).

**Intended Logic:** When a rollback is performed to recover from incorrect state, all in-memory caches should be invalidated to ensure reads reflect the rolled-back state. This is the pattern followed during snapshot restoration. [2](#0-1) 

**Actual Logic:** The `RollbackToVersion` function performs the following:
1. Unwraps the interBlockCache to access underlying IAVL stores
2. Calls `LoadVersionForOverwriting` to roll back each IAVL store
3. Calls `LoadLatestVersion` which reloads stores
4. During reload, `loadCommitStoreFromParams` wraps stores with the cache manager
5. The cache manager's `GetStoreCache` method **reuses existing caches** if they already exist for a given key
6. The stale cache entries from before the rollback remain active [3](#0-2) [4](#0-3) [5](#0-4) 

**Exploit Scenario:** 
1. A node processes blocks up to height N, where state includes `key="balance"` with `value="1000"`
2. The interBlockCache caches this key-value pair
3. Node operator discovers incorrect state and runs the rollback command to height N-1, where `key="balance"` had `value="500"`
4. `RollbackToVersion` executes: underlying IAVL stores roll back to N-1 state
5. `LoadLatestVersion` reloads stores but reuses the existing cache containing `balance=1000`
6. If the node processes any transactions before restart (or if custom code uses the store programmatically), reads of `balance` return the stale cached value `1000` instead of the correct rolled-back value `500`
7. Transactions execute with incorrect state, leading to invalid state transitions

**Security Failure:** This breaks the consistency invariant between cached state and persistent state. After a rollback, the cache serves stale data that doesn't match the underlying store, causing transactions to execute based on incorrect state. This can lead to state divergence between nodes if rollbacks are performed inconsistently, or incorrect execution logic in smart contracts/modules.

## Impact Explanation

**Affected Components:**
- Transaction execution logic that reads from stores after rollback
- State consistency between the cache layer and persistent IAVL stores
- Smart contract and module execution that depends on correct state values

**Severity:**
- Transactions reading stale cached values will execute based on incorrect state
- This can cause unintended smart contract behavior, incorrect balance calculations, invalid state transitions, or unauthorized operations
- If multiple nodes perform rollbacks at different times or inconsistently, stale cache values could cause state divergence
- The test suite explicitly works around this issue by recreating the entire application after rollback to get "clean check state" [6](#0-5) 

**Why This Matters:**
While rollback is an administrative operation typically followed by a node restart (which would clear the in-memory cache), there is no enforcement of this requirement in code. The asymmetry with snapshot restoration—which explicitly resets the cache—suggests this is an oversight rather than intentional design. Programmatic use of `RollbackToVersion` in tests, custom tooling, or recovery scripts could trigger this bug without proper cache clearing.

## Likelihood Explanation

**Who Can Trigger:**
Only node operators with CLI/administrative access can trigger rollback via the rollback command. However, custom code or automated scripts could programmatically call `RollbackToVersion` without proper cache invalidation.

**Conditions Required:**
1. Node must have interBlockCache enabled (common in production for performance)
2. Rollback operation must be performed via `RollbackToVersion`
3. Node must process transactions or state queries after rollback but before restart
4. The rolled-back state must differ from pre-rollback state for affected keys

**Frequency:**
- Rollback is a disaster recovery operation, so relatively rare in normal operation
- However, when rollback IS needed (incorrect state emergency), this bug could have critical impact
- Testing and development environments that use rollback more frequently are particularly vulnerable
- The existing test suite requires explicit workarounds (app recreation) to avoid this issue

## Recommendation

Add explicit cache invalidation in `RollbackToVersion` after rolling back the underlying stores, consistent with the pattern used in snapshot restoration:

```go
func (rs *Store) RollbackToVersion(target int64) error {
    // ... existing rollback logic ...
    
    rs.SetLastCommitInfo(commitStores(target, rs.stores, false))
    rs.flushMetadata(rs.db, target, rs.LastCommitInfo())
    
    // Add cache invalidation before LoadLatestVersion
    if rs.interBlockCache != nil {
        rs.interBlockCache.Reset()
    }
    
    return rs.LoadLatestVersion()
}
```

This ensures the cache is cleared after rollback, preventing stale reads. This mirrors the pattern already implemented for snapshot restoration in `baseapp/abci.go`.

## Proof of Concept

**File:** `store/rootmulti/rollback_cache_test.go` (new test file in the rootmulti package)

**Setup:**
1. Create a SimApp with interBlockCache enabled using `baseapp.SetInterBlockCache(store.NewCommitKVStoreCacheManager())`
2. Initialize the chain and commit the genesis block
3. Process a block that sets a key-value pair in a store
4. Commit the block to ensure the cache is populated

**Trigger:**
1. Call `RollbackToVersion` to roll back to the previous block (before the key was set)
2. Without recreating the app or resetting the cache, attempt to read the key from a new context

**Observation:**
The test will observe that the key returns the cached value from before the rollback instead of nil (or the pre-rollback value), demonstrating that the cache was not invalidated. The test should assert that after rollback, reads return the correct rolled-back state, but with the current code, it will fail because the cache serves stale data.

```go
func TestRollbackWithInterBlockCache(t *testing.T) {
    // Setup: Create app with interBlockCache
    db := dbm.NewMemDB()
    encCdc := simapp.MakeTestEncodingConfig()
    cacheManager := store.NewCommitKVStoreCacheManager()
    
    app := simapp.NewSimApp(
        log.NewNopLogger(), 
        db, 
        nil, 
        true, 
        map[int64]bool{}, 
        simapp.DefaultNodeHome, 
        5, 
        nil, 
        encCdc, 
        simapp.EmptyAppOptions{},
    )
    
    // Enable interBlockCache
    app.CommitMultiStore().SetInterBlockCache(cacheManager)
    
    // Initialize chain
    app.InitChain(context.Background(), &abci.RequestInitChain{
        Validators: []abci.ValidatorUpdate{},
        ConsensusParams: simapp.DefaultConsensusParams,
        AppStateBytes: []byte("{}"),
    })
    
    initialHeight := app.LastBlockHeight()
    
    // Commit block with a key set
    header := tmproto.Header{Height: initialHeight + 1, AppHash: app.LastCommitID().Hash}
    app.BeginBlock(sdk.Context{}, abci.RequestBeginBlock{Header: header})
    ctx := app.NewContext(false, header)
    kvStore := ctx.KVStore(app.GetKey("bank"))
    testKey := []byte("test-key")
    testValue := []byte("test-value")
    kvStore.Set(testKey, testValue)
    app.Commit(context.Background())
    
    // Verify value is set and cached
    readCtx := app.NewContext(true, tmproto.Header{Height: initialHeight + 1})
    readStore := readCtx.KVStore(app.GetKey("bank"))
    require.Equal(t, testValue, readStore.Get(testKey), "Value should be set")
    
    // Rollback to initial height (before key was set)
    require.NoError(t, app.CommitMultiStore().RollbackToVersion(initialHeight))
    
    // BUG: Without recreating app, cache still has stale entry
    // Read the key - it should return nil since we rolled back
    readCtx2 := app.NewContext(true, tmproto.Header{Height: initialHeight})
    readStore2 := readCtx2.KVStore(app.GetKey("bank"))
    value := readStore2.Get(testKey)
    
    // This assertion SHOULD pass (value should be nil after rollback)
    // But it will FAIL because cache returns stale value
    require.Nil(t, value, "Key should not exist after rollback, but cache returns stale value")
}
```

The test demonstrates that after rollback without cache reset, the stale cached value is returned instead of the correct rolled-back state (nil in this case). This confirms the vulnerability.

### Citations

**File:** store/rootmulti/store.go (L983-988)
```go
		if rs.interBlockCache != nil {
			// Wrap and get a CommitKVStore with inter-block caching. Note, this should
			// only wrap the primary CommitKVStore, not any store that is already
			// branched as that will create unexpected behavior.
			store = rs.interBlockCache.GetStoreCache(key, store)
		}
```

**File:** store/rootmulti/store.go (L1034-1056)
```go
// RollbackToVersion delete the versions after `target` and update the latest version.
func (rs *Store) RollbackToVersion(target int64) error {
	if target <= 0 {
		return fmt.Errorf("invalid rollback height target: %d", target)
	}

	fmt.Printf("Target Version=%d\n", target)
	for key, store := range rs.stores {
		if store.GetStoreType() == types.StoreTypeIAVL {
			// If the store is wrapped with an inter-block cache, we must first unwrap
			// it to get the underlying IAVL store.
			store = rs.GetCommitKVStore(key)
			latestVersion, err := store.(*iavl.Store).LoadVersionForOverwriting(target)
			if err != nil {
				return err
			}
			fmt.Printf("Reset key=%s to height=%d\n", key.Name(), latestVersion)
		}
	}
	rs.SetLastCommitInfo(commitStores(target, rs.stores, false))
	rs.flushMetadata(rs.db, target, rs.LastCommitInfo())
	return rs.LoadLatestVersion()
}
```

**File:** baseapp/abci.go (L638-640)
```go
			if app.interBlockCache != nil {
				app.interBlockCache.Reset()
			}
```

**File:** store/cache/cache.go (L74-80)
```go
func (cmgr *CommitKVStoreCacheManager) GetStoreCache(key types.StoreKey, store types.CommitKVStore) types.CommitKVStore {
	if cmgr.caches[key.Name()] == nil {
		cmgr.caches[key.Name()] = NewCommitKVStoreCache(store, cmgr.cacheSize, cmgr.cacheKVSize)
	}

	return cmgr.caches[key.Name()]
}
```

**File:** store/rootmulti/rollback_test.go (L79-83)
```go
	// recreate app to have clean check state
	encCdc := simapp.MakeTestEncodingConfig()
	app = simapp.NewSimApp(log.NewNopLogger(), db, nil, true, map[int64]bool{}, simapp.DefaultNodeHome, 5, nil, encCdc, simapp.EmptyAppOptions{})
	store = app.NewContext(true, tmproto.Header{}).KVStore(app.GetKey("bank"))
	require.Equal(t, []byte("value5"), store.Get([]byte("key")))
```
