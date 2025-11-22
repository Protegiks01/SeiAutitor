## Title
Missing Pruned Height Validation in CreateQueryContext Allows Queries to Return Incorrect Empty State for IBC Proofs

## Summary
The `CreateQueryContext` function in baseapp does not validate whether the requested query height has been pruned from state storage. When a pruned height is queried, `CacheMultiStoreWithVersion` succeeds by returning an empty cache multi store instead of an error. This causes all queries at pruned heights to return empty/nil state, which can mislead IBC clients and relayers into believing that state (packets, channels, connections) never existed at that height. [1](#0-0) 

## Impact
**Medium** - A bug in the network code that results in unintended behavior with no concrete funds at direct risk.

## Finding Description

**Location:** 
- Primary issue: `baseapp/abci.go`, function `CreateQueryContext` (lines 712-761)
- Contributing issue: `store/iavl/store.go`, function `GetImmutable` (lines 123-143)
- Contributing issue: `store/rootmulti/store.go`, function `CacheMultiStoreWithVersion` (lines 581-605)

**Intended Logic:**
When a client queries historical state at a specific height, the system should validate that the height is available. If the height has been pruned, the query should return an error indicating that the data is no longer available. [2](#0-1) 

**Actual Logic:**
1. `CreateQueryContext` only validates that the height is non-negative, not in the future, and >1 if proofs are requested. It does NOT check if the height has been pruned. [3](#0-2) 

2. When `CacheMultiStoreWithVersion(height)` is called with a pruned height, it calls `GetImmutable(version)` on each IAVL store.

3. `GetImmutable` checks `VersionExists(version)`. If false (height is pruned), it returns an **empty immutable tree** with **no error**. [4](#0-3) 

4. This behavior is intentional per test requirements - the test explicitly states "require no failure when given an invalid or pruned version". [5](#0-4) 

5. The empty cache multi store is returned successfully, and queries against it return empty/nil results.

**Exploit Scenario:**
1. A node has pruned heights 1-1000 due to pruning configuration
2. An IBC relayer or light client queries height 500 to verify packet existence
3. `CreateQueryContext(500, true)` is called
4. The function succeeds and creates a context with empty stores
5. The IBC query returns nil/empty state for all keys
6. The relayer incorrectly believes the packet doesn't exist at that height
7. This could cause the relayer to skip packet processing or make incorrect state assumptions

**Security Failure:**
The system violates data integrity guarantees by returning successful but incorrect query results. Instead of returning an error indicating the data is unavailable (pruned), it returns empty state that appears to be valid historical state.

## Impact Explanation

**Affected Components:**
- IBC relayers querying historical packet, channel, or connection state
- Light clients verifying consensus state at pruned heights
- Any application querying historical state for proof generation

**Severity:**
While this doesn't directly cause loss of funds, it can lead to:
1. IBC relayers making incorrect decisions based on false "empty state" responses
2. Light clients unable to distinguish between "state never existed" and "state was pruned"
3. Breaking the reliability of historical queries, which IBC depends on for cross-chain verification
4. Potential for incorrect packet timeout handling if relayers query pruned heights

The store module's `Query` method with `Prove=true` correctly handles this by checking `VersionExists` and returning an error: [6](#0-5) 

However, gRPC queries that use `CreateQueryContext` bypass this check entirely.

## Likelihood Explanation

**Triggering Conditions:**
- Any user or client can trigger this by querying a height below the earliest available version
- No special privileges required
- Occurs during normal operation when nodes have pruning enabled (common in production)

**Frequency:**
- High: Any query to a pruned height will exhibit this behavior
- Common in production where nodes prune old state to save disk space
- IBC relayers frequently query historical heights for verification

**Who Can Trigger:**
Any network participant making queries - particularly:
- IBC relayers querying packet states
- Light clients verifying historical consensus states  
- External applications querying historical state

## Recommendation

Add validation in `CreateQueryContext` to check if the requested height has been pruned:

```go
func (app *BaseApp) CreateQueryContext(height int64, prove bool) (sdk.Context, error) {
    // ... existing validation ...
    
    // Check if height has been pruned
    var earliestVersion int64
    if height < app.migrationHeight && app.qms != nil {
        earliestVersion = app.qms.GetEarliestVersion()
    } else {
        earliestVersion = app.cms.GetEarliestVersion()
    }
    
    if height > 0 && height < earliestVersion {
        return sdk.Context{},
            sdkerrors.Wrapf(
                sdkerrors.ErrInvalidRequest,
                "cannot query pruned height %d; earliest available height is %d", 
                height, earliestVersion,
            )
    }
    
    // ... rest of function ...
}
```

The `GetEarliestVersion()` method already exists in the store interface: [7](#0-6) 

## Proof of Concept

**File:** `baseapp/abci_test.go` (add new test function)

**Test Function Name:** `TestCreateQueryContextPrunedHeight`

**Setup:**
1. Create a BaseApp with a multi-store configured with aggressive pruning (keep only recent 5 versions)
2. Commit 20 blocks to ensure pruning occurs
3. Store some IBC-like state (e.g., set key "ibc/packets/1") at height 5
4. Trigger pruning by committing more blocks

**Trigger:**
1. Call `CreateQueryContext(5, false)` where height 5 has been pruned
2. Query for the key "ibc/packets/1" from the returned context

**Observation:**
The test should demonstrate that:
- `CreateQueryContext` succeeds (returns no error) for a pruned height
- Querying the key returns nil/empty instead of the actual value that existed at that height
- No error indicates the data was pruned

**Expected Behavior After Fix:**
`CreateQueryContext` should return an error like "cannot query pruned height 5; earliest available height is 16"

This proves that the current implementation incorrectly allows queries to pruned heights and returns misleading empty state instead of a clear error message.

### Citations

**File:** baseapp/abci.go (L712-761)
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
```

**File:** store/rootmulti/store.go (L588-595)
```go
			store = rs.GetCommitKVStore(key)

			// Attempt to lazy-load an already saved IAVL store version. If the
			// version does not exist or is pruned, an error should be returned.
			iavlStore, err := store.(*iavl.Store).GetImmutable(version)
			if err != nil {
				return nil, err
			}
```

**File:** store/rootmulti/store.go (L1238-1240)
```go
func (rs *Store) GetEarliestVersion() int64 {
	return rs.earliestVersion
}
```

**File:** store/iavl/store.go (L127-132)
```go
	if !st.VersionExists(version) {
		return &Store{
			tree:    &immutableTree{&iavl.ImmutableTree{}},
			treeMtx: &sync.RWMutex{},
		}, nil
	}
```

**File:** store/iavl/store.go (L368-371)
```go
		if !st.VersionExists(res.Height) {
			res.Log = iavl.ErrVersionDoesNotExist.Error()
			break
		}
```

**File:** store/rootmulti/store_test.go (L88-90)
```go
	// require no failure when given an invalid or pruned version
	_, err = ms.CacheMultiStoreWithVersion(cID.Version + 1)
	require.NoError(t, err)
```
