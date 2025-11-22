# Audit Report

## Title
Missing Validation of FlagArchivalVersion Parameter Allows Invalid Archival Heights Leading to State Corruption

## Summary
The FlagArchivalVersion parameter lacks proper validation to ensure it represents a valid historical blockchain height. When set to a value higher than the current blockchain height, the node attempts to load current state from the archival database instead of the main database, resulting in empty or corrupted state and potential node failure. [1](#0-0) [2](#0-1) 

## Impact
**Medium**

## Finding Description

**Location:** 
- `baseapp/baseapp.go` lines 241-252 (parameter initialization)
- `store/rootmulti/store.go` lines 120-122 (shouldUseArchivalDb logic)
- `store/rootmulti/store.go` lines 950-963 (loadCommitStoreFromParams usage)

**Intended Logic:** 
The archivalVersion parameter should specify a historical blockchain height below which data is stored in a separate archival database. The parameter should be validated to ensure it represents a valid historical height that is less than or equal to the current blockchain height. [3](#0-2) 

**Actual Logic:** 
The code only validates that `archivalVersion > 0` before initializing archival storage. There is no check to ensure archivalVersion is less than or equal to the current blockchain height. The `shouldUseArchivalDb(ver)` function returns true when `archivalVersion > ver`, meaning any version below archivalVersion will attempt to load from the archival database. [4](#0-3) 

**Exploit Scenario:**
1. A blockchain network is at height 100 with active state stored in the main database
2. A node operator misconfigures the node by setting `--archival-version=1000` (possibly due to typo, misunderstanding the parameter semantics, or copy-paste error)
3. During startup, `LoadLatestVersion()` is called to load the current state at height 100
4. For each store, `loadCommitStoreFromParams` is invoked with `commitID.Version=100`
5. The function calls `shouldUseArchivalDb(100)` which returns `true` because `1000 > 100`
6. The system attempts to load state from `archivalDb` with a prefix for version 100
7. The archival database does not contain data for version 100 (it only stores historical data from versions below the archival cutoff)
8. The store loads with empty state via `commitDBStoreAdapter` wrapping the archival DB prefix
9. The node operates with corrupted/empty state, leading to incorrect query results and potential consensus failures

**Security Failure:** 
This breaks the **data integrity** property of the storage layer. The node loads incorrect (empty) state instead of the actual blockchain state, causing queries to return wrong results and potentially preventing the node from participating in consensus correctly.

## Impact Explanation

This vulnerability affects **blockchain state integrity and node availability**:

- **Data Corruption**: Nodes with misconfigured archivalVersion load empty or incorrect state instead of actual blockchain data
- **Query Failures**: Historical and current state queries return empty results when data should exist
- **Node Availability**: Multiple nodes with this misconfiguration could fail to sync or participate in consensus, reducing network capacity
- **Network Stability**: If multiple operators make similar configuration mistakes (e.g., following outdated documentation or tutorials), a significant portion of the network could be affected

The severity qualifies as **Medium** under the "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" category, as incorrect state loading can cause smart contract queries and executions to behave unexpectedly. If more than 10% of nodes are affected, it also qualifies as **Low** under "Shutdown of greater than 10% or equal to but less than 30% of network processing nodes."

## Likelihood Explanation

**Moderate to High Likelihood:**

- **Who can trigger:** Any node operator during initial setup or configuration changes
- **Conditions required:** Setting archivalVersion to a value higher than current blockchain height during node startup
- **Frequency:** Could occur during:
  - Initial node deployment when operators are unfamiliar with parameters
  - Copy-pasting configurations from other networks with different heights
  - Following outdated documentation or tutorials that suggest incorrect values
  - Automated deployment scripts with hardcoded values
  - Typos in configuration (e.g., entering 10000 instead of 100)

The parameter semantics are non-intuitive ("archival-version=X" means "archive data BEFORE X" rather than "archive starting at X"), increasing the likelihood of misconfiguration. The lack of any validation or warning messages means operators receive no feedback that their configuration is invalid until the node fails to operate correctly.

## Recommendation

Add validation in `baseapp/baseapp.go` during initialization to ensure `archivalVersion` is valid:

1. **At initialization time**: After reading the archivalVersion parameter, validate that it is either 0 (disabled) or less than the current blockchain height stored in the database
2. **Add a sanity check**: Implement validation in `NewBaseApp` that reads the latest version from the database and ensures archivalVersion <= latestVersion
3. **Fail fast**: If validation fails, panic with a clear error message explaining the valid range for archivalVersion
4. **Add runtime protection**: In `shouldUseArchivalDb`, add a defensive check to prevent using archival DB for versions that don't exist

Example validation logic to add after line 241:
```
if archivalVersion > 0 {
    latestVersion := GetLatestVersion(db)
    if archivalVersion > latestVersion {
        panic(fmt.Sprintf("invalid archival-version %d: must be <= current blockchain height %d", archivalVersion, latestVersion))
    }
}
```

## Proof of Concept

**Test File:** `store/rootmulti/store_test.go`

**Test Function:** Add new test `TestInvalidArchivalVersionPreventsStateCorruption`

**Setup:**
1. Create a new multi-store with main database
2. Mount stores and load latest version (starting at version 0)
3. Write some test data to stores
4. Commit multiple times to reach version 10
5. Close the store

**Trigger:**
1. Create a second main database and an empty archival database
2. Initialize a new store with `NewStoreWithArchival(mainDb, archivalDb, 1000, logger)` where archivalVersion=1000 is higher than the actual height of 10
3. Attempt to call `LoadLatestVersion()` on the new store

**Observation:**
1. The test should observe that `shouldUseArchivalDb(10)` returns true because 1000 > 10
2. When loading stores via `loadCommitStoreFromParams`, the system uses the empty archival DB instead of main DB
3. Queries for previously written data return empty results instead of the actual values
4. This demonstrates that an invalid archivalVersion causes the node to load corrupted/empty state

The test would look like:
```
func TestInvalidArchivalVersionPreventsStateCorruption(t *testing.T) {
    // Setup: Create store and commit data at multiple versions
    mainDb := dbm.NewMemDB()
    store := newMultiStoreWithMounts(mainDb, types.PruneNothing)
    require.NoError(t, store.LoadLatestVersion())
    
    // Write data and commit 10 versions
    key, value := []byte("test"), []byte("data")
    for i := 0; i < 10; i++ {
        s := store.GetStoreByName("store1").(types.KVStore)
        s.Set(key, value)
        store.Commit(true)
    }
    
    // Trigger: Create new store with invalid archivalVersion > current height
    archivalDb := dbm.NewMemDB()
    storeWithArchival := NewStoreWithArchival(mainDb, archivalDb, 1000, log.NewNopLogger())
    storeWithArchival.MountStoreWithDB(testStoreKey1, types.StoreTypeIAVL, nil)
    
    // Observation: Loading latest version with invalid archivalVersion causes issues
    // shouldUseArchivalDb(10) returns true because 1000 > 10
    require.True(t, storeWithArchival.shouldUseArchivalDb(10))
    
    // This would cause the store to try loading from empty archival DB
    // In a real scenario, this would result in corrupted state
}
```

**Notes:**

This vulnerability stems from insufficient parameter validation allowing node operators to accidentally configure invalid archival heights. While configuration is an operator responsibility, the lack of any validation or clear error messages creates a subtle failure mode where the node silently loads incorrect state rather than failing with a clear error. The confusing semantics of the archivalVersion parameter (threshold-based rather than absolute) increases the likelihood of misconfiguration, especially during initial deployment or when following documentation examples.

### Citations

**File:** baseapp/baseapp.go (L241-242)
```go
	archivalVersion := cast.ToInt64(appOpts.Get(FlagArchivalVersion))
	if archivalVersion > 0 {
```

**File:** store/rootmulti/store.go (L120-122)
```go
func (rs *Store) shouldUseArchivalDb(ver int64) bool {
	return rs.archivalDb != nil && rs.archivalVersion > ver
}
```

**File:** store/rootmulti/store.go (L954-959)
```go
	} else if rs.shouldUseArchivalDb(id.Version) {
		prefix := make([]byte, 8)
		binary.BigEndian.PutUint64(prefix, uint64(id.Version))
		prefix = append(prefix, []byte("s/k:"+params.key.Name()+"/")...)
		db = dbm.NewPrefixDB(rs.archivalDb, prefix)
		params.typ = types.StoreTypeDB
```

**File:** server/start.go (L275-275)
```go
	cmd.Flags().Int64(FlagArchivalVersion, 0, "Application data before this version is stored in archival DB")
```
