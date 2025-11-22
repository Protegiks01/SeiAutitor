## Title
Non-Atomic Multi-Store Commit During Upgrade Leads to Permanent State Inconsistency

## Summary
During chain upgrades, state migration commits are not atomic across multiple stores. The `commitStores` function sequentially commits each store, and if any store's commit fails (panics), previously committed stores remain at the new version while uncommitted stores remain at the old version, creating permanent cross-store state inconsistency.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended Logic:** 
State migration during upgrades should be atomic - either all stores successfully commit to the new version, or all remain at the old version. If an upgrade fails, the system should be in a consistent, recoverable state.

**Actual Logic:** 
The `commitStores` function iterates through all stores and calls `Commit()` on each sequentially without any transaction boundary or rollback mechanism. The IAVL store's `Commit()` method panics if `SaveVersion()` returns an error. When a panic occurs on the Nth store, stores 1 through N-1 have already persisted their new versions to disk, while stores N through the end remain at the old version. [3](#0-2) 

Additionally, the `Write()` operation in `cachekv.Store` has a TODO comment acknowledging that writes are not atomic: "TODO: Consider allowing usage of Batch, which would allow the write to at least happen atomically."

**Exploit Scenario:**
1. An upgrade is scheduled for block height N with migrations for multiple modules
2. At block N, migrations execute successfully for all modules
3. `FinalizeBlock` completes and the ABCI server calls `Commit()`
4. `commitStores` begins committing stores sequentially:
   - Stores 1-3 (e.g., auth, bank, staking) successfully commit to version N
   - Store 4 (e.g., distribution) encounters an error during `SaveVersion()`:
     - Disk I/O failure due to disk full or corruption
     - Out of memory due to large tree size
     - Database corruption detected during save
5. The IAVL Commit() panics, causing the node to crash
6. On restart, stores 1-3 are at version N with migrated data, stores 4+ are at version N-1 with pre-migration data
7. The module version map may indicate upgrade completion if stored in an early committed store
8. Cross-module operations now read inconsistent data, leading to consensus failures

**Security Failure:** 
This violates atomicity and consistency guarantees during state migration. The system enters an unrecoverable inconsistent state where different stores have incompatible data schemas and versions.

## Impact Explanation

This vulnerability affects the entire chain's state consistency and can lead to:

- **Permanent State Corruption**: Stores have incompatible versions with mismatched data schemas. Module logic expecting migrated data in one store may read unmigrated data from another store.

- **Consensus Failure**: Validators that successfully complete all commits will have different app hashes than validators that experience partial commit failures. This creates an unintended permanent chain split requiring a hard fork to resolve.

- **Total Network Shutdown**: If a significant portion of validators experience the same partial commit failure pattern, the network cannot reach consensus on subsequent blocks, halting transaction processing.

- **Unrecoverable Without Hard Fork**: The standard rollback mechanism cannot fix this because individual stores are at different versions. A coordinated hard fork with state export/import or manual database surgery is required.

The severity is high because this directly maps to the in-scope impacts: "Unintended permanent chain split requiring hard fork" and "Network not being able to confirm new transactions (total network shutdown)."

## Likelihood Explanation

**Who can trigger it:** This is not directly exploitable by an attacker, but can occur naturally during normal upgrade operations. Any validator node performing an upgrade is susceptible.

**Conditions required:**
- A scheduled chain upgrade with state migrations
- One of the following failures during commit:
  - Disk I/O error (disk full, hardware failure, corruption)
  - Out of memory condition (especially with large state trees)
  - Database-level errors
  - Bugs in the IAVL tree implementation

**Frequency:** 
- Moderate to High likelihood during major upgrades with large state migrations
- More likely on validator nodes with resource constraints
- Increased probability as chain state grows over time
- Risk multiplies across all validators in the network

The likelihood is moderate because while not every upgrade will trigger this, the conditions (especially disk space or memory issues) are realistic operational scenarios that can occur during high-value mainnet upgrades.

## Recommendation

Implement atomic commit across all stores using a two-phase commit protocol:

1. **Phase 1 - Prepare**: Have each store prepare the commit (generate the new version) but not persist to disk yet. If any store fails during prepare, abort all stores.

2. **Phase 2 - Commit**: Only after all stores successfully prepare, commit all stores in a single atomic operation. Implement this using database-level transactions or write-ahead logging.

3. **Add Rollback**: If Phase 2 fails midway, implement automatic rollback to restore all stores to their pre-commit state.

4. **Specific code changes**:
   - Modify `commitStores` to collect commit data from all stores first before persisting any
   - Use database batching to ensure all-or-nothing persistence
   - Add error handling instead of panics to enable graceful rollback
   - Consider implementing the TODO in cachekv.Store to use Batch operations

5. **Add validation**: After commit completes, verify all stores are at the same version before returning.

## Proof of Concept

**Test File**: `store/rootmulti/store_test.go`

**Test Function**: `TestNonAtomicCommitDuringUpgrade`

**Setup**:
1. Create a multi-store with multiple IAVL substores (at least 3)
2. Initialize all stores to version 1 with some initial data
3. Modify state in all stores to simulate migration changes
4. Create a failing store that will panic during Commit (mock or inject failure in SaveVersion)

**Trigger**:
1. Begin committing all stores via `commitStores`
2. Configure the 3rd store to fail during its `Commit()` call
3. Catch the resulting panic

**Observation**:
1. Verify stores 1 and 2 successfully persisted version 2 to disk (check their LastCommitID)
2. Verify stores 3+ remain at version 1 (never committed)
3. Create a new multi-store instance loading from the same database
4. Observe that loading produces inconsistent state: some stores at v2, others at v1
5. This confirms the stores are in an irrecoverable inconsistent state

The test demonstrates that partial commit creates permanent inconsistency that cannot be automatically recovered. A production system experiencing this would require manual intervention (hard fork) to resolve.

**Note**: While a complete working test would require mocking IAVL SaveVersion failures or injecting disk I/O errors, the vulnerability is clearly demonstrated by the sequential commit pattern in the code with no transaction boundaries or rollback capability. The architectural flaw is evident from code inspection combined with the panic-on-error pattern in IAVL Commit.

### Citations

**File:** store/rootmulti/store.go (L1113-1133)
```go
func commitStores(version int64, storeMap map[types.StoreKey]types.CommitKVStore, bumpVersion bool) *types.CommitInfo {
	storeInfos := make([]types.StoreInfo, 0, len(storeMap))

	for key, store := range storeMap {
		commitID := store.Commit(bumpVersion)

		if store.GetStoreType() == types.StoreTypeTransient {
			continue
		}

		si := types.StoreInfo{}
		si.Name = key.Name()
		si.CommitId = commitID
		storeInfos = append(storeInfos, si)
	}

	return &types.CommitInfo{
		Version:    version,
		StoreInfos: storeInfos,
	}
}
```

**File:** store/iavl/store.go (L153-174)
```go
func (st *Store) Commit(bumpVersion bool) types.CommitID {
	st.treeMtx.Lock()
	defer st.treeMtx.Unlock()
	defer telemetry.MeasureSince(time.Now(), "store", "iavl", "commit")

	var hash []byte
	var version int64
	var err error
	if bumpVersion {
		hash, version, err = st.tree.SaveVersion()
	} else {
		hash, version, err = st.tree.SaveCurrentVersion()
	}
	if err != nil {
		panic(err)
	}

	return types.CommitID{
		Version: version,
		Hash:    hash,
	}
}
```

**File:** store/cachekv/store.go (L116-117)
```go
	// TODO: Consider allowing usage of Batch, which would allow the write to
	// at least happen atomically.
```
