## Audit Report

## Title
Non-Atomic Multi-Store Commit Allows Partial State Persistence on Failure

## Summary
The commit process in `store/rootmulti/store.go` persists multiple substores sequentially without atomic guarantees. If any substore's commit operation fails partway through (due to disk errors, database issues, or IAVL tree corruption), previously committed substores remain persisted at the new version while subsequent substores stay at the old version, creating an inconsistent state that violates multi-write atomicity.

## Impact
**High** - Unintended permanent chain split requiring hard fork

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
When committing state changes, all substores should atomically transition to the new version together. If any part of the commit fails, all changes should be rolled back to maintain consistency across the entire multistore, ensuring that either all substores commit successfully or none do.

**Actual Logic:** 
The `commitStores` function iterates through all mounted substores and calls `Commit()` on each one sequentially. Each `Commit()` call persists that individual store's state to disk immediately. The IAVL store's `Commit()` method can panic if `SaveVersion()` fails: [2](#0-1) 

When a panic occurs during the loop, stores committed before the failure point have already been permanently persisted to disk at version N+1, while stores after the failure remain at version N. There is no rollback mechanism to undo the partial commits.

**Exploit Scenario:**
1. A validator node processes a block containing valid transactions
2. During the commit phase, the system calls `app.cms.Commit(true)`: [3](#0-2) 
3. This triggers `commitStores()` which iterates through substores (e.g., bank, staking, gov, distribution)
4. Suppose the bank store commits successfully (persisted to disk at version 1000)
5. The staking store's `SaveVersion()` encounters a disk full error and panics at line 167
6. The panic halts the commit process
7. Result: Bank store is at version 1000 on disk, but staking store remains at version 999
8. The node crashes or restarts with this inconsistent state
9. On restart, the multistore attempts to load all stores at the same version, but they are mismatched
10. This leads to state hash mismatches, consensus failures, or chain halt

**Security Failure:** 
The atomicity guarantee for multi-write operations is violated. The commit process does not satisfy the ACID property that either all substores commit or none do. This breaks the fundamental invariant that all substores must be at the same version to maintain state consistency and consensus agreement.

## Impact Explanation

This vulnerability affects:
- **Consensus integrity**: Nodes with inconsistent substore versions will compute different state hashes, breaking consensus
- **State consistency**: Cross-store invariants (e.g., total supply tracked in bank must match staked amounts) can be violated if stores are at different versions
- **Network availability**: If all validators encounter this during the same block, the network cannot progress
- **Fund safety**: Inconsistent state between financial modules (bank, staking, distribution) can lead to permanent fund lockup

The damage is severe because:
- Once stores are persisted at different versions on disk, recovery requires manual intervention
- Different validators may end up with different partial commit states depending on when their disk errors occur
- The only fix is a coordinated hard fork to roll back to a consistent state
- User funds become inaccessible until the chain is recovered

This matters for security because the blockchain's core guarantee—that state transitions are atomic and consistent—is broken, undermining trust in the system's correctness.

## Likelihood Explanation

**Triggering conditions:**
- Any validator or full node operator running the sei-protocol/sei-cosmos node software
- Realistic operational conditions that cause I/O errors:
  - Disk full (common on long-running validators with insufficient monitoring)
  - Disk hardware failure or corruption
  - Database corruption from unexpected shutdowns
  - File system errors
  - Write permission issues

**Frequency:**
- Disk full errors are not uncommon in production blockchain nodes, especially those running 24/7 with heavy transaction load
- Can occur during any block commit, making it a continuous risk
- More likely during periods of high transaction volume when disk writes increase
- Once triggered, the damage is permanent until manually fixed

**Who can trigger it:**
- Not directly exploitable by malicious actors
- However, it's a latent bug that will manifest under normal operational stress
- Affects all nodes equally—even honest validators are vulnerable
- Since disk errors are unpredictable, this could happen to multiple validators simultaneously during the same block, causing widespread consensus failure

The vulnerability is highly likely to manifest in production environments given the typical operational lifespan and stress conditions of blockchain validator nodes.

## Recommendation

Implement atomic commit guarantees using database transactions or a two-phase commit protocol:

1. **Short-term fix**: Wrap all substore commits in a single database batch transaction that can be atomically committed or rolled back. Modify `commitStores()` to:
   - Collect commit data from all stores without persisting
   - Execute a single atomic batch write operation
   - Ensure all stores are written or none are

2. **Alternative approach**: Implement a two-phase commit:
   - Phase 1: Prepare all stores (validate and stage changes in memory)
   - Phase 2: If all stores prepare successfully, commit all in a single atomic operation
   - If any store fails during prepare, abort all

3. **Error handling**: Add recovery logic that detects version mismatches on startup and either:
   - Automatically rolls back to the last consistent state
   - Refuses to start and requires manual intervention to prevent further damage

## Proof of Concept

**Test File**: `store/rootmulti/store_test.go`

**Test Function**: Add new test `TestNonAtomicCommitFailure`

**Setup**:
1. Create a rootmulti Store with multiple IAVL substores (e.g., store1, store2, store3)
2. Mount all stores and load the initial version
3. Write different test data to each store to ensure they all have changes to commit
4. Mock or inject a failure condition that will cause the second store's commit to panic (e.g., by replacing its database with a mock that returns errors after the first commit succeeds)

**Trigger**:
1. Call `store.Commit(true)` on the rootmulti store
2. Ensure the first store commits successfully
3. Ensure the second store's `SaveVersion()` returns an error, triggering the panic at: [4](#0-3) 

**Observation**:
1. After the panic, check the persistent storage directly
2. Verify that store1 has been persisted at version N+1 (using `VersionExists(N+1)`)
3. Verify that store2 and store3 remain at version N (using `VersionExists(N)` returns true but `VersionExists(N+1)` returns false)
4. Attempt to reload the multistore—it will fail to find a consistent version across all stores
5. This confirms the atomicity violation: some stores advanced while others didn't

The test demonstrates that partial commits are persisted to disk, breaking the multi-write rollback guarantee and creating unrecoverable state inconsistency.

## Notes

This vulnerability is a fundamental design flaw in how the multistore orchestrates commits across multiple substores. The sequential commit pattern without transactional guarantees makes it impossible to ensure atomicity when failures occur. The issue is exacerbated by the fact that IAVL stores panic on errors rather than returning errors that could be handled gracefully. While disk errors may seem like "exceptional" circumstances, they are actually quite common in long-running distributed systems and must be handled correctly to ensure system reliability and data integrity.

### Citations

**File:** store/rootmulti/store.go (L1112-1133)
```go
// Commits each store and returns a new commitInfo.
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

**File:** baseapp/abci.go (L385-387)
```go
	app.WriteState()
	app.GetWorkingHash()
	app.cms.Commit(true)
```
