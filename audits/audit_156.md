# Audit Report

## Title
Transaction Revert After ReleaseCapability Causes Permanent Capability DoS via Inconsistent capMap State

## Summary
The `ReleaseCapability` function in `x/capability/keeper/keeper.go` deletes capability entries from the in-memory `capMap` at line 349, but this deletion is not automatically reverted when a transaction fails. Since `capMap` is a Go map outside the transactional KVStore system, failed transactions leave the system in an inconsistent state where the capability exists in memStore/persistent store but is missing from `capMap`, causing all subsequent `GetCapability` calls to panic. [1](#0-0) 

## Impact
**High** - This vulnerability allows an attacker to permanently freeze IBC channels and other capability-based operations, potentially causing network-wide transaction processing failures.

## Finding Description

**Location:** `x/capability/keeper/keeper.go`, function `ReleaseCapability` (lines 319-356), specifically the `capMap` deletion at line 349, and the subsequent panic in `GetCapability` at line 384. [2](#0-1) 

**Intended Logic:** When `ReleaseCapability` is called and no owners remain for a capability, the function should atomically remove the capability from both the persistent store and the in-memory `capMap`. If the transaction fails, all state changes should be reverted to maintain consistency.

**Actual Logic:** The `ReleaseCapability` function performs the following operations in sequence:
1. Lines 332, 336: Deletes forward/reverse mappings from memStore (TRANSACTIONAL - reverts on tx failure)
2. Lines 339-340: Removes owner from `capOwners` in-memory structure (NON-TRANSACTIONAL)
3. Line 347: Deletes from persistent store when no owners remain (TRANSACTIONAL - reverts on tx failure)
4. Line 349: Deletes from `capMap` when no owners remain (NON-TRANSACTIONAL - does NOT revert on tx failure)

When a transaction containing `ReleaseCapability` fails after line 349 executes, the memStore and persistent store changes are automatically reverted by the cache context mechanism, but the `capMap` deletion is NOT reverted because it's a standard Go map. [3](#0-2) 

**Exploit Scenario:**
1. Attacker creates or claims a capability (e.g., through IBC channel operations)
2. Attacker crafts a transaction with multiple messages where:
   - First message calls `ReleaseCapability` on the capability (as the last/only owner)
   - Second message intentionally fails (e.g., invalid operation, out of gas, etc.)
3. During execution:
   - `ReleaseCapability` executes completely, deleting from `capMap` at line 349
   - The second message fails, causing the transaction to abort
   - Cache context is not written, reverting memStore and persistent store changes
   - But `capMap` deletion is NOT reverted
4. Result: System enters inconsistent state where memStore/persistent store have the capability, but `capMap[index]` is nil

5. When ANY module subsequently calls `GetCapability` for that capability:
   - Line 368-369: Retrieves the index from memStore (which still exists after revert)
   - Line 382: Looks up `cap := sk.capMap[index]`
   - Line 383: `cap` is nil (deleted but not reverted)
   - Line 384: Panics with "capability found in memstore is missing from map" [4](#0-3) 

**Security Failure:** This breaks the critical invariant that `capMap` must always contain entries for all capabilities that exist in the memStore. The panic at line 384 causes a denial-of-service, making the capability permanently unusable and potentially crashing nodes that attempt to use it.

## Impact Explanation

**Affected Assets/Processes:**
- IBC channel capabilities: Channels become permanently frozen and unusable
- Port capabilities: Ports become inaccessible to modules
- Transaction processing: Any transaction attempting to use the affected capability will panic
- Node availability: Repeated attempts to use the capability can crash nodes

**Severity of Damage:**
- **Permanent capability freezing**: Once exploited, the capability cannot be used until a chain upgrade/hard fork fixes the inconsistent state
- **IBC channel DoS**: If an IBC channel capability is targeted, that channel is permanently frozen, preventing all packet transfers
- **Node crashes**: Transactions that attempt to authenticate or use the poisoned capability will panic, potentially taking down nodes
- **Network degradation**: Multiple exploits could freeze numerous channels/capabilities, severely degrading network functionality

**System Security Impact:**
This directly maps to the in-scope impact categories:
- **Medium**: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - IBC operations fail
- **Medium**: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" - If widely exploited, nodes attempting to process affected capabilities will crash
- **High**: "Network not being able to confirm new transactions" - Transactions involving the poisoned capability cannot be processed

## Likelihood Explanation

**Who can trigger it:**
- Any user who owns or can claim a capability can exploit this
- For IBC channels: Any user who can initiate channel operations
- No special privileges required beyond normal capability ownership

**Required conditions:**
- Attacker must be able to construct a multi-message transaction where:
  1. They are the last owner of a capability (or can release it as one of multiple owners)
  2. A subsequent message in the same transaction can be made to fail reliably
- This is trivially achievable through standard transaction construction

**Frequency of exploitation:**
- **Easily reproducible**: The attack is deterministic and doesn't rely on timing or race conditions
- **No rate limiting**: Can be executed repeatedly to poison multiple capabilities
- **Low cost**: Only requires gas fees for the failed transaction
- **High impact per attack**: Each successful exploit permanently disables a capability

The vulnerability is highly likely to be exploited if discovered because:
1. It's simple to execute (just needs a multi-message transaction)
2. The effects are permanent and devastating
3. It can target critical infrastructure like IBC channels
4. Detection is difficult until the capability is accessed again

## Recommendation

Implement one of the following fixes:

**Option 1 (Recommended - Minimal change):** Make `capMap` operations transactional by deferring deletions:
- Instead of directly deleting from `capMap` in `ReleaseCapability`, mark the capability for deletion in a transactional store
- Only actually delete from `capMap` after transaction commit succeeds
- On transaction failure, clear the deletion markers

**Option 2:** Track `capMap` changes in a transactional wrapper:
- Create a cache layer for `capMap` modifications within each transaction context
- Only commit `capMap` changes when the transaction successfully commits
- This mirrors how the KVStore cache contexts work

**Option 3:** Verify consistency in `GetCapability`:
- Before panicking at line 384, attempt to recover by checking if the persistent store still has the capability
- If it exists in persistent store but not in `capMap`, reinitialize the capability in `capMap`
- This is a defensive fix but doesn't address the root cause

**Immediate mitigation:** Add a check in `GetCapability` to handle the nil case gracefully rather than panicking, though this only prevents crashes and doesn't fully resolve the inconsistency.

## Proof of Concept

**File:** `x/capability/keeper/keeper_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func (suite *KeeperTestSuite) TestReleaseCapabilityRevertVulnerability() {
	sk := suite.keeper.ScopeToModule(banktypes.ModuleName)
	
	capName := "vulnerable-cap"
	
	// Step 1: Create a capability in the parent context
	cap, err := sk.NewCapability(suite.ctx, capName)
	suite.Require().NoError(err, "could not create capability")
	suite.Require().NotNil(cap)
	
	// Verify capability exists and is accessible
	got, ok := sk.GetCapability(suite.ctx, capName)
	suite.Require().True(ok, "capability should exist")
	suite.Require().Equal(cap, got)
	
	// Step 2: Create a cached context to simulate a transaction
	ms := suite.ctx.MultiStore()
	msCache := ms.CacheMultiStore()
	cacheCtx := suite.ctx.WithMultiStore(msCache)
	
	// Step 3: Release capability in cached context (simulating first message in tx)
	err = sk.ReleaseCapability(cacheCtx, cap)
	suite.Require().NoError(err, "could not release capability")
	
	// Step 4: Verify capability is released in cached context
	gotCache, ok := sk.GetCapability(cacheCtx, capName)
	suite.Require().False(ok, "capability should be released in cached context")
	suite.Require().Nil(gotCache)
	
	// Step 5: DO NOT write the cache (simulating transaction failure)
	// msCache.Write() is intentionally NOT called
	
	// Step 6: Try to get capability in parent context
	// This should work because the release was reverted, but it will panic
	// because capMap deletion was NOT reverted
	suite.Require().Panics(func() {
		sk.GetCapability(suite.ctx, capName)
	}, "GetCapability should panic due to inconsistent capMap state")
}
```

**Setup:**
- Uses the existing test suite infrastructure with `banktypes.ModuleName` scoped keeper
- Creates a capability in the main context to establish initial valid state

**Trigger:**
1. Creates a cached context (simulating a transaction)
2. Calls `ReleaseCapability` in the cached context, which deletes from `capMap`
3. Does NOT call `msCache.Write()`, simulating a transaction failure
4. Attempts to call `GetCapability` in the parent context

**Observation:**
The test will panic at line 384 of `keeper.go` with message "capability found in memstore is missing from map" because:
- The memStore in parent context still has the capability (reverted)
- The persistent store still has the capability (reverted)
- But `capMap[index]` is nil (NOT reverted)

This panic proves the vulnerability: the system is in an inconsistent state where the capability cannot be accessed despite existing in the stores, constituting a permanent denial-of-service of that capability.

### Citations

**File:** x/capability/keeper/keeper.go (L319-356)
```go
func (sk ScopedKeeper) ReleaseCapability(ctx sdk.Context, cap *types.Capability) error {
	if cap == nil {
		return sdkerrors.Wrap(types.ErrNilCapability, "cannot release nil capability")
	}
	name := sk.GetCapabilityName(ctx, cap)
	if len(name) == 0 {
		return sdkerrors.Wrap(types.ErrCapabilityNotOwned, sk.module)
	}

	memStore := ctx.KVStore(sk.memKey)

	// Delete the forward mapping between the module and capability tuple and the
	// capability name in the memKVStore
	memStore.Delete(types.FwdCapabilityKey(sk.module, cap))

	// Delete the reverse mapping between the module and capability name and the
	// index in the in-memory store.
	memStore.Delete(types.RevCapabilityKey(sk.module, name))

	// remove owner
	capOwners := sk.getOwners(ctx, cap)
	capOwners.Remove(types.NewOwner(sk.module, name))

	prefixStore := prefix.NewStore(ctx.KVStore(sk.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(cap.GetIndex())

	if len(capOwners.Owners) == 0 {
		// remove capability owner set
		prefixStore.Delete(indexKey)
		// since no one owns capability, we can delete capability from map
		delete(sk.capMap, cap.GetIndex())
	} else {
		// update capability owner set
		prefixStore.Set(indexKey, sk.cdc.MustMarshal(capOwners))
	}

	return nil
}
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
