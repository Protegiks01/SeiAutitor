# Audit Report

## Title
OCC Blind Write Vulnerability: Concurrent MsgGrant Transactions Succeed Without Conflict Detection Leading to Silent State Loss

## Summary
When Optimistic Concurrency Control (OCC) is enabled, concurrent transactions creating grants for the same (grantee, granter, msgType) tuple both succeed and charge gas fees, but only the highest-indexed transaction's state persists. The `SaveGrant` method performs blind writes without reading first, and OCC validation only detects read-write conflicts, not write-write conflicts, causing silent state loss for lower-indexed transactions despite returning success. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary vulnerability: `x/authz/keeper/keeper.go:144-160` (SaveGrant method)
- Missing validation: `store/multiversion/store.go:388-397` (ValidateTransactionState)
- State persistence logic: `store/multiversion/store.go:399-435` (WriteLatestToStore)
- Last-write-wins behavior: `store/multiversion/data_structures.go:60-79` (GetLatestNonEstimate)

**Intended Logic:**
When a transaction creates or updates an authorization grant, concurrent transactions modifying the same grant should be detected as conflicts and properly serialized. A successful transaction (Code=0) must guarantee its state changes persist to the blockchain.

**Actual Logic:**
The `SaveGrant` method performs a blind write operation by directly calling `store.Set(skey, bz)` without first reading the existing value. [1](#0-0)  This means the transaction's readset for that key remains empty.

OCC validation via `ValidateTransactionState` only checks iterator consistency and read value consistency through `checkIteratorAtIndex` and `checkReadsetAtIndex`. [2](#0-1)  There is no validation for write-write conflicts. Since concurrent transactions don't read the grant key before writing, both have empty readsets for that key and both pass validation.

When `WriteLatestToStore` commits the final state, it calls `GetLatestNonEstimate()` for each key. [3](#0-2)  The `GetLatestNonEstimate` method descends the btree and returns only the highest-indexed value. [4](#0-3)  Earlier writes to the same key are silently discarded.

**Exploitation Path:**
1. User submits Transaction A: MsgGrant(grantee, granter, MsgSend, limit=100)
2. User submits Transaction B: MsgGrant(grantee, granter, MsgSend, limit=200) in same block
3. Both transactions execute in parallel under OCC
4. Both call `SaveGrant` [5](#0-4)  which performs `store.Set(key, value)` without prior `store.Get(key)`
5. Neither transaction has read dependency on the key (empty readsets)
6. Both pass `ValidateTransactionState` (no read conflicts detected)
7. Both return Code=0 (success) and emit `EventGrant` events
8. Both charge gas fees
9. Only Transaction B's grant persists when `WriteLatestToStore` is called
10. Transaction A's effect is silently lost despite returning success

**Security Guarantee Broken:**
This violates the atomicity and finality guarantee of blockchain transactions: a successful transaction (Code=0) must guarantee its state changes persist. The vulnerability also causes event log inconsistency where `EventGrant` is emitted for both transactions but only one grant exists in state.

## Impact Explanation

This vulnerability constitutes "a bug in the network code that results in unintended smart contract behavior with no concrete funds at direct risk" (Medium severity). The OCC layer (network code) causes unintended behavior in the authz module with significant state inconsistency issues:

1. **Wasted Gas Fees:** Users pay gas for transactions whose effects are silently discarded. Unlike transaction failures, these transactions return success (Code=0), misleading users.

2. **Event Log Inconsistency:** Both transactions emit `EventGrant` events, causing off-chain applications, indexers, and monitoring systems to have incorrect state. Applications relying on events will believe both grants were created.

3. **State Consistency Violation:** Only one grant persists despite two successful transactions, breaking the invariant that successful transactions persist their changes.

4. **Authorization Security Concern:** Since grants control spending limits and permissions, unpredictable grant persistence could lead to authorization mismatches where applications expect different limits than what exists on-chain.

## Likelihood Explanation

**Trigger Conditions:**
- OCC must be enabled
- Multiple transactions targeting the same (grantee, granter, msgType) tuple in the same block
- Transactions execute concurrently in OCC's parallel execution phase

**Who Can Trigger:**
Any user can trigger this vulnerability by submitting normal MsgGrant transactions. No special privileges, unusual conditions, or attack setup is required.

**Frequency:**
- Occurs naturally when users submit concurrent grant updates or retry transactions
- More likely under high transaction throughput
- Particularly probable when frontends submit duplicate transactions
- In production networks with OCC enabled, this could happen regularly during normal operation

The inconsistency with the `update` method [6](#0-5)  which reads before writing suggests this is an oversight rather than intentional design.

## Recommendation

Modify `SaveGrant` to read the existing grant first, even if just to check existence. This creates a read dependency that enables existing OCC conflict detection:

```go
func (k Keeper) SaveGrant(...) error {
    store := ctx.KVStore(k.storeKey)
    skey := grantStoreKey(grantee, granter, authorization.MsgTypeURL())
    
    // Read to create OCC dependency (enables conflict detection)
    _ = store.Get(skey)
    
    grant, err := authz.NewGrant(authorization, expiration)
    // ... rest of implementation
}
```

This approach is simpler and consistent with the existing `update` method pattern which already follows read-before-write.

## Proof of Concept

**Test File:** `x/authz/keeper/keeper_test.go`

**Test Function:** `TestConcurrentGrantsOCCBlindWrite`

**Setup:**
1. Initialize SimApp with OCC enabled (`SetOccEnabled(true)`, `SetConcurrencyWorkers(2)`)
2. Create test accounts: granter (addr[0]), grantee (addr[1])
3. Fund granter account for gas fees
4. Create two MsgGrant transactions for the same (grantee, granter, msgType) with different spend limits

**Action:**
1. Build Transaction A: MsgGrant with SpendLimit=100
2. Build Transaction B: MsgGrant with SpendLimit=200 (same grantee, granter, msgType)
3. Submit both transactions in the same block using `DeliverTxBatch` with OCC enabled
4. Process the batch through the OCC scheduler

**Expected Result:**
1. Both transactions return Code=0 (success)
2. Both transactions emit EventGrant events
3. Both transactions charge gas
4. Query final state shows only ONE grant exists (SpendLimit=200)
5. Transaction A's SpendLimit=100 is silently lost despite success
6. This violates the blockchain invariant that successful transactions persist their changes

## Notes

The vulnerability is confirmed by the code flow analysis showing SaveGrant's blind write pattern combined with OCC's lack of write-write conflict detection. The inconsistency with the `update` method which reads before writing indicates this is an unintentional oversight rather than a design choice. No existing tests cover concurrent SaveGrant operations with OCC enabled, suggesting this scenario was not considered during development.

### Citations

**File:** x/authz/keeper/keeper.go (L51-72)
```go
func (k Keeper) update(ctx sdk.Context, grantee sdk.AccAddress, granter sdk.AccAddress, updated authz.Authorization) error {
	skey := grantStoreKey(grantee, granter, updated.MsgTypeURL())
	grant, found := k.getGrant(ctx, skey)
	if !found {
		return sdkerrors.ErrNotFound.Wrap("authorization not found")
	}

	msg, ok := updated.(proto.Message)
	if !ok {
		sdkerrors.ErrPackAny.Wrapf("cannot proto marshal %T", updated)
	}

	any, err := codectypes.NewAnyWithValue(msg)
	if err != nil {
		return err
	}

	grant.Authorization = any
	store := ctx.KVStore(k.storeKey)
	store.Set(skey, k.cdc.MustMarshal(&grant))
	return nil
}
```

**File:** x/authz/keeper/keeper.go (L144-160)
```go
func (k Keeper) SaveGrant(ctx sdk.Context, grantee, granter sdk.AccAddress, authorization authz.Authorization, expiration time.Time) error {
	store := ctx.KVStore(k.storeKey)

	grant, err := authz.NewGrant(authorization, expiration)
	if err != nil {
		return err
	}

	bz := k.cdc.MustMarshal(&grant)
	skey := grantStoreKey(grantee, granter, authorization.MsgTypeURL())
	store.Set(skey, bz)
	return ctx.EventManager().EmitTypedEvent(&authz.EventGrant{
		MsgTypeUrl: authorization.MsgTypeURL(),
		Granter:    granter.String(),
		Grantee:    grantee.String(),
	})
}
```

**File:** store/multiversion/store.go (L388-397)
```go
func (s *Store) ValidateTransactionState(index int) (bool, []int) {
	// defer telemetry.MeasureSince(time.Now(), "store", "mvs", "validate")

	// TODO: can we parallelize for all iterators?
	iteratorValid := s.checkIteratorAtIndex(index)

	readsetValid, conflictIndices := s.checkReadsetAtIndex(index)

	return iteratorValid && readsetValid, conflictIndices
}
```

**File:** store/multiversion/store.go (L399-435)
```go
func (s *Store) WriteLatestToStore() {
	// sort the keys
	keys := []string{}
	s.multiVersionMap.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	sort.Strings(keys)

	for _, key := range keys {
		val, ok := s.multiVersionMap.Load(key)
		if !ok {
			continue
		}
		mvValue, found := val.(MultiVersionValue).GetLatestNonEstimate()
		if !found {
			// this means that at some point, there was an estimate, but we have since removed it so there isn't anything writeable at the key, so we can skip
			continue
		}
		// we shouldn't have any ESTIMATE values when performing the write, because we read the latest non-estimate values only
		if mvValue.IsEstimate() {
			panic("should not have any estimate values when writing to parent store")
		}
		// if the value is deleted, then delete it from the parent store
		if mvValue.IsDeleted() {
			// We use []byte(key) instead of conv.UnsafeStrToBytes because we cannot
			// be sure if the underlying store might do a save with the byteslice or
			// not. Once we get confirmation that .Delete is guaranteed not to
			// save the byteslice, then we can assume only a read-only copy is sufficient.
			s.parentStore.Delete([]byte(key))
			continue
		}
		if mvValue.Value() != nil {
			s.parentStore.Set([]byte(key), mvValue.Value())
		}
	}
}
```

**File:** store/multiversion/data_structures.go (L60-79)
```go
func (item *multiVersionItem) GetLatestNonEstimate() (MultiVersionValueItem, bool) {
	item.mtx.RLock()
	defer item.mtx.RUnlock()

	var vItem *valueItem
	var found bool
	item.valueTree.Descend(func(bTreeItem btree.Item) bool {
		// only return if non-estimate
		item := bTreeItem.(*valueItem)
		if item.IsEstimate() {
			// if estimate, continue
			return true
		}
		// else we want to return
		vItem = item
		found = true
		return false
	})
	return vItem, found
}
```

**File:** x/authz/keeper/msg_server.go (L36-36)
```go
	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration)
```
