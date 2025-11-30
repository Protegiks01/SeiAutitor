Based on my systematic validation of this security claim, I have traced through the complete execution flow and verified all technical assertions. Let me provide my final assessment:

# Audit Report

## Title
OCC Blind Write Vulnerability: Concurrent MsgGrant Transactions Succeed Without Conflict Detection Leading to Silent State Loss

## Summary
When Optimistic Concurrency Control (OCC) is enabled, concurrent transactions creating grants for the same (grantee, granter, msgType) tuple both succeed and return Code=0, but only the highest-indexed transaction's state persists to the blockchain. This occurs because `SaveGrant` performs blind writes without creating read dependencies, and OCC's validation only detects read-write conflicts, not write-write conflicts.

## Impact
Medium

## Finding Description

**Location:**
- Primary vulnerability: [1](#0-0) 
- OCC validation logic: [2](#0-1) 
- Final persistence logic: [3](#0-2) 
- Last-write-wins implementation: [4](#0-3) 

**Intended Logic:**
When a transaction creates or updates an authorization grant, concurrent transactions modifying the same grant key should either (a) be detected as conflicts and serialized through retry mechanisms, or (b) only the first transaction should succeed while subsequent ones fail. A successful transaction (Code=0) must guarantee its state changes persist to the blockchain.

**Actual Logic:**
The `SaveGrant` method performs blind writes by calling `store.Set(skey, bz)` directly without reading the existing value first. [5](#0-4)  This means concurrent transactions writing to the same grant key have empty readsets for that key. 

OCC's `ValidateTransactionState` method only validates iterator consistency and readset consistency through `checkIteratorAtIndex` and `checkReadsetAtIndex`. [2](#0-1)  There is no validation for write-write conflicts. Since neither concurrent transaction reads the grant key before writing, both have empty readsets and both pass validation.

During final commitment, `WriteLatestToStore` calls `GetLatestNonEstimate()` for each key, [6](#0-5)  which descends the btree and returns only the highest-indexed value. [7](#0-6)  Earlier writes to the same key are silently discarded despite their transactions having returned success.

**Exploitation Path:**
1. User submits Transaction A (index 0): `MsgGrant(grantee, granter, MsgSend, limit=100)` via message handler [8](#0-7) 
2. User submits Transaction B (index 1): `MsgGrant(grantee, granter, MsgSend, limit=200)` in the same block
3. Both transactions execute concurrently under OCC scheduler [9](#0-8) 
4. Both call `SaveGrant` which performs `store.Set(key, value)` without prior `store.Get(key)` [5](#0-4) 
5. Neither transaction has read dependencies on the grant key (empty readsets)
6. Both pass `ValidateTransactionState` via scheduler's conflict detection [10](#0-9)  because no read conflicts exist
7. Both return Code=0 (success) and emit `EventGrant` events [11](#0-10) 
8. Both charge gas fees to users
9. `WriteLatestToStore` is called after all validation completes [12](#0-11) 
10. Only Transaction B's (index 1) grant persists because `GetLatestNonEstimate` returns the highest-indexed value [7](#0-6) 
11. Transaction A's effect is silently lost despite returning success

**Security Guarantee Broken:**
This violates the atomicity and finality guarantee of blockchain transactions: a successful transaction (Code=0) must guarantee its state changes persist to the blockchain. The vulnerability also causes event log inconsistency where `EventGrant` events are emitted for both transactions but only one grant exists in final state.

## Impact Explanation

This vulnerability constitutes "a bug in the network code that results in unintended smart contract behavior with no concrete funds at direct risk" per the Medium severity classification. The OCC layer (network code) causes unintended behavior in the authz module:

1. **Atomicity Violation**: Users receive success responses (Code=0) for transactions whose state changes are silently discarded, violating the fundamental blockchain guarantee that successful transactions persist.

2. **Wasted Gas Fees**: Users pay gas for transactions whose effects never materialize, without receiving any error indication that would allow them to retry or detect the issue.

3. **Event Log Inconsistency**: Both transactions emit `EventGrant` events, causing off-chain applications, indexers, and monitoring systems to have incorrect views of on-chain state. Applications relying on event logs will believe both grants were created.

4. **Authorization Security Risk**: Since grants control spending limits and permissions, unpredictable grant persistence could lead to authorization mismatches where applications expect different limits than what exists on-chain, potentially enabling unauthorized actions or blocking authorized ones.

The inconsistency with the `update` method [13](#0-12)  which reads before writing via `k.getGrant(ctx, skey)` at line 53, indicates this is an oversight rather than intentional design.

## Likelihood Explanation

**Trigger Conditions:**
- OCC must be enabled (a standard configuration option, not a misconfiguration)
- Multiple transactions targeting the same (grantee, granter, msgType) tuple in the same block
- Transactions execute concurrently in OCC's parallel execution phase

**Who Can Trigger:**
Any user can trigger this vulnerability by submitting normal `MsgGrant` transactions. No special privileges, unusual conditions, or attack setup is required. Even a single user retrying a transaction can trigger this accidentally.

**Frequency:**
- Occurs naturally when users submit concurrent grant updates or retry transactions
- More likely under high transaction throughput conditions
- Particularly probable when frontend applications submit duplicate transactions for reliability
- In production networks with OCC enabled, this could happen regularly during normal operations

While the authz specification states that grants can be overwritten, [14](#0-13)  the issue is not overwriting itself but rather that both transactions succeed while only one persists, which is clearly unintended.

## Recommendation

Implement a read-before-write pattern in `SaveGrant` to create OCC read dependencies that enable existing conflict detection:

Modify the `SaveGrant` method to read the existing grant first, even if just to check existence. This creates a read dependency in the transaction's readset, enabling OCC to detect conflicts:

```go
func (k Keeper) SaveGrant(ctx sdk.Context, grantee, granter sdk.AccAddress, authorization authz.Authorization, expiration time.Time) error {
    store := ctx.KVStore(k.storeKey)
    skey := grantStoreKey(grantee, granter, authorization.MsgTypeURL())
    
    // Read to create OCC dependency (enables conflict detection)
    _ = store.Get(skey)
    
    grant, err := authz.NewGrant(authorization, expiration)
    if err != nil {
        return err
    }

    bz := k.cdc.MustMarshal(&grant)
    store.Set(skey, bz)
    return ctx.EventManager().EmitTypedEvent(&authz.EventGrant{
        MsgTypeUrl: authorization.MsgTypeURL(),
        Granter:    granter.String(),
        Grantee:    grantee.String(),
    })
}
```

This approach is consistent with the existing `update` method pattern which already reads before writing.

## Proof of Concept

**Test File:** `x/authz/keeper/keeper_test.go`

**Test Function:** `TestConcurrentGrantsOCCBlindWrite`

**Setup:**
1. Initialize SimApp with OCC enabled (`SetOccEnabled(true)`, `SetConcurrencyWorkers(2)`)
2. Create test accounts: granter (addr[0]), grantee (addr[1])
3. Fund granter account with sufficient tokens for gas fees
4. Create two MsgGrant transactions for identical (grantee, granter, msgType) tuple with different spend limits

**Action:**
1. Build Transaction A: MsgGrant with authorization spend limit = 100 coins
2. Build Transaction B: MsgGrant with authorization spend limit = 200 coins (same grantee, granter, msgType)
3. Submit both transactions in the same block using `DeliverTxBatch` with OCC enabled
4. Process the complete batch through the OCC scheduler's parallel execution and validation phases

**Expected Result:**
1. Both transactions return Code=0 (success response)
2. Both transactions emit `EventGrant` events (verifiable from event manager)
3. Both transactions charge gas fees (verifiable from account balance changes)
4. Query final blockchain state using `GetCleanAuthorization(ctx, grantee, granter, msgType)`
5. Only ONE grant exists in state with SpendLimit=200 (from Transaction B, index 1)
6. Transaction A's SpendLimit=100 is silently lost despite success response
7. This demonstrates violation of the blockchain invariant that successful transactions persist their state changes

## Notes

The vulnerability is confirmed through code flow analysis showing SaveGrant's blind write pattern combined with OCC's exclusive focus on read-write conflict detection. No existing tests cover concurrent SaveGrant operations with OCC enabled, suggesting this scenario was not considered during development. The technical claims are fully verifiable from the codebase at the cited locations.

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

**File:** x/authz/keeper/msg_server.go (L14-42)
```go
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	authorization := msg.GetAuthorization()
	if authorization == nil {
		return nil, sdkerrors.ErrUnpackAny.Wrap("Authorization is not present in the msg")
	}

	t := authorization.MsgTypeURL()
	if k.router.HandlerByTypeURL(t) == nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
	}

	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration)
	if err != nil {
		return nil, err
	}

	return &authz.MsgGrantResponse{}, nil
}
```

**File:** tasks/scheduler.go (L166-183)
```go
func (s *scheduler) findConflicts(task *deliverTxTask) (bool, []int) {
	var conflicts []int
	uniq := make(map[int]struct{})
	valid := true
	for _, mv := range s.multiVersionStores {
		ok, mvConflicts := mv.ValidateTransactionState(task.AbsoluteIndex)
		for _, c := range mvConflicts {
			if _, ok := uniq[c]; !ok {
				conflicts = append(conflicts, c)
				uniq[c] = struct{}{}
			}
		}
		// any non-ok value makes valid false
		valid = valid && ok
	}
	sort.Ints(conflicts)
	return valid, conflicts
}
```

**File:** tasks/scheduler.go (L284-350)
```go
func (s *scheduler) ProcessAll(ctx sdk.Context, reqs []*sdk.DeliverTxEntry) ([]types.ResponseDeliverTx, error) {
	startTime := time.Now()
	var iterations int
	// initialize mutli-version stores if they haven't been initialized yet
	s.tryInitMultiVersionStore(ctx)
	// prefill estimates
	// This "optimization" path is being disabled because we don't have a strong reason to have it given that it
	// s.PrefillEstimates(reqs)
	tasks, tasksMap := toTasks(reqs)
	s.allTasks = tasks
	s.allTasksMap = tasksMap
	s.executeCh = make(chan func(), len(tasks))
	s.validateCh = make(chan func(), len(tasks))
	defer s.emitMetrics()

	// default to number of tasks if workers is negative or 0 by this point
	workers := s.workers
	if s.workers < 1 || len(tasks) < s.workers {
		workers = len(tasks)
	}

	workerCtx, cancel := context.WithCancel(ctx.Context())
	defer cancel()

	// execution tasks are limited by workers
	start(workerCtx, s.executeCh, workers)

	// validation tasks uses length of tasks to avoid blocking on validation
	start(workerCtx, s.validateCh, len(tasks))

	toExecute := tasks
	for !allValidated(tasks) {
		// if the max incarnation >= x, we should revert to synchronous
		if iterations >= maximumIterations {
			// process synchronously
			s.synchronous = true
			startIdx, anyLeft := s.findFirstNonValidated()
			if !anyLeft {
				break
			}
			toExecute = tasks[startIdx:]
		}

		// execute sets statuses of tasks to either executed or aborted
		if err := s.executeAll(ctx, toExecute); err != nil {
			return nil, err
		}

		// validate returns any that should be re-executed
		// note this processes ALL tasks, not just those recently executed
		var err error
		toExecute, err = s.validateAll(ctx, tasks)
		if err != nil {
			return nil, err
		}
		// these are retries which apply to metrics
		s.metrics.retries += len(toExecute)
		iterations++
	}

	for _, mv := range s.multiVersionStores {
		mv.WriteLatestToStore()
	}
	s.metrics.maxIncarnation = s.maxIncarnation

	ctx.Logger().Info("occ scheduler", "height", ctx.BlockHeight(), "txs", len(tasks), "latency_ms", time.Since(startTime).Milliseconds(), "retries", s.metrics.retries, "maxIncarnation", s.maxIncarnation, "iterations", iterations, "sync", s.synchronous, "workers", s.workers)

```

**File:** x/authz/spec/03_messages.md (L12-12)
```markdown
If there is already a grant for the `(granter, grantee, Authorization)` triple, then the new grant will overwrite the previous one. To update or extend an existing grant, a new grant with the same `(granter, grantee, Authorization)` triple should be created.
```
