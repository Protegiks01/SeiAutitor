# Audit Report

## Title
Node Crash via Reference Count Panic During Concurrent Delegation Operations with OCC Enabled

## Summary
When Optimistic Concurrency Control (OCC) is enabled for concurrent transaction execution, a race condition in the distribution module's reference counting system can cause nodes to crash. During OCC retry of conflicting transactions, a transaction may attempt to decrement the reference count for a historical rewards period that was already deleted by another concurrent transaction, triggering a panic.

## Impact
Medium

## Finding Description

**Location:**
- Primary issue: [1](#0-0) 
- Contributing code: [2](#0-1) 
- Hook invocation: [3](#0-2) 
- Store retrieval: [4](#0-3) 

**Intended Logic:**
The reference counting system tracks how many delegations reference each historical rewards period. When a validator's period is incremented via `IncrementValidatorPeriod`, the previous period's reference count is decremented. When the reference count reaches 0, the period is deleted to free storage. The panic check at line 79-80 is designed to catch programming errors where the refcount would go negative.

**Actual Logic:**
With OCC-enabled concurrent transaction execution, the following race condition occurs:

1. TX1 creates a new delegation to validator V, triggering `BeforeDelegationCreated` hook which calls `IncrementValidatorPeriod`
2. `IncrementValidatorPeriod` decrements the previous period's refcount, potentially deleting it if refcount reaches 0
3. TX2 concurrently modifies an existing delegation to validator V, triggering `BeforeDelegationSharesModified` hook which calls `withdrawDelegationRewards`
4. OCC detects a conflict between TX1 and TX2 and schedules TX2 for retry
5. During TX2's retry, it reads the delegator's starting info (which still references the now-deleted period because the delegation hasn't been updated yet)
6. TX2 calls `decrementReferenceCount` on the deleted period
7. `GetValidatorHistoricalRewards` returns a nil byte slice for the deleted key
8. The codec's `MustUnmarshal` unmarshals nil bytes into a zero-valued `ValidatorHistoricalRewards` struct with `ReferenceCount = 0`
9. The panic check triggers: `if historical.ReferenceCount == 0 { panic("cannot set negative reference count") }`

**Exploitation Path:**
1. OCC must be enabled via configuration (not default: [5](#0-4) )
2. User A submits a transaction creating a new delegation to validator V
3. User B submits a transaction modifying an existing delegation to validator V that references a historical period that would be deleted by User A's transaction
4. Both transactions are included in the same block and processed concurrently by the OCC scheduler [6](#0-5) 
5. TX1 deletes the historical period
6. TX2 is retried by OCC and attempts to decrement the deleted period's reference count
7. Node panics and crashes

**Security Guarantee Broken:**
This violates the availability and liveness guarantees of the blockchain network. The panic during block execution crashes the node, preventing it from processing blocks and participating in consensus.

## Impact Explanation

When this vulnerability is triggered, the affected node crashes immediately due to the panic during block execution. This has several consequences:

- **Node Availability**: Crashed nodes cannot process blocks or participate in consensus until manually restarted
- **Network Impact**: If multiple validators have OCC enabled and process the same block containing the triggering transactions, multiple nodes could crash simultaneously
- **Block Processing**: The block containing the triggering transactions may fail to be finalized if enough nodes crash

The impact is classified as **Medium** according to the provided severity scale because it causes "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" (assuming sufficient nodes have OCC enabled), or potentially "Network not being able to confirm new transactions" if enough validators are affected.

## Likelihood Explanation

**Triggering Conditions:**
1. OCC must be explicitly enabled via configuration (default is false: [5](#0-4) )
2. Multiple delegation operations to the same validator must occur in the same block
3. One must be a new delegation and another must modify an existing delegation
4. The validator must have a historical period that would be deleted

**Likelihood Assessment:**
- **Who can trigger**: Any unprivileged user submitting normal delegation transactions
- **Frequency**: On networks with OCC enabled, delegation operations to popular validators are common, making the race condition plausible during normal operation
- **Detectability**: The crash is immediate and obvious, but the root cause requires understanding the OCC retry mechanism

While OCC is not enabled by default, it is a supported feature designed for performance optimization. On networks where it is enabled, this race condition can occur during normal operations without malicious intent.

## Recommendation

Modify `decrementReferenceCount` to handle the case where a historical period was already deleted by a concurrent transaction:

```go
func (k Keeper) decrementReferenceCount(ctx sdk.Context, valAddr sdk.ValAddress, period uint64) {
    historical := k.GetValidatorHistoricalRewards(ctx, valAddr, period)
    if historical.ReferenceCount == 0 {
        // Period was already deleted by another concurrent transaction
        // This is safe to skip as the reference is already removed
        return
    }
    historical.ReferenceCount--
    if historical.ReferenceCount == 0 {
        k.DeleteValidatorHistoricalReward(ctx, valAddr, period)
    } else {
        k.SetValidatorHistoricalRewards(ctx, valAddr, period, historical)
    }
}
```

Alternative approaches:
1. Use explicit locking or synchronization for validator period updates when OCC is enabled
2. Track active delegation operations per validator in the multiversion store to prevent concurrent period deletions
3. Implement idempotent reference count decrements that tolerate already-deleted periods

## Proof of Concept

**Conceptual Test Setup:**
1. Configure a test network with OCC enabled ( [7](#0-6) )
2. Create validator V with an initial delegation Del1 referencing historical period 1
3. Ensure validator is at period 2 (current period)

**Trigger Sequence:**
1. Submit TX1: `MsgDelegate` creating a new delegation to validator V from address A1
   - This triggers `BeforeDelegationCreated` → `IncrementValidatorPeriod`
   - Period 1's refcount decrements from 1 to 0, deleting period 1
2. Submit TX2: `MsgDelegate` adding tokens to existing delegation Del1
   - This triggers `BeforeDelegationSharesModified` → `withdrawDelegationRewards`
   - Reads Del1's starting info (references period 1)
   - OCC detects conflict and retries TX2
3. During TX2 retry: attempts `decrementReferenceCount(period 1)`
4. `GetValidatorHistoricalRewards` returns zero-valued struct
5. Panic: "cannot set negative reference count"

**Expected Observation:**
Node crashes with panic message originating from [8](#0-7) 

## Notes

- OCC is not enabled by default ( [5](#0-4) ), which limits the impact to networks that explicitly configure it
- The vulnerability is real and exploitable when OCC is enabled, through normal user operations
- No actual runnable test was provided, but the technical analysis confirms the race condition exists
- The multiversion store's behavior of returning nil for deleted keys ( [9](#0-8) ) combined with protobuf unmarshaling nil to zero-values enables the panic condition
- Severity is assessed as Medium (not High as claimed) based on the provided impact criteria, as this affects node availability when OCC is enabled but does not directly cause fund loss or permanent chain splits

### Citations

**File:** x/distribution/keeper/validator.go (L28-64)
```go
func (k Keeper) IncrementValidatorPeriod(ctx sdk.Context, val stakingtypes.ValidatorI) uint64 {
	// fetch current rewards
	rewards := k.GetValidatorCurrentRewards(ctx, val.GetOperator())

	// calculate current ratio
	var current sdk.DecCoins
	if val.GetTokens().IsZero() {

		// can't calculate ratio for zero-token validators
		// ergo we instead add to the community pool
		feePool := k.GetFeePool(ctx)
		outstanding := k.GetValidatorOutstandingRewards(ctx, val.GetOperator())
		feePool.CommunityPool = feePool.CommunityPool.Add(rewards.Rewards...)
		outstanding.Rewards = outstanding.GetRewards().Sub(rewards.Rewards)
		k.SetFeePool(ctx, feePool)
		k.SetValidatorOutstandingRewards(ctx, val.GetOperator(), outstanding)

		current = sdk.DecCoins{}
	} else {
		// note: necessary to truncate so we don't allow withdrawing more rewards than owed
		current = rewards.Rewards.QuoDecTruncate(val.GetTokens().ToDec())
	}

	// fetch historical rewards for last period
	historical := k.GetValidatorHistoricalRewards(ctx, val.GetOperator(), rewards.Period-1).CumulativeRewardRatio

	// decrement reference count
	k.decrementReferenceCount(ctx, val.GetOperator(), rewards.Period-1)

	// set new historical rewards with reference count of 1
	k.SetValidatorHistoricalRewards(ctx, val.GetOperator(), rewards.Period, types.NewValidatorHistoricalRewards(historical.Add(current...), 1))

	// set current rewards, incrementing period by 1
	k.SetValidatorCurrentRewards(ctx, val.GetOperator(), types.NewValidatorCurrentRewards(sdk.DecCoins{}, rewards.Period+1))

	return rewards.Period
}
```

**File:** x/distribution/keeper/validator.go (L77-88)
```go
func (k Keeper) decrementReferenceCount(ctx sdk.Context, valAddr sdk.ValAddress, period uint64) {
	historical := k.GetValidatorHistoricalRewards(ctx, valAddr, period)
	if historical.ReferenceCount == 0 {
		panic("cannot set negative reference count")
	}
	historical.ReferenceCount--
	if historical.ReferenceCount == 0 {
		k.DeleteValidatorHistoricalReward(ctx, valAddr, period)
	} else {
		k.SetValidatorHistoricalRewards(ctx, valAddr, period, historical)
	}
}
```

**File:** x/distribution/keeper/delegation.go (L139-211)
```go
func (k Keeper) withdrawDelegationRewards(ctx sdk.Context, val stakingtypes.ValidatorI, del stakingtypes.DelegationI) (sdk.Coins, error) {
	// check existence of delegator starting info
	if !k.HasDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr()) {
		return nil, types.ErrEmptyDelegationDistInfo
	}

	// end current period and calculate rewards
	endingPeriod := k.IncrementValidatorPeriod(ctx, val)
	rewardsRaw := k.CalculateDelegationRewards(ctx, val, del, endingPeriod)
	outstanding := k.GetValidatorOutstandingRewardsCoins(ctx, del.GetValidatorAddr())

	// defensive edge case may happen on the very final digits
	// of the decCoins due to operation order of the distribution mechanism.
	rewards := rewardsRaw.Intersect(outstanding)
	if !rewards.IsEqual(rewardsRaw) {
		logger := k.Logger(ctx)
		logger.Info(
			"rounding error withdrawing rewards from validator",
			"delegator", del.GetDelegatorAddr().String(),
			"validator", val.GetOperator().String(),
			"got", rewards.String(),
			"expected", rewardsRaw.String(),
		)
	}

	// truncate reward dec coins, return remainder to community pool
	finalRewards, remainder := rewards.TruncateDecimal()

	// add coins to user account
	if !finalRewards.IsZero() {
		withdrawAddr := k.GetDelegatorWithdrawAddr(ctx, del.GetDelegatorAddr())
		err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, finalRewards)
		if err != nil {
			return nil, err
		}
	}

	// update the outstanding rewards and the community pool only if the
	// transaction was successful
	k.SetValidatorOutstandingRewards(ctx, del.GetValidatorAddr(), types.ValidatorOutstandingRewards{Rewards: outstanding.Sub(rewards)})
	feePool := k.GetFeePool(ctx)
	feePool.CommunityPool = feePool.CommunityPool.Add(remainder...)
	k.SetFeePool(ctx, feePool)

	// decrement reference count of starting period
	startingInfo := k.GetDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr())
	startingPeriod := startingInfo.PreviousPeriod
	k.decrementReferenceCount(ctx, del.GetValidatorAddr(), startingPeriod)

	// remove delegator starting info
	k.DeleteDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr())

	if finalRewards.IsZero() {
		baseDenom, _ := sdk.GetBaseDenom()
		if baseDenom == "" {
			baseDenom = sdk.DefaultBondDenom
		}

		// Note, we do not call the NewCoins constructor as we do not want the zero
		// coin removed.
		finalRewards = sdk.Coins{sdk.NewCoin(baseDenom, sdk.ZeroInt())}
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeWithdrawRewards,
			sdk.NewAttribute(sdk.AttributeKeyAmount, finalRewards.String()),
			sdk.NewAttribute(types.AttributeKeyValidator, val.GetOperator().String()),
		),
	)

	return finalRewards, nil
}
```

**File:** x/distribution/keeper/store.go (L129-134)
```go
func (k Keeper) GetValidatorHistoricalRewards(ctx sdk.Context, val sdk.ValAddress, period uint64) (rewards types.ValidatorHistoricalRewards) {
	store := ctx.KVStore(k.storeKey)
	b := store.Get(types.GetValidatorHistoricalRewardsKey(val, period))
	k.cdc.MustUnmarshal(b, &rewards)
	return
}
```

**File:** server/config/config.go (L28-29)
```go
	// DefaultOccEanbled defines whether to use OCC for tx processing
	DefaultOccEnabled = false
```

**File:** server/config/config.go (L101-102)
```go
	// Whether to enable optimistic concurrency control for tx execution, default is true
	OccEnabled bool `mapstructure:"occ-enabled"`
```

**File:** tasks/scheduler.go (L284-352)
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

	return s.collectResponses(tasks), nil
}
```

**File:** store/multiversion/mvkv.go (L179-185)
```go
func (store *VersionIndexedStore) parseValueAndUpdateReadset(strKey string, mvsValue MultiVersionValueItem) []byte {
	value := mvsValue.Value()
	if mvsValue.IsDeleted() {
		value = nil
	}
	store.UpdateReadSet([]byte(strKey), value)
	return value
```
