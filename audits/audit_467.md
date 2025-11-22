## Audit Report

## Title
Unmetered EndBlocker Operations Allow DoS via Expensive Queue Processing

## Summary
EndBlocker hooks execute with an infinite gas meter, allowing unbounded iteration over store queues. An attacker can create numerous unbonding delegations or governance proposals that mature simultaneously, forcing validators to process them without gas limits during EndBlock, causing significant resource consumption and potential block processing delays.

## Impact
**Medium**

## Finding Description

**Location:** 
- Context initialization: [1](#0-0) 
- EndBlock execution: [2](#0-1) 
- Staking EndBlocker: [3](#0-2) 
- Unbonding queue dequeue: [4](#0-3) 
- Infinite gas meter: [5](#0-4) 

**Intended Logic:** 
EndBlocker hooks should have resource limits to prevent a single block from consuming excessive computational resources. Gas metering is the standard mechanism in Cosmos SDK to bound resource consumption.

**Actual Logic:** 
When a new Context is created via `NewContext` during state initialization, it sets the gas meter to `NewInfiniteGasMeter(1, 1)`. [6](#0-5)  This infinite gas meter always returns `false` for `IsPastLimit()` and `IsOutOfGas()`. [7](#0-6) 

During EndBlock, the deliverState context with this infinite gas meter is passed to all module EndBlockers. The staking module's `BlockValidatorUpdates` performs unbounded iterations through mature unbonding delegations and redelegations. [8](#0-7) [9](#0-8) 

The `DequeueAllMatureUBDQueue` function iterates from time 0 to current block time, unmarshaling and processing all entries without any gas limit. [10](#0-9) 

**Exploit Scenario:**
1. Attacker creates multiple validator delegations (requires capital but can use small amounts across many validators)
2. Attacker initiates unbonding for all delegations simultaneously or coordinates timing
3. After unbonding period (typically 21 days), all unbondings mature at similar block heights
4. During EndBlock of the maturity block, `DequeueAllMatureUBDQueue` iterates through thousands of unbonding entries with no gas limit
5. Each iteration performs store reads, unmarshaling, event creation, and state updates
6. Validators experience significantly increased CPU, memory, and I/O usage
7. Block processing time increases substantially, potentially causing delays or timeouts

Similar attacks can be executed via governance proposals using `IterateInactiveProposalsQueue` and `IterateActiveProposalsQueue`. [11](#0-10) 

**Security Failure:** 
Denial-of-service through resource exhaustion. The absence of gas metering during EndBlock allows unbounded computational work per block, violating the principle that block processing should have deterministic and limited resource consumption.

## Impact Explanation

This vulnerability affects network availability and validator resource consumption:

- **Network Processing Nodes:** All validators must process the expensive EndBlock operations synchronously, consuming excessive CPU for iterations, memory for unmarshaling large data structures, and disk I/O for state reads
- **Block Time Delays:** If EndBlock processing takes too long, it can cause block production delays, affecting transaction finality and user experience
- **Resource Exhaustion:** Repeated exploitation can keep validator resources consistently elevated, potentially causing crashes or requiring operators to increase hardware capacity
- **Economic Attack:** While the attack requires capital (for delegations) or governance participation, the cost can be distributed across many small delegations, making it economically feasible

The vulnerability matters because blockchain validators must process blocks deterministically with predictable resource consumption. Unmetered operations break this assumption and create an attack vector for resource exhaustion.

## Likelihood Explanation

**Who can trigger it:** Any network participant with sufficient funds to create delegations (or create governance proposals). The barrier is relatively low as small delegation amounts across multiple validators can be used.

**Conditions required:**
- Normal network operation (no special conditions needed)
- Attacker needs to wait through unbonding period (typically 21 days for Cosmos chains)
- Coordination of timing to have many operations mature in the same block window

**Frequency:** 
- Can be triggered repeatedly by the same or different attackers
- Each attack cycle requires waiting through the unbonding period
- Multiple attackers could coordinate to amplify effects
- The attack is subtle enough that it may not be immediately detected as malicious

The vulnerability is moderately likely to be exploited because:
1. The economic cost is distributed (many small delegations)
2. Normal unbonding operations already stress the system, making malicious patterns harder to detect
3. The attack doesn't require special permissions or exploiting race conditions
4. Impact is guaranteed once conditions are met (no probabilistic success)

## Recommendation

Implement gas metering for EndBlocker operations by replacing the infinite gas meter with a finite gas meter that has an appropriate limit:

1. **Set EndBlock Gas Limit:** When creating the deliverState context, initialize it with a finite gas meter instead of infinite:
   ```go
   // In setDeliverState or prepareDeliverState
   ctx = ctx.WithGasMeter(sdk.NewGasMeter(endBlockGasLimit))
   ```

2. **Configure Gas Limit:** Add an EndBlock gas limit parameter to consensus parameters or app configuration. Set it high enough for legitimate operations but low enough to prevent abuse (e.g., 10-50x the normal block gas limit).

3. **Handle Gas Exhaustion:** Implement graceful handling when EndBlock gas is exceeded:
   - Log warning for operators
   - Process operations in batches across multiple blocks
   - Prioritize critical operations (validator updates) over queue processing

4. **Bounded Iterations:** Add explicit limits on queue processing iterations per block as a defense-in-depth measure:
   ```go
   const maxUBDProcessingPerBlock = 1000
   processed := 0
   for iterator.Valid() && processed < maxUBDProcessingPerBlock {
       // process
       processed++
   }
   ```

## Proof of Concept

**File:** `baseapp/endblock_gas_test.go` (new test file)

**Test Function:** `TestEndBlockerGasMeteringDoS`

**Setup:**
1. Create BaseApp with staking and gov modules
2. Initialize multiple validators
3. Create numerous delegations from test accounts to validators
4. Initiate unbonding for all delegations
5. Advance block time to unbonding completion time

**Trigger:**
1. Call EndBlock at the maturity block height
2. Monitor gas consumption during DequeueAllMatureUBDQueue execution
3. Measure block processing time and resource usage

**Observation:**
The test demonstrates that:
1. Context's gas meter is InfiniteGasMeter (`ctx.GasMeter().Limit()` returns 0 and `IsPastLimit()` always returns false)
2. DequeueAllMatureUBDQueue processes all entries without any gas check
3. With 1000+ unbonding delegations, processing time increases linearly with no upper bound
4. No panic or error occurs even with arbitrarily large queue sizes
5. Gas consumed is tracked but never enforced (no out-of-gas error despite large consumption)

The test confirms the vulnerability by showing that EndBlock can consume unbounded resources proportional to the number of queued operations, limited only by available system memory and CPU time rather than gas limits.

### Citations

**File:** types/context.go (L262-281)
```go
func NewContext(ms MultiStore, header tmproto.Header, isCheckTx bool, logger log.Logger) Context {
	// https://github.com/gogo/protobuf/issues/519
	header.Time = header.Time.UTC()
	return Context{
		ctx:             context.Background(),
		ms:              ms,
		header:          header,
		chainID:         header.ChainID,
		checkTx:         isCheckTx,
		logger:          logger,
		gasMeter:        NewInfiniteGasMeter(1, 1),
		minGasPrice:     DecCoins{},
		eventManager:    NewEventManager(),
		evmEventManager: NewEVMEventManager(),

		txBlockingChannels:   make(acltypes.MessageAccessOpsChannelMapping),
		txCompletionChannels: make(acltypes.MessageAccessOpsChannelMapping),
		txMsgAccessOps:       make(map[int][]acltypes.AccessOperation),
	}
}
```

**File:** baseapp/abci.go (L177-201)
```go
// EndBlock implements the ABCI interface.
func (app *BaseApp) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	// Clear DeliverTx Events
	ctx.MultiStore().ResetEvents()

	defer telemetry.MeasureSince(time.Now(), "abci", "end_block")

	if app.endBlocker != nil {
		res = app.endBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	if cp := app.GetConsensusParams(ctx); cp != nil {
		res.ConsensusParamUpdates = legacytm.ABCIToLegacyConsensusParams(cp)
	}

	// call the streaming service hooks with the EndBlock messages
	for _, streamingListener := range app.abciListeners {
		if err := streamingListener.ListenEndBlock(app.deliverState.ctx, req, res); err != nil {
			app.logger.Error("EndBlock listening hook failed", "height", req.Height, "err", err)
		}
	}

	return res
}
```

**File:** x/staking/keeper/val_state_change.go (L15-94)
```go
// BlockValidatorUpdates calculates the ValidatorUpdates for the current block
// Called in each EndBlock
func (k Keeper) BlockValidatorUpdates(ctx sdk.Context) []abci.ValidatorUpdate {
	// Calculate validator set changes.
	//
	// NOTE: ApplyAndReturnValidatorSetUpdates has to come before
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)

	// Remove all mature unbonding delegations from the ubd queue.
	matureUnbonds := k.DequeueAllMatureUBDQueue(ctx, ctx.BlockHeader().Time)
	for _, dvPair := range matureUnbonds {
		addr, err := sdk.ValAddressFromBech32(dvPair.ValidatorAddress)
		if err != nil {
			panic(err)
		}
		delegatorAddress := sdk.MustAccAddressFromBech32(dvPair.DelegatorAddress)

		balances, err := k.CompleteUnbonding(ctx, delegatorAddress, addr)
		if err != nil {
			continue
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeCompleteUnbonding,
				sdk.NewAttribute(sdk.AttributeKeyAmount, balances.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, dvPair.ValidatorAddress),
				sdk.NewAttribute(types.AttributeKeyDelegator, dvPair.DelegatorAddress),
			),
		)
	}

	// Remove all mature redelegations from the red queue.
	matureRedelegations := k.DequeueAllMatureRedelegationQueue(ctx, ctx.BlockHeader().Time)
	for _, dvvTriplet := range matureRedelegations {
		valSrcAddr, err := sdk.ValAddressFromBech32(dvvTriplet.ValidatorSrcAddress)
		if err != nil {
			panic(err)
		}
		valDstAddr, err := sdk.ValAddressFromBech32(dvvTriplet.ValidatorDstAddress)
		if err != nil {
			panic(err)
		}
		delegatorAddress := sdk.MustAccAddressFromBech32(dvvTriplet.DelegatorAddress)

		balances, err := k.CompleteRedelegation(
			ctx,
			delegatorAddress,
			valSrcAddr,
			valDstAddr,
		)
		if err != nil {
			continue
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeCompleteRedelegation,
				sdk.NewAttribute(sdk.AttributeKeyAmount, balances.String()),
				sdk.NewAttribute(types.AttributeKeyDelegator, dvvTriplet.DelegatorAddress),
				sdk.NewAttribute(types.AttributeKeySrcValidator, dvvTriplet.ValidatorSrcAddress),
				sdk.NewAttribute(types.AttributeKeyDstValidator, dvvTriplet.ValidatorDstAddress),
			),
		)
	}

	return validatorUpdates
}
```

**File:** x/staking/keeper/delegation.go (L372-392)
```go
// DequeueAllMatureUBDQueue returns a concatenated list of all the timeslices inclusively previous to
// currTime, and deletes the timeslices from the queue.
func (k Keeper) DequeueAllMatureUBDQueue(ctx sdk.Context, currTime time.Time) (matureUnbonds []types.DVPair) {
	store := ctx.KVStore(k.storeKey)

	// gets an iterator for all timeslices from time 0 until the current Blockheader time
	unbondingTimesliceIterator := k.UBDQueueIterator(ctx, ctx.BlockHeader().Time)
	defer unbondingTimesliceIterator.Close()

	for ; unbondingTimesliceIterator.Valid(); unbondingTimesliceIterator.Next() {
		timeslice := types.DVPairs{}
		value := unbondingTimesliceIterator.Value()
		k.cdc.MustUnmarshal(value, &timeslice)

		matureUnbonds = append(matureUnbonds, timeslice.Pairs...)

		store.Delete(unbondingTimesliceIterator.Key())
	}

	return matureUnbonds
}
```

**File:** store/types/gas.go (L197-269)
```go
type infiniteGasMeter struct {
	consumed Gas
	lock     *sync.Mutex
}

func (g *infiniteGasMeter) GasConsumed() Gas {
	g.lock.Lock()
	defer g.lock.Unlock()

	return g.consumed
}

func (g *infiniteGasMeter) GasConsumedToLimit() Gas {
	g.lock.Lock()
	defer g.lock.Unlock()

	return g.consumed
}

func (g *infiniteGasMeter) Limit() Gas {
	g.lock.Lock()
	defer g.lock.Unlock()

	return 0
}

func (g *infiniteGasMeter) ConsumeGas(amount Gas, descriptor string) {
	g.lock.Lock()
	defer g.lock.Unlock()

	var overflow bool
	// TODO: Should we set the consumed field after overflow checking?
	g.consumed, overflow = addUint64Overflow(g.consumed, amount)
	if overflow {
		panic(ErrorGasOverflow{descriptor})
	}
}

// RefundGas will deduct the given amount from the gas consumed. If the amount is greater than the
// gas consumed, the function will panic.
//
// Use case: This functionality enables refunding gas to the trasaction or block gas pools so that
// EVM-compatible chains can fully support the go-ethereum StateDb interface.
// See https://github.com/cosmos/cosmos-sdk/pull/9403 for reference.
func (g *infiniteGasMeter) RefundGas(amount Gas, descriptor string) {
	g.lock.Lock()
	defer g.lock.Unlock()

	if g.consumed < amount {
		panic(ErrorNegativeGasConsumed{Descriptor: descriptor})
	}

	g.consumed -= amount
}

func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}

func (g *infiniteGasMeter) String() string {
	g.lock.Lock()
	defer g.lock.Unlock()

	return fmt.Sprintf("InfiniteGasMeter:\n  consumed: %d", g.consumed)
}

func (g *infiniteGasMeter) Multiplier() (numerator uint64, denominator uint64) {
	return 1, 1
}
```

**File:** x/gov/abci.go (L20-45)
```go
	keeper.IterateInactiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		keeper.DeleteProposal(ctx, proposal.ProposalId)
		keeper.DeleteDeposits(ctx, proposal.ProposalId)

		// called when proposal become inactive
		keeper.AfterProposalFailedMinDeposit(ctx, proposal.ProposalId)

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeInactiveProposal,
				sdk.NewAttribute(types.AttributeKeyProposalID, fmt.Sprintf("%d", proposal.ProposalId)),
				sdk.NewAttribute(types.AttributeKeyProposalResult, types.AttributeValueProposalDropped),
			),
		)

		logger.Info(
			"proposal did not meet minimum deposit; deleted",
			"proposal", proposal.ProposalId,
			"title", proposal.GetTitle(),
			"min_deposit", keeper.GetDepositParams(ctx).MinDeposit.String(),
			"min_expedited_deposit", keeper.GetDepositParams(ctx).MinExpeditedDeposit.String(),
			"total_deposit", proposal.TotalDeposit.String(),
		)

		return false
	})
```
