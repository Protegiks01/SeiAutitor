# Audit Report

## Title
Unmetered EndBlocker Operations Allow DoS via Unbounded Queue Processing

## Summary
The EndBlock phase executes with an infinite gas meter, allowing unbounded iteration over unbonding delegation and redelegation queues. An attacker can create numerous unbonding operations that mature simultaneously, forcing validators to process them without resource limits during EndBlock, causing resource exhaustion and potential block processing delays.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:**
The Cosmos SDK documentation explicitly states that block gas meters exist to "Make sure blocks are not consuming too many resources and will be finalized." All block processing operations should have bounded resource consumption to prevent denial-of-service attacks. [5](#0-4) 

**Actual Logic:**
When a Context is created via `NewContext`, it initializes with an infinite gas meter. [6](#0-5)  This infinite gas meter always returns `false` for `IsPastLimit()` and `IsOutOfGas()`. [7](#0-6) 

During EndBlock execution, the deliverState context (which has this infinite gas meter) is passed to all module EndBlockers. The staking module's `BlockValidatorUpdates` function processes all mature unbonding delegations by calling `DequeueAllMatureUBDQueue`, which iterates through the entire queue from time 0 to current block time without any iteration limit or gas check. [8](#0-7) 

While `MaxEntries` limits entries per delegator-validator pair to 7 by default, it does not limit the total number of unbonding operations across different delegator accounts or validators. [9](#0-8) 

**Exploitation Path:**
1. Attacker creates multiple delegator accounts (requires only private key generation)
2. Each account delegates tokens to various validators (requires capital and transaction fees)
3. Attacker initiates unbonding from all accounts (7 unbonding entries per delegator-validator pair, transaction fees required)
4. After the unbonding period (typically 21 days), all unbondings mature in the same block range
5. During EndBlock, `DequeueAllMatureUBDQueue` must iterate through all mature entries with no gas limit
6. Each iteration performs: store reads, protobuf unmarshaling, memory allocation, event creation, and store deletions
7. With sufficient unbonding operations (e.g., 100 accounts × 10 validators × 7 entries = 7,000 operations), validators experience significantly increased CPU, memory, and I/O consumption
8. Block processing time increases, potentially causing delays beyond normal block times

**Security Guarantee Broken:**
The fundamental blockchain security principle that "block processing must have bounded and predictable resource consumption" is violated. The documentation explicitly warns that complex EndBlocker functions "can slow down or even halt the chain." [10](#0-9) 

## Impact Explanation

This vulnerability enables a resource exhaustion denial-of-service attack affecting all network validators:

- **Network-Wide Resource Consumption**: All validators must synchronously process expensive EndBlock operations, consuming excessive CPU for iteration and unmarshaling, memory for storing queued entries, and disk I/O for state reads and deletions.

- **Block Processing Delays**: Unbounded processing time in EndBlock can delay block production beyond normal timeframes, affecting transaction finality and user experience. The impact scales linearly with the number of queued operations.

- **Validator Resource Exhaustion**: Repeated exploitation keeps validator resources consistently elevated. In extreme cases, this could cause validator crashes or require operators to significantly increase hardware capacity.

- **Economic Feasibility**: While the attack requires capital for delegations and transaction fees for unbonding operations, the cost is distributed across many small delegations and is recoverable after the unbonding period. The MaxEntries limit of 7 per pair does not prevent creating thousands of pairs across different accounts and validators.

This meets the **Medium** severity threshold of "Increasing network processing node resource consumption by at least 30% without brute force actions" because the attack uses legitimate protocol operations (unbonding delegations) to trigger unbounded computation that all validators must process.

## Likelihood Explanation

**Who can trigger it:** Any network participant with sufficient funds to create delegations. The barrier is low as small delegation amounts across multiple validators can be used, and the capital is recoverable after unbonding.

**Conditions required:**
- Standard network operation (no special conditions)
- Attacker must wait through the unbonding period (typically 21 days)
- Timing coordination to have many operations mature in the same block range
- No privileged access or special permissions needed

**Frequency:**
- Can be triggered repeatedly by the same or different attackers
- Each cycle requires waiting through the unbonding period
- Multiple attackers could coordinate to amplify effects
- Normal unbonding operations already stress the system, making malicious patterns harder to distinguish

The vulnerability is likely to be exploited because:
1. The economic cost is distributed and recoverable
2. The attack uses legitimate protocol operations
3. No special permissions or race conditions need to be exploited
4. Impact is deterministic once conditions are met
5. The code provides no protection against this scenario

## Recommendation

**Primary Fix**: Replace the infinite gas meter with a finite gas meter for EndBlock operations:

```go
// In setDeliverState, after creating the context:
endBlockGasLimit := app.GetConsensusParams(ctx).Block.MaxGas * 10 // Configure appropriately
ctx = ctx.WithGasMeter(sdk.NewGasMeter(endBlockGasLimit))
```

**Secondary Mitigations**:

1. **Add Per-Block Processing Limits**: Implement explicit limits on queue processing iterations per block as defense-in-depth:
```go
const maxUBDProcessingPerBlock = 1000
processed := 0
for iterator.Valid() && processed < maxUBDProcessingPerBlock {
    // process entry
    processed++
}
```

2. **Batch Processing**: If gas exhaustion occurs or limits are hit, defer remaining entries to the next block rather than failing.

3. **Monitoring**: Add metrics to track EndBlock processing time and resource consumption to detect anomalous patterns.

4. **Graceful Degradation**: Prioritize critical operations (validator set updates) over queue processing when resource limits are approached.

## Proof of Concept

**Conceptual Test**: `baseapp/endblock_gas_test.go` - `TestEndBlockerGasMeteringDoS`

**Setup:**
1. Initialize BaseApp with staking module
2. Create multiple test accounts (delegators)
3. Create multiple validators
4. Each delegator delegates to multiple validators (e.g., 100 accounts × 10 validators)
5. Initiate unbonding for all delegations (up to 7 entries per pair due to MaxEntries)
6. Advance chain time past unbonding completion time

**Trigger:**
1. Call `EndBlock` at maturity block height
2. Monitor gas consumption during `DequeueAllMatureUBDQueue` execution
3. Verify context gas meter is `InfiniteGasMeter` (check `ctx.GasMeter().Limit() == 0`)
4. Measure iteration count and processing time

**Expected Result:**
- Context gas meter returns limit of 0 (infinite)
- `IsPastLimit()` always returns `false` despite high consumption
- All unbonding entries are processed in a single block
- Processing time scales linearly with number of entries
- No out-of-gas panic occurs regardless of operations performed
- Resource consumption (CPU, memory, I/O) increases proportionally to entry count without upper bound

The vulnerability is confirmed by code analysis showing that `NewContext` initializes with `NewInfiniteGasMeter`, which is never replaced during EndBlock execution, and `DequeueAllMatureUBDQueue` performs unbounded iteration without any gas or iteration limit checks.

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

**File:** docs/basics/gas-fees.md (L15-18)
```markdown
In the Cosmos SDK, `gas` is a special unit that is used to track the consumption of resources during execution. `gas` is typically consumed whenever read and writes are made to the store, but it can also be consumed if expensive computation needs to be done. It serves two main purposes:

- Make sure blocks are not consuming too many resources and will be finalized. This is implemented by default in the SDK via the [block gas meter](#block-gas-meter).
- Prevent spam and abuse from end-user. To this end, `gas` consumed during [`message`](../building-modules/messages-and-queries.md#messages) execution is typically priced, resulting in a `fee` (`fees = gas * gas-prices`). `fees` generally have to be paid by the sender of the `message`. Note that the SDK does not enforce `gas` pricing by default, as there may be other ways to prevent spam (e.g. bandwidth schemes). Still, most applications will implement `fee` mechanisms to prevent spam. This is done via the [`AnteHandler`](#antehandler).
```

**File:** store/types/gas.go (L252-257)
```go
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
```

**File:** x/staking/types/params.go (L26-27)
```go
	// Default maximum entries in a UBD/RED pair
	DefaultMaxEntries uint32 = 7
```

**File:** docs/building-modules/beginblock-endblock.md (L15-15)
```markdown
`BeginBlocker` and `EndBlocker` are a way for module developers to add automatic execution of logic to their module. This is a powerful tool that should be used carefully, as complex automatic functions can slow down or even halt the chain.
```
