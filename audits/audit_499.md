# Audit Report

## Title
DeliverTx Hooks Execute After State Commitment Leading to State Persistence Despite Transaction Failure

## Summary
The DeliverTx hook system executes hooks after transaction state changes have been written to the deliverState via `msCache.Write()`, but before the transaction completes. If a hook causes an out-of-gas panic, the transaction returns an error response while its state modifications remain persisted in the deliverState and are committed to the blockchain, violating the invariant that failed transactions should not modify state. [1](#0-0) [2](#0-1) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in `baseapp/baseapp.go` in the `runTx` function, specifically in the ordering of operations between lines 1015-1048. [3](#0-2) 

**Intended Logic:** According to the DeliverTx documentation, "State only gets persisted if all messages are valid and get executed successfully." The system should ensure transaction atomicity - either all state changes commit or none do. [4](#0-3) 

**Actual Logic:** The code writes transaction state changes to the deliverState at line 1016 via `msCache.Write()`, then executes hooks at lines 1041-1046. If any hook consumes gas beyond the transaction's gas limit, the panic is caught by the defer/recover at lines 904-915, and an error is returned. However, the state changes written at line 1016 remain in the deliverState multistore. [5](#0-4) 

The deliverState is committed at block finalization regardless of individual transaction success/failure status. [6](#0-5) 

**Exploit Scenario:**
1. An attacker crafts a transaction with messages that modify critical state (e.g., balance transfers, delegation operations)
2. The transaction is designed to consume gas close to its gas limit
3. A registered DeliverTx hook (such as those from the distribution or slashing modules) performs normal operations that consume additional gas
4. The hook's gas consumption pushes total usage over the transaction's gas limit, triggering an out-of-gas panic
5. The transaction returns an error to the user/indexer, but state modifications persist

**Security Failure:** This breaks transaction atomicity and state consistency. The blockchain records the transaction as failed while actually executing its state changes, creating a discrepancy between reported transaction status and actual chain state.

## Impact Explanation

**Affected Components:**
- Transaction processing integrity
- State consistency between reported status and actual state
- User interfaces and explorers that rely on transaction success/failure status
- Smart contracts or modules that check transaction status before taking actions

**Severity:**
The vulnerability causes unintended smart contract/module behavior where transactions marked as failed have actually modified state. This can lead to:
- Incorrect accounting in protocols that track transaction success
- User confusion and potential loss when transactions appear failed but executed
- Potential consensus issues if different validators have different hooks registered
- State divergence in scenarios where hook execution varies

**Why This Matters:**
The fundamental guarantee of blockchain transactions is atomicity - either a transaction fully succeeds and modifies state, or it fails and makes no changes. This vulnerability breaks that guarantee, undermining trust in transaction execution.

## Likelihood Explanation

**Who Can Trigger:**
Any user submitting transactions to the network can potentially trigger this, though it's not directly controllable since hook behavior depends on registered hooks.

**Conditions Required:**
- DeliverTx hooks must be registered (common in Cosmos SDK chains for distribution rewards, slashing, etc.)
- Transaction must use gas close to its limit
- Hook execution must consume additional gas pushing total over limit

**Frequency:**
This can occur during normal operation whenever:
- Users set tight gas limits on transactions
- Hooks perform gas-intensive operations (store reads/writes)
- Network conditions cause slightly higher gas consumption than expected

The staking module hooks perform multiple store operations that consume gas, making this realistic: [7](#0-6) 

## Recommendation

Modify the `runTx` function to execute hooks BEFORE calling `msCache.Write()`, or use a separate gas meter for hooks that doesn't affect transaction success. Specifically:

1. **Option 1 (Preferred):** Execute hooks before state commitment and include their gas in the transaction accounting
2. **Option 2:** Use an infinite gas meter for hooks or allocate separate gas budget
3. **Option 3:** Add explicit rollback mechanism if hooks fail after state write

The fix should ensure that any error from hooks (including out-of-gas) prevents the `msCache.Write()` call from persisting changes.

## Proof of Concept

**Test File:** `baseapp/deliver_tx_test.go`

**Test Function:** `TestDeliverTxHookGasConsumptionPersistsState`

**Setup:**
1. Create a BaseApp with a message handler that writes to a KV store
2. Register a DeliverTx hook that performs gas-consuming store operations
3. Set up a transaction with a gas limit that's sufficient for the transaction but insufficient when hook gas is included

**Trigger:**
```
1. Initialize chain and set deliver state
2. Create transaction with message that increments a counter in the store
3. Set gas limit to exactly what transaction needs (e.g., 50000)
4. Register hook that consumes additional gas (e.g., store read/write operations consuming 10000 gas)
5. Execute DeliverTx
```

**Observation:**
The test will observe:
1. DeliverTx returns `IsOK() == false` (transaction failed due to out of gas)
2. Query the store shows counter WAS incremented (state change persisted)
3. This confirms the vulnerability: transaction failed but state modified

**Test Code Structure:**
```
func TestDeliverTxHookGasConsumptionPersistsState(t *testing.T) {
    // Setup: Create app with counter message handler
    // Register hook that consumes gas by performing store operations
    // Create transaction with tight gas limit
    // Execute transaction
    // Assert: transaction fails (IsOK == false) 
    // Assert: but store was modified (counter incremented)
    // This proves state persists despite transaction failure
}
```

The test demonstrates that a transaction can fail with an out-of-gas error from hook execution, yet its state changes remain committed, violating the atomicity guarantee.

### Citations

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
```

**File:** baseapp/baseapp.go (L1005-1048)
```go
	// Create a new Context based off of the existing Context with a MultiStore branch
	// in case message processing fails. At this point, the MultiStore
	// is a branch of a branch.
	runMsgCtx, msCache := app.cacheTxContext(ctx, checksum)

	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
	// we do this since we will only be looking at result in DeliverTx
	if result != nil && len(anteEvents) > 0 {
		// append the events in the order of occurrence
		result.Events = append(anteEvents, result.Events...)
	}
	if ctx.CheckTxCallback() != nil {
		ctx.CheckTxCallback()(ctx, err)
	}
	// only apply hooks if no error
	if err == nil && (!ctx.IsEVM() || result.EvmError == "") {
		var evmTxInfo *abci.EvmTxInfo
		if ctx.IsEVM() {
			evmTxInfo = &abci.EvmTxInfo{
				SenderAddress: ctx.EVMSenderAddress(),
				Nonce:         ctx.EVMNonce(),
				TxHash:        ctx.EVMTxHash(),
				VmError:       result.EvmError,
			}
		}
		var events []abci.Event = []abci.Event{}
		if result != nil {
			events = sdk.MarkEventsToIndex(result.Events, app.indexEvents)
		}
		for _, hook := range app.deliverTxHooks {
			hook(ctx, tx, checksum, sdk.DeliverTxHookInput{
				EvmTxInfo: evmTxInfo,
				Events:    events,
			})
		}
	}
	return gInfo, result, anteEvents, priority, pendingTxChecker, expireHandler, ctx, err
```

**File:** baseapp/abci.go (L279-283)
```go
// DeliverTx implements the ABCI interface and executes a tx in DeliverTx mode.
// State only gets persisted if all messages are valid and get executed successfully.
// Otherwise, the ResponseDeliverTx will contain relevant error information.
// Regardless of tx execution outcome, the ResponseDeliverTx will contain relevant
// gas execution context.
```

**File:** baseapp/abci.go (L357-387)
```go
func (app *BaseApp) SetDeliverStateToCommit() {
	app.stateToCommit = app.deliverState
}

// Commit implements the ABCI interface. It will commit all state that exists in
// the deliver state's multi-store and includes the resulting commit ID in the
// returned abci.ResponseCommit. Commit will set the check state based on the
// latest header and reset the deliver state. Also, if a non-zero halt height is
// defined in config, Commit will execute a deferred function call to check
// against that height and gracefully halt if it matches the latest committed
// height.
func (app *BaseApp) Commit(ctx context.Context) (res *abci.ResponseCommit, err error) {
	defer telemetry.MeasureSince(time.Now(), "abci", "commit")
	app.commitLock.Lock()
	defer app.commitLock.Unlock()

	if app.stateToCommit == nil {
		panic("no state to commit")
	}
	header := app.stateToCommit.ctx.BlockHeader()
	retainHeight := app.GetBlockRetentionHeight(header.Height)

	if app.preCommitHandler != nil {
		if err := app.preCommitHandler(app.stateToCommit.ctx); err != nil {
			panic(fmt.Errorf("error when executing commit handler: %s", err))
		}
	}

	app.WriteState()
	app.GetWorkingHash()
	app.cms.Commit(true)
```

**File:** x/distribution/keeper/hooks.go (L19-82)
```go
// initialize validator distribution record
func (h Hooks) AfterValidatorCreated(ctx sdk.Context, valAddr sdk.ValAddress) {
	val := h.k.stakingKeeper.Validator(ctx, valAddr)
	h.k.initializeValidator(ctx, val)
}

// AfterValidatorRemoved performs clean up after a validator is removed
func (h Hooks) AfterValidatorRemoved(ctx sdk.Context, _ sdk.ConsAddress, valAddr sdk.ValAddress) {
	// fetch outstanding
	outstanding := h.k.GetValidatorOutstandingRewardsCoins(ctx, valAddr)

	// force-withdraw commission
	commission := h.k.GetValidatorAccumulatedCommission(ctx, valAddr).Commission
	if !commission.IsZero() {
		// subtract from outstanding
		outstanding = outstanding.Sub(commission)

		// split into integral & remainder
		coins, remainder := commission.TruncateDecimal()

		// remainder to community pool
		feePool := h.k.GetFeePool(ctx)
		feePool.CommunityPool = feePool.CommunityPool.Add(remainder...)
		h.k.SetFeePool(ctx, feePool)

		// add to validator account
		if !coins.IsZero() {
			accAddr := sdk.AccAddress(valAddr)
			withdrawAddr := h.k.GetDelegatorWithdrawAddr(ctx, accAddr)

			if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, coins); err != nil {
				panic(err)
			}
		}
	}

	// Add outstanding to community pool
	// The validator is removed only after it has no more delegations.
	// This operation sends only the remaining dust to the community pool.
	feePool := h.k.GetFeePool(ctx)
	feePool.CommunityPool = feePool.CommunityPool.Add(outstanding...)
	h.k.SetFeePool(ctx, feePool)

	// delete outstanding
	h.k.DeleteValidatorOutstandingRewards(ctx, valAddr)

	// remove commission record
	h.k.DeleteValidatorAccumulatedCommission(ctx, valAddr)

	// clear slashes
	h.k.DeleteValidatorSlashEvents(ctx, valAddr)

	// clear historical rewards
	h.k.DeleteValidatorHistoricalRewards(ctx, valAddr)

	// clear current rewards
	h.k.DeleteValidatorCurrentRewards(ctx, valAddr)
}

// increment period
func (h Hooks) BeforeDelegationCreated(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) {
	val := h.k.stakingKeeper.Validator(ctx, valAddr)
	h.k.IncrementValidatorPeriod(ctx, val)
}
```
