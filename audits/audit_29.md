# Audit Report

## Title
Stale Consensus Parameters in Simulate Mode Lead to Divergent Simulation Results

## Summary
The `getContextForTx` function at line 821 in `baseapp/baseapp.go` retrieves consensus parameters from `checkState` when executing in simulate mode. However, `checkState` is not updated with new consensus parameters until after block commit, causing simulations to use stale parameters during block execution. This results in simulation results that differ from actual execution, violating the core invariant that simulations accurately predict transaction outcomes. [1](#0-0) 

## Impact
**Medium** - A bug in the layer 1 network code that results in unintended smart contract behavior with no concrete funds at direct risk, and causes network processing nodes to process transactions from the mempool beyond set parameters.

## Finding Description

**Location:** 
- Primary: `baseapp/baseapp.go`, function `getContextForTx`, line 821
- Related: `baseapp/baseapp.go`, function `getState`, lines 805-811
- Related: `baseapp/abci.go`, function `Commit`, line 393 [2](#0-1) 

**Intended Logic:** 
The simulation mode should use the same consensus parameters that will be active during actual transaction execution, ensuring that simulation results accurately predict whether a transaction will succeed or fail. The `getContextForTx` function is supposed to set consensus parameters that match the current blockchain state.

**Actual Logic:**
When `getContextForTx` is called in simulate mode, it retrieves the context from `checkState` via `getState(runTxModeSimulate)`. The function then calls `GetConsensusParams(ctx)` which reads from the param store using this `checkState` context. However, `checkState` is only updated after block commit, not during block execution. If consensus parameters are updated during a block (e.g., via governance proposal in `EndBlock`), the updates are written to `deliverState` but not visible in `checkState` until after commit. [3](#0-2) 

**Exploit Scenario:**
1. Block N begins with consensus parameter `MaxGas = 10000`
2. During block N execution, a governance proposal passes that updates `MaxGas = 5000` in the param store (written to `deliverState`)
3. A user calls the simulate endpoint with a transaction requesting `gas = 7000`
4. The simulation uses `checkState` which still has `MaxGas = 10000` (old value)
5. Simulation succeeds because `7000 < 10000`, and the ante handler validation passes [4](#0-3) 

6. Block N commits, and `checkState` is updated with the new consensus parameters
7. User submits the transaction for actual execution in block N+1
8. Transaction fails validation because `7000 > 5000`, rejecting a transaction that passed simulation [5](#0-4) 

**Security Failure:**
This breaks the simulation invariant - that simulation results match actual execution results. The ante handler performs validation checks against consensus parameters, and these checks produce different results in simulation vs execution when parameters change mid-block.

## Impact Explanation

**Affected Components:**
- Transaction simulation accuracy for all users and applications
- Gas estimation and transaction fee calculation
- Block gas limits and transaction size limits
- All consensus parameters: `MaxGas`, `MaxBytes`, `EvidenceParams`, `ValidatorParams`, etc. [6](#0-5) 

**Severity:**
- **User Experience Impact:** Users receive false positive simulation results, leading them to submit transactions that fail in actual execution, wasting gas fees
- **Application Impact:** DApps, wallets, and other applications that rely on simulation for gas estimation will submit transactions that fail, breaking their functionality
- **Network Impact:** Nodes process transactions that should have been rejected during simulation, consuming mempool resources and potentially exceeding intended block gas limits
- **Parameter Validation Bypass:** Transactions can be submitted that violate newly-enacted consensus parameter limits because simulation incorrectly validated them against old parameters

This matters because simulation is a critical feature used throughout the ecosystem for transaction validation before submission. Breaking this invariant undermines trust in the simulation endpoint and causes real economic losses through wasted gas fees.

## Likelihood Explanation

**Trigger Conditions:**
- **Who:** Any network participant can trigger this by calling the simulate endpoint during a block where consensus parameters are being updated
- **When:** This occurs whenever consensus parameters are updated via governance proposals or other parameter change mechanisms during block execution
- **Frequency:** While consensus parameter updates are not extremely frequent, they do occur during chain upgrades, governance decisions, and network optimizations. Each time they occur, there is a window (between parameter update in `EndBlock` and the next `Commit`) where all simulations will use stale parameters

**Exploitability:**
- No special privileges required - any user can call the public simulation endpoint
- No complex timing required - simply calling simulate during the block where parameters change is sufficient
- The vulnerability affects all consensus parameters, not just `MaxGas`, broadening the attack surface
- Applications that continuously simulate transactions for gas estimation are particularly vulnerable

**Real-World Scenario:**
A common pattern is for governance to adjust gas limits in response to network conditions. When such a proposal executes, all simulations during that block will use incorrect parameters, potentially causing widespread transaction failures for applications that relied on those simulations.

## Recommendation

**Fix:** Modify `getContextForTx` to use `deliverState` consensus parameters for simulate mode instead of `checkState` parameters. Specifically, at line 821, retrieve consensus parameters from the latest committed or in-progress state rather than from the potentially stale `checkState`.

**Implementation Options:**

1. **Option 1 (Recommended):** Always read consensus parameters from `deliverState` when it exists:
```go
func (app *BaseApp) getContextForTx(mode runTxMode, txBytes []byte) sdk.Context {
    app.votesInfoLock.RLock()
    defer app.votesInfoLock.RUnlock()
    ctx := app.getState(mode).Context().
        WithTxBytes(txBytes).
        WithVoteInfos(app.voteInfos)
    
    // Use deliverState for consensus params if available (during block execution)
    // Otherwise fall back to checkState
    cpCtx := ctx
    if app.deliverState != nil {
        cpCtx = app.deliverState.Context()
    }
    ctx = ctx.WithConsensusParams(app.GetConsensusParams(cpCtx))
    
    if mode == runTxModeReCheck {
        ctx = ctx.WithIsReCheckTx(true)
    }
    
    if mode == runTxModeSimulate {
        ctx, _ = ctx.CacheContext()
    }
    
    return ctx
}
```

2. **Option 2:** Update `checkState` immediately when consensus parameters change, not just after commit

3. **Option 3:** Add a flag or dedicated method to retrieve "effective" consensus parameters that returns the most up-to-date values regardless of which state they're in

The recommended fix ensures simulations always use the consensus parameters that will be active for the next block, maintaining the invariant that simulation results match actual execution.

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** `TestSimulateWithStaleConsensusParams`

**Setup:**
1. Initialize a BaseApp with initial consensus parameters `MaxGas = 10000`
2. Mount necessary stores and set ante handler that validates gas against `MaxGas` consensus parameter
3. Initialize chain with the initial parameters
4. Begin a new block

**Trigger:**
1. During block execution, update consensus parameters in `deliverState` to set `MaxGas = 5000` using `StoreConsensusParams`
2. Create a transaction with `gas = 7000` (between the old and new limits)
3. Call `app.Simulate()` with this transaction

**Observation:**
1. The simulation should use `checkState` which has `MaxGas = 10000`
2. Transaction passes simulation (7000 < 10000)
3. Commit the block to apply the parameter change
4. Begin a new block
5. Attempt to deliver the same transaction
6. Transaction fails in actual execution (7000 > 5000)
7. **Test demonstrates:** Simulation result (success) differs from actual execution result (failure)

**Expected Test Code Structure:**
```go
func TestSimulateWithStaleConsensusParams(t *testing.T) {
    // Setup app with MaxGas = 10000
    anteOpt := func(bapp *BaseApp) {
        bapp.SetAnteHandler(NewDefaultSetUpContextDecorator().AnteHandle)
    }
    app := setupBaseApp(t, anteOpt)
    
    // Initialize with MaxGas = 10000
    app.InitChain(context.Background(), &abci.RequestInitChain{
        ConsensusParams: &tmproto.ConsensusParams{
            Block: &tmproto.BlockParams{MaxGas: 10000},
        },
    })
    
    // Start block N
    header := tmproto.Header{Height: 1}
    app.setDeliverState(header)
    app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})
    
    // Update consensus params in deliverState (simulating governance update)
    newParams := &tmproto.ConsensusParams{
        Block: &tmproto.BlockParams{MaxGas: 5000},
    }
    app.StoreConsensusParams(app.deliverState.ctx, newParams)
    
    // Create tx with gas = 7000 (between old and new limits)
    tx := newTxWithGas(7000)
    txBytes, _ := encodeTx(tx)
    
    // Simulate - should pass with stale params (7000 < 10000)
    _, simResult, simErr := app.Simulate(txBytes)
    require.NoError(t, simErr, "Simulation should pass with old MaxGas=10000")
    require.True(t, simResult.IsOK(), "Simulation should succeed")
    
    // Commit block to apply parameter change
    app.Commit(context.Background())
    
    // Start new block
    header.Height = 2
    app.setDeliverState(header)
    app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})
    
    // Deliver same tx - should fail with new params (7000 > 5000)
    _, deliverResult, deliverErr := app.Deliver(txEncoder, tx)
    require.Error(t, deliverErr, "Delivery should fail with new MaxGas=5000")
    require.False(t, deliverResult.IsOK(), "Delivery should fail")
    
    // VULNERABILITY: Simulation passed but delivery failed
    assert.NotEqual(t, simResult.IsOK(), deliverResult.IsOK(), 
        "BUG: Simulation result differs from actual execution")
}
```

This test demonstrates that simulation during a block where consensus parameters are updated uses stale parameters from `checkState`, while actual execution uses the updated parameters, violating the simulation invariant.

### Citations

**File:** baseapp/baseapp.go (L673-731)
```go
// GetConsensusParams returns the current consensus parameters from the BaseApp's
// ParamStore. If the BaseApp has no ParamStore defined, nil is returned.
func (app *BaseApp) GetConsensusParams(ctx sdk.Context) *tmproto.ConsensusParams {
	if app.paramStore == nil {
		return nil
	}

	cp := new(tmproto.ConsensusParams)

	if app.paramStore.Has(ctx, ParamStoreKeyBlockParams) {
		var bp tmproto.BlockParams

		app.paramStore.Get(ctx, ParamStoreKeyBlockParams, &bp)
		cp.Block = &bp
	}

	if app.paramStore.Has(ctx, ParamStoreKeyEvidenceParams) {
		var ep tmproto.EvidenceParams

		app.paramStore.Get(ctx, ParamStoreKeyEvidenceParams, &ep)
		cp.Evidence = &ep
	}

	if app.paramStore.Has(ctx, ParamStoreKeyValidatorParams) {
		var vp tmproto.ValidatorParams

		app.paramStore.Get(ctx, ParamStoreKeyValidatorParams, &vp)
		cp.Validator = &vp
	}

	if app.paramStore.Has(ctx, ParamStoreKeyVersionParams) {
		var vp tmproto.VersionParams

		app.paramStore.Get(ctx, ParamStoreKeyVersionParams, &vp)
		cp.Version = &vp
	}

	if app.paramStore.Has(ctx, ParamStoreKeySynchronyParams) {
		var vp tmproto.SynchronyParams

		app.paramStore.Get(ctx, ParamStoreKeySynchronyParams, &vp)
		cp.Synchrony = &vp
	}

	if app.paramStore.Has(ctx, ParamStoreKeyTimeoutParams) {
		var vp tmproto.TimeoutParams

		app.paramStore.Get(ctx, ParamStoreKeyTimeoutParams, &vp)
		cp.Timeout = &vp
	}

	if app.paramStore.Has(ctx, ParamStoreKeyABCIParams) {
		var vp tmproto.ABCIParams

		app.paramStore.Get(ctx, ParamStoreKeyABCIParams, &vp)
		cp.Abci = &vp
	}

	return cp
```

**File:** baseapp/baseapp.go (L805-811)
```go
func (app *BaseApp) getState(mode runTxMode) *state {
	if mode == runTxModeDeliver {
		return app.deliverState
	}

	return app.checkState
}
```

**File:** baseapp/baseapp.go (L814-831)
```go
func (app *BaseApp) getContextForTx(mode runTxMode, txBytes []byte) sdk.Context {
	app.votesInfoLock.RLock()
	defer app.votesInfoLock.RUnlock()
	ctx := app.getState(mode).Context().
		WithTxBytes(txBytes).
		WithVoteInfos(app.voteInfos)

	ctx = ctx.WithConsensusParams(app.GetConsensusParams(ctx))

	if mode == runTxModeReCheck {
		ctx = ctx.WithIsReCheckTx(true)
	}

	if mode == runTxModeSimulate {
		ctx, _ = ctx.CacheContext()
	}

	return ctx
```

**File:** baseapp/abci.go (L133-157)
```go
// BeginBlock implements the ABCI application interface.
func (app *BaseApp) BeginBlock(ctx sdk.Context, req abci.RequestBeginBlock) (res abci.ResponseBeginBlock) {
	defer telemetry.MeasureSince(time.Now(), "abci", "begin_block")

	if !req.Simulate {
		if err := app.validateHeight(req); err != nil {
			panic(err)
		}
	}

	if app.beginBlocker != nil {
		res = app.beginBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	// call the streaming service hooks with the EndBlock messages
	if !req.Simulate {
		for _, streamingListener := range app.abciListeners {
			if err := streamingListener.ListenBeginBlock(app.deliverState.ctx, req, res); err != nil {
				app.logger.Error("EndBlock listening hook failed", "height", req.Header.Height, "err", err)
			}
		}
	}
	return res
}
```

**File:** baseapp/abci.go (L389-396)
```go
	// Reset the Check state to the latest committed.
	//
	// NOTE: This is safe because Tendermint holds a lock on the mempool for
	// Commit. Use the header from this latest block.
	app.setCheckState(header)

	// empty/reset the deliver state
	app.resetStatesExceptCheckState()
```

**File:** x/auth/ante/setup.go (L54-60)
```go
	if cp := ctx.ConsensusParams(); cp != nil && cp.Block != nil {
		// If there exists a maximum block gas limit, we must ensure that the tx
		// does not exceed it.
		if cp.Block.MaxGas > 0 && gasTx.GetGas() > uint64(cp.Block.MaxGas) {
			return newCtx, sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "tx gas wanted %d exceeds block max gas limit %d", gasTx.GetGas(), cp.Block.MaxGas)
		}
	}
```
