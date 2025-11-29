Based on my thorough investigation of the codebase, I can now provide my final validation:

# Audit Report

## Title
Block Gas Limit Bypass Due to Missing Cumulative Gas Tracking

## Summary
The sei-cosmos blockchain fails to enforce cumulative gas limits at the block level. While individual transactions are validated against the `MaxGas` consensus parameter in the ante handler, the removal of block gas meter functionality allows validators to propose blocks containing multiple transactions whose collective gas consumption exceeds `MaxGas`, forcing all network nodes to process transactions beyond set parameters.

## Impact
Medium

## Finding Description

- **location**: 
  - Individual check: [1](#0-0) 
  - Missing cumulative tracking: [2](#0-1) 
  - Unused block gas meter field: [3](#0-2) 

- **intended logic**: According to the documentation [4](#0-3) , the block gas meter should track cumulative gas consumption across all transactions in a block. When processing transactions via `DeliverTx`, the system should check if cumulative gas exceeds the limit and reject subsequent transactions. After each transaction, the consumed gas should be added to the block gas meter.

- **actual logic**: The current implementation only validates that each individual transaction's requested gas does not exceed `MaxGas` in the ante handler. No cumulative gas tracking occurs during block processing. The `blockGasMeter` field exists in the Context struct but has no accessor method and is never initialized or used. Evidence of intentional removal: [5](#0-4) 

- **exploitation path**: 
  1. When a validator's turn arrives to propose a block, they construct a block with multiple transactions
  2. Each transaction requests gas below `MaxGas` (e.g., 60 when MaxGas=100)  
  3. Each transaction passes the individual validation check in SetUpContextDecorator
  4. All transactions are processed via DeliverTx without any cumulative gas check
  5. The block's total gas consumption (e.g., 3 transactions × 60 gas = 180) exceeds MaxGas (100)
  6. All network nodes process these transactions, consuming resources beyond configured limits

- **security guarantee broken**: The consensus parameter `ConsensusParams.Block.MaxGas` is designed to limit the total computational work per block. This vulnerability allows validators to bypass this limit, violating the resource constraint invariant that protects nodes from excessive processing requirements.

## Impact Explanation

This vulnerability enables validators to force all network nodes to process blocks with cumulative gas consumption exceeding the configured `MaxGas` limit. This causes:

- Increased CPU, memory, and I/O consumption on all full nodes beyond design parameters
- Network performance degradation and potentially increased block times
- Denial of service risk if exploited aggressively with maximum-sized transactions
- Consensus parameters become unenforceable for block-level gas limiting

The impact directly matches: "Causing network processing nodes to process transactions from the mempool beyond set parameters" (Medium severity).

## Likelihood Explanation

**Trigger frequency**: High. Any validator can exploit this during their normal block proposal turn, which occurs regularly in validator rotation (approximately 1/N blocks for N validators).

**Prerequisites**: 
- Validator role (privileged but regularly rotating)
- No special timing or state conditions required
- Can be triggered repeatedly and consistently

**Realistic scenario**: While validators are trusted participants, consensus parameters exist specifically to constrain validator behavior. Violating `MaxGas` is beyond a validator's intended authority - the parameter defines the limits of what they are authorized to include in blocks. A single malicious or compromised validator can exploit this, or even well-intentioned validators with buggy block construction software could inadvertently trigger it.

The commented-out tests [6](#0-5)  show this functionality previously existed and was intentionally removed, but without proper replacement validation.

## Recommendation

Restore block-level cumulative gas tracking by:

1. Add a `BlockGasMeter()` accessor method to the `Context` type
2. Initialize the block gas meter in `BeginBlock` or state initialization with limit from `ConsensusParams.Block.MaxGas`
3. Before processing each transaction in `DeliverTx`, check if adding its gas would exceed the block gas limit
4. After each successful transaction execution, consume gas from the block gas meter:
```go
ctx.BlockGasMeter().ConsumeGas(
    ctx.GasMeter().GasConsumedToLimit(),
    "block gas meter",
)
```
5. Re-enable and update the commented-out `TestMaxBlockGasLimits` test to verify proper enforcement

This restores the documented behavior and consensus parameter enforcement.

## Proof of Concept

**Test scenario** (conceptual, based on commented test structure):

- **setup**: Initialize BaseApp with consensus params setting `MaxGas = 100`. Configure ante handler to grant requested gas. Set up message router to consume specified gas amounts.

- **action**: 
  1. Begin new block with MaxGas=100 consensus parameter
  2. Deliver transaction requesting 60 gas (passes: 60 < 100)
  3. Deliver second transaction requesting 60 gas (passes individual check: 60 < 100)  
  4. Deliver third transaction requesting 60 gas (passes individual check: 60 < 100)
  
- **result**: All three transactions succeed and are committed. Total cumulative gas consumed is 180, which is 180% of the configured MaxGas limit of 100. The system processes all transactions despite violating the block gas limit consensus parameter. In a properly functioning system with block gas meter enforcement, the second or third transaction should be rejected with an "out of gas" error when the cumulative limit is exceeded.

The existence of commented-out test code at [6](#0-5)  demonstrates this exact scenario was previously tested before the block gas meter was removed.

### Citations

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

**File:** baseapp/abci.go (L284-337)
```go
func (app *BaseApp) DeliverTx(ctx sdk.Context, req abci.RequestDeliverTx, tx sdk.Tx, checksum [32]byte) (res abci.ResponseDeliverTx) {
	defer telemetry.MeasureSince(time.Now(), "abci", "deliver_tx")
	defer func() {
		for _, streamingListener := range app.abciListeners {
			if err := streamingListener.ListenDeliverTx(app.deliverState.ctx, req, res); err != nil {
				app.logger.Error("DeliverTx listening hook failed", "err", err)
			}
		}
	}()

	gInfo := sdk.GasInfo{}
	resultStr := "successful"

	defer func() {
		telemetry.IncrCounter(1, "tx", "count")
		telemetry.IncrCounter(1, "tx", resultStr)
		telemetry.SetGauge(float32(gInfo.GasUsed), "tx", "gas", "used")
		telemetry.SetGauge(float32(gInfo.GasWanted), "tx", "gas", "wanted")
	}()

	gInfo, result, anteEvents, _, _, _, resCtx, err := app.runTx(ctx.WithTxBytes(req.Tx).WithTxSum(checksum).WithVoteInfos(app.voteInfos), runTxModeDeliver, tx, checksum)
	if err != nil {
		resultStr = "failed"
		// if we have a result, use those events instead of just the anteEvents
		if result != nil {
			return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(result.Events, app.indexEvents), app.trace)
		}
		return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(anteEvents, app.indexEvents), app.trace)
	}

	res = abci.ResponseDeliverTx{
		GasWanted: int64(gInfo.GasWanted), // TODO: Should type accept unsigned ints?
		GasUsed:   int64(gInfo.GasUsed),   // TODO: Should type accept unsigned ints?
		Log:       result.Log,
		Data:      result.Data,
		Events:    sdk.MarkEventsToIndex(result.Events, app.indexEvents),
	}
	if resCtx.IsEVM() {
		res.EvmTxInfo = &abci.EvmTxInfo{
			SenderAddress: resCtx.EVMSenderAddress(),
			Nonce:         resCtx.EVMNonce(),
			TxHash:        resCtx.EVMTxHash(),
			VmError:       result.EvmError,
		}
		// TODO: populate error data for EVM err
		if result.EvmError != "" {
			evmErr := sdkerrors.Wrap(sdkerrors.ErrEVMVMError, result.EvmError)
			res.Codespace, res.Code, res.Log = sdkerrors.ABCIInfo(evmErr, app.trace)
			resultStr = "failed"
			return
		}
	}
	return
}
```

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

**File:** docs/basics/gas-fees.md (L49-62)
```markdown
### Block Gas Meter

`ctx.BlockGasMeter()` is the gas meter used to track gas consumption per block and make sure it does not go above a certain limit. A new instance of the `BlockGasMeter` is created each time [`BeginBlock`](../core/baseapp.md#beginblock) is called. The `BlockGasMeter` is finite, and the limit of gas per block is defined in the application's consensus parameters. By default Cosmos SDK applications use the default consensus parameters provided by Tendermint:

+++ https://github.com/tendermint/tendermint/blob/v0.34.0-rc6/types/params.go#L34-L41

When a new [transaction](../core/transactions.md) is being processed via `DeliverTx`, the current value of `BlockGasMeter` is checked to see if it is above the limit. If it is, `DeliverTx` returns immediately. This can happen even with the first transaction in a block, as `BeginBlock` itself can consume gas. If not, the transaction is processed normally. At the end of `DeliverTx`, the gas tracked by `ctx.BlockGasMeter()` is increased by the amount consumed to process the transaction:

```go
ctx.BlockGasMeter().ConsumeGas(
	ctx.GasMeter().GasConsumedToLimit(),
	"block gas meter",
)
```
```

**File:** baseapp/deliver_tx_test.go (L754-853)
```go
// func TestMaxBlockGasLimits(t *testing.T) {
// 	gasGranted := uint64(10)
// 	anteOpt := func(bapp *BaseApp) {
// 		bapp.SetAnteHandler(func(ctx sdk.Context, tx sdk.Tx, simulate bool) (newCtx sdk.Context, err error) {
// 			newCtx = ctx.WithGasMeter(sdk.NewGasMeterWithMultiplier(ctx, gasGranted))

// 			defer func() {
// 				if r := recover(); r != nil {
// 					switch rType := r.(type) {
// 					case sdk.ErrorOutOfGas:
// 						err = sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "out of gas in location: %v", rType.Descriptor)
// 					default:
// 						panic(r)
// 					}
// 				}
// 			}()

// 			count := tx.(txTest).Counter
// 			newCtx.GasMeter().ConsumeGas(uint64(count), "counter-ante")

// 			return
// 		})
// 	}

// 	routerOpt := func(bapp *BaseApp) {
// 		r := sdk.NewRoute(routeMsgCounter, func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
// 			count := msg.(*msgCounter).Counter
// 			ctx.GasMeter().ConsumeGas(uint64(count), "counter-handler")
// 			return &sdk.Result{}, nil
// 		})
// 		bapp.Router().AddRoute(r)
// 	}

// 	app := setupBaseApp(t, anteOpt, routerOpt)
// 	app.InitChain(context.Background(), &abci.RequestInitChain{
// 		ConsensusParams: &tmproto.ConsensusParams{
// 			Block: &tmproto.BlockParams{
// 				MaxGas: 100,
// 			},
// 		},
// 	})

// 	testCases := []struct {
// 		tx                *txTest
// 		numDelivers       int
// 		gasUsedPerDeliver uint64
// 		fail              bool
// 		failAfterDeliver  int
// 	}{
// 		{newTxCounter(0, 0), 0, 0, false, 0},
// 		{newTxCounter(9, 1), 2, 10, false, 0},
// 		{newTxCounter(10, 0), 3, 10, false, 0},
// 		{newTxCounter(10, 0), 10, 10, false, 0},
// 		{newTxCounter(2, 7), 11, 9, false, 0},
// 		{newTxCounter(10, 0), 10, 10, false, 0}, // hit the limit but pass

// 		{newTxCounter(10, 0), 11, 10, true, 10},
// 		{newTxCounter(10, 0), 15, 10, true, 10},
// 		{newTxCounter(9, 0), 12, 9, true, 11}, // fly past the limit
// 	}

// 	for i, tc := range testCases {
// 		tx := tc.tx

// 		// reset the block gas
// 		header := tmproto.Header{Height: app.LastBlockHeight() + 1}
// 		app.setDeliverState(header)
// 		app.deliverState.ctx = app.deliverState.ctx.WithBlockGasMeter(sdk.NewGasMeter(app.getMaximumBlockGas(app.deliverState.ctx), 1, 1))
// 		app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header})

// 		// execute the transaction multiple times
// 		for j := 0; j < tc.numDelivers; j++ {
// 			_, result, err := app.Deliver(aminoTxEncoder(), tx)

// 			ctx := app.getState(runTxModeDeliver).ctx

// 			// check for failed transactions
// 			if tc.fail && (j+1) > tc.failAfterDeliver {
// 				require.Error(t, err, fmt.Sprintf("tc #%d; result: %v, err: %s", i, result, err))
// 				require.Nil(t, result, fmt.Sprintf("tc #%d; result: %v, err: %s", i, result, err))

// 				space, code, _ := sdkerrors.ABCIInfo(err, false)
// 				require.EqualValues(t, sdkerrors.ErrOutOfGas.Codespace(), space, err)
// 				require.EqualValues(t, sdkerrors.ErrOutOfGas.ABCICode(), code, err)
// 				require.True(t, ctx.BlockGasMeter().IsOutOfGas())
// 			} else {
// 				// check gas used and wanted
// 				blockGasUsed := ctx.BlockGasMeter().GasConsumed()
// 				expBlockGasUsed := tc.gasUsedPerDeliver * uint64(j+1)
// 				require.Equal(
// 					t, expBlockGasUsed, blockGasUsed,
// 					fmt.Sprintf("%d,%d: %v, %v, %v, %v", i, j, tc, expBlockGasUsed, blockGasUsed, result),
// 				)

// 				require.NotNil(t, result, fmt.Sprintf("tc #%d; currDeliver: %d, result: %v, err: %s", i, j, result, err))
// 				require.False(t, ctx.BlockGasMeter().IsPastLimit())
// 			}
// 		}
// 	}
// }
```

**File:** baseapp/deliver_tx_test.go (L1144-1144)
```go
	// removed the block gas exceeded because of removal of block gas meter, gasWanted < max block gas is still fulfilled by various other checks
```
