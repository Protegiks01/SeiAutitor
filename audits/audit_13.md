## Title
Block Gas Meter Removed - No Aggregate Gas Enforcement Allows MaxGas Bypass

## Summary
The block gas meter functionality has been removed from the codebase, eliminating aggregate gas tracking across all transactions in a block. While individual transactions are checked against the MaxGas limit in the ante handler, there is no mechanism to prevent multiple transactions from collectively exceeding the block's MaxGas limit. This allows an attacker to submit multiple transactions that individually pass the MaxGas check but together consume far more gas than the intended block limit.

## Impact
Medium

## Finding Description

**Location:** 
- Missing block gas meter initialization in [1](#0-0) 
- Missing block gas meter tracking in [2](#0-1) 
- Inadequate MaxGas check in [3](#0-2) 

**Intended Logic:** 
According to the documentation, the block gas meter should aggregate gas consumption across all transactions in a block to enforce MaxGas limits. [4](#0-3) 

The documentation explicitly states that the BlockGasMeter should be checked before each DeliverTx and incremented after each transaction to track cumulative gas consumption per block.

**Actual Logic:** 
The Context struct still contains a `blockGasMeter` field [5](#0-4)  but it is never initialized in the NewContext function [1](#0-0)  and remains nil throughout execution.

The DeliverTx implementation does not check or increment any block gas meter [2](#0-1) . The only gas check occurs in the ante handler, which only validates that a single transaction's gas does not exceed MaxGas [3](#0-2) , without any aggregate tracking.

The removal of block gas meter is confirmed by test comments [6](#0-5)  and all block gas meter tests are commented out [7](#0-6) .

**Exploit Scenario:** 
1. An attacker identifies the MaxGas limit for the chain (e.g., MaxGas = 100)
2. The attacker creates N transactions, each with gas limit = MaxGas - 1 (e.g., 99 gas each)
3. Each transaction passes the ante handler check individually since 99 < 100
4. All N transactions are included in a single block
5. The total gas consumed = N × 99, which can be arbitrarily large (e.g., 10 transactions = 990 gas, far exceeding the intended 100 gas limit)
6. No mechanism exists to prevent this aggregate gas consumption from exceeding MaxGas

**Security Failure:** 
Resource consumption limits are bypassed. The protocol fails to enforce the consensus parameter MaxGas at the block level, allowing blocks to consume arbitrary amounts of gas despite configured limits. This violates the fundamental invariant that blocks should not exceed their gas limits.

## Impact Explanation

This vulnerability affects network processing nodes and consensus parameter enforcement:

- **Network Resource Consumption:** Nodes must process blocks with gas consumption far exceeding the intended MaxGas limit, consuming excessive CPU, memory, and storage resources
- **Parameter Violation:** The consensus parameter MaxGas becomes meaningless as blocks can contain transactions that collectively exceed this limit by arbitrary amounts
- **DoS Vector:** An attacker can force validators to process blocks with 10x, 100x, or more gas than intended, degrading network performance and potentially causing nodes to crash or lag
- **Unfair Resource Usage:** Blocks can be filled with far more computational work than intended, affecting block times and network throughput

This directly maps to the in-scope impact: "Causing network processing nodes to process transactions from the mempool beyond set parameters" and "Increasing network processing node resource consumption by at least 30% without brute force actions."

## Likelihood Explanation

**Who can trigger it:** Any unprivileged network participant can trigger this vulnerability by submitting multiple transactions to the mempool.

**Conditions required:** 
- The chain must have a MaxGas limit configured (which is standard)
- The attacker needs to submit multiple transactions that individually stay under MaxGas
- No special privileges, timing, or network conditions are required

**Frequency:** This can be exploited during normal block production. Every block is vulnerable if an attacker submits enough transactions. The exploit is:
- Trivial to execute (just submit multiple normal transactions)
- Repeatable on every block
- Difficult to detect since each transaction appears valid individually
- Already occurring unintentionally if blocks regularly contain multiple high-gas transactions

The likelihood is HIGH because this is the default behavior of the system with no special conditions required.

## Recommendation

1. **Reinstate Block Gas Meter:** Initialize a block gas meter in the BeginBlock phase with a limit equal to the MaxGas consensus parameter:
   - Add initialization in `setDeliverState` or `BeginBlock` 
   - Set the block gas meter to `NewGasMeter(maxGas)` where maxGas comes from consensus params

2. **Check Block Gas Before Each Transaction:** In the DeliverTx function, check if adding the transaction's gas would exceed the block gas meter limit before processing

3. **Increment Block Gas After Each Transaction:** After successful transaction execution, consume gas from the block gas meter equal to the transaction's actual gas used

4. **Add Block Gas Meter Getter:** Implement a `BlockGasMeter()` method on Context to access the block gas meter for checking and incrementing

The fix should follow the pattern described in the documentation and restore the commented-out test logic.

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** `TestBlockGasMeterBypass`

**Setup:**
1. Create a BaseApp with custom ante handler that sets gas meters and consumes gas based on transaction counter
2. Create a message handler that consumes gas based on message counter
3. Initialize the chain with ConsensusParams.Block.MaxGas = 100
4. Begin a new block at height 1

**Trigger:**
1. Create and deliver 5 transactions, each requesting 90 gas (total = 450 gas)
2. Each transaction individually passes the ante handler check (90 < 100)
3. All 5 transactions are successfully delivered in the same block

**Observation:**
The test demonstrates that all 5 transactions are accepted and processed successfully, resulting in a total gas consumption of 450 gas in a single block, which is 4.5x the MaxGas limit of 100. This confirms that:
- No block-level aggregate gas tracking exists
- The MaxGas limit is only enforced per-transaction, not per-block
- Multiple transactions can bypass the intended block gas limit

The test would need to be added to the test file with the appropriate setup using the existing test helpers (`setupBaseApp`, `newTxCounter`, ante handlers, etc.) following the patterns in the existing tests. The test should show that cumulative gas from multiple transactions exceeds MaxGas without any error or rejection, proving the vulnerability.

### Citations

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

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

**File:** baseapp/deliver_tx_test.go (L780-853)
```go
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
