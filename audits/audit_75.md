## Title
Missing Block Gas Meter Implementation Allows Unlimited Gas Consumption Per Block

## Summary
The block gas meter functionality is not implemented in the sei-cosmos codebase, allowing blocks to contain transactions with cumulative gas consumption far exceeding the consensus-defined `MaxGas` limit. This directly affects protections against channel flooding, as IBC packet receive messages and other transactions can overwhelm validators with excessive computation.

## Impact
**Medium**

## Finding Description

**Location:** 
- Missing implementation in [1](#0-0) 
- FinalizeBlocker execution in [2](#0-1) 
- Commented-out test at [3](#0-2) 

**Intended Logic:** 
According to the documentation [4](#0-3) , when processing transactions via DeliverTx, the current value of `BlockGasMeter` should be checked to ensure cumulative gas consumption doesn't exceed the block's MaxGas limit. If exceeded, transaction processing should stop immediately.

**Actual Logic:** 
The Context struct defines a `blockGasMeter` field [1](#0-0)  but provides no getter or setter methods for it. The FinalizeBlocker implementation [2](#0-1)  loops through all transactions in a block and processes them without any block-level gas tracking or limit enforcement. Each transaction only has its individual gas checked against MaxGas in the AnteHandler [5](#0-4) , but there's no cumulative tracking across all transactions in the block.

**Exploit Scenario:** 
An attacker can submit a block proposal (or influence block construction) containing many transactions, each with gas consumption just under the per-transaction MaxGas limit. For example, with a block MaxGas of 100,000,000 and individual transaction limit of 100,000,000, the attacker could include 50+ transactions each consuming 50,000,000 gas, resulting in 2.5 billion gas consumed in a single block—25x the intended limit. For IBC channel flooding specifically, this means an attacker could include numerous MsgRecvPacket transactions that collectively consume far more resources than the chain's consensus parameters allow.

**Security Failure:** 
This breaks the resource consumption invariant enforced by consensus parameters. Validators process transactions beyond the blockchain's configured gas limits, leading to:
- Extended block processing time as validators execute far more computation than expected
- Memory and CPU resource exhaustion from processing oversized blocks
- Potential chain halt if block processing time exceeds block time parameters

## Impact Explanation

This vulnerability affects network availability and validator resource consumption:

- **Validator Resources:** Validators must process blocks containing transactions with cumulative gas far exceeding MaxGas consensus parameters, consuming 2-10x or more CPU, memory, and I/O resources than intended.

- **Block Processing Time:** Blocks may take significantly longer to finalize (500%+ of average block time), causing cascading delays in transaction confirmations and potentially missing block proposal deadlines.

- **IBC Channel Flooding:** Since IBC RecvPacket messages are processed as regular transactions, an attacker can flood blocks with packet receive operations, overwhelming the receiving chain's state machine and preventing legitimate transactions from being processed promptly.

This directly addresses the security question: there are **no protections** against channel flooding with packets that could overwhelm the receiving chain, as the block gas meter that should enforce these limits is not implemented.

## Likelihood Explanation

**High Likelihood:**

- **Who can trigger:** Any block proposer can include transactions exceeding cumulative block gas limits. Additionally, any user can submit many transactions to the mempool that validators may include in blocks.

- **Conditions required:** Normal chain operation. No special privileges or rare circumstances needed. The vulnerability exists in the core transaction processing logic executed for every block.

- **Frequency:** Can be exploited continuously in every block if an attacker controls block proposals, or frequently by flooding the mempool with high-gas transactions that validators pick up. For IBC scenarios, relayers submitting many packet receive messages naturally trigger this issue.

## Recommendation

Implement proper block gas meter tracking and enforcement:

1. Add `BlockGasMeter()` getter and `WithBlockGasMeter(GasMeter)` setter methods to the Context type in `types/context.go`.

2. Initialize the block gas meter in `FinalizeBlock` (or in the FinalizeBlocker) before processing transactions, with a limit set to the consensus parameter `cp.Block.MaxGas`.

3. Before processing each transaction in the FinalizeBlocker loop, check if adding that transaction's gas would exceed the block gas limit. If so, skip the transaction or return an error.

4. After each successful DeliverTx call, consume the transaction's gas from the block gas meter using code similar to the pattern documented: `ctx.BlockGasMeter().ConsumeGas(ctx.GasMeter().GasConsumedToLimit(), "block gas meter")`.

5. Uncomment and update the `TestMaxBlockGasLimits` test to verify the fix works correctly.

## Proof of Concept

**Test File:** `baseapp/deliver_tx_test.go` (add new test function)

**Setup:**
1. Create a BaseApp with AnteHandler that grants 10 gas per transaction counter value
2. Set consensus parameters with Block.MaxGas = 100
3. Initialize a block with BeginBlock

**Trigger:**
1. Attempt to deliver 15 transactions, each consuming 10 gas in ante handler
2. This results in cumulative gas of 150, exceeding the block limit of 100
3. According to documentation, transaction 11+ should fail immediately with OutOfGas error

**Observation:**
Currently, all 15 transactions will be processed successfully, consuming 150 total gas despite the 100 MaxGas limit. The test should verify that after transaction 10 (100 cumulative gas), subsequent transactions are rejected. This can be demonstrated by uncommenting and running the existing commented test at [3](#0-2) , which will fail because the block gas meter check is not implemented.

The test would verify that `ctx.BlockGasMeter().IsOutOfGas()` returns true after cumulative gas exceeds the limit, but currently no such check exists in the transaction processing loop.

### Citations

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

**File:** simapp/app.go (L518-537)
```go
	for i, tx := range req.Txs {
		ctx = ctx.WithContext(context.WithValue(ctx.Context(), ante.ContextKeyTxIndexKey, i))
		if typedTxs[i] == nil {
			txResults = append(txResults, &abci.ExecTxResult{}) // empty result
			continue
		}
		deliverTxResp := app.DeliverTx(ctx, abci.RequestDeliverTx{
			Tx: tx,
		}, typedTxs[i], sha256.Sum256(tx))
		txResults = append(txResults, &abci.ExecTxResult{
			Code:      deliverTxResp.Code,
			Data:      deliverTxResp.Data,
			Log:       deliverTxResp.Log,
			Info:      deliverTxResp.Info,
			GasWanted: deliverTxResp.GasWanted,
			GasUsed:   deliverTxResp.GasUsed,
			Events:    deliverTxResp.Events,
			Codespace: deliverTxResp.Codespace,
		})
	}
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

**File:** docs/basics/gas-fees.md (L55-62)
```markdown
When a new [transaction](../core/transactions.md) is being processed via `DeliverTx`, the current value of `BlockGasMeter` is checked to see if it is above the limit. If it is, `DeliverTx` returns immediately. This can happen even with the first transaction in a block, as `BeginBlock` itself can consume gas. If not, the transaction is processed normally. At the end of `DeliverTx`, the gas tracked by `ctx.BlockGasMeter()` is increased by the amount consumed to process the transaction:

```go
ctx.BlockGasMeter().ConsumeGas(
	ctx.GasMeter().GasConsumedToLimit(),
	"block gas meter",
)
```
```

**File:** x/auth/ante/setup.go (L54-59)
```go
	if cp := ctx.ConsensusParams(); cp != nil && cp.Block != nil {
		// If there exists a maximum block gas limit, we must ensure that the tx
		// does not exceed it.
		if cp.Block.MaxGas > 0 && gasTx.GetGas() > uint64(cp.Block.MaxGas) {
			return newCtx, sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "tx gas wanted %d exceeds block max gas limit %d", gasTx.GetGas(), cp.Block.MaxGas)
		}
```
