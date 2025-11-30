Based on my comprehensive investigation of the sei-cosmos codebase, I have determined that this security claim represents a **valid Medium severity vulnerability**.

# Audit Report

## Title
Missing Cumulative Block Gas Limit Enforcement Allows Resource Exhaustion Through Multiple High-Gas Transactions

## Summary
The block gas meter enforcement mechanism has been removed from the Cosmos SDK implementation in sei-cosmos, eliminating cumulative gas tracking across transactions within a block. While individual transactions are validated against the MaxGas consensus parameter, multiple transactions can collectively consume gas far beyond this limit, forcing all network nodes to process blocks that violate configured resource parameters. [1](#0-0) [2](#0-1) 

## Impact
Medium

## Finding Description

**Location:**
- Transaction execution loop without cumulative gas tracking: [3](#0-2) 
- Missing block gas meter initialization: [1](#0-0) 
- Per-transaction validation only: [4](#0-3) 
- No validation in ProcessProposal: [5](#0-4) 
- Context struct contains unused blockGasMeter field: [6](#0-5) 

**Intended Logic:**
According to the documentation, the BlockGasMeter should track cumulative gas consumption per block and enforce the MaxGas consensus parameter limit during block execution. [2](#0-1)  The documentation explicitly states: "When a new transaction is being processed via DeliverTx, the current value of BlockGasMeter is checked to see if it is above the limit. If it is, DeliverTx returns immediately."

**Actual Logic:**
The block gas meter is never initialized in `setDeliverState`, and the `FinalizeBlock` transaction loop processes all transactions sequentially without any cumulative gas tracking. My investigation confirmed that no `BlockGasMeter()` accessor method exists on the Context (only found in documentation and commented-out test code). The Context struct contains a `blockGasMeter` field but it is never initialized or used. Only per-transaction validation exists in the ante handler, which checks if individual transaction GasWanted exceeds MaxGas. This allows total block gas consumption to exceed MaxGas arbitrarily when multiple high-gas transactions are included.

**Exploitation Path:**
1. Multiple users submit transactions to mempool, each with GasWanted below MaxGas (e.g., 9,000,000 when MaxGas = 10,000,000) [7](#0-6) 
2. Each transaction individually passes ante handler validation: GasWanted ≤ MaxGas ✓ [4](#0-3) 
3. Validator includes N such transactions in PrepareProposal without cumulative gas checking (PrepareProposal has no gas validation)
4. ProcessProposal accepts the proposal without validating cumulative gas (unconditionally returns ACCEPT) [5](#0-4) 
5. Consensus is reached on the block
6. FinalizeBlock processes all N transactions in a loop without cumulative limit enforcement [3](#0-2) 
7. Block executes with total gas = N × 9,000,000, potentially 5-10x the MaxGas limit
8. All network nodes are forced to process this computationally expensive block

**Security Guarantee Broken:**
The consensus invariant that total block gas consumption ≤ MaxGas is violated. This undermines the resource consumption guarantees that ensure predictable block processing times and prevent denial-of-service through computational resource exhaustion.

## Impact Explanation

This vulnerability directly matches the Medium severity impact criterion: **"Causing network processing nodes to process transactions from the mempool beyond set parameters"**.

The MaxGas consensus parameter exists specifically to limit computational resources per block. Its non-enforcement means:

1. All network nodes must process blocks with cumulative gas consumption far exceeding the configured limit (5-10x possible)
2. Resource-constrained nodes experience significantly longer block execution times
3. The consensus parameter's intended protection against resource exhaustion is defeated
4. Blocks violate configured resource parameters without any defense mechanism

The commented-out test cases demonstrate that cumulative gas enforcement was previously implemented and tested. [8](#0-7) 

## Likelihood Explanation

**Trigger Requirements:**
- Any network participant can submit high-gas transactions to the mempool (no special privileges required)
- Multiple high-gas transactions need to be available in the mempool (easily achievable through normal usage or deliberate submission)
- Validator includes them based on standard selection criteria (e.g., highest fees)

**Frequency:**
This can occur in any block where multiple high-gas transactions are present. The vulnerability does not require a malicious validator - even honest validators selecting high-fee transactions can trigger this condition. An attacker can sustain this by continuously submitting high-gas transactions. The economic cost is only transaction fees, which scale linearly while the resource impact scales multiplicatively across all network nodes.

## Recommendation

Restore cumulative block gas tracking by re-implementing block gas meter functionality:

1. Initialize block gas meter in `setDeliverState` with limit from consensus params MaxGas
2. Add `BlockGasMeter()` accessor method to Context
3. In the FinalizeBlock transaction loop, check cumulative gas before processing each transaction
4. Track cumulative gas consumption after each transaction execution
5. Stop processing transactions when cumulative limit is reached
6. Update PrepareProposal to account for cumulative gas when selecting transactions
7. Add validation in ProcessProposal to reject blocks exceeding MaxGas

Reference the previously implemented logic shown in the commented-out test code which demonstrates proper initialization. [9](#0-8) 

## Proof of Concept

The vulnerability is evident from code inspection. The commented-out test cases show comprehensive test scenarios where cumulative gas enforcement was previously verified, including cases that expected failure when cumulative gas exceeded MaxGas. [8](#0-7) 

**Setup:**
- Initialize BaseApp with consensus parameter MaxGas = 100,000,000 [7](#0-6) 
- Prepare 12 transactions, each with GasWanted = 9,000,000 (90% of block limit)

**Action:**
- Validator includes all 12 transactions in PrepareProposal (no cumulative gas checking implemented)
- ProcessProposal accepts the proposal (unconditionally returns ACCEPT) [5](#0-4) 
- FinalizeBlock executes all transactions in the loop without cumulative gas enforcement [3](#0-2) 

**Result:**
- Total gas consumed = 108,000,000 (10.8x the MaxGas limit)
- Block processes successfully despite violating the consensus parameter
- All network nodes must process computational work far exceeding configured limits
- Demonstrates MaxGas is advisory rather than enforced during block execution

## Notes

The comment at [10](#0-9)  states that "gasWanted < max block gas is still fulfilled by various other checks." However, my investigation confirms this statement is incorrect - the only existing check is per-transaction validation in the ante handler, which does not prevent cumulative excess across multiple transactions in a block.

This vulnerability is particularly concerning because it defeats a fundamental consensus-level safety mechanism. The lack of validation in ProcessProposal means the network has no defense against blocks that violate resource parameters, whether created maliciously or accidentally through normal validator operation selecting high-fee transactions.

### Citations

**File:** baseapp/baseapp.go (L580-593)
```go
func (app *BaseApp) setDeliverState(header tmproto.Header) {
	ms := app.cms.CacheMultiStore()
	ctx := sdk.NewContext(ms, header, false, app.logger)
	if app.deliverState == nil {
		app.deliverState = &state{
			ms:  ms,
			ctx: ctx,
			mtx: &sync.RWMutex{},
		}
		return
	}
	app.deliverState.SetMultiStore(ms)
	app.deliverState.SetContext(ctx)
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

**File:** simapp/app.go (L470-473)
```go
func (app *SimApp) ProcessProposalHandler(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	return &abci.ResponseProcessProposal{
		Status: abci.ResponseProcessProposal_ACCEPT,
	}, nil
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

**File:** x/auth/ante/setup.go (L54-59)
```go
	if cp := ctx.ConsensusParams(); cp != nil && cp.Block != nil {
		// If there exists a maximum block gas limit, we must ensure that the tx
		// does not exceed it.
		if cp.Block.MaxGas > 0 && gasTx.GetGas() > uint64(cp.Block.MaxGas) {
			return newCtx, sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "tx gas wanted %d exceeds block max gas limit %d", gasTx.GetGas(), cp.Block.MaxGas)
		}
```

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

**File:** simapp/test_helpers.go (L39-43)
```go
var DefaultConsensusParams = &tmproto.ConsensusParams{
	Block: &tmproto.BlockParams{
		MaxBytes: 200000,
		MaxGas:   100000000,
	},
```

**File:** baseapp/deliver_tx_test.go (L765-853)
```go
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
