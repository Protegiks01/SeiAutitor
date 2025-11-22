## Title
Block Gas Limit Bypass Due to Missing Cumulative Gas Tracking

## Summary
The sei-cosmos blockchain fails to enforce cumulative gas limits at the block level, allowing blocks to contain transactions whose total gas consumption exceeds the configured `MaxGas` consensus parameter. While individual transactions are validated against `MaxGas` in the ante handler, the removal of the block gas meter enables validators to include multiple transactions that collectively exceed the intended block gas limit. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability spans multiple components:
- Primary check location: `x/auth/ante/setup.go` lines 54-60
- Missing enforcement: `baseapp/abci.go` (DeliverTx processing)
- Removed functionality: Block gas meter (referenced in documentation but not implemented)

**Intended Logic:** According to the Cosmos SDK documentation and consensus parameters, the block gas meter should track cumulative gas consumption across all transactions in a block and reject transactions when the cumulative gas would exceed `ConsensusParams.Block.MaxGas`. The documentation explicitly describes this behavior: [2](#0-1) 

**Actual Logic:** The current implementation only validates that each individual transaction's gas does not exceed `MaxGas`, but does not track or enforce cumulative gas across all transactions in a block: [1](#0-0) 

The `Context` struct contains a `blockGasMeter` field that is never initialized or used: [3](#0-2) 

Evidence of removal is found in test comments: [4](#0-3) 

**Exploit Scenario:**
1. A validator/block proposer constructs a block with multiple transactions
2. Each transaction has gas limit slightly below `MaxGas` (e.g., `MaxGas - 1`)
3. Each transaction passes the individual check in `SetUpContextDecorator`
4. If the block contains N transactions, total gas = N × (MaxGas - 1)
5. The cumulative block gas far exceeds `MaxGas`, violating consensus parameters
6. All transactions are processed and committed, consuming excessive resources

**Security Failure:** This violates the consensus-critical invariant that blocks must not consume more than `MaxGas` total gas. The security property of resource limitation per block is broken, allowing validators to force nodes to process arbitrarily large amounts of computation per block (limited only by transaction count and byte size constraints).

## Impact Explanation

**Affected Processes:**
- Block validation and processing across all full nodes
- Network resource consumption and throughput
- Consensus parameter enforcement

**Severity:**
- Validators can force nodes to process blocks with gas consumption far exceeding the configured limit
- This increases CPU, memory, and I/O consumption beyond designed parameters
- Network nodes must process transactions beyond the intended `MaxGas` limit
- This can lead to increased block times, node performance degradation, and potential DOS conditions
- The consensus parameters become effectively meaningless for gas limiting

**System Impact:**
This matches the in-scope impact definition: "Causing network processing nodes to process transactions from the mempool beyond set parameters" (Medium severity). While it doesn't immediately cause fund loss or chain halt, it violates critical resource limitation guarantees and can degrade network performance significantly.

## Likelihood Explanation

**Trigger Conditions:**
- Any validator/block proposer can exploit this during their proposal turn
- No special conditions or timing required
- Can be triggered repeatedly in normal network operation

**Exploitation Frequency:**
- High likelihood: Any malicious or compromised validator can trigger this
- In a network with N validators, each validator proposes approximately 1/N of blocks
- A single malicious validator could consistently create oversized blocks when it's their turn to propose
- Even unintentional bugs in custom block construction logic could trigger this

**Realistic Scenario:**
This is highly likely to be exploited or accidentally triggered because:
1. The missing validation is not obvious to developers
2. Block proposers have full control over transaction selection
3. No runtime checks prevent this condition
4. The removed block gas meter means existing tooling won't detect the issue

## Recommendation

Restore block-level gas metering to track cumulative gas consumption across all transactions in a block:

1. Add a `BlockGasMeter()` accessor method to the `Context` type
2. Initialize a block gas meter in `BeginBlock` with limit set to `ConsensusParams.Block.MaxGas`
3. After each `DeliverTx`, consume gas from the block gas meter:
   ```go
   ctx.BlockGasMeter().ConsumeGas(
       ctx.GasMeter().GasConsumedToLimit(),
       "block gas meter",
   )
   ```
4. Check the block gas meter before processing each transaction and reject if it would exceed the limit
5. Re-enable the commented-out `TestMaxBlockGasLimits` test to verify the fix

This restores the original Cosmos SDK behavior that was documented but removed from the codebase.

## Proof of Concept

**File:** `baseapp/deliver_tx_test.go`

**Test Function:** Add `TestBlockGasLimitBypass` after the existing gas limit tests (around line 753)

**Setup:**
1. Create a BaseApp with consensus params setting `MaxGas = 100`
2. Configure ante handler to grant exactly the gas requested by transactions
3. Set up a simple message router that consumes the specified gas

**Trigger:**
1. Begin a new block with the configured consensus params
2. Deliver first transaction with `gas = 60` (less than MaxGas)
   - This should succeed as 60 < 100
3. Deliver second transaction with `gas = 60`
   - This should succeed individually as 60 < 100
   - But cumulative gas is now 120, exceeding MaxGas of 100
4. Deliver third transaction with `gas = 60`
   - Cumulative gas now 180, far exceeding limit

**Observation:**
All three transactions succeed and are committed, even though the cumulative block gas (180) far exceeds the configured `MaxGas` (100). The test demonstrates that:
- Each individual transaction passes the `setup.go` check
- No cumulative gas tracking occurs
- The block gas limit is effectively bypassed
- Total gas consumed is 180% of the configured maximum

This violates the consensus parameter invariant and proves the vulnerability. In a properly functioning system, the second or third transaction should be rejected due to block gas limit exceeded.

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

**File:** types/context.go (L41-41)
```go
	blockGasMeter     GasMeter
```

**File:** baseapp/deliver_tx_test.go (L1144-1144)
```go
	// removed the block gas exceeded because of removal of block gas meter, gasWanted < max block gas is still fulfilled by various other checks
```
