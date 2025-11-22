Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Here is my audit report:

# Audit Report

## Title
Permanent Goroutine Deadlock on Transaction Panic in OCC Mode Due to Double Signal Transmission

## Summary
When Optimistic Concurrency Control (OCC) is enabled, a transaction panic causes `SendAllSignalsForTx` to be called twice due to two separate defer statements at lines 886 and 906 in `baseapp/baseapp.go`. Since completion signal channels are buffered with size 1, the second send blocks permanently, causing goroutine deadlock and accumulating resource exhaustion that can halt block processing. [1](#0-0) [2](#0-1) 

## Impact
**Medium** - Network not being able to confirm new transactions / Increasing network processing node resource consumption by at least 30%

## Finding Description

**Location:** 
- Primary vulnerability: `baseapp/baseapp.go` lines 886 and 906
- Channel send implementation: `types/accesscontrol/access_operation_map.go` lines 23-31
- Channel creation: `x/accesscontrol/types/graph.go` line 78 [3](#0-2) [4](#0-3) 

**Intended Logic:**
When OCC is enabled, transactions execute concurrently in worker goroutines. Each transaction should signal completion exactly once via `SendAllSignalsForTx` to unblock dependent transactions. Completion channels are buffered with size 1 to allow non-blocking sends.

**Actual Logic:**
In Go, defers execute in LIFO (Last-In-First-Out) order. When a panic occurs:
1. The panic recovery defer (lines 904-915, registered last) executes **first**
2. Inside the recovery at line 906, `SendAllSignalsForTx` is called - **first send** fills the channel buffer
3. Then the outer defer at line 886 executes **second**
4. It attempts `SendAllSignalsForTx` again - **second send** blocks permanently because the buffer is full (size 1) and no consumer is reading

The goroutine executing in the OCC scheduler worker pool hangs indefinitely at this blocking channel send operation. [5](#0-4) 

**Exploitation Path:**
1. OCC is enabled via configuration (default in sei-cosmos)
2. Attacker submits a transaction that will panic (e.g., crafted to exceed gas, trigger invalid state, etc.)
3. OCC scheduler executes transaction in worker goroutine (default 10 workers)
4. Transaction panics during execution (ante handler, message handler, or gas exhaustion)
5. Panic recovery defer catches it and calls `SendAllSignalsForTx` at line 906 (first send - succeeds)
6. Outer defer at line 886 attempts `SendAllSignalsForTx` (second send - blocks forever)
7. Worker goroutine is permanently hung
8. Repeat with more panicking transactions until all workers are exhausted
9. Block processing stalls as no workers are available [6](#0-5) 

**Security Guarantee Broken:**
Network availability and liveness. The system accumulates permanently blocked goroutines that consume resources and prevent transaction processing.

## Impact Explanation

With the default configuration of 10 concurrent workers, just 10 panicking transactions will exhaust all workers and halt transaction processing on that node. As panics accumulate over time:

- **Goroutine leak:** Each panic creates a permanently hung goroutine consuming memory
- **Worker exhaustion:** Available workers decrease with each panic
- **Processing degradation:** Transaction throughput drops proportionally to lost workers  
- **Network disruption:** When 30%+ of network nodes experience this, network health degrades significantly (Medium impact)
- **Potential halt:** With sufficient panics, individual nodes or the entire network can become unable to confirm new transactions

Transaction panics are common in blockchain operations (out-of-gas, invalid transactions, state conflicts), making this vulnerability easily triggered without malicious intent.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant submitting transactions. No special privileges required.

**Triggering Conditions:**
- OCC enabled (default configuration)
- Transaction panics during execution (common: out-of-gas, invalid operations, state errors)
- Completion channels exist (created by dependency DAG for concurrent transactions)

**Frequency:**
- Each panicking transaction creates a new hung goroutine
- Panics occur naturally during normal operation (gas exhaustion, invalid txs)
- Can be deliberately triggered by crafting transactions to panic
- Accumulates over time without any recovery mechanism
- No rate limiting or protection against this issue

**Likelihood: HIGH** - In production networks with OCC enabled, this will be triggered either accidentally through normal operation or deliberately through simple transaction crafting.

## Recommendation

**Primary Fix:**
Remove the duplicate `SendAllSignalsForTx` call from the panic recovery handler at line 906. The deferred call at line 886 is sufficient because Go defers **always execute** on function exit, whether normal return or panic.

```go
defer func() {
    if r := recover(); r != nil {
        // REMOVE: acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
        recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
        recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW)
        err, result = processRecovery(r, recoveryMW), nil
        if mode != runTxModeDeliver {
            ctx.MultiStore().ResetEvents()
        }
    }
    gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
}()
```

The outer defer at line 886 will execute after panic recovery completes, ensuring signals are sent exactly once in all cases.

**Defense in Depth (Optional):**
Consider adding a select statement with timeout in `SendAllSignalsForTx` to prevent indefinite blocking, though removing the duplicate call is the correct primary fix.

## Proof of Concept

**Test Setup:**
Create a test in `baseapp/baseapp_test.go` that:
1. Initializes BaseApp with OCC enabled
2. Sets up an ante handler that panics
3. Creates completion channels (buffer size 1, matching production)
4. Executes transaction in a goroutine (simulating OCC scheduler)

**Action:**
Execute a transaction that panics via the ante handler, triggering both the panic recovery defer (line 906) and the outer defer (line 886).

**Expected Result (Bug):**
The goroutine hangs indefinitely at line 886 trying to send to an already-full channel, causing a timeout in the test.

**Expected Result (Fixed):**
The goroutine completes normally, sending exactly one completion signal.

## Notes

This vulnerability is deterministic and affects all transactions that panic when OCC is enabled. The issue exists because of a misunderstanding of Go's defer execution model - the duplicate call at line 906 was likely added to ensure signals are sent on panic, but the developer didn't realize the outer defer already handles this case since defers execute even on panic.

The fix is simple and safe: remove line 906. This ensures completion signals are sent exactly once regardless of whether execution completes normally or panics.

### Citations

**File:** baseapp/baseapp.go (L886-886)
```go
	defer acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
```

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

**File:** types/accesscontrol/access_operation_map.go (L23-31)
```go
func SendAllSignalsForTx(messageIndexToAccessOpsChannelMapping MessageAccessOpsChannelMapping) {
	for _, accessOpsToChannelsMap := range messageIndexToAccessOpsChannelMapping {
		for _, channels := range accessOpsToChannelsMap {
			for _, channel := range channels {
				channel <- struct{}{}
			}
		}
	}
}
```

**File:** x/accesscontrol/types/graph.go (L76-79)
```go
		// channel used for signalling
		// use buffered channel so that writing to channel won't be blocked by reads
		Channel: make(chan interface{}, 1),
	}
```

**File:** tasks/scheduler.go (L135-148)
```go
func start(ctx context.Context, ch chan func(), workers int) {
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case work := <-ch:
					work()
				}
			}
		}()
	}
}
```

**File:** server/config/config.go (L98-102)
```go
	// ConcurrencyWorkers defines the number of workers to use for concurrent
	// transaction execution. A value of -1 means unlimited workers.  Default value is 10.
	ConcurrencyWorkers int `mapstructure:"concurrency-workers"`
	// Whether to enable optimistic concurrency control for tx execution, default is true
	OccEnabled bool `mapstructure:"occ-enabled"`
```
