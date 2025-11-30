# Audit Report

## Title
Race Condition in CheckTx Allows Duplicate Nonce Transactions to Enter Mempool

## Summary
A race condition exists in concurrent CheckTx execution that allows multiple transactions with identical sequence numbers (nonces) from the same account to pass validation and enter the mempool simultaneously. The sequence validation and increment operations lack atomic synchronization across concurrent CheckTx calls.

## Impact
Low

## Finding Description

**Location:**
- Primary: `IncrementSequenceDecorator` in [1](#0-0) 
- Sequence validation: `SigVerificationDecorator` in [2](#0-1) 
- Cache context creation: [3](#0-2) 
- CheckTx entry point: [4](#0-3) 

**Intended Logic:**
The sequence number system should ensure only one transaction per sequence number from each account can be accepted into the mempool. The `checkState` tracks sequence numbers across CheckTx calls, and `IncrementSequenceDecorator` increments the sequence to prevent replay attacks. The design assumes atomic read-validate-increment-write operations.

**Actual Logic:**
When concurrent CheckTx calls execute for the same account, each creates an isolated cached context that reads from the shared checkState. The vulnerability occurs because:

1. Thread A calls `getContextForTx` which acquires `state.mtx.RLock()` to read the context, then releases it [5](#0-4) 
2. Thread A calls `cacheTxContext` to create a cache layer on top of checkState [3](#0-2) 
3. Thread B (concurrently) also reads the context and creates its own cache layer
4. Both threads read account with sequence=0 from checkState
5. Both validate signature against sequence=0 (passes for both)
6. Both increment sequence to 1 in their respective cache layers
7. Both call `msCache.Write()` to write sequence=1 back to checkState [6](#0-5) 
8. Result: checkState has sequence=1, but TWO transactions with sequence=0 were accepted

The `checkTxStateLock` [7](#0-6)  only protects initialization of checkState, not the CheckTx execution itself. The `state.mtx` lock is released immediately after reading the context, leaving the subsequent operations unprotected.

**Exploitation Path:**
1. Attacker creates two different transactions (tx1, tx2) with different content (different hashes) but identical sequence=0 from the same account
2. Submits both transactions concurrently to a node (e.g., via two simultaneous RPC calls)
3. Both CheckTx calls execute in parallel, race condition occurs during sequence validation
4. Both pass `SigVerificationDecorator` (both read sequence=0 from checkState)
5. Both pass `IncrementSequenceDecorator` (non-atomic increment in separate caches)
6. Both enter mempool because mempool deduplication is hash-based, not nonce-based [8](#0-7) 
7. During block execution (DeliverTx), only one succeeds; the other fails with sequence mismatch

**Security Guarantee Broken:**
The invariant that "only one transaction per sequence number per account exists in the mempool at any time" is violated, allowing mempool pollution.

## Impact Explanation

This vulnerability allows mempool pollution where multiple transactions with duplicate nonces coexist in the mempool. The consequences include:

1. **Resource Waste**: Nodes validate, store, and propagate invalid transactions that will ultimately fail in DeliverTx
2. **Mempool Space Reduction**: Duplicate-nonce transactions consume mempool slots, reducing space for legitimate transactions  
3. **Network Bandwidth**: Invalid transactions are propagated across the network unnecessarily

This directly matches the Low severity impact: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - nodes process and store multiple transactions for the same nonce when design parameters dictate only one should be valid.

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger**: Any user with an account can exploit this by submitting concurrent transactions
- **Prerequisites**: Only requires submitting multiple transactions with the same nonce concurrently - no special privileges, no complex setup
- **Frequency**: Can occur naturally during normal network operation whenever transactions arrive concurrently, which is common in high-throughput scenarios
- **Cost**: Attacker must pay gas fees for each transaction, but even failed transactions consume network resources during CheckTx and mempool propagation

The vulnerability is exploitable because CheckTx is explicitly designed to handle concurrent requests for throughput, yet no synchronization protects the sequence number validation flow. The codebase has OCC (Optimistic Concurrency Control) for DeliverTx but explicitly does NOT apply it to CheckTx [9](#0-8) .

## Recommendation

Implement per-account locking around sequence number validation and increment operations:

**Option 1: Per-Account Lock Manager**
Add a lock manager to `IncrementSequenceDecorator` that acquires per-account locks before reading/incrementing sequence numbers, ensuring atomicity of the read-check-increment-write sequence across concurrent CheckTx calls.

**Option 2: Extended CheckTx State Locking**
Extend the existing `checkTxStateLock` to protect the entire CheckTx execution path per account, or implement per-account synchronization at the CheckTx entry point to serialize CheckTx operations for the same account.

**Option 3: Sequence Check in Cached Context**
After `msCache.Write()`, re-read the checkState sequence and verify it matches expectations. If a race occurred (another transaction incremented it), reject the current transaction.

## Proof of Concept

The report provides a conceptual PoC test in `baseapp/deliver_tx_test.go`:

**Setup:**
1. Initialize test app with an account at sequence=0
2. Create two different transactions (tx1, tx2) from the same account, both with sequence=0
3. Ensure different message content so transaction hashes differ

**Action:**
Launch two goroutines that simultaneously call `CheckTx` with tx1 and tx2

**Expected Result:**
Both CheckTx calls return success (Code=0), demonstrating that both duplicate-nonce transactions were accepted into the mempool. The checkState sequence is only incremented to 1 (not 2), proving the race condition allowed both to read the initial sequence=0 and pass validation.

## Notes

The vulnerability exists because the cache-based state access pattern creates isolated cache branches [10](#0-9)  that don't synchronize sequence reads across concurrent executions. While individual cache write operations use mutex protection [11](#0-10) , this doesn't prevent the TOCTOU (Time-Of-Check-Time-Of-Use) race in the complete read-check-increment-write sequence. The mempool's hash-based deduplication cannot prevent different transactions with identical nonces from coexisting when they have different transaction hashes.

### Citations

**File:** x/auth/ante/sigverify.go (L269-278)
```go
		// Check account sequence number.
		if sig.Sequence != acc.GetSequence() {
			params := svd.ak.GetParams(ctx)
			if !params.GetDisableSeqnoCheck() {
				return ctx, sdkerrors.Wrapf(
					sdkerrors.ErrWrongSequence,
					"account sequence mismatch, expected %d, got %d", acc.GetSequence(), sig.Sequence,
				)
			}
		}
```

**File:** x/auth/ante/sigverify.go (L352-369)
```go
func (isd IncrementSequenceDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
	}

	// increment sequence of all signers
	for _, addr := range sigTx.GetSigners() {
		acc := isd.ak.GetAccount(ctx, addr)
		if err := acc.SetSequence(acc.GetSequence() + 1); err != nil {
			panic(err)
		}

		isd.ak.SetAccount(ctx, acc)
	}

	return next(ctx, tx, simulate)
}
```

**File:** baseapp/baseapp.go (L168-168)
```go
	checkTxStateLock *sync.RWMutex
```

**File:** baseapp/baseapp.go (L834-850)
```go
// cacheTxContext returns a new context based off of the provided context with
// a branched multi-store.
func (app *BaseApp) cacheTxContext(ctx sdk.Context, checksum [32]byte) (sdk.Context, sdk.CacheMultiStore) {
	ms := ctx.MultiStore()
	// TODO: https://github.com/cosmos/cosmos-sdk/issues/2824
	msCache := ms.CacheMultiStore()
	if msCache.TracingEnabled() {
		msCache = msCache.SetTracingContext(
			sdk.TraceContext(
				map[string]interface{}{
					"txHash": fmt.Sprintf("%X", checksum),
				},
			),
		).(sdk.CacheMultiStore)
	}

	return ctx.WithMultiStore(msCache), msCache
```

**File:** baseapp/baseapp.go (L978-979)
```go
		// Dont need to validate in checkTx mode
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
```

**File:** baseapp/baseapp.go (L998-998)
```go
		msCache.Write()
```

**File:** baseapp/abci.go (L209-231)
```go
func (app *BaseApp) CheckTx(ctx context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTxV2, error) {
	defer telemetry.MeasureSince(time.Now(), "abci", "check_tx")

	var mode runTxMode

	switch {
	case req.Type == abci.CheckTxType_New:
		mode = runTxModeCheck

	case req.Type == abci.CheckTxType_Recheck:
		mode = runTxModeReCheck

	default:
		panic(fmt.Sprintf("unknown RequestCheckTx type: %s", req.Type))
	}

	sdkCtx := app.getContextForTx(mode, req.Tx)
	tx, err := app.txDecoder(req.Tx)
	if err != nil {
		res := sdkerrors.ResponseCheckTx(err, 0, 0, app.trace)
		return &abci.ResponseCheckTxV2{ResponseCheckTx: &res}, err
	}
	gInfo, result, _, priority, pendingTxChecker, expireTxHandler, txCtx, err := app.runTx(sdkCtx, mode, tx, sha256.Sum256(req.Tx))
```

**File:** baseapp/state.go (L37-41)
```go
func (st *state) Context() sdk.Context {
	st.mtx.RLock()
	defer st.mtx.RUnlock()
	return st.ctx
}
```

**File:** docs/basics/tx-lifecycle.md (L117-127)
```markdown
The **mempool** serves the purpose of keeping track of transactions seen by all full-nodes.
Full-nodes keep a **mempool cache** of the last `mempool.cache_size` transactions they have seen, as a first line of
defense to prevent replay attacks. Ideally, `mempool.cache_size` is large enough to encompass all
of the transactions in the full mempool. If the the mempool cache is too small to keep track of all
the transactions, `CheckTx` is responsible for identifying and rejecting replayed transactions.

Currently existing preventative measures include fees and a `sequence` (nonce) counter to distinguish
replayed transactions from identical but valid ones. If an attacker tries to spam nodes with many
copies of a `Tx`, full-nodes keeping a mempool cache will reject identical copies instead of running
`CheckTx` on all of them. Even if the copies have incremented `sequence` numbers, attackers are
disincentivized by the need to pay fees.
```

**File:** store/cachemulti/store.go (L142-147)
```go
func (cms Store) Write() {
	cms.db.Write()
	for _, store := range cms.stores {
		store.Write()
	}
}
```

**File:** store/cachekv/store.go (L101-103)
```go
func (store *Store) Write() {
	store.mtx.Lock()
	defer store.mtx.Unlock()
```
