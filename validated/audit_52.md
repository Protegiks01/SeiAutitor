# Audit Report

## Title
Race Condition in CheckTx Allows Duplicate Nonce Transactions to Enter Mempool

## Summary
A race condition exists in concurrent CheckTx execution that allows multiple transactions with identical sequence numbers from the same account to pass validation and enter the mempool. The sequence validation and increment operations lack atomic synchronization, enabling mempool pollution.

## Impact
Low

## Finding Description

**Location:**
- Primary: `x/auth/ante/sigverify.go:352-369` (IncrementSequenceDecorator)
- Validation: `x/auth/ante/sigverify.go:269-278` (SigVerificationDecorator)
- Entry point: `baseapp/abci.go:209-231` (CheckTx)
- Cache creation: `baseapp/baseapp.go:834-850` (cacheTxContext) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:**
The sequence number system ensures only one transaction per sequence number from each account can be accepted into the mempool, preventing replay attacks as documented. [5](#0-4) 

**Actual Logic:**
When concurrent CheckTx calls execute for the same account, each creates an isolated cached context via `cacheTxContext` that reads from the shared checkState without synchronization: [6](#0-5) 

1. Thread A: Creates cache, reads account (sequence=N), validates sequence=N, increments to N+1 in cache
2. Thread B (concurrent): Creates cache, reads account (sequence=N still), validates sequence=N, increments to N+1 in cache  
3. Both execute `msCache.Write()` writing sequence=N+1 back to checkState [7](#0-6) 

4. Result: Both transactions with sequence=N passed validation, checkState shows N+1 (not N+2)

The `checkTxStateLock` is only used in `setCheckState` and `GetCheckCtx`, not during CheckTx execution: [8](#0-7) [9](#0-8) 

The comment confirms Tendermint only holds mempool lock during Commit, not CheckTx: [10](#0-9) 

**Exploitation Path:**
1. Attacker creates two transactions with different content (different hashes) but identical sequence=N from the same account
2. Submits both transactions concurrently to a node
3. Both CheckTx calls execute in parallel, creating separate cached contexts
4. Both read sequence=N from checkState, validate, and increment to N+1 in their caches
5. Both write back sequence=N+1 to checkState (last write wins, no atomic increment)
6. Both enter mempool (mempool deduplicates by hash, not sequence)
7. During block execution, only one succeeds; the other fails with sequence mismatch

**Security Guarantee Broken:**
The invariant that only one transaction per sequence number per account exists in the mempool at any time is violated.

## Impact Explanation

This vulnerability enables mempool pollution where multiple transactions with duplicate nonces coexist temporarily in the mempool:

1. **Resource Waste**: Nodes validate, store, and propagate transactions that will ultimately fail in DeliverTx
2. **Mempool Space Consumption**: Duplicate-nonce transactions consume mempool slots, reducing space for legitimate transactions
3. **Network Bandwidth**: Invalid transactions are propagated across the network unnecessarily

This directly matches the Low severity impact criterion: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - nodes process and store multiple transactions for the same sequence number when design parameters dictate only one should be valid per the transaction lifecycle documentation.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Who can trigger**: Any user with an account
- **Prerequisites**: Submit multiple transactions with the same nonce concurrently - no special privileges required
- **Frequency**: Can occur naturally during normal operation when transactions arrive concurrently, which is common in production
- **Cost**: Attacker pays gas fees for each transaction, but failed transactions still consume network resources before rejection

The vulnerability is exploitable because CheckTx is designed to handle concurrent requests (evidenced by the cached context architecture), yet no synchronization protects the sequence number validation flow.

## Recommendation

Implement per-account locking around sequence number validation and increment operations:

**Option 1: Per-Account Lock Manager**
Add a lock manager to `IncrementSequenceDecorator` that acquires locks for all transaction signers before performing sequence operations, ensuring atomic read-validate-increment-write sequences.

**Option 2: Serialize CheckTx Per Account**
Add per-account synchronization at the CheckTx entry point to ensure only one CheckTx per account executes at a time, preventing concurrent reads of the same account's sequence number.

**Option 3: Optimistic Concurrency Control**
Implement version checking where the sequence write fails if the base sequence has changed since the read, forcing a retry.

## Proof of Concept

**Conceptual Test** (to be added to `baseapp/deliver_tx_test.go`):

**Setup**:
1. Initialize test application with account at sequence=0 using existing test infrastructure [11](#0-10) 

2. Create two different transactions (tx1, tx2) from same account, both with sequence=0
3. Ensure different message content so transaction hashes differ

**Action**:
Launch two goroutines calling `CheckTx` simultaneously with both transactions, exploiting the race window between account read and sequence write.

**Expected Result**:
Both CheckTx calls return success (Code=0), proving both duplicate-nonce transactions were accepted. The checkState sequence is only incremented to 1 (not 2), demonstrating the race condition allowed both to read the initial sequence=0 and pass validation.

## Notes

The vulnerability exists because the state access pattern creates isolated cache branches that don't synchronize sequence reads across concurrent executions. While individual cache write operations use mutex protection, this doesn't prevent the TOCTOU (Time-of-Check-Time-of-Use) race in the complete read-check-increment-write sequence: [12](#0-11) 

The state struct's mutex only protects struct field access, not the logical sequence validation operations across concurrent CheckTx invocations: [13](#0-12) 

The mempool's hash-based deduplication cannot prevent different transactions with identical nonces from coexisting when they have different transaction hashes.

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

**File:** baseapp/abci.go (L391-392)
```go
	// NOTE: This is safe because Tendermint holds a lock on the mempool for
	// Commit. Use the header from this latest block.
```

**File:** baseapp/baseapp.go (L168-168)
```go
	checkTxStateLock *sync.RWMutex
```

**File:** baseapp/baseapp.go (L559-563)
```go
func (app *BaseApp) setCheckState(header tmproto.Header) {
	ms := app.cms.CacheMultiStore()
	ctx := sdk.NewContext(ms, header, true, app.logger).WithMinGasPrices(app.minGasPrices)
	app.checkTxStateLock.Lock()
	defer app.checkTxStateLock.Unlock()
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

**File:** baseapp/baseapp.go (L945-945)
```go
		anteCtx, msCache = app.cacheTxContext(ctx, checksum)
```

**File:** baseapp/baseapp.go (L998-998)
```go
		msCache.Write()
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

**File:** baseapp/deliver_tx_test.go (L1517-1576)
```go
func TestCheckTx(t *testing.T) {
	// This ante handler reads the key and checks that the value matches the current counter.
	// This ensures changes to the kvstore persist across successive CheckTx.
	counterKey := []byte("counter-key")

	anteOpt := func(bapp *BaseApp) { bapp.SetAnteHandler(anteHandlerTxTest(t, capKey1, counterKey)) }
	routerOpt := func(bapp *BaseApp) {
		// TODO: can remove this once CheckTx doesnt process msgs.
		bapp.Router().AddRoute(sdk.NewRoute(routeMsgCounter, func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
			return &sdk.Result{}, nil
		}))
	}

	pchOpt := func(bapp *BaseApp) {
		bapp.SetPreCommitHandler(func(ctx sdk.Context) error {
			return nil
		})
	}

	app := setupBaseApp(t, anteOpt, routerOpt, pchOpt)

	nTxs := int64(5)
	app.InitChain(context.Background(), &abci.RequestInitChain{})

	// Create same codec used in txDecoder
	codec := codec.NewLegacyAmino()
	registerTestCodec(codec)

	for i := int64(0); i < nTxs; i++ {
		tx := newTxCounter(i, 0) // no messages
		txBytes, err := codec.Marshal(tx)
		require.NoError(t, err)
		r, _ := app.CheckTx(context.Background(), &abci.RequestCheckTx{Tx: txBytes})
		require.True(t, r.IsOK(), fmt.Sprintf("%v", r))
	}

	checkStateStore := app.checkState.ctx.KVStore(capKey1)
	storedCounter := getIntFromStore(checkStateStore, counterKey)

	// Ensure AnteHandler ran
	require.Equal(t, nTxs, storedCounter)

	// If a block is committed, CheckTx state should be reset.
	header := tmproto.Header{Height: 1}
	app.setDeliverState(header)
	app.checkState.ctx = app.checkState.ctx.WithHeaderHash([]byte("hash"))
	app.BeginBlock(app.deliverState.ctx, abci.RequestBeginBlock{Header: header, Hash: []byte("hash")})

	require.NotEmpty(t, app.checkState.ctx.HeaderHash())

	app.EndBlock(app.deliverState.ctx, abci.RequestEndBlock{})
	require.Empty(t, app.deliverState.ctx.MultiStore().GetEvents())

	app.SetDeliverStateToCommit()
	app.Commit(context.Background())

	checkStateStore = app.checkState.ctx.KVStore(capKey1)
	storedBytes := checkStateStore.Get(counterKey)
	require.Nil(t, storedBytes)
}
```

**File:** store/cachekv/store.go (L101-103)
```go
func (store *Store) Write() {
	store.mtx.Lock()
	defer store.mtx.Unlock()
```

**File:** baseapp/state.go (L9-13)
```go
type state struct {
	ms  sdk.CacheMultiStore
	ctx sdk.Context
	mtx *sync.RWMutex
}
```
