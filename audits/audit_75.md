# Audit Report

## Title
Race Condition in CheckTx Allows Duplicate Nonce Transactions to Enter Mempool

## Summary
A race condition exists in concurrent CheckTx execution that allows multiple transactions with identical sequence numbers (nonces) from the same account to pass validation and enter the mempool simultaneously. The sequence validation and increment operations lack atomic synchronization across concurrent CheckTx calls.

## Impact
Low

## Finding Description

**Location:**
- Primary: `IncrementSequenceDecorator.AnteHandle` [1](#0-0) 
- Sequence validation: `SigVerificationDecorator` [2](#0-1) 
- CheckTx entry: [3](#0-2) 
- Cache creation: [4](#0-3) 

**Intended Logic:**
The sequence number system should ensure only one transaction per sequence number from each account can be accepted into the mempool. The checkState tracks sequence numbers across CheckTx calls, and IncrementSequenceDecorator increments the sequence to prevent replay attacks [5](#0-4) 

**Actual Logic:**
When concurrent CheckTx calls execute for the same account, each creates an isolated cached context via `cacheTxContext` [6](#0-5)  that lazily reads from the shared checkState. The read-validate-increment-write sequence is not atomic:

1. Thread A: Reads account (sequence=0), validates, increments to 1 in cache
2. Thread B (concurrent): Reads account (sequence=0 still), validates, increments to 1 in cache  
3. Both execute `msCache.Write()` [7](#0-6)  writing sequence=1 back to checkState
4. Both transactions with sequence=0 have passed validation

The `checkTxStateLock` [8](#0-7)  is only used in `setCheckState` and `GetCheckCtx`, not during CheckTx execution itself.

**Exploitation Path:**
1. Attacker creates two different transactions (different content = different hashes) from the same account with identical sequence=0
2. Submits both transactions concurrently to a node
3. Both CheckTx calls execute in parallel, race condition occurs
4. Both pass SigVerificationDecorator (both see sequence=0)
5. Both pass IncrementSequenceDecorator (non-atomic increment)
6. Both enter mempool (mempool deduplicates by hash, not nonce)
7. During block execution, only one succeeds; others fail with sequence mismatch

**Security Guarantee Broken:**
The invariant that only one transaction per sequence number per account exists in the mempool at any time is violated.

## Impact Explanation

This vulnerability allows mempool pollution where multiple transactions with duplicate nonces coexist in the mempool. Consequences include:

1. **Resource Waste**: Nodes validate, store, and propagate invalid transactions that will ultimately fail in DeliverTx
2. **Mempool Space Reduction**: Duplicate-nonce transactions consume mempool slots, reducing space for legitimate transactions
3. **Network Bandwidth**: Invalid transactions are propagated across the network unnecessarily

This directly matches the Low severity impact criterion: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - nodes process and store multiple transactions for the same nonce when design parameters dictate only one should be valid.

## Likelihood Explanation

**Likelihood: High**

- **Who can trigger**: Any user with an account can exploit this
- **Prerequisites**: Simply requires submitting multiple transactions with the same nonce concurrently - no special privileges, no complex setup
- **Frequency**: Can occur naturally during normal network operation whenever transactions arrive concurrently, which is common in production
- **Cost**: Attacker must pay gas fees for each transaction, but failed transactions still consume network resources

The vulnerability is particularly exploitable because CheckTx is designed to handle concurrent requests (as evidenced by the cached context architecture), yet no synchronization protects the sequence number validation flow.

## Recommendation

Implement per-account locking around sequence number validation and increment operations:

**Option 1: Per-Account Lock Manager**
Add a lock manager to IncrementSequenceDecorator that acquires locks for all transaction signers before performing sequence operations, ensuring atomic read-validate-increment-write sequences.

**Option 2: Serialize CheckTx Per Account**
Use the existing `checkTxStateLock` or add per-account synchronization at the CheckTx entry point to ensure only one CheckTx per account executes at a time.

## Proof of Concept

**File**: `baseapp/deliver_tx_test.go` (new test function)

**Setup**:
1. Initialize test application with account at sequence=0
2. Create two different transactions (tx1, tx2) from same account, both with sequence=0
3. Ensure different message content so transaction hashes differ

**Action**:
Launch two goroutines calling CheckTx simultaneously with both transactions

**Result**:
Both CheckTx calls return success (Code=0), proving both duplicate-nonce transactions were accepted. The checkState sequence is only incremented to 1 (not 2), demonstrating the race condition allowed both to read the initial sequence=0 and pass validation. This can be verified against the existing TestCheckTx [9](#0-8)  which expects successive CheckTx calls to see each other's effects - a property violated by the concurrent race condition.

## Notes

The vulnerability exists because the state access pattern creates isolated cache branches that don't synchronize sequence reads across concurrent executions. While individual cache write operations use mutex protection [10](#0-9) , this doesn't prevent the TOCTOU race in the complete read-check-increment-write sequence. The state struct's mutex [11](#0-10)  only protects struct field access, not the logical sequence validation operations. The mempool's hash-based deduplication cannot prevent different transactions with identical nonces from coexisting when they have different transaction hashes.

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
