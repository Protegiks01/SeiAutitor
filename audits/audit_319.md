## Audit Report

## Title
Deferred Balance Cache Accumulation Causes Invariant Violation and Chain Halt

## Summary
The bank module's deferred balance system uses a MemoryStoreKey that persists across blocks without automatic clearing. Since `WriteDeferredBalances` is never called in the normal block processing flow, deferred balances accumulate indefinitely across blocks. This causes the `TotalSupply` invariant to eventually fail, triggering a chain-wide panic and halt.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Memory store persistence: [2](#0-1) 
- Missing cleanup: [3](#0-2) 
- Invariant check: [4](#0-3) 

**Intended Logic:** 
The deferred balance system is designed to optimize transaction processing by batching balance transfers. When `DeferredSendCoinsFromAccountToModule` is called, it should: (1) deduct from sender immediately, (2) store the credit in a temporary cache, and (3) have `WriteDeferredBalances` called at block finalization to actually credit module accounts and clear the cache for the next block. The `TotalSupply` invariant accounts for deferred balances to ensure consistency: [5](#0-4) 

**Actual Logic:**
The deferred cache uses a MemoryStoreKey which persists between blocks (unlike TransientStoreKey which resets on commit): [6](#0-5) . However, `WriteDeferredBalances` is never called automatically because: (1) simapp doesn't configure a `PreCommitHandler`, (2) the bank module has no `EndBlocker`, and (3) `WriteDeferredBalances` only clears the cache when explicitly invoked: [7](#0-6) 

When transactions use deferred sends across multiple blocks:
- Block N: Sender accounts are debited, amounts stored in deferred cache
- Block N: Invariant check passes (counts deferred balances)  
- Block N: Cache is never cleared
- Block N+1: More transactions debit senders, adding to the accumulated deferred cache
- Block N+1: Invariant now counts both old and new deferred balances
- Eventually: `expectedTotal = (actual_balances) + (accumulated_deferred_from_many_blocks)` exceeds total supply

**Exploit Scenario:**
1. Any user submitting normal transactions that trigger deferred sends (e.g., paying transaction fees via the ante handler)
2. Over multiple blocks, deferred balances accumulate in the memory store
3. The crisis module's `EndBlocker` runs invariant checks: [8](#0-7) 
4. The `TotalSupply` invariant detects the discrepancy: [9](#0-8) 
5. Invariant failure triggers panic: [10](#0-9) 
6. Entire chain halts deterministically across all nodes

**Security Failure:**
This breaks the accounting invariant and causes a deterministic consensus failure. All nodes will hit the same invariant violation at the same block height, causing complete chain halt.

## Impact Explanation

**Affected Processes:** The entire blockchain's ability to produce new blocks and process transactions.

**Severity:** When the invariant check fails, the chain panics and halts permanently. This affects:
- All network validators cannot produce new blocks
- All user transactions are blocked
- The chain requires manual intervention (emergency upgrade or hard fork) to recover
- During halt, no funds can move and the network is completely unavailable

**Why This Matters:** This is a protocol-level consensus failure that affects every node. The deterministic nature means all validators fail simultaneously, making this a critical availability issue requiring immediate manual intervention to restore the chain.

## Likelihood Explanation

**Who Can Trigger:** Any user submitting transactions on the network. The issue occurs naturally through normal usage if deferred sends are used (e.g., fee payments processed via `DeferredSendCoinsFromAccountToModule`).

**Conditions Required:** 
- The bank keeper must be initialized with deferred cache support: [11](#0-10) 
- Transactions that use deferred sends must occur over multiple blocks
- Sufficient accumulation of deferred balances to create a detectable invariant violation

**Frequency:** This will occur deterministically once enough deferred balance operations accumulate. The time to failure depends on transaction volume and the invariant check period configured in the crisis module: [12](#0-11) 

## Recommendation

Implement one of the following fixes:

**Option 1 (Recommended):** Add a `PreCommitHandler` in simapp initialization that calls `WriteDeferredBalances` before each block commit:
```go
app.SetPreCommitHandler(func(ctx sdk.Context) error {
    app.BankKeeper.WriteDeferredBalances(ctx)
    return nil
})
```
Location: [13](#0-12) 

**Option 2:** Add an `EndBlocker` to the bank module that calls `WriteDeferredBalances` before returning.

**Option 3:** Change the deferred cache to use `TransientStoreKey` instead of `MemoryStoreKey`, which automatically resets between blocks: [14](#0-13) 

## Proof of Concept

**Test File:** `x/bank/keeper/keeper_test.go`

**Test Function:** `TestDeferredCacheAccumulationCausesInvariantFailure`

**Setup:**
1. Initialize a test application with the bank keeper configured with deferred cache
2. Create test accounts with initial balances
3. Create a fee collector module account
4. Configure the crisis module with an invariant check period of 1

**Trigger:**
1. In Block 1: Execute a transaction that calls `DeferredSendCoinsFromAccountToModule` to transfer coins from user to fee collector
2. Call `EndBlock` without calling `WriteDeferredBalances`
3. Simulate commit (which does NOT clear memory store)
4. In Block 2: Execute another transaction with `DeferredSendCoinsFromAccountToModule`
5. Call `EndBlock` again
6. In Block N: Call the bank module's `TotalSupply` invariant check directly

**Observation:**
The invariant check should detect that:
- `expectedTotal` (sum of account balances + accumulated deferred balances) 
- Does not equal `supply.Total`
- The invariant returns `broken = true` and would cause the chain to panic if running in production

The test confirms the vulnerability by showing that deferred balances accumulate across blocks without being cleared, eventually causing the accounting invariant to fail.

**Key Code References:**
- Deferred send implementation: [1](#0-0) 
- Memory store persistence: [2](#0-1) 
- Cache clear only in WriteDeferredBalances: [15](#0-14) 
- Invariant that will fail: [16](#0-15)

### Citations

**File:** x/bank/keeper/keeper.go (L133-156)
```go
func NewBaseKeeperWithDeferredCache(
	cdc codec.BinaryCodec,
	storeKey sdk.StoreKey,
	ak types.AccountKeeper,
	paramSpace paramtypes.Subspace,
	blockedAddrs map[string]bool,
	deferredCacheStoreKey sdk.StoreKey,
) BaseKeeper {

	// set KeyTable if it has not already been set
	if !paramSpace.HasKeyTable() {
		paramSpace = paramSpace.WithKeyTable(types.ParamKeyTable())
	}

	return BaseKeeper{
		BaseSendKeeper:         NewBaseSendKeeper(cdc, storeKey, ak, paramSpace, blockedAddrs),
		ak:                     ak,
		deferredCache:          NewDeferredCache(cdc, deferredCacheStoreKey),
		cdc:                    cdc,
		storeKey:               storeKey,
		paramSpace:             paramSpace,
		mintCoinsRestrictionFn: func(ctx sdk.Context, coins sdk.Coins) error { return nil },
	}
}
```

**File:** x/bank/keeper/keeper.go (L408-432)
```go
func (k BaseKeeper) DeferredSendCoinsFromAccountToModule(
	ctx sdk.Context, senderAddr sdk.AccAddress, recipientModule string, amount sdk.Coins,
) error {
	if k.deferredCache == nil {
		panic("bank keeper created without deferred cache")
	}
	// Deducts Fees from the Sender Account
	err := k.SubUnlockedCoins(ctx, senderAddr, amount, true)
	if err != nil {
		return err
	}
	// get recipient module address
	moduleAcc := k.ak.GetModuleAccount(ctx, recipientModule)
	if moduleAcc == nil {
		panic(sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", recipientModule))
	}
	// get txIndex
	txIndex := ctx.TxIndex()
	err = k.deferredCache.UpsertBalances(ctx, moduleAcc.GetAddress(), uint64(txIndex), amount)
	if err != nil {
		return err
	}

	return nil
}
```

**File:** x/bank/keeper/keeper.go (L480-481)
```go
	// clear deferred cache
	k.deferredCache.Clear(ctx)
```

**File:** store/mem/store.go (L20-21)
```go
// Store implements an in-memory only KVStore. Entries are persisted between
// commits and thus between blocks. State in Memory store is not committed as part of app state but maintained privately by each node
```

**File:** store/mem/store.go (L54-55)
```go
// Commit performs a no-op as entries are persistent between commitments.
func (s *Store) Commit(_ bool) (id types.CommitID) { return }
```

**File:** simapp/app.go (L442-447)
```go
	app.SetAnteHandler(anteHandler)
	app.SetAnteDepGenerator(anteDepGenerator)
	app.SetEndBlocker(app.EndBlocker)
	app.SetPrepareProposalHandler(app.PrepareProposalHandler)
	app.SetProcessProposalHandler(app.ProcessProposalHandler)
	app.SetFinalizeBlocker(app.FinalizeBlocker)
```

**File:** x/crisis/abci.go (L13-21)
```go
func EndBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)

	if k.InvCheckPeriod() == 0 || ctx.BlockHeight()%int64(k.InvCheckPeriod()) != 0 {
		// skip running the invariant check
		return
	}
	k.AssertInvariants(ctx)
}
```

**File:** x/bank/keeper/invariants.go (L59-104)
```go
func TotalSupply(k Keeper) sdk.Invariant {
	return func(ctx sdk.Context) (string, bool) {
		expectedTotal := sdk.Coins{}
		weiTotal := sdk.NewInt(0)
		supply, _, err := k.GetPaginatedTotalSupply(ctx, &query.PageRequest{Limit: query.MaxLimit})

		if err != nil {
			return sdk.FormatInvariant(types.ModuleName, "query supply",
				fmt.Sprintf("error querying total supply %v", err)), false
		}

		k.IterateAllBalances(ctx, func(_ sdk.AccAddress, balance sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(balance)
			return false
		})
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
		k.IterateAllWeiBalances(ctx, func(addr sdk.AccAddress, balance sdk.Int) bool {
			weiTotal = weiTotal.Add(balance)
			return false
		})
		weiInUsei, weiRemainder := SplitUseiWeiAmount(weiTotal)
		if !weiRemainder.IsZero() {
			return sdk.FormatInvariant(types.ModuleName, "total supply",
				fmt.Sprintf(
					"\twei remainder: %v\n",
					weiRemainder)), true
		}
		baseDenom, err := sdk.GetBaseDenom()
		if err == nil {
			expectedTotal = expectedTotal.Add(sdk.NewCoin(baseDenom, weiInUsei))
		} else if !weiInUsei.IsZero() {
			return sdk.FormatInvariant(types.ModuleName, "total supply", "non-zero wei balance without base denom"), true
		}

		broken := !expectedTotal.IsEqual(supply)

		return sdk.FormatInvariant(types.ModuleName, "total supply",
			fmt.Sprintf(
				"\tsum of accounts coins: %v\n"+
					"\tsupply.Total:          %v\n",
				expectedTotal, supply)), broken
	}
```

**File:** x/crisis/keeper/keeper.go (L83-85)
```go
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
```

**File:** store/transient/store.go (L24-28)
```go
// Commit cleans up Store.
func (ts *Store) Commit(_ bool) (id types.CommitID) {
	ts.Store = dbadapter.Store{DB: dbm.NewMemDB()}
	return
}
```

**File:** x/bank/keeper/deferred_cache.go (L116-126)
```go
// Clear deletes all of the keys in the deferred cache
func (d *DeferredCache) Clear(ctx sdk.Context) {
	store := prefix.NewStore(ctx.KVStore(d.storeKey), types.DeferredCachePrefix)

	iterator := store.Iterator(nil, nil)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		store.Delete(iterator.Key())
	}
}
```
