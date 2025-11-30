# Audit Report

## Title
Deferred Balance Cache Accumulation Causes Invariant Violation and Chain Halt

## Summary
The bank module's deferred balance system uses a MemoryStoreKey that persists data across blocks, but `WriteDeferredBalances` is never called in production to clear this cache. This causes deferred balances to accumulate indefinitely across multiple blocks. Eventually, the `TotalSupply` invariant detects that the sum of account balances plus accumulated deferred balances exceeds the actual supply, triggering a panic that halts the entire chain.

## Impact
High

## Finding Description

**Location:**
- Deferred send implementation: [1](#0-0) 
- Ante handler fee deduction: [2](#0-1) 
- Memory store configuration: [3](#0-2) 
- Invariant check: [4](#0-3) 
- Crisis module EndBlocker: [5](#0-4) 

**Intended Logic:**
The deferred balance system was designed to batch balance transfers for efficiency. According to the code comment [6](#0-5) , when `DeferredSendCoinsFromAccountToModule` is called, it should: (1) deduct from sender immediately, (2) store the credit in a temporary cache, and (3) have `WriteDeferredBalances` called "In the EndBlocker" to credit module accounts and clear the cache.

**Actual Logic:**
The deferred cache uses a MemoryStoreKey [7](#0-6)  which explicitly persists between blocks [8](#0-7)  and performs a no-op on commit [9](#0-8) . However, `WriteDeferredBalances` (which clears the cache [10](#0-9) ) is never called because: (1) simapp doesn't configure a PreCommitHandler [11](#0-10) , (2) the bank module has no EndBlocker implementation, and (3) the cache clear only occurs when `WriteDeferredBalances` is explicitly invoked.

**Exploitation Path:**
1. Any user submits a transaction that pays fees
2. The ante handler calls `DeferredSendCoinsFromAccountToModule` [12](#0-11) 
3. User's balance is deducted [13](#0-12)  and amount stored in deferred cache [14](#0-13) 
4. Block ends, MemoryStore persists (no clearing occurs)
5. Next block: more transactions accumulate additional deferred balances in the same cache
6. Crisis module's EndBlocker runs invariant checks periodically [15](#0-14) 
7. The `TotalSupply` invariant counts all accumulated deferred balances from multiple blocks [16](#0-15) 
8. Invariant detects expectedTotal (account_balances + accumulated_deferred) ≠ supply [17](#0-16) 
9. Invariant failure triggers panic [18](#0-17) 
10. Chain halts deterministically across all nodes

**Security Guarantee Broken:**
The accounting invariant that total supply equals the sum of all account balances plus current in-flight deferred transfers is violated. The system incorrectly accumulates deferred balances from multiple blocks instead of clearing them after each block, causing the invariant to detect an apparent supply mismatch.

## Impact Explanation

This vulnerability causes a complete network shutdown. When the invariant check runs and detects the accumulated deferred balances causing a supply mismatch, the chain panics and halts. This affects:
- All network validators cannot produce new blocks
- All user transactions are permanently blocked
- The chain requires manual intervention (emergency upgrade or hard fork) to recover
- During the halt, no funds can move and the network is completely unavailable

This is a protocol-level consensus failure that affects every node deterministically at the same block height, making this a critical availability issue qualifying as "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:** Any user submitting normal transactions on the network. The issue occurs naturally through regular usage as every fee-paying transaction accumulates deferred balances.

**Conditions Required:**
- The bank keeper is initialized with deferred cache support (default in simapp) [3](#0-2) 
- Transactions that pay fees occur over multiple blocks (normal network activity)
- Sufficient accumulation of deferred balances to create a detectable invariant violation
- Invariant checks are enabled and run periodically (controlled by invCheckPeriod)

**Frequency:** This will occur deterministically once enough fee-paying transactions accumulate across blocks. The time to failure depends on transaction volume and the invariant check period. Given that every transaction paying fees contributes to the accumulation, this is highly likely to occur in any active network.

## Recommendation

Implement a PreCommitHandler in simapp initialization that calls `WriteDeferredBalances` before each block commit:

```go
app.SetPreCommitHandler(func(ctx sdk.Context) error {
    app.BankKeeper.WriteDeferredBalances(ctx)
    return nil
})
```

This should be added after the SetFinalizeBlocker call in simapp/app.go (around line 447). The PreCommitHandler executes after state transitions but before commit [19](#0-18) , which is the correct time to flush deferred balances and clear the cache for the next block.

Alternative: Implement an EndBlocker for the bank module that calls `WriteDeferredBalances`, as originally intended by the code comment.

## Proof of Concept

**Setup:**
1. Initialize simapp with default configuration (bank keeper with deferred cache)
2. Create test accounts with initial balances
3. Configure crisis module with invCheckPeriod = 5

**Action:**
1. Block N: Execute transaction with fee payment
   - `DeductFees` called → `DeferredSendCoinsFromAccountToModule` executed
   - User balance deducted, amount stored in deferred cache (MemoryStore)
2. Call `EndBlock` (no `WriteDeferredBalances` called)
3. `Commit` occurs (MemoryStore persists, cache NOT cleared)
4. Block N+1: Execute another transaction with fee payment
   - Another balance deducted, amount ADDED to existing deferred cache
5. Repeat for multiple blocks
6. Block N+5: Crisis module EndBlocker runs TotalSupply invariant
   - Invariant counts: expectedTotal = account_balances + accumulated_deferred_from_all_blocks
   - expectedTotal > supply (module accounts never credited)
   - Invariant returns broken = true

**Result:**
Chain panics with error message from [18](#0-17)  indicating invariant broken, halting all block production.

## Notes

The vulnerability exists because of a mismatch between the intended design (documented in code comments suggesting EndBlocker usage) and the actual implementation (no mechanism to call `WriteDeferredBalances`). The use of MemoryStoreKey instead of TransientStoreKey [20](#0-19)  compounds the issue by persisting data across blocks. This is a critical implementation gap in the default simapp configuration.

### Citations

**File:** x/bank/keeper/keeper.go (L404-407)
```go
// DeferredSendCoinsFromAccountToModule transfers coins from an AccAddress to a ModuleAccount.
// It deducts the balance from an accAddress and stores the balance in a mapping for ModuleAccounts.
// In the EndBlocker, it will then perform one deposit for each module account.
// It will panic if the module account does not exist.
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

**File:** x/auth/ante/fee.go (L203-214)
```go
func DeductFees(bankKeeper types.BankKeeper, ctx sdk.Context, acc types.AccountI, fees sdk.Coins) error {
	if !fees.IsValid() {
		return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFee, "invalid fee amount: %s", fees)
	}

	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, err.Error())
	}

	return nil
}
```

**File:** simapp/app.go (L230-230)
```go
	memKeys := sdk.NewMemoryStoreKeys(capabilitytypes.MemStoreKey, "testingkey", banktypes.DeferredCacheStoreKey)
```

**File:** simapp/app.go (L264-266)
```go
	app.BankKeeper = bankkeeper.NewBaseKeeperWithDeferredCache(
		appCodec, keys[banktypes.StoreKey], app.AccountKeeper, app.GetSubspace(banktypes.ModuleName), app.ModuleAccountAddrs(), memKeys[banktypes.DeferredCacheStoreKey],
	)
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

**File:** x/crisis/keeper/keeper.go (L83-85)
```go
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
```

**File:** baseapp/abci.go (L379-383)
```go
	if app.preCommitHandler != nil {
		if err := app.preCommitHandler(app.stateToCommit.ctx); err != nil {
			panic(fmt.Errorf("error when executing commit handler: %s", err))
		}
	}
```

**File:** store/transient/store.go (L24-28)
```go
// Commit cleans up Store.
func (ts *Store) Commit(_ bool) (id types.CommitID) {
	ts.Store = dbadapter.Store{DB: dbm.NewMemDB()}
	return
}
```
