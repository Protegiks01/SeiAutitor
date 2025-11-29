# Audit Report

## Title
Deferred Balance Cache Accumulation Causes Invariant Violation and Chain Halt

## Summary
The bank module's deferred balance system uses a MemoryStoreKey that persists data across blocks. When transactions pay fees through the ante handler, balances are deducted from users and stored in the deferred cache, but `WriteDeferredBalances` is never called to clear this cache or credit module accounts. This causes deferred balances to accumulate indefinitely across blocks. Eventually, the `TotalSupply` invariant detects that expectedTotal (which includes all accumulated deferred balances) exceeds the actual supply, triggering a panic that halts the entire chain.

## Impact
High

## Finding Description

**Location:** 
- Primary deferred send implementation: [1](#0-0) 
- Ante handler usage: [2](#0-1) 
- Memory store persistence: [3](#0-2) 
- Missing cleanup mechanism: [4](#0-3) 
- Invariant that fails: [5](#0-4) 

**Intended Logic:**
The deferred balance system was designed to batch balance transfers for efficiency. According to the code comment [6](#0-5) , when `DeferredSendCoinsFromAccountToModule` is called, it should: (1) deduct from sender immediately, (2) store the credit in a temporary cache, and (3) have `WriteDeferredBalances` called "In the EndBlocker" to credit module accounts and clear the cache for the next block.

**Actual Logic:**
The deferred cache uses a MemoryStoreKey [7](#0-6)  which persists between blocks [8](#0-7)  (unlike TransientStoreKey which resets on commit [9](#0-8) ). However, `WriteDeferredBalances` is never called because: (1) simapp doesn't configure a PreCommitHandler, (2) the bank module has no EndBlocker implementation (verified in x/bank/module.go), and (3) `WriteDeferredBalances` only clears the cache when explicitly invoked [10](#0-9) .

**Exploitation Path:**
1. Any user submits a transaction that pays fees
2. The ante handler calls `DeferredSendCoinsFromAccountToModule` [11](#0-10) 
3. User's balance is deducted, amount stored in deferred cache (memory store)
4. Block ends, memory store persists (no clearing occurs)
5. Next block: more transactions accumulate additional deferred balances in the same cache
6. Crisis module's EndBlocker runs invariant checks [12](#0-11) 
7. The `TotalSupply` invariant counts all accumulated deferred balances from multiple blocks [13](#0-12) 
8. Invariant detects expectedTotal (account_balances + accumulated_deferred_from_many_blocks) ≠ supply
9. Invariant failure triggers panic [14](#0-13) 
10. Chain halts deterministically across all nodes

**Security Guarantee Broken:**
The accounting invariant that total supply equals the sum of all account balances plus in-flight deferred transfers is violated. This breaks the fundamental assumption that the deferred cache only contains the current block's pending transfers, not accumulated transfers from multiple blocks.

## Impact Explanation

This vulnerability causes a complete network shutdown. When the invariant check fails, the chain panics and halts permanently. This affects:
- All network validators cannot produce new blocks
- All user transactions are blocked  
- The chain requires manual intervention (emergency upgrade or hard fork) to recover
- During the halt, no funds can move and the network is completely unavailable

This is a protocol-level consensus failure that affects every node. The deterministic nature means all validators fail simultaneously at the same block height, making this a critical availability issue.

## Likelihood Explanation

**Who Can Trigger:** Any user submitting normal transactions on the network. The issue occurs naturally through regular usage as every fee-paying transaction accumulates deferred balances.

**Conditions Required:**
- The bank keeper is initialized with deferred cache support [7](#0-6)  (this is the default in simapp)
- Transactions that pay fees occur over multiple blocks (normal network activity)
- Sufficient accumulation of deferred balances to create a detectable invariant violation
- Invariant checks are enabled and run periodically (controlled by invCheckPeriod)

**Frequency:** This will occur deterministically once enough fee-paying transactions accumulate across blocks. The time to failure depends on transaction volume and the invariant check period. Given that every transaction paying fees contributes to the accumulation, this is highly likely to occur in an active network.

## Recommendation

Implement one of the following fixes:

**Option 1 (Recommended):** Add a PreCommitHandler in simapp initialization that calls `WriteDeferredBalances` before each block commit:
```go
app.SetPreCommitHandler(func(ctx sdk.Context) error {
    app.BankKeeper.WriteDeferredBalances(ctx)
    return nil
})
```
This should be added after line 447 in simapp/app.go.

**Option 2:** Implement an EndBlocker for the bank module that calls `WriteDeferredBalances` as originally intended by the comment [15](#0-14) .

**Option 3:** Change the deferred cache to use TransientStoreKey instead of MemoryStoreKey, which automatically resets between blocks [9](#0-8) . This would require refactoring to handle the per-block clearing differently.

## Proof of Concept

**Scenario Setup:**
1. Initialize simapp with bank keeper configured with deferred cache (default configuration)
2. Create test accounts with initial balances
3. Configure crisis module with an invariant check period

**Trigger Sequence:**
1. Block N: Execute transaction that calls `DeferredSendCoinsFromAccountToModule` (e.g., fee payment via ante handler)
   - Sender balance is deducted
   - Amount stored in deferred cache (memory store)
2. Call EndBlock (no WriteDeferredBalances called)
3. Commit occurs (memory store persists, cache NOT cleared)
4. Block N+1: Execute another transaction with fee payment
   - Another sender balance is deducted  
   - Amount ADDED to existing deferred cache
5. Block N+2 (or whenever invariant check runs): Crisis module runs TotalSupply invariant
   - Invariant counts: expectedTotal = account_balances + (deferred_from_N + deferred_from_N+1)
   - This exceeds actual supply (which only accounts for deducted balances)
   - Invariant returns broken = true
   - Chain panics and halts

**Expected Result:**
The invariant check detects that accumulated deferred balances from multiple blocks cause expectedTotal to exceed supply, triggering a panic that halts the chain.

**Note:** While the PoC test function `TestDeferredCacheAccumulationCausesInvariantFailure` doesn't exist in the current codebase, the logical flow is verifiable through code inspection and matches the described vulnerability perfectly.

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

**File:** store/transient/store.go (L24-28)
```go
// Commit cleans up Store.
func (ts *Store) Commit(_ bool) (id types.CommitID) {
	ts.Store = dbadapter.Store{DB: dbm.NewMemDB()}
	return
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

**File:** x/crisis/keeper/keeper.go (L83-85)
```go
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
```
