# Audit Report

## Title
Deferred Balance Cache Accumulation Causes Invariant Violation and Chain Halt

## Summary
The bank module's deferred balance system accumulates fee payments across blocks without ever clearing the cache, eventually causing the TotalSupply invariant to fail and the chain to halt. The `WriteDeferredBalances` method that should clear the cache is never called in production code, despite being designed to run "In the EndBlocker" according to code comments. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Deferred cache implementation: x/bank/keeper/keeper.go (lines 408-432)
- Fee deduction entry point: x/auth/ante/fee.go (line 208)
- Invariant check: x/bank/keeper/invariants.go (lines 74-78, 97)
- Missing cleanup: No call to WriteDeferredBalances in production code

**Intended Logic:**
When `DeferredSendCoinsFromAccountToModule` is called during fee payment, it should: (1) deduct coins from the sender's account, (2) store the pending credit in a temporary cache, and (3) have `WriteDeferredBalances` called in an EndBlocker to credit module accounts and clear the cache for the next block. [2](#0-1) 

**Actual Logic:**
The deferred cache uses a MemoryStoreKey which persists data between commits and blocks [3](#0-2) , unlike TransientStoreKey which resets on each commit [4](#0-3) . However, `WriteDeferredBalances` is never called because: (1) simapp does not configure a PreCommitHandler [5](#0-4) , (2) the bank module has no EndBlocker implementation, and (3) grep search confirms `WriteDeferredBalances` only appears in test files.

**Exploitation Path:**
1. User submits a transaction with fees
2. Ante handler calls `DeductFees` which invokes `DeferredSendCoinsFromAccountToModule` [6](#0-5) 
3. User's balance is deducted, amount stored in deferred cache
4. Block commits, but MemoryStore persists (no clearing) [7](#0-6) 
5. Additional transactions in subsequent blocks accumulate more deferred balances in the same cache
6. Crisis module EndBlocker periodically runs invariant checks [8](#0-7) 
7. TotalSupply invariant iterates over all accumulated deferred balances and adds them to expectedTotal [9](#0-8) 
8. Invariant detects that expectedTotal (account_balances + accumulated_deferred_from_multiple_blocks) ≠ supply
9. Invariant returns broken=true, triggering panic [10](#0-9) 
10. Chain halts deterministically across all nodes

**Security Guarantee Broken:**
The accounting invariant that total supply equals the sum of all account balances plus current in-flight transfers is violated. The system incorrectly assumes the deferred cache only contains the current block's pending transfers, not accumulated transfers from multiple blocks.

## Impact Explanation

This vulnerability causes a complete network shutdown. When the TotalSupply invariant check fails, the crisis module triggers a panic that halts the chain. This affects:
- All network validators cannot produce new blocks
- All user transactions are blocked
- The chain requires manual intervention (emergency upgrade or governance action) to recover
- During the halt, the network is completely unavailable

This is a protocol-level consensus failure that affects every node. The deterministic nature means all validators fail simultaneously at the same block height.

## Likelihood Explanation

**Who Can Trigger:** Any user submitting normal transactions on the network. The issue occurs naturally through regular usage as every fee-paying transaction accumulates deferred balances.

**Conditions Required:**
- Bank keeper initialized with deferred cache support (default in simapp) [11](#0-10) 
- Transactions that pay fees over multiple blocks (normal network activity)
- Sufficient accumulation to create a detectable invariant violation
- Invariant checks enabled and running periodically (invCheckPeriod > 0)

**Frequency:** This will occur deterministically once enough fee-paying transactions accumulate across blocks. The time to failure depends on transaction volume and invariant check frequency. Given that every fee-paying transaction contributes to accumulation, this is inevitable in an active network.

## Recommendation

**Option 1 (Recommended):** Add a PreCommitHandler in simapp that calls `WriteDeferredBalances` before each block commit:
```go
app.SetPreCommitHandler(func(ctx sdk.Context) error {
    app.BankKeeper.WriteDeferredBalances(ctx)
    return nil
})
```

**Option 2:** Implement an EndBlocker for the bank module that calls `WriteDeferredBalances` as intended by the code comment.

**Option 3:** Change the deferred cache to use TransientStoreKey instead of MemoryStoreKey, though this requires refactoring the per-block clearing logic.

## Proof of Concept

The logical flow is verifiable through code inspection:

**Setup:**
1. Simapp initializes BankKeeper with deferred cache using MemoryStoreKey
2. Crisis module configured with invariant check period > 0

**Action:**
1. Block N: User transaction pays fees → ante handler calls `DeferredSendCoinsFromAccountToModule` → sender balance deducted, amount stored in memory store
2. Block N commits → MemoryStore Commit() is no-op, cache persists
3. Block N+1: Another user transaction pays fees → additional amount added to existing deferred cache
4. Block N+2 (when invariant runs): Crisis module calls `TotalSupply` invariant → invariant iterates deferred balances → counts accumulated balances from blocks N and N+1 → expectedTotal exceeds supply → returns broken=true

**Result:**
Chain panics and halts with error: "invariant broken: total supply" because expectedTotal (which includes all accumulated deferred balances from multiple blocks) does not equal the actual supply.

**Supporting Evidence:**
Test files demonstrate the expected behavior - `WriteDeferredBalances` must be explicitly called to credit module accounts and clear the cache, but this never happens in production code (only in tests).

## Notes

This vulnerability exists due to an implementation gap between intended design (as documented in code comments) and actual implementation (no EndBlocker or PreCommitHandler calls `WriteDeferredBalances`). The deferred balance system was correctly designed but incompletely implemented, making the chain vulnerable to deterministic halt through normal operation.

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

**File:** store/transient/store.go (L24-28)
```go
// Commit cleans up Store.
func (ts *Store) Commit(_ bool) (id types.CommitID) {
	ts.Store = dbadapter.Store{DB: dbm.NewMemDB()}
	return
}
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

**File:** x/bank/keeper/invariants.go (L74-78)
```go
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
```

**File:** x/crisis/keeper/keeper.go (L83-85)
```go
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
```
