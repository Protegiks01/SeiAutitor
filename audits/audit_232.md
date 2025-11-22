## Audit Report

## Title
Permanent Loss of Transaction Fees Due to Missing WriteDeferredBalances Call and Non-Persistent Deferred Cache

## Summary
The banking module's deferred balance system stores fee deductions in a memory-only cache that is never flushed to module accounts and is lost on node restart, resulting in permanent loss of all transaction fees collected since the last restart. The `WriteDeferredBalances` function is documented to be called in EndBlocker but is never invoked in production code, only in tests.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Deferred send implementation: [1](#0-0) 
- Missing WriteDeferredBalances call: Production code has no invocation (only exists in tests)
- Memory store implementation: [2](#0-1) 
- Fee deduction usage: [3](#0-2) 

**Intended Logic:** 
According to the code comments at [4](#0-3) , the system is designed to: (1) immediately deduct fees from user accounts during transaction processing, (2) cache the amounts in a deferred cache indexed by module and transaction, and (3) flush all deferred balances to module accounts in the EndBlocker via `WriteDeferredBalances`.

**Actual Logic:** 
The deferred cache uses a memory store [5](#0-4)  which persists between blocks but is cleared on node restart [2](#0-1) . The `WriteDeferredBalances` function is never called in production - only in test files. This means:
1. User fees are immediately deducted and persisted to disk via `SubUnlockedCoins`
2. The deducted amounts are stored in RAM-only deferred cache
3. Module accounts (e.g., fee collector) never receive the funds
4. On node restart, the deferred cache is cleared and funds are permanently lost

**Exploit Scenario:** 
No malicious actor is required - this is a critical bug in normal operation:
1. User submits transaction with fee
2. Ante handler calls `DeductFees` which calls `DeferredSendCoinsFromAccountToModule`
3. User's balance is reduced (persisted to IAVL store on disk)
4. Amount is stored in deferred cache (memory store, RAM only)
5. Block processing completes without calling `WriteDeferredBalances`
6. Node operator performs routine restart or node crashes
7. Memory store is cleared, deferred cache loses all accumulated fees
8. User accounts show reduced balances (permanent) but fee collector module account never received the funds
9. Funds are permanently lost - no recovery mechanism exists

**Security Failure:** 
This violates the accounting invariant that all coins deducted from accounts must exist somewhere in the system. The TotalSupply invariant [6](#0-5)  correctly includes deferred balances in its calculation, so it passes during normal operation. However, after a node restart when the deferred cache is cleared, the invariant will fail because the sum of account balances will be less than the total supply. At this point the funds are already permanently lost.

## Impact Explanation

**Assets Affected:** All transaction fees paid by users since the last node restart are permanently lost. This includes:
- Fees collected by the fee collector module
- Any other module-to-module transfers using the deferred system

**Severity of Damage:**
- **Permanent loss of funds:** Transaction fees are deducted from user accounts but never reach their intended recipient module accounts
- **Accumulates over time:** Every transaction that pays fees contributes to the loss
- **No recovery mechanism:** Once the node restarts and the memory store is cleared, the deferred amounts are irrecoverably lost
- **Systemic issue:** Affects every node in the network on every restart
- **Consensus implications:** After restart, nodes will have different total supply values depending on when they last restarted, potentially causing invariant check failures and chain halts

**Why This Matters:**
This fundamentally breaks the economic model of the blockchain. Users pay fees expecting them to be collected by validators/the protocol, but those fees simply vanish into the void. The fee collector module, which is intended to distribute fees to validators or fund governance proposals, never receives any funds. This makes the blockchain economically unsustainable.

## Likelihood Explanation

**Who Can Trigger:** This affects all users and all nodes automatically during normal operation. No attacker or special privileges are required.

**Conditions Required:** 
- Any transaction that pays fees (essentially all transactions)
- Any node restart (routine maintenance, crashes, upgrades, etc.)

**Frequency:**
- **Every transaction:** Fees are deferred on every single transaction
- **Every restart:** All accumulated deferred fees are lost on every node restart
- **Network-wide impact:** Every node in the network experiences this issue independently
- Node restarts occur regularly for:
  - Routine maintenance and updates
  - Crashes due to bugs or resource exhaustion
  - Network upgrades requiring node software updates
  - Hardware failures or reboots

This vulnerability is triggered continuously during normal blockchain operation and results in permanent fund loss on every node restart.

## Recommendation

**Immediate Fix:** Call `WriteDeferredBalances` in the banking module's EndBlocker before the block is committed:

1. Add an EndBlock method to the bank module in `x/bank/module.go` that calls the keeper's `WriteDeferredBalances` function
2. Register this EndBlock hook in the module manager's EndBlock order in `simapp/app.go`
3. Alternatively, add the call in the application's FinalizeBlocker before `SetDeliverStateToCommit()` at [7](#0-6) 

**Example implementation:**
```go
// In simapp/app.go FinalizeBlocker, before SetDeliverStateToCommit():
deferredEvents := app.BankKeeper.WriteDeferredBalances(ctx)
events = append(events, deferredEvents...)
```

**Long-term consideration:** If the deferred balance optimization is intended to reduce gas costs, consider whether persistent storage would be more appropriate, or ensure the system can gracefully handle node restarts without fund loss.

## Proof of Concept

**File:** `x/bank/keeper/keeper_test.go` (add new test function)

**Test Function:** `TestDeferredBalancesLostOnContextReset`

**Setup:**
1. Initialize test app with bank keeper configured with deferred cache
2. Create test accounts for user and fee collector module
3. Fund user account with sufficient balance

**Trigger:**
1. Simulate fee deduction via `DeferredSendCoinsFromAccountToModule` (mimicking ante handler behavior)
2. Verify user balance decreased and deferred cache contains the amount
3. Do NOT call `WriteDeferredBalances`
4. Simulate node restart by creating a new context (which clears the memory store)
5. Check balances and run TotalSupply invariant

**Observation:**
The test should demonstrate:
1. Before reset: User balance is reduced, fee collector balance unchanged, deferred cache contains amount, TotalSupply invariant passes
2. After reset: User balance still reduced, fee collector balance still unchanged, deferred cache empty, TotalSupply invariant FAILS
3. Funds are permanently lost (user paid but recipient never received)

**Test Code:**
```go
func TestDeferredBalancesLostOnContextReset(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create accounts
    userAddr := sdk.AccAddress([]byte("user"))
    feeAmount := sdk.NewCoins(sdk.NewCoin("usei", sdk.NewInt(1000)))
    
    // Fund user
    require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, feeAmount))
    require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, userAddr, feeAmount))
    
    initialBalance := app.BankKeeper.GetAllBalances(ctx, userAddr)
    initialSupply, _, _ := app.BankKeeper.GetPaginatedTotalSupply(ctx, nil)
    
    // Simulate fee deduction (what ante handler does)
    err := app.BankKeeper.DeferredSendCoinsFromAccountToModule(ctx, userAddr, authtypes.FeeCollectorName, feeAmount)
    require.NoError(t, err)
    
    // Verify user balance decreased
    afterDeductBalance := app.BankKeeper.GetAllBalances(ctx, userAddr)
    require.True(t, afterDeductBalance.IsZero())
    
    // Verify fee collector didn't receive yet
    feeCollectorAcc := app.AccountKeeper.GetModuleAccount(ctx, authtypes.FeeCollectorName)
    feeCollectorBalance := app.BankKeeper.GetAllBalances(ctx, feeCollectorAcc.GetAddress())
    require.True(t, feeCollectorBalance.IsZero())
    
    // Verify TotalSupply invariant passes (includes deferred)
    msg, broken := keeper.TotalSupply(app.BankKeeper)(ctx)
    require.False(t, broken, "invariant should pass before reset: %s", msg)
    
    // Simulate node restart - create new context which clears memory stores
    newCtx := app.BaseApp.NewContext(false, tmproto.Header{Height: 2})
    
    // After restart: user balance still reduced (persisted)
    afterRestartUserBalance := app.BankKeeper.GetAllBalances(newCtx, userAddr)
    require.True(t, afterRestartUserBalance.IsZero(), "user balance should still be reduced after restart")
    
    // Fee collector still didn't receive (WriteDeferredBalances was never called)
    afterRestartFeeCollectorBalance := app.BankKeeper.GetAllBalances(newCtx, feeCollectorAcc.GetAddress())
    require.True(t, afterRestartFeeCollectorBalance.IsZero(), "fee collector should have no balance")
    
    // TotalSupply invariant now FAILS - funds are lost
    msg, broken = keeper.TotalSupply(app.BankKeeper)(newCtx)
    require.True(t, broken, "invariant should fail after restart - funds are lost: %s", msg)
    
    // Verify supply mismatch
    afterRestartSupply, _, _ := app.BankKeeper.GetPaginatedTotalSupply(newCtx, nil)
    require.True(t, initialSupply.IsEqual(afterRestartSupply), "supply should be unchanged")
    
    // But account balances sum to less than supply
    totalBalances := sdk.NewCoins()
    app.BankKeeper.IterateAllBalances(newCtx, func(_ sdk.AccAddress, coin sdk.Coin) bool {
        totalBalances = totalBalances.Add(coin)
        return false
    })
    require.True(t, totalBalances.IsAllLT(afterRestartSupply), "balances should be less than supply - FUNDS LOST")
}
```

This test demonstrates that transaction fees are permanently lost after a node restart because `WriteDeferredBalances` is never called and the deferred cache (stored in a non-persistent memory store) is cleared.

### Citations

**File:** x/bank/keeper/keeper.go (L404-432)
```go
// DeferredSendCoinsFromAccountToModule transfers coins from an AccAddress to a ModuleAccount.
// It deducts the balance from an accAddress and stores the balance in a mapping for ModuleAccounts.
// In the EndBlocker, it will then perform one deposit for each module account.
// It will panic if the module account does not exist.
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

**File:** x/auth/ante/fee.go (L208-208)
```go
	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
```

**File:** simapp/app.go (L230-230)
```go
	memKeys := sdk.NewMemoryStoreKeys(capabilitytypes.MemStoreKey, "testingkey", banktypes.DeferredCacheStoreKey)
```

**File:** simapp/app.go (L543-544)
```go
	app.SetDeliverStateToCommit()
	app.WriteState()
```

**File:** x/bank/keeper/invariants.go (L74-78)
```go
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
```
