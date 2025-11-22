# Audit Report

## Title
Missing Coin Events for Base Denomination Balance Changes During Wei Operations

## Summary
When `SubWei` and `AddWei` operations cause changes to the usei (base denomination) balance due to wei-to-usei conversions, these usei balance changes are not emitted as `coin_spent` or `coin_received` events. Only `wei_spent` or `wei_received` events are emitted, creating an incomplete audit trail for the base denomination and breaking transaction traceability. [1](#0-0) [2](#0-1) 

## Impact
**Medium** - This bug results in unintended behavior for systems that rely on complete event emissions to track base denomination balance changes, with no concrete funds at direct risk.

## Finding Description

**Location:** `x/bank/keeper/send.go`, functions `SubWei` (lines 357-384) and `AddWei` (lines 386-412)

**Intended Logic:** All balance changes for any denomination, including the base denomination (usei), should emit corresponding `coin_spent` or `coin_received` events to ensure complete transaction traceability. The system should maintain a complete audit trail of all balance modifications.

**Actual Logic:** When `SubWei` or `AddWei` operations require conversion between wei and usei balances (because the wei amount crosses the 1 usei = 10^12 wei threshold), the code directly modifies the usei balance via `setBalance` without emitting `coin_spent` or `coin_received` events. Only `wei_spent` or `wei_received` events are emitted. [3](#0-2) [4](#0-3) 

In contrast, regular coin operations properly emit events: [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. An account holds 1 usei + 500,000,000,000 wei (total: 1.5 usei equivalent)
2. User calls `SubWei` with 1,200,000,000,000 wei (1.2 usei equivalent)
3. The aggregated balance becomes 0.3 usei equivalent = 0 usei + 300,000,000,000 wei
4. The usei balance changes from 1 to 0 via `setBalance` call at line 380
5. Only `wei_spent` event is emitted (line 364) - NO `coin_spent` event for the 1 usei reduction
6. External systems monitoring `coin_spent` events miss this usei balance change

**Security Failure:** Transaction traceability and audit trail completeness is broken. Systems that rely on `coin_spent` and `coin_received` events to track all base denomination balance changes will have incomplete or incorrect state.

## Impact Explanation

**Affected Systems:**
- Blockchain explorers tracking all balance changes via events
- Compliance and auditing systems requiring complete transaction trails
- Off-chain systems, indexers, or smart contracts on connected chains that monitor base denomination transfers
- Regulatory reporting systems that depend on event completeness

**Severity:**
While no funds are directly at risk and protocol state remains correct, this creates significant operational and compliance issues:
- External systems will show incorrect balance change histories
- Audit trails are incomplete, potentially violating financial compliance requirements
- Integration systems relying on events for state synchronization will desynchronize
- Users and operators lose visibility into the complete flow of base denomination transfers

This matters because the Cosmos SDK's event system is designed as the canonical source of truth for observability, and many ecosystem tools depend on complete event emissions.

## Likelihood Explanation

**Triggering Conditions:**
- Any user can trigger this by performing wei operations that cross the wei-to-usei conversion boundary
- This occurs whenever `SubWei` or `AddWei` is called with amounts that require borrowing from or crediting to the usei balance
- Normal operation of EVM-compatible features will regularly trigger this

**Frequency:**
High - This will occur frequently during normal EVM operations where precision below 1 usei is required. Every time a wei operation causes a carry-over to or from the usei denomination, the event gap appears.

## Recommendation

Modify `SubWei` and `AddWei` to emit additional `coin_spent` and `coin_received` events when they modify the usei balance:

1. In `SubWei` (lines 379-383): Calculate the usei difference before and after, and emit a `coin_spent` event if the usei balance decreased
2. In `AddWei` (lines 407-411): Calculate the usei credit amount and emit a `coin_received` event if usei was added
3. Ensure these events are emitted in addition to (not instead of) the wei events, to maintain complete traceability at both granularity levels

Alternative: Document this behavior clearly and ensure all ecosystem tools understand that wei events must be aggregated with coin events to track complete balance changes.

## Proof of Concept

**File:** `x/bank/keeper/keeper_test.go`

**Test Function:** `TestWeiOperationsEmitCoinEvents` (add this new test)

**Setup:**
1. Create a test account with 2 usei + 0 wei initial balance
2. Initialize a fresh event manager to track all events

**Trigger:**
1. Call `SubWei` with 1.7 * 10^12 wei (1.7 usei equivalent)
2. This should reduce balance to 0 usei + 300,000,000,000 wei (0.3 usei equivalent)
3. The usei balance changes from 2 to 0 (2 usei decrease)

**Observation:**
1. Check events emitted - should find `wei_spent` event for 1.7 * 10^12 wei
2. Check for `coin_spent` event for 2 usei - THIS WILL BE MISSING (bug confirmation)
3. Query the actual balance - confirms usei changed from 2 to 0
4. This proves usei balance changed without corresponding coin event

```go
func (suite *IntegrationTestSuite) TestWeiOperationsEmitCoinEvents() {
    app, ctx := suite.app, suite.ctx
    addr := sdk.AccAddress([]byte("test_addr___________"))
    
    // Setup: Fund account with 2 usei
    initialCoins := sdk.NewCoins(sdk.NewInt64Coin(sdk.MustGetBaseDenom(), 2))
    suite.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr, initialCoins))
    
    // Verify initial balance
    initialUseiBalance := app.BankKeeper.GetBalance(ctx, addr, sdk.MustGetBaseDenom())
    suite.Require().Equal(sdk.NewInt(2), initialUseiBalance.Amount)
    
    // Create fresh event manager
    ctx = ctx.WithEventManager(sdk.NewEventManager())
    
    // Trigger: SubWei 1.7 usei worth (1700000000000 wei)
    // This should reduce balance to 0 usei + 300000000000 wei
    weiAmount := sdk.NewInt(1700000000000)
    suite.Require().NoError(app.BankKeeper.SubWei(ctx, addr, weiAmount))
    
    // Verify final balances
    finalUseiBalance := app.BankKeeper.GetBalance(ctx, addr, sdk.MustGetBaseDenom())
    finalWeiBalance := app.BankKeeper.GetWeiBalance(ctx, addr)
    suite.Require().Equal(sdk.NewInt(0), finalUseiBalance.Amount) // usei changed from 2 to 0
    suite.Require().Equal(sdk.NewInt(300000000000), finalWeiBalance)
    
    // Check events
    events := ctx.EventManager().ABCIEvents()
    
    // Find wei_spent event - SHOULD EXIST
    hasWeiSpent := false
    for _, event := range events {
        if event.Type == types.EventTypeWeiSpent {
            hasWeiSpent = true
        }
    }
    suite.Require().True(hasWeiSpent, "wei_spent event should be emitted")
    
    // Find coin_spent event for 2 usei - BUG: THIS WILL BE MISSING
    hasCoinSpent := false
    for _, event := range events {
        if event.Type == types.EventTypeCoinSpent {
            hasCoinSpent = true
        }
    }
    
    // This assertion FAILS on current code, proving the bug
    suite.Require().True(hasCoinSpent, "BUG: coin_spent event missing for 2 usei balance decrease")
}
```

This test demonstrates that when `SubWei` causes a 2 usei decrease (from 2 to 0), no `coin_spent` event is emitted, despite the balance change being real and permanent.

### Citations

**File:** x/bank/keeper/send.go (L206-246)
```go
// SubUnlockedCoins removes the unlocked amt coins of the given account. An error is
// returned if the resulting balance is negative or the initial amount is invalid.
// A coin_spent event is emitted after.
func (k BaseSendKeeper) SubUnlockedCoins(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Coins, checkNeg bool) error {
	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	lockedCoins := k.LockedCoins(ctx, addr)

	for _, coin := range amt {
		balance := k.GetBalance(ctx, addr, coin.Denom)
		if checkNeg {
			locked := sdk.NewCoin(coin.Denom, lockedCoins.AmountOf(coin.Denom))
			spendable := balance.Sub(locked)

			_, hasNeg := sdk.Coins{spendable}.SafeSub(sdk.Coins{coin})
			if hasNeg {
				return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "%s is smaller than %s", spendable, coin)
			}
		}

		var newBalance sdk.Coin
		if checkNeg {
			newBalance = balance.Sub(coin)
		} else {
			newBalance = balance.SubUnsafe(coin)
		}

		err := k.setBalance(ctx, addr, newBalance, checkNeg)
		if err != nil {
			return err
		}
	}

	// emit coin spent event
	ctx.EventManager().EmitEvent(
		types.NewCoinSpentEvent(addr, amt),
	)
	return nil
}
```

**File:** x/bank/keeper/send.go (L248-274)
```go
// AddCoins increase the addr balance by the given amt. Fails if the provided amt is invalid.
// It emits a coin received event.
func (k BaseSendKeeper) AddCoins(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Coins, checkNeg bool) error {
	if !k.CanSendTo(ctx, addr) {
		return sdkerrors.ErrInvalidRecipient
	}
	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	for _, coin := range amt {
		balance := k.GetBalance(ctx, addr, coin.Denom)
		newBalance := balance.Add(coin)

		err := k.setBalance(ctx, addr, newBalance, checkNeg)
		if err != nil {
			return err
		}
	}

	// emit coin received event
	ctx.EventManager().EmitEvent(
		types.NewCoinReceivedEvent(addr, amt),
	)

	return nil
}
```

**File:** x/bank/keeper/send.go (L357-384)
```go
func (k BaseSendKeeper) SubWei(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Int) (err error) {
	if amt.Equal(sdk.ZeroInt()) {
		return nil
	}
	defer func() {
		if err == nil {
			ctx.EventManager().EmitEvent(
				types.NewWeiSpentEvent(addr, amt),
			)
		}
	}()
	currentWeiBalance := k.GetWeiBalance(ctx, addr)
	if amt.LTE(currentWeiBalance) {
		// no need to change usei balance
		return k.setWeiBalance(ctx, addr, currentWeiBalance.Sub(amt))
	}
	currentUseiBalance := k.GetBalance(ctx, addr, sdk.MustGetBaseDenom()).Amount
	currentAggregatedBalance := currentUseiBalance.Mul(OneUseiInWei).Add(currentWeiBalance)
	postAggregatedbalance := currentAggregatedBalance.Sub(amt)
	if postAggregatedbalance.IsNegative() {
		return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "%swei is smaller than %swei", currentAggregatedBalance, amt)
	}
	useiBalance, weiBalance := SplitUseiWeiAmount(postAggregatedbalance)
	if err := k.setBalance(ctx, addr, sdk.NewCoin(sdk.MustGetBaseDenom(), useiBalance), true); err != nil {
		return err
	}
	return k.setWeiBalance(ctx, addr, weiBalance)
}
```

**File:** x/bank/keeper/send.go (L386-412)
```go
func (k BaseSendKeeper) AddWei(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Int) (err error) {
	if !k.CanSendTo(ctx, addr) {
		return sdkerrors.ErrInvalidRecipient
	}
	if amt.Equal(sdk.ZeroInt()) {
		return nil
	}
	defer func() {
		if err == nil {
			ctx.EventManager().EmitEvent(
				types.NewWeiReceivedEvent(addr, amt),
			)
		}
	}()
	currentWeiBalance := k.GetWeiBalance(ctx, addr)
	postWeiBalance := currentWeiBalance.Add(amt)
	if postWeiBalance.LT(OneUseiInWei) {
		// no need to change usei balance
		return k.setWeiBalance(ctx, addr, postWeiBalance)
	}
	currentUseiBalance := k.GetBalance(ctx, addr, sdk.MustGetBaseDenom()).Amount
	useiCredit, weiBalance := SplitUseiWeiAmount(postWeiBalance)
	if err := k.setBalance(ctx, addr, sdk.NewCoin(sdk.MustGetBaseDenom(), currentUseiBalance.Add(useiCredit)), true); err != nil {
		return err
	}
	return k.setWeiBalance(ctx, addr, weiBalance)
}
```
