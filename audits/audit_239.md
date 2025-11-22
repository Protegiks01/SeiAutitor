# Audit Report

## Title
Missing Non-Negative Validation for Wei Balances in InitGenesis Allows Invalid Genesis State

## Summary
The `InitGenesis` function in the bank keeper validates that total wei balance has no remainder when divided by `OneUseiInWei`, but fails to validate that individual wei balances are non-negative. This allows a malicious genesis file to include negative wei balances that pass the remainder check, resulting in a chain starting with accounts holding negative balances, which violates fundamental accounting invariants.

## Impact
**Medium** - A bug in the layer 1 network code that results in unintended behavior with potential for chain halt when invariant checks detect the invalid state.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The genesis initialization should ensure that all account balances (including wei balances) are valid and non-negative before the chain starts. The remainder check is intended to ensure proper accounting between wei and usei denominations.

**Actual Logic:** The code iterates through genesis wei balances, calls `AddWei` for each entry, and accumulates them into `totalWeiBalance`. It then checks only that `totalWeiBalance % OneUseiInWei == 0` but does not validate that individual wei amounts or the total are non-negative. [2](#0-1) 

The `AddWei` function does not validate for negative inputs and will store negative wei balances: [3](#0-2) 

The `setWeiBalance` function stores any value without sign validation: [4](#0-3) 

**Exploit Scenario:**
1. An attacker influences the genesis file (e.g., during testnet setup or through social engineering)
2. They craft `WeiBalances` entries with negative amounts that sum to a value divisible by `OneUseiInWei`:
   - Account A: `-1000000000000` wei
   - Account B: `3000000000000` wei
   - Total: `2000000000000` wei (divisible by `1000000000000`, no remainder)
3. During `InitGenesis`, the remainder check passes
4. Account A is stored with `-1000000000000` wei (equivalent to -1 usei)
5. The chain starts with invalid state containing negative balances

**Security Failure:** The fundamental accounting invariant that all balances must be non-negative is violated. This breaks the `NonnegativeBalanceInvariant` which checks for this condition: [5](#0-4) 

## Impact Explanation

**Affected Assets/Processes:**
- Chain state integrity - accounts can have negative balances
- Accounting invariants - the non-negative balance requirement is violated
- Network operation - if `halt-on-invariant` is enabled, the chain will halt

**Severity:**
- The chain starts with fundamentally invalid state (negative balances)
- Invariant checks will detect this and potentially halt the chain
- Accounts with negative balances cannot spend (SubWei prevents it) but can receive funds to "pay off" the debt: [6](#0-5) 
- This creates an accounting inconsistency where some accounts have negative value

**Why It Matters:**
Starting a blockchain with invalid state undermines trust in the network and can cause operational issues. If the chain halts due to invariant failure, it requires manual intervention or a hard fork to fix. Even if it doesn't halt immediately, the presence of negative balances represents a fundamental violation of accounting principles.

## Likelihood Explanation

**Who Can Trigger:**
Anyone who can influence the genesis file content. This includes:
- Network operators setting up new testnets
- Participants in governance processes that modify genesis
- Attackers who compromise genesis file distribution

**Conditions Required:**
- The negative wei balances must sum (with positive balances) to a value divisible by `OneUseiInWei` to pass the remainder check
- The genesis file must be accepted by validators (requires social engineering or insider access)

**Frequency:**
Low under normal conditions, but possible during network launches, testnet deployments, or chain upgrades that involve genesis file modifications.

## Recommendation

Add validation in `InitGenesis` to ensure all wei balances are non-negative before processing:

```go
for _, weiBalance := range genState.WeiBalances {
    if weiBalance.Amount.IsNegative() {
        panic(fmt.Errorf("negative wei balance %s for address %s", weiBalance.Amount, weiBalance.Address))
    }
    addr := sdk.MustAccAddressFromBech32(weiBalance.Address)
    if err := k.AddWei(ctx, addr, weiBalance.Amount); err != nil {
        panic(fmt.Errorf("error on setting wei balance %w", err))
    }
    totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
}
```

Additionally, consider adding the same check in the genesis validation function: [7](#0-6) 

## Proof of Concept

**File:** `x/bank/keeper/genesis_test.go`

**Test Function:** Add this test to the existing test suite:

```go
func (suite *IntegrationTestSuite) TestInitGenesisWithNegativeWeiBalances() {
    // Setup: Create genesis state with negative wei balances that sum to valid total
    defaultGenesis := types.DefaultGenesisState()
    
    // Account A has negative wei, Account B has positive
    // Total: -1000000000000 + 3000000000000 = 2000000000000 (divisible by 1000000000000)
    weiBalances := []types.WeiBalance{
        {Amount: sdk.NewInt(-1000000000000), Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"},
        {Amount: sdk.NewInt(3000000000000), Address: "cosmos1t5u0jfg3ljsjrh2m9e47d4ny2hea7eehxrzdgd"},
    }
    
    totalSupply := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(2)))
    genesis := types.NewGenesisState(defaultGenesis.Params, []types.Balance{}, totalSupply, defaultGenesis.DenomMetadata, weiBalances)
    
    // Trigger: Call InitGenesis - it should panic but currently doesn't
    suite.app.BankKeeper.InitGenesis(suite.ctx, genesis)
    
    // Observation: Check that account A has negative wei balance (this proves the vulnerability)
    addrA, _ := sdk.AccAddressFromBech32("cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0")
    weiBalanceA := suite.app.BankKeeper.GetWeiBalance(suite.ctx, addrA)
    
    // This assertion will pass on vulnerable code, proving negative balance was stored
    suite.Require().True(weiBalanceA.IsNegative(), "Account A should have negative wei balance")
    suite.Require().Equal(sdk.NewInt(-1000000000000), weiBalanceA, "Account A should have -1000000000000 wei")
    
    // Verify that the NonnegativeBalanceInvariant would fail
    _, broken := keeper.NonnegativeBalanceInvariant(suite.app.BankKeeper)(suite.ctx)
    suite.Require().True(broken, "NonnegativeBalanceInvariant should be broken with negative wei balance")
}
```

**Expected Behavior:** 
- On vulnerable code: Test passes, confirming negative balance is stored
- On fixed code: InitGenesis panics with "negative wei balance" error before the assertion

This PoC demonstrates that InitGenesis accepts negative wei balances when their sum has no remainder, resulting in invalid chain state that violates the non-negative balance invariant.

### Citations

**File:** x/bank/keeper/genesis.go (L28-38)
```go
	for _, weiBalance := range genState.WeiBalances {
		addr := sdk.MustAccAddressFromBech32(weiBalance.Address)
		if err := k.AddWei(ctx, addr, weiBalance.Amount); err != nil {
			panic(fmt.Errorf("error on setting wei balance %w", err))
		}
		totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
	}
	weiInUsei, weiRemainder := SplitUseiWeiAmount(totalWeiBalance)
	if !weiRemainder.IsZero() {
		panic(fmt.Errorf("non-zero wei remainder %s", weiRemainder))
	}
```

**File:** x/bank/keeper/send.go (L315-326)
```go
func (k BaseSendKeeper) setWeiBalance(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Int) error {
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.WeiBalancesPrefix)
	if amt.IsZero() {
		store.Delete(addr)
		return nil
	}
	val, err := amt.Marshal()
	if err != nil {
		return err
	}
	store.Set(addr, val)
	return nil
```

**File:** x/bank/keeper/send.go (L376-378)
```go
	if postAggregatedbalance.IsNegative() {
		return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "%swei is smaller than %swei", currentAggregatedBalance, amt)
	}
```

**File:** x/bank/keeper/send.go (L386-404)
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
```

**File:** x/bank/keeper/invariants.go (L40-47)
```go
		k.IterateAllWeiBalances(ctx, func(addr sdk.AccAddress, balance sdk.Int) bool {
			if balance.IsNegative() {
				count++
				msg += fmt.Sprintf("\t%s has a negative wei balance of %s\n", addr, balance)
			}

			return false
		})
```

**File:** x/bank/types/genesis.go (L69-71)
```go
	for _, weiBalance := range genState.WeiBalances {
		totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
	}
```
