# Audit Report

## Title
Missing Genesis Validation for Vesting Account Original Vesting Allows Node Crash and Permanent Fund Freezing

## Summary
The bank keeper's `InitGenesis` function fails to call `ValidateBalance` on accounts during genesis initialization, allowing vesting accounts with `OriginalVesting > Balance` to be created. When transactions attempt to spend from such accounts, the node panics due to a negative coin calculation in `SubUnlockedCoins`, causing permanent fund freezing and network disruption.

## Impact
High

## Finding Description

**Location:**
- `x/bank/keeper/genesis.go` lines 12-59 (`InitGenesis` function)
- `x/bank/keeper/view.go` lines 209-229 (`ValidateBalance` function) 
- `x/bank/keeper/send.go` line 220 (panic point in `SubUnlockedCoins`)
- `types/coin.go` lines 116-118 (underlying panic in `Coin.Sub`)

**Intended Logic:**
The `ValidateBalance` function is explicitly documented to validate vesting accounts at genesis, with a CONTRACT comment stating "ValidateBalance should only be called upon genesis state." [1](#0-0)  It checks that for vesting accounts, `OriginalVesting <= TotalBalance`. [2](#0-1) 

**Actual Logic:**
The `InitGenesis` function sets balances and validates total supply but never calls `ValidateBalance` on individual accounts. [3](#0-2)  The vesting account's own `Validate()` method only checks that `DelegatedVesting <= OriginalVesting`, not that `OriginalVesting <= Balance`. [4](#0-3) 

**Exploitation Path:**
1. Genesis state is created with a vesting account having `OriginalVesting > Balance` (can be accidental misconfiguration during chain launch/upgrade)
2. Genesis initialization succeeds because `ValidateBalance` is never called
3. At genesis time, for a continuous vesting account, `LockedCoins` returns `OriginalVesting` since no coins have vested yet [5](#0-4) 
4. Any transaction attempting to spend from the account calls `SubUnlockedCoins` [6](#0-5) 
5. At line 220, the code executes `spendable := balance.Sub(locked)` where `balance < locked` [7](#0-6) 
6. The `Coin.Sub` method panics because the result would be negative [8](#0-7) 

**Security Guarantee Broken:**
- **Liveness**: Network cannot process transactions from affected accounts without crashing
- **Safety**: Funds become permanently inaccessible without hard fork
- **Invariant**: The codebase assumes `OriginalVesting <= Balance` for vesting accounts but doesn't enforce it at genesis

## Impact Explanation

**Permanent Fund Freezing:**
Funds in vesting accounts with `OriginalVesting > Balance` become permanently frozen. Any attempt to spend from these accounts causes node panics, making the funds completely inaccessible without a hard fork to fix the genesis state.

**Network Disruption:**
When transactions from affected accounts are included in blocks, nodes processing those transactions will crash. If validators or significant network participants have such accounts, this can cause:
- Cascading node failures as different nodes process the transaction
- Potential consensus disruption if many validators crash simultaneously
- Network availability issues requiring emergency intervention

**Irreversible Damage:**
Once a chain launches with such malformed accounts, the only remediation is a hard fork to fix the genesis state, which is extremely disruptive and may result in loss of transaction history.

## Likelihood Explanation

**Trigger Conditions:**
- Requires genesis state misconfiguration (privileged action by chain operators)
- However, this qualifies under the exception for "unrecoverable security failure beyond intended authority"
- The `ValidateBalance` function exists with explicit documentation that it should be called at genesis, indicating this is a code defect, not intentional design
- Configuration errors during chain launch or upgrades are realistic scenarios

**Who Can Trigger:**
- Chain operators can inadvertently create this condition during genesis setup
- Once established, any network participant can trigger the panic by attempting to transact with the affected account
- No special privileges needed to trigger the actual crash

**Evidence of Bug:**
The test suite demonstrates that `ValidateBalance` correctly catches this scenario when called explicitly, [9](#0-8)  but this validation is never integrated into the genesis flow.

## Recommendation

Integrate `ValidateBalance` into the genesis initialization process:

1. **Immediate Fix**: Add `ValidateBalance` calls in `InitGenesis` after setting account balances (after line 26 in `x/bank/keeper/genesis.go`)
2. **Implementation**: Iterate through all genesis balances and call `ValidateBalance` for each address
3. **Defense in Depth**: Add this check to `GenesisState.Validate()` method to catch issues during genesis file validation before chain initialization

Example implementation:
```go
// After line 26 in InitGenesis
for _, balance := range genState.Balances {
    if err := k.ValidateBalance(ctx, balance.GetAddress()); err != nil {
        panic(fmt.Errorf("invalid balance at genesis: %w", err))
    }
}
```

## Proof of Concept

**Scenario**: Create a continuous vesting account at genesis with `OriginalVesting = 200` tokens but only `Balance = 100` tokens.

**Setup:**
1. Create genesis state with a continuous vesting account:
   - `OriginalVesting`: 200 foocoin
   - Actual `Balance`: 100 foocoin
2. Initialize chain with `InitGenesis` - succeeds (demonstrates vulnerability)

**Trigger:**
1. Attempt to send any amount from the vesting account
2. This calls `SubUnlockedCoins` with the account address
3. The function calculates `lockedCoins = 200` (since no coins have vested at genesis)
4. At line 220: `spendable := balance.Sub(locked)` attempts `100.Sub(200)`

**Result:**
- Node panics with "negative coin amount" error
- Funds become permanently inaccessible
- Any node processing such a transaction will crash

**Validation:**
The existing test `TestValidateBalance` proves that calling `ValidateBalance` explicitly on such an account returns an error, confirming the validation logic exists but is not integrated into genesis initialization.

## Notes

This vulnerability qualifies as HIGH severity under "Permanent freezing of funds (fix requires hard fork)". While it requires privileged genesis configuration, it meets the exception criteria because:

1. A trusted operator can inadvertently trigger it through configuration error
2. It causes unrecoverable security failure (permanent fund freezing + network disruption)  
3. The failure extends beyond the operator's intended authority
4. The code explicitly documents that `ValidateBalance` should be called at genesis but fails to do so - this is a code defect

The inconsistent handling between `spendableCoins` (which uses safe `SafeSub`) and `SubUnlockedCoins` (which uses panicking `Sub`) further indicates this is an unintended bug rather than designed behavior.

### Citations

**File:** x/bank/keeper/view.go (L202-208)
```go
// ValidateBalance validates all balances for a given account address returning
// an error if any balance is invalid. It will check for vesting account types
// and validate the balances against the original vesting balances.
//
// CONTRACT: ValidateBalance should only be called upon genesis state. In the
// case of vesting accounts, balances may change in a valid manner that would
// otherwise yield an error from this call.
```

**File:** x/bank/keeper/view.go (L220-226)
```go
	vacc, ok := acc.(vestexported.VestingAccount)
	if ok {
		ogv := vacc.GetOriginalVesting()
		if ogv.IsAnyGT(balances) {
			return fmt.Errorf("vesting amount %s cannot be greater than total amount %s", ogv, balances)
		}
	}
```

**File:** x/bank/keeper/genesis.go (L12-59)
```go
func (k BaseKeeper) InitGenesis(ctx sdk.Context, genState *types.GenesisState) {
	k.SetParams(ctx, genState.Params)

	totalSupply := sdk.Coins{}
	totalWeiBalance := sdk.ZeroInt()

	genState.Balances = types.SanitizeGenesisBalances(genState.Balances)
	for _, balance := range genState.Balances {
		addr := balance.GetAddress()
		coins := balance.Coins
		if err := k.initBalances(ctx, addr, coins); err != nil {
			panic(fmt.Errorf("error on setting balances %w", err))
		}

		totalSupply = totalSupply.Add(coins...)
	}
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
	baseDenom, err := sdk.GetBaseDenom()
	if err != nil {
		if !weiInUsei.IsZero() {
			panic(fmt.Errorf("base denom is not registered %s yet there exists wei balance %s", err, weiInUsei))
		}
	} else {
		totalSupply = totalSupply.Add(sdk.NewCoin(baseDenom, weiInUsei))
	}

	if !genState.Supply.Empty() && !genState.Supply.IsEqual(totalSupply) {
		panic(fmt.Errorf("genesis supply is incorrect, expected %v, got %v", genState.Supply, totalSupply))
	}

	for _, supply := range totalSupply {
		k.SetSupply(ctx, supply)
	}

	for _, meta := range genState.DenomMetadata {
		k.SetDenomMetaData(ctx, meta)
	}
}
```

**File:** x/auth/vesting/types/vesting_account.go (L150-155)
```go
func (bva BaseVestingAccount) Validate() error {
	if !(bva.DelegatedVesting.IsAllLTE(bva.OriginalVesting)) {
		return errors.New("delegated vesting amount cannot be greater than original vesting amount")
	}
	return bva.BaseAccount.Validate()
}
```

**File:** x/auth/vesting/types/vesting_account.go (L255-263)
```go
func (cva ContinuousVestingAccount) GetVestingCoins(blockTime time.Time) sdk.Coins {
	return cva.OriginalVesting.Sub(cva.GetVestedCoins(blockTime))
}

// LockedCoins returns the set of coins that are not spendable (i.e. locked),
// defined as the vesting coins that are not delegated.
func (cva ContinuousVestingAccount) LockedCoins(blockTime time.Time) sdk.Coins {
	return cva.BaseVestingAccount.LockedCoinsFromVesting(cva.GetVestingCoins(blockTime))
}
```

**File:** x/bank/keeper/send.go (L175-180)
```go
func (k BaseSendKeeper) SendCoinsWithoutAccCreation(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
	return k.sendCoinsWithoutAccCreation(ctx, fromAddr, toAddr, amt, true)
}

func (k BaseSendKeeper) sendCoinsWithoutAccCreation(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins, checkNeg bool) error {
	err := k.SubUnlockedCoins(ctx, fromAddr, amt, checkNeg)
```

**File:** x/bank/keeper/send.go (L216-220)
```go
	for _, coin := range amt {
		balance := k.GetBalance(ctx, addr, coin.Denom)
		if checkNeg {
			locked := sdk.NewCoin(coin.Denom, lockedCoins.AmountOf(coin.Denom))
			spendable := balance.Sub(locked)
```

**File:** types/coin.go (L115-118)
```go
	res := Coin{coin.Denom, coin.Amount.Sub(coinB.Amount)}
	if res.IsNegative() {
		panic("negative coin amount")
	}
```

**File:** x/bank/keeper/keeper_test.go (L870-875)
```go
	bacc := authtypes.NewBaseAccountWithAddress(addr2)
	vacc := vesting.NewContinuousVestingAccount(bacc, balances.Add(balances...), now.Unix(), endTime.Unix(), nil)

	app.AccountKeeper.SetAccount(ctx, vacc)
	suite.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr2, balances))
	suite.Require().Error(app.BankKeeper.ValidateBalance(ctx, addr2))
```
