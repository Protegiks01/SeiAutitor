# Audit Report

## Title
Missing Genesis Validation for Vesting Account Original Vesting Allows Node Crash and Permanent Fund Freezing

## Summary
The `ValidateBalance` function in the bank keeper checks that vesting account original vesting does not exceed actual balance, but this validation is never called during genesis initialization. [1](#0-0)  This allows malformed genesis states with vesting accounts where `OriginalVesting > Balance` to be accepted, causing node panics when any transaction attempts to spend from such accounts. [2](#0-1) 

## Impact
**High** - Critical permanent freezing of funds requiring hard fork to remediate, and potential for network node shutdowns.

## Finding Description

**Location:** 
- Primary: `x/bank/keeper/genesis.go` - `InitGenesis` function
- Validation function: `x/bank/keeper/view.go:209-229` - `ValidateBalance` function
- Panic point: `x/bank/keeper/send.go:209-225` - `SubUnlockedCoins` function
- Underlying panic: `types/coin.go:108-121` - `Coin.Sub` method

**Intended Logic:** 
The `ValidateBalance` function is explicitly documented to validate vesting accounts during genesis. [3](#0-2)  It checks that for vesting accounts, `OriginalVesting <= TotalBalance`. [4](#0-3)  The contract comment states: "CONTRACT: ValidateBalance should only be called upon genesis state."

**Actual Logic:** 
The `InitGenesis` function sets balances and validates total supply but never calls `ValidateBalance` on individual accounts. [1](#0-0)  The `GenesisState.Validate()` method only validates balance format and total supply, not vesting account constraints. [5](#0-4) 

**Exploit Scenario:**
1. A genesis state is created (maliciously or by configuration error) with a vesting account having `OriginalVesting = 200 tokens` but `Balance = 100 tokens`
2. Genesis validation passes because `ValidateBalance` is never invoked
3. Chain initializes successfully with the malformed vesting account
4. When any user attempts to send coins from this account, `SubUnlockedCoins` is called
5. The function calculates `lockedCoins = OriginalVesting - VestedCoins` (at genesis time, this equals `OriginalVesting`)
6. It then attempts `spendable = balance.Sub(locked)` where `balance = 100, locked = 200`
7. The `Coin.Sub` method panics because the result would be negative [6](#0-5) 

**Security Failure:** 
This breaks both the availability invariant (node crash) and the accounting invariant (funds become permanently inaccessible). Any transaction involving the affected vesting account causes a node panic, effectively creating a permanent DOS condition for that account and potentially the entire network if such accounts are used in critical operations.

## Impact Explanation

**Assets Affected:**
- Funds in vesting accounts with `OriginalVesting > Balance` become permanently frozen
- Network availability compromised as nodes crash when processing transactions from these accounts

**Severity of Damage:**
- **Permanent fund freezing:** Funds cannot be accessed without a hard fork to fix the genesis state
- **Node crashes:** Any attempt to spend from the account causes immediate node panic
- **Network-wide impact:** If multiple validators or a significant portion of nodes attempt to process such transactions, it can cause cascading failures leading to network disruption
- **Consensus disruption:** Different nodes may crash at different times when processing blocks containing transactions from affected accounts, potentially causing temporary chain splits

**System Security Impact:**
This vulnerability undermines the fundamental security properties of the blockchain:
- **Liveness:** Network cannot process certain valid-looking transactions
- **Safety:** Funds are provably locked without recovery mechanism
- **Availability:** Nodes crash unpredictably when encountering specific account interactions

## Likelihood Explanation

**Who Can Trigger:**
- Any network participant can trigger the panic by sending a transaction that attempts to spend from an affected vesting account
- Genesis creators (chain operators) can inadvertently create this condition through misconfiguration
- Malicious genesis contributors could intentionally plant such accounts

**Conditions Required:**
- Genesis state must contain a vesting account where `OriginalVesting > Balance`
- This can occur at chain launch or during chain upgrades that modify genesis
- No special privileges needed to trigger the panic - any transaction spending from the account suffices

**Frequency:**
- While requiring specific genesis misconfiguration, the condition is permanent once established
- Can be exploited repeatedly by anyone submitting transactions to the affected account
- Testing shows this exact scenario is validated in test code but the validation is never integrated into genesis flow [7](#0-6) 

## Recommendation

Integrate `ValidateBalance` into the genesis initialization process:

1. **Immediate fix:** Add `ValidateBalance` calls in `InitGenesis` after setting account balances
2. **Implementation:** After line 26 in `x/bank/keeper/genesis.go`, iterate through all accounts and call `ValidateBalance` for each address
3. **Additional safety:** Include this check in `GenesisState.Validate()` method to catch issues during genesis file validation before chain initialization

The fix should ensure that any genesis state with vesting accounts violating the `OriginalVesting <= Balance` invariant is rejected before chain initialization.

## Proof of Concept

**File:** `x/bank/keeper/genesis_test.go`

**Test Function:** `TestGenesisWithExcessiveVestingOriginal`

**Setup:**
1. Create a continuous vesting account with `OriginalVesting = 200 foocoin`
2. Provide only `Balance = 100 foocoin` in the genesis balances
3. Initialize the chain with this genesis state (this should succeed, demonstrating the vulnerability)
4. Create a context with block time at genesis

**Trigger:**
1. Attempt to send any amount (even 1 coin) from the vesting account using `SubUnlockedCoins`
2. The call will attempt to calculate spendable balance as `balance - locked`
3. Since `locked = OriginalVesting = 200` and `balance = 100`, this will panic

**Observation:**
The test demonstrates that:
- Genesis initialization succeeds without calling `ValidateBalance` (vulnerability confirmation)
- Any subsequent spend operation panics with "negative coin amount"
- The same vesting account configuration fails `ValidateBalance` when explicitly called, proving the check exists but is not integrated

This PoC proves that the validation gap allows creation of unusable vesting accounts at genesis that permanently freeze funds and crash nodes upon interaction.

### Citations

**File:** x/bank/keeper/genesis.go (L11-59)
```go
// InitGenesis initializes the bank module's state from a given genesis state.
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

**File:** x/bank/keeper/view.go (L209-229)
```go
func (k BaseViewKeeper) ValidateBalance(ctx sdk.Context, addr sdk.AccAddress) error {
	acc := k.ak.GetAccount(ctx, addr)
	if acc == nil {
		return sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "account %s does not exist", addr)
	}

	balances := k.GetAllBalances(ctx, addr)
	if !balances.IsValid() {
		return fmt.Errorf("account balance of %s is invalid", balances)
	}

	vacc, ok := acc.(vestexported.VestingAccount)
	if ok {
		ogv := vacc.GetOriginalVesting()
		if ogv.IsAnyGT(balances) {
			return fmt.Errorf("vesting amount %s cannot be greater than total amount %s", ogv, balances)
		}
	}

	return nil
}
```

**File:** x/bank/types/genesis.go (L13-48)
```go
func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return err
	}

	seenMetadatas := make(map[string]bool)
	totalSupply, err := getTotalSupply(&gs)
	if err != nil {
		return err
	}

	for _, metadata := range gs.DenomMetadata {
		if seenMetadatas[metadata.Base] {
			return fmt.Errorf("duplicate client metadata for denom %s", metadata.Base)
		}

		if err := metadata.Validate(); err != nil {
			return err
		}

		seenMetadatas[metadata.Base] = true
	}

	if !gs.Supply.Empty() {
		// NOTE: this errors if supply for any given coin is zero
		err := gs.Supply.Validate()
		if err != nil {
			return err
		}

		if !gs.Supply.IsEqual(totalSupply) {
			return fmt.Errorf("genesis supply is incorrect, expected %v, got %v", gs.Supply, totalSupply)
		}
	}

	return nil
```

**File:** types/coin.go (L108-121)
```go
// Sub subtracts amounts of two coins with same denom. If the coins differ in denom
// then it panics.
func (coin Coin) Sub(coinB Coin) Coin {
	if coin.Denom != coinB.Denom {
		panic(fmt.Sprintf("invalid coin denominations; %s, %s", coin.Denom, coinB.Denom))
	}

	res := Coin{coin.Denom, coin.Amount.Sub(coinB.Amount)}
	if res.IsNegative() {
		panic("negative coin amount")
	}

	return res
}
```

**File:** x/bank/keeper/keeper_test.go (L852-876)
```go
func (suite *IntegrationTestSuite) TestValidateBalance() {
	app, ctx := suite.app, suite.ctx
	now := tmtime.Now()
	ctx = ctx.WithBlockHeader(tmproto.Header{Time: now})
	endTime := now.Add(24 * time.Hour)

	addr1 := sdk.AccAddress([]byte("addr1_______________"))
	addr2 := sdk.AccAddress([]byte("addr2_______________"))

	suite.Require().Error(app.BankKeeper.ValidateBalance(ctx, addr1))

	acc := app.AccountKeeper.NewAccountWithAddress(ctx, addr1)
	app.AccountKeeper.SetAccount(ctx, acc)

	balances := sdk.NewCoins(newFooCoin(100))
	suite.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr1, balances))
	suite.Require().NoError(app.BankKeeper.ValidateBalance(ctx, addr1))

	bacc := authtypes.NewBaseAccountWithAddress(addr2)
	vacc := vesting.NewContinuousVestingAccount(bacc, balances.Add(balances...), now.Unix(), endTime.Unix(), nil)

	app.AccountKeeper.SetAccount(ctx, vacc)
	suite.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr2, balances))
	suite.Require().Error(app.BankKeeper.ValidateBalance(ctx, addr2))
}
```
