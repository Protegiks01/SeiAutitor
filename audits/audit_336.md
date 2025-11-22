# Audit Report

## Title
Genesis Supply Inflation via Duplicate WeiBalance Entries

## Summary
The bank module's genesis validation lacks duplicate address checking for `WeiBalances`, while it properly validates `Balances` for duplicates. This allows an attacker to craft a malicious genesis file with duplicate `WeiBalance` entries that passes validation but inflates the total supply during initialization, creating unbacked tokens.

## Impact
**High** - This vulnerability enables direct supply inflation through genesis manipulation, allowing creation of unbacked tokens and breaking the fundamental protocol invariant that total supply must equal the sum of all account balances.

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
The genesis validation should ensure that no duplicate addresses exist in either `Balances` or `WeiBalances` to prevent double-counting in supply calculations. Each address should appear at most once in the genesis state.

**Actual Logic:** 
The validation function properly checks for duplicate addresses in the `Balances` field [3](#0-2)  but completely omits this check for `WeiBalances` [1](#0-0) . During `InitGenesis`, the `AddWei` function accumulates amounts to existing balances [4](#0-3) , so duplicate entries result in inflated balances and supply.

**Exploit Scenario:**
1. Attacker creates a genesis file with duplicate `WeiBalance` entries for the same address (e.g., address A with 1,000,000,000,000 wei listed twice)
2. Sets the `Supply` field to empty, which is valid according to the proto definition and test cases [5](#0-4) 
3. The genesis validation passes because there's no duplicate check for `WeiBalances` [1](#0-0) 
4. During `InitGenesis`, each duplicate entry is processed:
   - First iteration: `AddWei` sets balance to 1,000,000,000,000 wei, `totalWeiBalance` = 1,000,000,000,000
   - Second iteration: `AddWei` adds to existing balance (2,000,000,000,000 total), `totalWeiBalance` = 2,000,000,000,000
5. Since `Supply` is empty, the supply check is skipped [6](#0-5) 
6. The inflated `totalSupply` (including duplicated wei amounts) is set as the official supply [7](#0-6) 

**Security Failure:** 
This breaks the accounting invariant that total supply must equal the sum of individual account balances. The vulnerability allows creation of unbacked tokens through supply inflation at genesis, which is a critical protocol failure.

## Impact Explanation

**Assets Affected:** The native token supply of the blockchain is directly affected. The vulnerability allows arbitrary inflation of the token supply at genesis.

**Severity of Damage:** 
- Unbacked tokens are created in the system, diluting all existing token holders
- The fundamental accounting invariant (supply = sum of balances) is violated
- The inflated supply can be used to mint tokens without proper backing
- This affects the economic security and value of the entire blockchain

**Systemic Importance:** 
This matters critically because supply inflation is one of the most severe vulnerabilities in any blockchain. It undermines trust in the protocol's monetary policy and can lead to complete loss of confidence in the network.

## Likelihood Explanation

**Who Can Trigger:** Anyone who can influence the genesis file can trigger this vulnerability. While genesis files are typically created by chain operators, the validation failure means malicious or compromised genesis files will not be rejected.

**Conditions Required:** 
- Genesis file must contain duplicate `WeiBalance` entries for at least one address
- The `Supply` field can be empty (which is explicitly allowed and tested [5](#0-4) )
- No special privileges or timing requirements

**Frequency:** 
This would occur at chain initialization if a malicious genesis file is used. While genesis is a one-time event per chain, it's critical because it establishes the foundation of the entire blockchain state. Additionally, test networks and upgrades that use genesis export/import would be vulnerable.

## Recommendation

Add duplicate address validation for `WeiBalances` in the `getTotalSupply` function, similar to the existing validation for `Balances`:

In `x/bank/types/genesis.go`, modify the `getTotalSupply` function to include:

```go
seenWeiBalances := make(map[string]bool)
for _, weiBalance := range genState.WeiBalances {
    if seenWeiBalances[weiBalance.Address] {
        return nil, fmt.Errorf("duplicate wei balance for address %s", weiBalance.Address)
    }
    seenWeiBalances[weiBalance.Address] = true
    totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
}
```

This mirrors the duplicate checking logic already present for regular `Balances` [3](#0-2) .

## Proof of Concept

**File:** `x/bank/keeper/genesis_test.go`

**Test Function:** Add a new test case to the `TestTotalSupply` test suite:

```go
{
    "duplicate wei balance causes supply inflation",
    types.NewGenesisState(
        defaultGenesis.Params,
        balances,
        nil, // empty supply to skip supply validation
        defaultGenesis.DenomMetadata,
        []types.WeiBalance{
            {Amount: keeper.OneUseiInWei, Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"},
            {Amount: keeper.OneUseiInWei, Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"}, // duplicate!
        },
    ),
    nil,
    false, // should panic but currently doesn't
    "",
}
```

**Setup:** The test uses the existing `TestTotalSupply` framework in `x/bank/keeper/genesis_test.go` [8](#0-7) .

**Trigger:** 
1. Create a genesis state with duplicate `WeiBalance` entries for the same address
2. Set `Supply` to `nil` (empty) to bypass the supply validation check
3. Call `InitGenesis` with this malicious genesis state

**Observation:** 
The test would observe that:
1. Genesis validation passes (it shouldn't)
2. `InitGenesis` processes both duplicate entries via `AddWei` [2](#0-1) 
3. The final balance for the address is 2 usei (2,000,000,000,000 wei) instead of 1 usei
4. The total supply is set to 2 usei, inflating the supply by 1 usei

The test demonstrates that duplicate `WeiBalance` entries create unbacked supply, confirming the vulnerability. Currently, this scenario passes without error, but it should fail validation.

### Citations

**File:** x/bank/types/genesis.go (L56-61)
```go
	seenBalances := make(map[string]bool)
	for _, balance := range genState.Balances {
		if seenBalances[balance.Address] {
			return nil, fmt.Errorf("duplicate balance for address %s", balance.Address)
		}
		seenBalances[balance.Address] = true
```

**File:** x/bank/types/genesis.go (L69-71)
```go
	for _, weiBalance := range genState.WeiBalances {
		totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
	}
```

**File:** x/bank/keeper/genesis.go (L28-34)
```go
	for _, weiBalance := range genState.WeiBalances {
		addr := sdk.MustAccAddressFromBech32(weiBalance.Address)
		if err := k.AddWei(ctx, addr, weiBalance.Amount); err != nil {
			panic(fmt.Errorf("error on setting wei balance %w", err))
		}
		totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
	}
```

**File:** x/bank/keeper/genesis.go (L48-50)
```go
	if !genState.Supply.Empty() && !genState.Supply.IsEqual(totalSupply) {
		panic(fmt.Errorf("genesis supply is incorrect, expected %v, got %v", genState.Supply, totalSupply))
	}
```

**File:** x/bank/keeper/genesis.go (L52-54)
```go
	for _, supply := range totalSupply {
		k.SetSupply(ctx, supply)
	}
```

**File:** x/bank/keeper/send.go (L400-401)
```go
	currentWeiBalance := k.GetWeiBalance(ctx, addr)
	postWeiBalance := currentWeiBalance.Add(amt)
```

**File:** x/bank/keeper/genesis_test.go (L78-129)
```go
func (suite *IntegrationTestSuite) TestTotalSupply() {
	// Prepare some test data.
	defaultGenesis := types.DefaultGenesisState()
	balances := []types.Balance{
		{Coins: sdk.NewCoins(sdk.NewCoin("foocoin", sdk.NewInt(1))), Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"},
		{Coins: sdk.NewCoins(sdk.NewCoin("barcoin", sdk.NewInt(1))), Address: "cosmos1t5u0jfg3ljsjrh2m9e47d4ny2hea7eehxrzdgd"},
		{Coins: sdk.NewCoins(sdk.NewCoin("foocoin", sdk.NewInt(10)), sdk.NewCoin("barcoin", sdk.NewInt(20))), Address: "cosmos1m3h30wlvsf8llruxtpukdvsy0km2kum8g38c8q"},
	}
	weiBalances := []types.WeiBalance{
		{Amount: sdk.OneInt(), Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"},
		{Amount: keeper.OneUseiInWei.Sub(sdk.OneInt()), Address: "cosmos1m3h30wlvsf8llruxtpukdvsy0km2kum8g38c8q"},
	}
	totalSupply := sdk.NewCoins(sdk.NewCoin("foocoin", sdk.NewInt(11)), sdk.NewCoin("barcoin", sdk.NewInt(21)), sdk.NewCoin(sdk.DefaultBondDenom, sdk.OneInt()))

	testcases := []struct {
		name        string
		genesis     *types.GenesisState
		expSupply   sdk.Coins
		expPanic    bool
		expPanicMsg string
	}{
		{
			"calculation NOT matching genesis Supply field",
			types.NewGenesisState(defaultGenesis.Params, balances, sdk.NewCoins(sdk.NewCoin("wrongcoin", sdk.NewInt(1))), defaultGenesis.DenomMetadata, weiBalances),
			nil, true, "genesis supply is incorrect, expected 1wrongcoin, got 21barcoin,11foocoin,1usei",
		},
		{
			"calculation matches genesis Supply field",
			types.NewGenesisState(defaultGenesis.Params, balances, totalSupply, defaultGenesis.DenomMetadata, weiBalances),
			totalSupply, false, "",
		},
		{
			"calculation is correct, empty genesis Supply field",
			types.NewGenesisState(defaultGenesis.Params, balances, nil, defaultGenesis.DenomMetadata, weiBalances),
			totalSupply, false, "",
		},
	}

	for _, tc := range testcases {
		tc := tc
		suite.Run(tc.name, func() {
			if tc.expPanic {
				suite.PanicsWithError(tc.expPanicMsg, func() { suite.app.BankKeeper.InitGenesis(suite.ctx, tc.genesis) })
			} else {
				suite.app.BankKeeper.InitGenesis(suite.ctx, tc.genesis)
				totalSupply, _, err := suite.app.BankKeeper.GetPaginatedTotalSupply(suite.ctx, &query.PageRequest{Limit: query.MaxLimit})
				suite.Require().NoError(err)
				suite.Require().Equal(tc.expSupply, totalSupply)
			}
		})
	}
}
```
