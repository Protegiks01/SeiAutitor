# Audit Report

## Title
Chain Fails to Start When Genesis Contains Wei Balances Due to Missing Base Denom Registration

## Summary
The bank keeper's `InitGenesis` function panics during chain initialization when the genesis state contains wei balances but `sdk.RegisterDenom()` has never been called. Since `RegisterDenom()` is only invoked in test setup functions and never in the production application startup sequence, any genesis file containing wei balances will cause total network shutdown, preventing all validators from starting the chain. [1](#0-0) 

## Impact
High

## Finding Description

**Location:**
- Primary: `x/bank/keeper/genesis.go`, lines 39-46 in the `InitGenesis` function
- Secondary: `types/denom.go`, lines 48-54 in the `GetBaseDenom` function [1](#0-0) [2](#0-1) 

**Intended logic:** 
The code expects that `sdk.RegisterDenom()` is called during application startup to register the base denomination before `InitGenesis` processes wei balances. Wei balances (with 18-decimal precision) should be converted to the base denomination during genesis initialization for EVM compatibility. [3](#0-2) 

**Actual logic:**
`sdk.RegisterDenom()` is never called in the production startup path. The function only appears in test setup code. The package-level variable `baseDenom` remains an empty string. When `InitGenesis` processes wei balances:
1. Wei balances are accumulated into `weiInUsei`
2. The code calls `sdk.GetBaseDenom()` which returns an error ("no denom is registered") because `baseDenom` is empty
3. Since `weiInUsei` is non-zero, the panic condition triggers
4. All validator nodes fail with: "base denom is not registered ... yet there exists wei balance" [4](#0-3) [5](#0-4) [6](#0-5) 

**Exploitation path:**
1. Chain operators prepare a genesis file with wei balances (a documented feature for EVM compatibility)
2. Validators execute normal chain startup (`simd start`)
3. During ABCI `InitChain`, the module manager calls `bank.InitGenesis`
4. InitGenesis processes wei balances but panics due to unregistered base denomination
5. All validator nodes crash before producing any blocks [7](#0-6) [8](#0-7) 

**Security guarantee broken:**
Network availability - the chain cannot initialize and produce blocks despite using documented features correctly.

## Impact Explanation

This vulnerability causes complete network shutdown. When a genesis file contains wei balances:
- 100% of validator nodes panic on startup with identical errors
- The chain cannot produce any blocks or process transactions (zero throughput)
- Network is completely non-functional until codebase is patched or genesis is modified
- All users, validators, and applications depending on the network are affected

Wei balances are a core feature providing 18-decimal precision for EVM compatibility (similar to Ethereum's wei system with `OneUseiInWei = 1,000,000,000,000`). The feature is properly implemented throughout the banking module but the initialization sequence is broken. [9](#0-8) 

## Likelihood Explanation

The likelihood is HIGH for any chain attempting to use wei balances in genesis:

**Triggering conditions:**
- Genesis file contains non-zero wei balances in the bank module's `WeiBalances` field
- Chain performs initial startup or restarts from genesis (e.g., during upgrades)
- Normal chain startup procedure is followed

**Probability factors:**
- Wei balances are documented in the proto definition as a standard feature
- EVM compatibility is a key feature of Sei (requiring wei precision)
- Genesis files commonly initialize balances for token distribution
- This will trigger 100% of the time when wei balances are present
- Every validator is affected identically

While controlled by chain operators (trusted role), using wei balances is a legitimate, documented use case - not misconfiguration. The resulting unrecoverable failure extends beyond the operators' intended authority.

## Recommendation

Add `sdk.RegisterDenom()` call in the application initialization before modules are initialized. Implement in `simapp/simd/cmd/root.go` in the `initRootCmd` function before `cfg.Seal()`:

```go
func initRootCmd(rootCmd *cobra.Command, encodingConfig params.EncodingConfig) {
    cfg := sdk.GetConfig()
    // Register the base denomination before sealing config
    if err := sdk.RegisterDenom(sdk.DefaultBondDenom, sdk.OneDec()); err != nil {
        panic(err)
    }
    cfg.Seal()
    // ... rest of function
}
```

This ensures the base denomination is registered before any module initialization occurs, matching the pattern used in all test files. [10](#0-9) 

## Proof of Concept

**Setup:**
Create a genesis state with wei balances without calling `sdk.RegisterDenom()` to simulate production startup behavior.

**Action:**
Call `InitGenesis` with the genesis state containing wei balances through the normal chain initialization sequence (ABCI `InitChain` → `app.InitChainer` → `app.mm.InitGenesis` → `bank.InitGenesis`). [11](#0-10) 

**Result:**
The function panics with error: "base denom is not registered no denom is registered yet there exists wei balance X", preventing the chain from starting. This can be verified by examining the existing test suite which always calls `sdk.RegisterDenom()` before testing genesis with wei balances, demonstrating awareness of this dependency.

The vulnerability is reproducible 100% of the time when genesis contains wei balances and proves that production chains would experience total startup failure when attempting to use this documented feature.

### Citations

**File:** x/bank/keeper/genesis.go (L39-46)
```go
	baseDenom, err := sdk.GetBaseDenom()
	if err != nil {
		if !weiInUsei.IsZero() {
			panic(fmt.Errorf("base denom is not registered %s yet there exists wei balance %s", err, weiInUsei))
		}
	} else {
		totalSupply = totalSupply.Add(sdk.NewCoin(baseDenom, weiInUsei))
	}
```

**File:** types/denom.go (L14-31)
```go
// RegisterDenom registers a denomination with a corresponding unit. If the
// denomination is already registered, an error will be returned.
func RegisterDenom(denom string, unit Dec) error {
	if err := ValidateDenom(denom); err != nil {
		return err
	}

	if _, ok := denomUnits[denom]; ok {
		return fmt.Errorf("denom %s already registered", denom)
	}

	denomUnits[denom] = unit

	if baseDenom == "" || unit.LT(denomUnits[baseDenom]) {
		baseDenom = denom
	}
	return nil
}
```

**File:** types/denom.go (L48-54)
```go
// GetBaseDenom returns the denom of smallest unit registered
func GetBaseDenom() (string, error) {
	if baseDenom == "" {
		return "", fmt.Errorf("no denom is registered")
	}
	return baseDenom, nil
}
```

**File:** simapp/simd/cmd/root.go (L149-152)
```go
func initRootCmd(rootCmd *cobra.Command, encodingConfig params.EncodingConfig) {
	cfg := sdk.GetConfig()
	cfg.Seal()

```

**File:** simapp/simd/main.go (L12-24)
```go
func main() {
	rootCmd, _ := cmd.NewRootCmd()

	if err := svrcmd.Execute(rootCmd, simapp.DefaultNodeHome); err != nil {
		switch e := err.(type) {
		case server.ErrorCode:
			os.Exit(e.Code)

		default:
			os.Exit(1)
		}
	}
}
```

**File:** x/bank/keeper/keeper_test.go (L100-101)
```go
func (suite *IntegrationTestSuite) SetupTest() {
	sdk.RegisterDenom(sdk.DefaultBondDenom, sdk.OneDec())
```

**File:** simapp/app.go (L591-599)
```go
// InitChainer application update at chain initialization
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
	return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
}
```

**File:** proto/cosmos/bank/v1beta1/genesis.proto (L26-28)
```text
  // wei balances
  repeated WeiBalance wei_balances = 5 [(gogoproto.nullable) = false];
}
```

**File:** x/bank/keeper/send.go (L52-52)
```go
var OneUseiInWei sdk.Int = sdk.NewInt(1_000_000_000_000)
```

**File:** types/staking.go (L7-7)
```go
	DefaultBondDenom = "usei"
```

**File:** x/bank/keeper/genesis_test.go (L86-89)
```go
	weiBalances := []types.WeiBalance{
		{Amount: sdk.OneInt(), Address: "cosmos1f9xjhxm0plzrh9cskf4qee4pc2xwp0n0556gh0"},
		{Amount: keeper.OneUseiInWei.Sub(sdk.OneInt()), Address: "cosmos1m3h30wlvsf8llruxtpukdvsy0km2kum8g38c8q"},
	}
```
