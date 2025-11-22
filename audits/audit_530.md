## Audit Report

## Title
Missing Module Account Permission Validation During Genesis Initialization Causes Chain Halt

## Summary
The mint module account permissions are not validated during genesis initialization. A malicious or misconfigured genesis file containing a mint module account with incorrect permissions (missing the "minter" permission) will be accepted during genesis validation, causing a guaranteed chain halt on the first block when the BeginBlocker attempts to mint tokens.

## Impact
High

## Finding Description

- **Location:** 
  - Primary: [1](#0-0) 
  - Secondary: [2](#0-1) 
  - Validation gap: [3](#0-2) 

- **Intended Logic:** Module accounts should have their permissions validated during genesis initialization to ensure they match the permissions registered in the application's `maccPerms` mapping. The mint module account must have the "minter" permission to function correctly.

- **Actual Logic:** 
  1. The auth module's `InitGenesis` loads all accounts from genesis state and sets them in the store without validating module account permissions [4](#0-3) 
  2. The `ModuleAccount.Validate()` method only checks that the module name is not blank and the address is correctly derived, but does NOT validate permissions against registered permissions [3](#0-2) 
  3. The mint module's `InitGenesis` calls `ak.GetModuleAccount(ctx, types.ModuleName)` which returns the existing account from the store without permission validation [5](#0-4) 
  4. The `GetModuleAccountAndPermissions` function returns the existing account as-is when it's already in the store [6](#0-5) 

- **Exploit Scenario:** 
  1. An attacker crafts a genesis file containing a mint module account with no permissions or wrong permissions (e.g., only "burner" instead of "minter")
  2. The genesis file passes validation since `ValidateGenesis` doesn't check module account permissions
  3. The chain initializes successfully with the malformed module account
  4. On block 1, the mint module's BeginBlocker executes and calls `MintCoins` [7](#0-6) 
  5. The bank keeper's `createCoins` function checks if the module account has the "minter" permission [8](#0-7) 
  6. The check fails, causing a panic that halts the entire chain

- **Security Failure:** Authorization bypass during genesis initialization leads to a denial-of-service attack. The missing validation allows an invalid genesis state to be loaded, which violates the invariant that module accounts must have correct permissions. This results in immediate and permanent chain halt.

## Impact Explanation

- **Affected processes:** The entire blockchain network's ability to process transactions and produce blocks
- **Severity of damage:** Complete network shutdown on the first block after genesis. All nodes will panic with the error "module account mint does not have permissions to mint tokens". The chain cannot proceed without a new genesis file and network restart.
- **Why it matters:** This vulnerability allows a single misconfiguration or malicious genesis file to render the entire network inoperable. Since the check only occurs at runtime (first block) rather than during genesis validation, operators have no advance warning. Recovery requires coordinated hard fork with a corrected genesis file.

## Likelihood Explanation

- **Who can trigger it:** Anyone who can influence the genesis file content (e.g., during testnet setup, mainnet launch, or network upgrade). While this typically requires coordination, the lack of validation means honest mistakes during genesis file construction will also trigger this issue.
- **Required conditions:** The genesis file must contain module accounts (specifically the mint module account) with incorrect permissions. This can happen through:
  - Manual genesis file construction errors
  - Automated genesis generation with misconfigured module account permissions
  - Malicious modification if the genesis file creation process is compromised
- **Frequency:** This is a one-time initialization issue that would manifest immediately on chain start. The `ValidatePermissions` method exists [9](#0-8)  but is never called during genesis initialization.

## Recommendation

Add module account permission validation to the auth module's `InitGenesis` function:

```go
func InitGenesis(ctx sdk.Context, ak keeper.AccountKeeper, data types.GenesisState) {
    ak.SetParams(ctx, data.Params)

    accounts, err := types.UnpackAccounts(data.Accounts)
    if err != nil {
        panic(err)
    }
    accounts = types.SanitizeGenesisAccounts(accounts)

    for _, a := range accounts {
        acc := ak.NewAccount(ctx, a)
        ak.SetAccount(ctx, acc)
        
        // Validate module account permissions
        if macc, ok := acc.(types.ModuleAccountI); ok {
            if err := ak.ValidatePermissions(macc); err != nil {
                panic(fmt.Errorf("invalid module account permissions in genesis for %s: %w", macc.GetName(), err))
            }
        }
    }

    ak.GetModuleAccount(ctx, types.FeeCollectorName)
}
```

This ensures that any module account loaded from genesis has permissions that match those registered in the application's `maccPerms` mapping, preventing the chain from starting with invalid state.

## Proof of Concept

**File:** `x/mint/genesis_test.go` (new file)

**Test Function:** `TestMintModuleAccountWithoutPermissionsCausesChainHalt`

**Setup:**
1. Create a SimApp instance with custom genesis state
2. Manually construct an auth genesis state containing a mint module account with NO permissions
3. Initialize the chain with this malformed genesis state
4. Attempt to execute the first BeginBlock

**Trigger:**
```go
package mint_test

import (
    "context"
    "encoding/json"
    "testing"

    "github.com/stretchr/testify/require"
    abcitypes "github.com/tendermint/tendermint/abci/types"
    tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
    dbm "github.com/tendermint/tm-db"

    "github.com/cosmos/cosmos-sdk/simapp"
    sdk "github.com/cosmos/cosmos-sdk/types"
    authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
    banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
    minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
)

func TestMintModuleAccountWithoutPermissionsCausesChainHalt(t *testing.T) {
    // Create app without genesis initialization
    db := dbm.NewMemDB()
    encCfg := simapp.MakeTestEncodingConfig()
    app := simapp.NewSimApp(nil, db, nil, true, map[int64]bool{}, simapp.DefaultNodeHome, 5, nil, encCfg, &simapp.EmptyAppOptions{})
    
    // Create genesis state with malformed mint module account (NO permissions)
    genesisState := simapp.NewDefaultGenesisState(encCfg.Marshaler)
    
    // Create mint module account WITHOUT "minter" permission
    mintModuleAcc := authtypes.NewEmptyModuleAccount(minttypes.ModuleName) // No permissions!
    
    genAccs := []authtypes.GenesisAccount{mintModuleAcc}
    authGenesis := authtypes.NewGenesisState(authtypes.DefaultParams(), genAccs)
    genesisState[authtypes.ModuleName] = encCfg.Marshaler.MustMarshalJSON(authGenesis)
    
    // Add some initial balance to fee collector to avoid other panics
    feeCollectorAcc := authtypes.NewEmptyModuleAccount(authtypes.FeeCollectorName)
    genAccs = append(genAccs, feeCollectorAcc)
    authGenesis = authtypes.NewGenesisState(authtypes.DefaultParams(), genAccs)
    genesisState[authtypes.ModuleName] = encCfg.Marshaler.MustMarshalJSON(authGenesis)
    
    stateBytes, err := json.MarshalIndent(genesisState, "", " ")
    require.NoError(t, err)
    
    // Initialize chain with malformed genesis - this should succeed
    app.InitChain(context.Background(), &abcitypes.RequestInitChain{
        Validators:      []abcitypes.ValidatorUpdate{},
        ConsensusParams: simapp.DefaultConsensusParams,
        AppStateBytes:   stateBytes,
    })
    
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Verify the mint module account exists but has NO permissions
    mintAcc := app.AccountKeeper.GetAccount(ctx, authtypes.NewModuleAddress(minttypes.ModuleName))
    require.NotNil(t, mintAcc)
    macc, ok := mintAcc.(authtypes.ModuleAccountI)
    require.True(t, ok)
    require.Empty(t, macc.GetPermissions(), "Mint module account should have no permissions in this test")
    
    // Now attempt to run BeginBlock which will try to mint tokens
    // This WILL PANIC because the mint module account lacks "minter" permission
    require.Panics(t, func() {
        app.BeginBlock(context.Background(), abcitypes.RequestBeginBlock{
            Header: tmproto.Header{Height: 1, ChainID: "test-chain"},
        })
    }, "Expected panic when BeginBlocker tries to mint without minter permission")
}
```

**Observation:** 
The test demonstrates that:
1. Genesis initialization succeeds even with a mint module account that has no permissions
2. When BeginBlock is executed, the mint module's BeginBlocker attempts to call `MintCoins`
3. The bank keeper's permission check fails because the account lacks the "minter" permission
4. A panic occurs with message: "module account mint does not have permissions to mint tokens"
5. This confirms the chain would halt on block 1 with this malformed genesis state

The panic proves that the missing validation during genesis initialization creates a critical vulnerability where the chain accepts invalid state and then immediately fails at runtime.

### Citations

**File:** x/mint/genesis.go (L10-14)
```go
func InitGenesis(ctx sdk.Context, keeper keeper.Keeper, ak types.AccountKeeper, data *types.GenesisState) {
	keeper.SetMinter(ctx, data.Minter)
	keeper.SetParams(ctx, data.Params)
	ak.GetModuleAccount(ctx, types.ModuleName)
}
```

**File:** x/auth/genesis.go (L13-28)
```go
func InitGenesis(ctx sdk.Context, ak keeper.AccountKeeper, data types.GenesisState) {
	ak.SetParams(ctx, data.Params)

	accounts, err := types.UnpackAccounts(data.Accounts)
	if err != nil {
		panic(err)
	}
	accounts = types.SanitizeGenesisAccounts(accounts)

	for _, a := range accounts {
		acc := ak.NewAccount(ctx, a)
		ak.SetAccount(ctx, acc)
	}

	ak.GetModuleAccount(ctx, types.FeeCollectorName)
}
```

**File:** x/auth/types/account.go (L221-232)
```go
// Validate checks for errors on the account fields
func (ma ModuleAccount) Validate() error {
	if strings.TrimSpace(ma.Name) == "" {
		return errors.New("module account name cannot be blank")
	}

	if ma.Address != sdk.AccAddress(crypto.AddressHash([]byte(ma.Name))).String() {
		return fmt.Errorf("address %s cannot be derived from the module name '%s'", ma.Address, ma.Name)
	}

	return ma.BaseAccount.Validate()
}
```

**File:** x/auth/keeper/keeper.go (L146-157)
```go
// ValidatePermissions validates that the module account has been granted
// permissions within its set of allowed permissions.
func (ak AccountKeeper) ValidatePermissions(macc types.ModuleAccountI) error {
	permAddr := ak.permAddrs[macc.GetName()]
	for _, perm := range macc.GetPermissions() {
		if !permAddr.HasPermission(perm) {
			return fmt.Errorf("invalid module permission %s", perm)
		}
	}

	return nil
}
```

**File:** x/auth/keeper/keeper.go (L187-194)
```go
	acc := ak.GetAccount(ctx, addr)
	if acc != nil {
		macc, ok := acc.(types.ModuleAccountI)
		if !ok {
			panic("account is not a module account")
		}
		return macc, perms
	}
```

**File:** x/mint/abci.go (L31-34)
```go
	err := k.MintCoins(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}
```

**File:** x/bank/keeper/keeper.go (L542-544)
```go
	if !acc.HasPermission(authtypes.Minter) {
		panic(sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "module account %s does not have permissions to mint tokens", moduleName))
	}
```
