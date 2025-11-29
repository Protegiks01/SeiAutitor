# Audit Report

## Title
Genesis Validation Bypass Allows Node Panic via Empty Granter/Grantee Addresses in Authz Module

## Summary
The authz module's `ValidateGenesis` function returns `nil` without performing any validation on granter and grantee addresses in the genesis state. When `InitGenesis` subsequently processes these entries using `MustAccAddressFromBech32`, empty or invalid addresses cause a panic, resulting in all nodes crashing on startup and preventing network initialization. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Primary vulnerability: `x/authz/genesis.go` at the `ValidateGenesis` function (lines 14-17)
- Panic trigger: `x/authz/keeper/keeper.go` at the `InitGenesis` function (lines 246-260) [2](#0-1) 

**Intended Logic:** 
The `ValidateGenesis` function is documented to "check the given genesis state has no integrity issues" and should validate that all granter and grantee addresses are valid, non-empty bech32 addresses before chain initialization. This validation layer exists to catch data integrity issues early, preventing runtime failures.

**Actual Logic:** 
The `ValidateGenesis` function returns `nil` immediately without performing any validation checks. This allows genesis files containing empty or malformed addresses to pass validation. During `InitGenesis`, the keeper calls `sdk.MustAccAddressFromBech32()` on both granter and grantee addresses, which explicitly panics when encountering empty strings or invalid bech32 format. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Genesis file is created for new chain initialization or chain upgrade containing authz grant entries with empty/invalid granter or grantee addresses (can occur through bugs in genesis generation tooling, manual errors, or data corruption)
2. The `validate-genesis` command is run, which calls `BasicManager.ValidateGenesis()`
3. For the authz module, `AppModuleBasic.ValidateGenesis()` is invoked, which calls `authz.ValidateGenesis(data)`
4. Validation passes because `ValidateGenesis()` returns `nil` without checking addresses
5. Nodes attempt to start using this genesis file
6. During initialization, `AppModule.InitGenesis()` calls `keeper.InitGenesis()`
7. The keeper iterates through authorization entries and calls `sdk.MustAccAddressFromBech32(entry.Grantee)` and `sdk.MustAccAddressFromBech32(entry.Granter)`
8. `MustAccAddressFromBech32` calls `AccAddressFromBech32`, which returns error "empty address string is not allowed" for empty strings
9. `MustAccAddressFromBech32` panics with this error
10. All validator nodes crash on startup, preventing network initialization [5](#0-4) [6](#0-5) 

**Security Guarantee Broken:** 
This violates the defense-in-depth principle and the data integrity validation guarantee. The validation layer fails to prevent invalid data from entering the initialization process, and the subsequent panic causes a complete denial of service. The documented purpose of `ValidateGenesis` is to catch integrity issues, but it performs no checks.

## Impact Explanation

**Affected Components:**
- **Network availability**: All validator nodes attempting to initialize with invalid genesis data
- **Chain initialization**: The entire network cannot start if the genesis contains invalid authz grants  
- **Node operation**: Individual nodes crash immediately on startup with unrecoverable panic

**Severity of Damage:**
- **Complete network shutdown**: If the invalid genesis is used for chain initialization or upgrade, no nodes can start
- **Persistent until manual intervention**: Nodes will panic on every restart attempt until the genesis file is manually corrected
- **No transaction processing**: Because nodes cannot complete initialization, no blocks can be produced and no transactions can be confirmed

**System Security Impact:**
This vulnerability creates a critical single point of failure during chain initialization and upgrades. While it requires the invalid genesis to be adopted (through coordination or tooling), the validation layer's failure to detect the issue means that:
- Bugs in genesis generation tooling can cause network-wide outages
- Manual errors in genesis file creation go undetected until it's too late
- Data corruption during genesis file transmission is not caught
- No safety net exists to prevent initialization failures from invalid data

## Likelihood Explanation

**Who Can Trigger It:**
This can be triggered inadvertently by anyone involved in genesis creation:
- Core developers creating genesis files for new chains
- Teams setting up testnets who may make manual errors
- Genesis generation tools with bugs that produce invalid output
- Data corruption during genesis file transmission or storage

**Conditions Required:**
- The invalid genesis file must be adopted by the network (through coordination, governance, or initial chain setup)
- The authz module must be enabled (standard in Cosmos SDK chains)
- At least one grant entry in the genesis must contain an empty or invalid granter/grantee address

**Frequency:**
- Most likely during testnet launches, mainnet launches, or chain upgrades when genesis files are actively being created or modified
- Can occur from legitimate bugs in tooling rather than malicious intent
- Once triggered, affects all nodes attempting to start with that genesis
- Repeatable on every node restart until the genesis file is manually corrected

**Comparison with Other Modules:**
Other modules in the same codebase properly implement genesis validation. For example, the feegrant module validates its genesis data by calling `ValidateBasic()` on each grant, and the bank module's Balance type validates addresses using `AccAddressFromBech32()`. This demonstrates that the authz module's lack of validation is an incomplete implementation rather than intentional design. [7](#0-6) [8](#0-7) 

## Recommendation

Implement proper validation in the `ValidateGenesis` function to verify all granter and grantee addresses before allowing genesis initialization:

```go
func ValidateGenesis(data GenesisState) error {
    for _, grant := range data.Authorization {
        // Validate granter address
        if len(strings.TrimSpace(grant.Granter)) == 0 {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "granter address cannot be empty")
        }
        if _, err := sdk.AccAddressFromBech32(grant.Granter); err != nil {
            return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid granter address: %s", err)
        }
        
        // Validate grantee address
        if len(strings.TrimSpace(grant.Grantee)) == 0 {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "grantee address cannot be empty")
        }
        if _, err := sdk.AccAddressFromBech32(grant.Grantee); err != nil {
            return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid grantee address: %s", err)
        }
        
        // Additional validation: granter and grantee should not be identical
        if grant.Granter == grant.Grantee {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be the same")
        }
    }
    return nil
}
```

This ensures that invalid addresses are caught during the validation phase rather than causing panics during initialization, following the pattern used by other modules in the codebase.

## Proof of Concept

**Test File:** `x/authz/keeper/genesis_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func (suite *GenesisTestSuite) TestInitGenesisWithEmptyGranterPanics() {
    now := suite.ctx.BlockHeader().Time
    
    // Create a SendAuthorization
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    grant := &bank.SendAuthorization{SpendLimit: coins}
    
    // Convert to Any
    authAny, err := cdctypes.NewAnyWithValue(grant)
    suite.Require().NoError(err)
    
    // Create genesis state with empty granter address
    genesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       "", // Empty - will cause panic
                Grantee:       granteeAddr.String(),
                Authorization: authAny,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // This panics because MustAccAddressFromBech32 is called with empty string
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, genesis)
    })
}

func (suite *GenesisTestSuite) TestValidateGenesisDoesNotCatchEmptyAddresses() {
    now := suite.ctx.BlockHeader().Time
    
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    grant := &bank.SendAuthorization{SpendLimit: coins}
    
    authAny, err := cdctypes.NewAnyWithValue(grant)
    suite.Require().NoError(err)
    
    // Genesis with empty addresses
    genesisData := authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       "",
                Grantee:       "",
                Authorization: authAny,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // ValidateGenesis incorrectly returns no error
    err = authz.ValidateGenesis(genesisData)
    suite.Require().NoError(err)
}
```

**Setup:** Uses the existing `GenesisTestSuite` with initialized test context and keeper.

**Action:** Creates a `GenesisState` with authorization grants containing empty granter/grantee addresses, then calls `InitGenesis`.

**Result:** `InitGenesis` panics when `MustAccAddressFromBech32` attempts to parse empty strings, while `ValidateGenesis` incorrectly returns no error, demonstrating that the validation layer fails to catch the invalid data.

## Notes

This vulnerability represents a defense-in-depth failure where the validation layer exists but does not perform its documented function. The impact matches the provided severity criteria: "Network not being able to confirm new transactions (total network shutdown)" classified as High severity. The issue can be triggered through legitimate bugs or errors in genesis creation processes, not just malicious intent, making it a realistic threat to network availability during critical initialization phases.

### Citations

**File:** x/authz/genesis.go (L14-17)
```go
// ValidateGenesis check the given genesis state has no integrity issues
func ValidateGenesis(data GenesisState) error {
	return nil
}
```

**File:** x/authz/keeper/keeper.go (L246-260)
```go
func (k Keeper) InitGenesis(ctx sdk.Context, data *authz.GenesisState) {
	for _, entry := range data.Authorization {
		grantee := sdk.MustAccAddressFromBech32(entry.Grantee)
		granter := sdk.MustAccAddressFromBech32(entry.Granter)
		a, ok := entry.Authorization.GetCachedValue().(authz.Authorization)
		if !ok {
			panic("expected authorization")
		}

		err := k.SaveGrant(ctx, grantee, granter, a, entry.Expiration)
		if err != nil {
			panic(err)
		}
	}
}
```

**File:** types/address.go (L157-165)
```go
// MustAccAddressFromBech32 calls AccAddressFromBech32 and panics on error.
func MustAccAddressFromBech32(address string) AccAddress {
	addr, err := AccAddressFromBech32(address)
	if err != nil {
		panic(err)
	}

	return addr
}
```

**File:** types/address.go (L168-171)
```go
func AccAddressFromBech32(address string) (addr AccAddress, err error) {
	if len(strings.TrimSpace(address)) == 0 {
		return AccAddress{}, errors.New("empty address string is not allowed")
	}
```

**File:** x/authz/module/module.go (L63-71)
```go
// ValidateGenesis performs genesis state validation for the authz module.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config sdkclient.TxEncodingConfig, bz json.RawMessage) error {
	var data authz.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return sdkerrors.Wrapf(err, "failed to unmarshal %s genesis state", authz.ModuleName)
	}

	return authz.ValidateGenesis(data)
}
```

**File:** x/genutil/client/cli/validate_genesis.go (L54-62)
```go

			var genState map[string]json.RawMessage
			if err = json.Unmarshal(genDoc.AppState, &genState); err != nil {
				return fmt.Errorf("error unmarshalling genesis doc %s: %s", genesis, err.Error())
			}

			if err = mbm.ValidateGenesis(cdc, clientCtx.TxConfig, genState); err != nil {
				return fmt.Errorf("error validating genesis file %s: %s", genesis, err.Error())
			}
```

**File:** x/feegrant/genesis.go (L16-29)
```go
// ValidateGenesis ensures all grants in the genesis state are valid
func ValidateGenesis(data GenesisState) error {
	for _, f := range data.Allowances {
		grant, err := f.GetGrant()
		if err != nil {
			return err
		}
		err = grant.ValidateBasic()
		if err != nil {
			return err
		}
	}
	return nil
}
```

**File:** x/bank/types/balance.go (L25-36)
```go
// Validate checks for address and coins correctness.
func (b Balance) Validate() error {
	if _, err := sdk.AccAddressFromBech32(b.Address); err != nil {
		return err
	}

	if err := b.Coins.Validate(); err != nil {
		return err
	}

	return nil
}
```
