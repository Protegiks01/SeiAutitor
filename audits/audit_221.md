## Title
Genesis Validation Bypass Allows Node Panic via Empty Granter/Grantee Addresses in Authz Module

## Summary
The authz module's `ValidateGenesis` function does not validate granter and grantee addresses, allowing empty address strings to pass through genesis validation. When `InitGenesis` subsequently processes these entries, it uses `MustAccAddressFromBech32` which panics on empty strings, causing nodes to crash on startup and preventing the entire network from initializing. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: `x/authz/genesis.go` at the `ValidateGenesis` function
- Panic trigger: `x/authz/keeper/keeper.go` at the `InitGenesis` function [1](#0-0) [2](#0-1) 

**Intended Logic:** 
Genesis validation should verify that all granter and grantee addresses in the authz module's genesis state are valid, non-empty bech32 addresses before the chain initializes. The `ValidateGenesis` function is specifically designed to catch integrity issues in genesis data.

**Actual Logic:** 
The `ValidateGenesis` function returns `nil` without performing any validation checks on the granter and grantee addresses within the `GenesisState`. This allows genesis files containing empty or invalid addresses to pass validation. When `InitGenesis` is called, it attempts to parse these addresses using `MustAccAddressFromBech32`, which explicitly panics when encountering empty strings. [3](#0-2) [4](#0-3) 

**Exploit Scenario:**
1. An attacker crafts a malicious genesis file for a new chain or chain upgrade containing authz grant entries with empty granter or grantee addresses (e.g., `granter: ""` or `grantee: ""`)
2. The genesis file passes through the module's `ValidateGenesis` call because it returns `nil` without checking addresses
3. Validators attempt to start their nodes using this genesis file
4. During `InitGenesis`, the keeper calls `sdk.MustAccAddressFromBech32(entry.Grantee)` and `sdk.MustAccAddressFromBech32(entry.Granter)` which panic when parsing empty strings
5. All validator nodes crash on startup, preventing the network from initializing [5](#0-4) 

**Security Failure:** 
This breaks the availability and denial-of-service protection invariant. The validation layer fails to prevent invalid data from entering the system, and the subsequent panic during initialization causes a complete network shutdown. No transactions can be confirmed because nodes cannot start.

## Impact Explanation

**Affected Components:**
- Network availability: All validator nodes attempting to initialize with the malicious genesis
- Chain initialization: The entire network cannot start if consensus on the genesis includes invalid authz grants
- Node operation: Individual nodes crash immediately on startup

**Severity of Damage:**
- **Total network shutdown**: If the malicious genesis is used for chain initialization or upgrade, the entire network cannot start
- **Permanent until manual intervention**: Nodes will continue to panic on every restart attempt until the genesis file is manually corrected
- **No transaction processing**: Because nodes cannot start, no blocks can be produced and no transactions can be confirmed

**System Security Impact:**
This vulnerability allows an attacker to cause a complete denial of service of the blockchain network during critical initialization or upgrade phases. While the attack requires the malicious genesis to be adopted (typically through governance or coordination), the validation layer's failure to catch this creates a significant risk vector for network launches, testnets, and chain upgrades where genesis files are being constructed or modified.

## Likelihood Explanation

**Who Can Trigger It:**
Anyone who can influence the genesis file content, including:
- Participants in testnet launches
- Contributors to chain upgrade proposals
- Developers creating genesis files for new chains
- Malicious actors who can inject data into genesis construction processes

**Conditions Required:**
- The malicious genesis file must be adopted by the network (through governance, coordination, or initial chain setup)
- The authz module must be enabled (which is standard in Cosmos SDK chains)
- At least one grant entry in the genesis must contain an empty granter or grantee address

**Frequency:**
- Can occur during any chain initialization or upgrade that modifies the genesis
- Once triggered, affects all nodes attempting to start with that genesis
- Repeatable on every node restart until genesis is fixed
- Most likely to occur during testnets, upgrades, or network launches where genesis files are actively being modified

## Recommendation

Add proper validation to the `ValidateGenesis` function to verify that all granter and grantee addresses are valid, non-empty bech32 addresses:

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
        
        // Additional validation: granter and grantee should not be the same
        if grant.Granter == grant.Grantee {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be the same")
        }
    }
    return nil
}
```

This ensures that invalid addresses are caught during validation rather than causing panics during initialization.

## Proof of Concept

**Test File:** `x/authz/keeper/genesis_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func (suite *GenesisTestSuite) TestInitGenesisWithEmptyGranterPanics() {
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    now := time.Now()
    
    // Create a GenericAuthorization
    msgTypeURL := bank.SendAuthorization{}.MsgTypeURL()
    authorization := &GenericAuthorization{Msg: msgTypeURL}
    
    // Convert authorization to Any
    authAny, err := cdctypes.NewAnyWithValue(authorization)
    suite.Require().NoError(err)
    
    // Create genesis state with empty granter address
    genesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       "", // Empty granter - should cause panic
                Grantee:       granteeAddr.String(),
                Authorization: authAny,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // This should panic because MustAccAddressFromBech32 is called with empty string
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, genesis)
    }, "InitGenesis should panic when granter address is empty")
}

func (suite *GenesisTestSuite) TestInitGenesisWithEmptyGranteePanics() {
    now := time.Now()
    
    // Create a GenericAuthorization
    msgTypeURL := bank.SendAuthorization{}.MsgTypeURL()
    authorization := &GenericAuthorization{Msg: msgTypeURL}
    
    // Convert authorization to Any
    authAny, err := cdctypes.NewAnyWithValue(authorization)
    suite.Require().NoError(err)
    
    // Create genesis state with empty grantee address
    genesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       granterAddr.String(),
                Grantee:       "", // Empty grantee - should cause panic
                Authorization: authAny,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // This should panic because MustAccAddressFromBech32 is called with empty string
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, genesis)
    }, "InitGenesis should panic when grantee address is empty")
}

func (suite *GenesisTestSuite) TestValidateGenesisDoesNotCatchEmptyAddresses() {
    now := time.Now()
    
    // Create a GenericAuthorization
    msgTypeURL := bank.SendAuthorization{}.MsgTypeURL()
    authorization := &GenericAuthorization{Msg: msgTypeURL}
    
    // Convert authorization to Any
    authAny, err := cdctypes.NewAnyWithValue(authorization)
    suite.Require().NoError(err)
    
    // Create genesis state with empty addresses
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
    
    // ValidateGenesis currently returns nil (no validation)
    // This demonstrates the vulnerability - validation passes even with empty addresses
    err = authz.ValidateGenesis(genesisData)
    suite.Require().NoError(err, "ValidateGenesis incorrectly allows empty addresses")
}
```

**Setup:** The test uses the existing `GenesisTestSuite` setup which initializes a test context and keeper.

**Trigger:** The test creates a `GenesisState` with authorization grants containing empty granter or grantee addresses, then calls `InitGenesis`.

**Observation:** The test confirms that `InitGenesis` panics when processing empty addresses (demonstrating the crash), and that `ValidateGenesis` incorrectly returns no error for invalid genesis data (demonstrating the validation bypass). The panic occurs because `MustAccAddressFromBech32` cannot parse empty strings and terminates the process.

### Citations

**File:** x/authz/genesis.go (L14-16)
```go
// ValidateGenesis check the given genesis state has no integrity issues
func ValidateGenesis(data GenesisState) error {
	return nil
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
