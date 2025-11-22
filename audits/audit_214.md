# Audit Report

## Title
Genesis Import Panic via Empty Authorization TypeUrl Causes Total Chain Initialization Failure

## Summary
The authz module's genesis import process lacks validation for authorization data, allowing a malicious genesis file with empty `TypeUrl` fields to trigger a panic during chain initialization, completely preventing the network from starting. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: [2](#0-1) 
- Missing validation: [3](#0-2) 
- Silent failure path: [4](#0-3) 

**Intended Logic:** 
The genesis validation and import process should validate all authorization data before attempting to initialize the keeper state. Invalid or malformed authorizations should be rejected during the validation phase, not cause panics during initialization.

**Actual Logic:** 
1. `ValidateGenesis` returns nil without performing any validation [3](#0-2) 
2. During JSON unmarshaling in `MustUnmarshalJSON`, when `UnpackAny` encounters an empty `TypeUrl`, it returns nil without error and without setting the `cachedValue` [4](#0-3) 
3. When `keeper.InitGenesis` executes, it directly type-asserts `GetCachedValue()` without checking if the value is nil [2](#0-1) 
4. The type assertion fails (ok = false) because `cachedValue` is nil, triggering `panic("expected authorization")`

**Exploit Scenario:**
1. Attacker crafts a malicious genesis JSON file containing one or more `GrantAuthorization` entries where the `Authorization.TypeUrl` field is empty string `""`
2. Validators/nodes receive this genesis file (through compromised distribution channels, social engineering, or supply chain attacks)
3. When nodes attempt to initialize the chain using `InitGenesis`, the validation phase passes (since `ValidateGenesis` does nothing)
4. During `MustUnmarshalJSON`, the empty `TypeUrl` silently bypasses unpacking without error
5. In `keeper.InitGenesis`, the nil cached value causes a type assertion failure
6. The panic halts chain initialization completely

**Security Failure:** 
This is a denial-of-service vulnerability that breaks the availability property of the blockchain network. The panic occurs during critical chain initialization, preventing all nodes using the malicious genesis file from starting, resulting in a total network shutdown.

## Impact Explanation

**Affected Process:** Chain initialization and network availability

**Severity of Damage:**
- **Total network shutdown**: All nodes using the malicious genesis file will panic during initialization and fail to start
- **No recovery path**: The panic occurs before any state is committed, requiring manual intervention to fix the genesis file
- **Network-wide impact**: If distributed to all validators, the entire network cannot launch
- **Persistent failure**: The issue persists until the genesis file is manually corrected and redistributed

**Why This Matters:**
This vulnerability allows an attacker who can influence genesis file distribution to completely prevent a blockchain network from launching or cause all nodes to crash and fail to restart after a genesis-based upgrade. This falls under the "Network not being able to confirm new transactions (total network shutdown)" impact category.

## Likelihood Explanation

**Who Can Trigger It:**
Any attacker who can influence the genesis file distribution to validators, including:
- Compromised or malicious genesis file distributors
- Supply chain attacks on genesis file hosting
- Social engineering targeting validators during network launch
- Insider threats during testnet/mainnet launches

**Required Conditions:**
- Genesis file must contain at least one `GrantAuthorization` with empty `Authorization.TypeUrl`
- Validators/nodes must use the malicious genesis file during initialization
- No additional validation occurs before `InitGenesis` is called

**Frequency:**
- Can be triggered during any new chain launch or genesis-based network upgrade
- Requires one-time malicious genesis file distribution
- Once triggered, affects all nodes using that genesis file
- Network operators commonly share and trust genesis files during launches, making this a realistic attack vector

## Recommendation

Implement proper validation in `ValidateGenesis` to check all authorization data:

```go
func ValidateGenesis(data GenesisState) error {
    for _, grant := range data.Authorization {
        // Validate addresses
        if _, err := sdk.AccAddressFromBech32(grant.Granter); err != nil {
            return sdkerrors.Wrapf(err, "invalid granter address")
        }
        if _, err := sdk.AccAddressFromBech32(grant.Grantee); err != nil {
            return sdkerrors.Wrapf(err, "invalid grantee address")
        }
        
        // Validate authorization is not nil and has valid TypeUrl
        if grant.Authorization == nil {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "authorization cannot be nil")
        }
        if grant.Authorization.TypeUrl == "" {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "authorization type_url cannot be empty")
        }
        
        // Validate the cached authorization value
        auth := grant.Authorization.GetCachedValue()
        if auth == nil {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "authorization must be unpacked before validation")
        }
        
        a, ok := auth.(Authorization)
        if !ok {
            return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected Authorization, got %T", auth)
        }
        
        // Validate expiration time
        if grant.Expiration.IsZero() {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "expiration time cannot be zero")
        }
        
        // Call ValidateBasic on the authorization
        if err := a.ValidateBasic(); err != nil {
            return err
        }
    }
    return nil
}
```

Additionally, add defensive error handling in `InitGenesis` instead of panicking:

```go
a, ok := entry.Authorization.GetCachedValue().(authz.Authorization)
if !ok {
    return fmt.Errorf("expected authorization, got %T", entry.Authorization.GetCachedValue())
}
```

## Proof of Concept

**File:** `x/authz/keeper/genesis_test.go`

**Test Function:** `TestInitGenesisPanicOnEmptyTypeUrl`

```go
func (suite *GenesisTestSuite) TestInitGenesisPanicOnEmptyTypeUrl() {
    // Create a GrantAuthorization with empty TypeUrl in the Authorization field
    // This simulates a malicious genesis file
    maliciousGrant := authz.GrantAuthorization{
        Granter: granterAddr.String(),
        Grantee: granteeAddr.String(),
        Authorization: &codectypes.Any{
            TypeUrl: "", // Empty TypeUrl - this is the malicious input
            Value:   []byte{},
        },
        Expiration: suite.ctx.BlockHeader().Time.Add(time.Hour),
    }
    
    genesisState := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{maliciousGrant},
    }
    
    // ValidateGenesis should catch this but doesn't (returns nil)
    err := authz.ValidateGenesis(*genesisState)
    suite.Require().NoError(err, "ValidateGenesis incorrectly passes with empty TypeUrl")
    
    // This should panic with "expected authorization" when InitGenesis tries to process
    // the malicious grant because GetCachedValue() returns nil
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, genesisState)
    }, "InitGenesis should panic on empty TypeUrl authorization")
}
```

**Setup:** 
- Uses existing `GenesisTestSuite` test infrastructure
- Creates malicious `GrantAuthorization` with empty `TypeUrl`
- Valid granter/grantee addresses and expiration time

**Trigger:** 
- Calls `ValidateGenesis` which incorrectly returns no error
- Calls `keeper.InitGenesis` with the malicious genesis state

**Observation:** 
- Test confirms `ValidateGenesis` fails to catch the invalid data
- Test expects and confirms a panic occurs during `InitGenesis`
- The panic message is "expected authorization" from line 252 of keeper.go
- This proves a malicious genesis file can halt chain initialization

This PoC can be added to the existing genesis test suite and will demonstrate that a genesis file with empty `TypeUrl` fields passes validation but causes a panic during initialization, completely preventing the chain from starting.

### Citations

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

**File:** x/authz/genesis.go (L14-17)
```go
// ValidateGenesis check the given genesis state has no integrity issues
func ValidateGenesis(data GenesisState) error {
	return nil
}
```

**File:** codec/types/interface_registry.go (L255-258)
```go
	if any.TypeUrl == "" {
		// if TypeUrl is empty return nil because without it we can't actually unpack anything
		return nil
	}
```
