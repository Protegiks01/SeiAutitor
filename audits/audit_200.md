## Title
Missing Genesis Validation Causes Chain Start Failure via Invalid Authorization Addresses

## Summary
The authz module's `ValidateGenesis` function is a no-op that performs no validation on genesis authorization entries. This allows invalid bech32 addresses, empty addresses, or malformed authorizations to be included in the genesis file, causing all nodes to panic during chain initialization when `InitGenesis` calls `sdk.MustAccAddressFromBech32`, resulting in complete network shutdown. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Validation gap: `x/authz/genesis.go` lines 14-17 (`ValidateGenesis` function)
- Panic point: `x/authz/keeper/keeper.go` lines 246-260 (`InitGenesis` function)

**Intended Logic:** 
Before chain initialization, `ValidateGenesis` should validate all genesis state data to ensure it is well-formed and will not cause runtime errors. Specifically for authz, it should validate that all granter/grantee addresses are valid bech32 addresses, are non-empty, are not identical, and that all authorizations are properly formed. This follows the pattern used by other Cosmos SDK modules like feegrant. [2](#0-1) 

**Actual Logic:** 
The authz `ValidateGenesis` function simply returns nil without performing any validation checks: [1](#0-0) 

During chain initialization, `InitGenesis` blindly processes all genesis authorization entries: [3](#0-2) 

When an invalid address is encountered, `sdk.MustAccAddressFromBech32` panics at lines 248-249, causing the node to crash. Similarly, if the authorization is not properly unpacked, line 252 panics.

**Exploit Scenario:**
1. During chain initialization or a coordinated genesis upgrade, a genesis file is created containing authz entries with invalid addresses (e.g., malformed bech32, empty strings, or wrong prefix)
2. The genesis file passes through `ValidateGenesis` without errors since it returns nil
3. Validators and nodes accept the genesis file as valid
4. When any node attempts to start and calls `InitGenesis`, it panics at the first invalid address
5. All nodes in the network fail to start, causing complete network shutdown

**Security Failure:** 
This breaks the **availability** and **consensus initialization** security properties. The genesis validation phase exists specifically to catch malformed data before runtime, but the missing validation allows invalid data to persist until chain start, at which point recovery requires manual intervention and genesis file modification.

## Impact Explanation

**Affected Components:**
- Network availability: All nodes fail to initialize
- Chain state: Cannot begin processing transactions
- Consensus: Cannot establish initial validator set

**Severity of Damage:**
- **Total network shutdown**: No nodes can start, preventing any transaction processing
- **Requires manual intervention**: The genesis file must be manually corrected and redistributed to all validators
- **No automatic recovery**: Unlike runtime panics that can be fixed with upgrades, this prevents the chain from ever starting
- **Affects critical operations**: Impacts new chain launches, hard forks, and major upgrades that modify genesis

**Why This Matters:**
This vulnerability can cause a complete denial of service at the most critical phase - chain initialization. In contrast to runtime bugs that can be patched via governance proposals, a genesis validation failure prevents the chain from ever starting, requiring coordinated manual intervention from all validators. This is particularly severe for:
- New chain launches where initial genesis misconfiguration causes immediate failure
- Hard fork upgrades where export/import of state with invalid authz grants causes network-wide outage
- Coordinated attacks during genesis ceremony where malicious participants inject invalid data

## Likelihood Explanation

**Who Can Trigger:**
This can be triggered by anyone who can influence the genesis file content:
- During new chain initialization: validators participating in the genesis ceremony
- During chain upgrades: anyone who can propose or contribute to the exported/modified genesis state
- Accidental triggers: operators making manual edits to genesis files without proper validation tools

**Conditions Required:**
- Genesis file must contain authz authorization entries with:
  - Invalid bech32 addresses (malformed encoding)
  - Empty granter or grantee address strings
  - Addresses with wrong bech32 prefix
  - Authorizations that fail to unpack properly
- The modified genesis must be accepted by validators (which it will be, since ValidateGenesis passes)

**Frequency:**
- **High likelihood during genesis operations**: Every time a genesis file is manually edited or generated programmatically without external validation
- **Can occur accidentally**: Simple typos or copy-paste errors in genesis file editing
- **No protection**: Currently zero validation means 100% of invalid authz entries will cause startup failure
- **Recurring risk**: Every chain upgrade or fork that involves genesis export/import is vulnerable

The likelihood is particularly high because:
1. The validation gap affects normal operational procedures (upgrades, forks)
2. Genesis files are often manually edited or generated by scripts
3. There is no warning or error until the critical moment of chain start
4. MsgGrant has proper validation, creating a false sense of security that genesis would too

## Recommendation

Implement proper genesis validation in the `ValidateGenesis` function by following the pattern used in other modules like feegrant. The validation should:

1. **Iterate through all authorization entries** in the genesis state
2. **Validate addresses**: Check that granter and grantee are valid bech32 addresses using `sdk.AccAddressFromBech32` (not the Must variant)
3. **Check for self-grants**: Verify granter and grantee are not the same address
4. **Validate authorization content**: Unpack and call `ValidateBasic()` on each authorization
5. **Check for empty fields**: Ensure no required fields are empty

Example implementation structure:

```go
func ValidateGenesis(data GenesisState) error {
    for _, entry := range data.Authorization {
        // Validate granter address
        _, err := sdk.AccAddressFromBech32(entry.Granter)
        if err != nil {
            return sdkerrors.Wrap(err, "invalid granter address")
        }
        
        // Validate grantee address  
        _, err = sdk.AccAddressFromBech32(entry.Grantee)
        if err != nil {
            return sdkerrors.Wrap(err, "invalid grantee address")
        }
        
        // Check not self-grant
        if entry.Granter == entry.Grantee {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
        }
        
        // Validate authorization
        authorization, ok := entry.Authorization.GetCachedValue().(Authorization)
        if !ok {
            return sdkerrors.Wrap(sdkerrors.ErrInvalidType, "failed to unpack authorization")
        }
        
        if err := authorization.ValidateBasic(); err != nil {
            return err
        }
    }
    return nil
}
```

This follows the same validation pattern as `MsgGrant.ValidateBasic()`: [4](#0-3) 

## Proof of Concept

**File:** `x/authz/keeper/genesis_test.go`

**Test Function:** Add the following test case to demonstrate the panic:

```go
func (suite *GenesisTestSuite) TestInitGenesisWithInvalidAddress() {
    // This test demonstrates that InitGenesis panics when genesis contains
    // invalid addresses because ValidateGenesis does not validate them
    
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    now := suite.ctx.BlockHeader().Time
    grant := &bank.SendAuthorization{SpendLimit: coins}
    
    // Create authorization with properly packed grant
    msg, _ := grant.(proto.Message)
    any, _ := codectypes.NewAnyWithValue(msg)
    
    // Create genesis state with INVALID bech32 addresses
    invalidGenesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       "invalid-address",  // Invalid bech32 address
                Grantee:       granteeAddr.String(),
                Authorization: any,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // ValidateGenesis should fail but doesn't - it returns nil
    err := authz.ValidateGenesis(*invalidGenesis)
    suite.Require().NoError(err, "ValidateGenesis incorrectly passes invalid genesis")
    
    // InitGenesis will panic when it tries to process the invalid address
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, invalidGenesis)
    }, "InitGenesis should panic on invalid granter address")
}

func (suite *GenesisTestSuite) TestInitGenesisWithEmptyAddress() {
    // Test with empty addresses
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    now := suite.ctx.BlockHeader().Time
    grant := &bank.SendAuthorization{SpendLimit: coins}
    
    msg, _ := grant.(proto.Message)
    any, _ := codectypes.NewAnyWithValue(msg)
    
    invalidGenesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       "",  // Empty granter address
                Grantee:       granteeAddr.String(),
                Authorization: any,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // ValidateGenesis passes but shouldn't
    err := authz.ValidateGenesis(*invalidGenesis)
    suite.Require().NoError(err)
    
    // InitGenesis panics on empty address
    suite.Require().Panics(func() {
        suite.keeper.InitGenesis(suite.ctx, invalidGenesis)
    })
}

func (suite *GenesisTestSuite) TestInitGenesisWithSelfGrant() {
    // Test with same granter and grantee (should be rejected but isn't)
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    now := suite.ctx.BlockHeader().Time
    grant := &bank.SendAuthorization{SpendLimit: coins}
    
    msg, _ := grant.(proto.Message)
    any, _ := codectypes.NewAnyWithValue(msg)
    
    invalidGenesis := &authz.GenesisState{
        Authorization: []authz.GrantAuthorization{
            {
                Granter:       granterAddr.String(),
                Grantee:       granterAddr.String(),  // Same as granter
                Authorization: any,
                Expiration:    now.Add(time.Hour),
            },
        },
    }
    
    // ValidateGenesis should reject self-grants but doesn't
    err := authz.ValidateGenesis(*invalidGenesis)
    suite.Require().NoError(err)
    
    // InitGenesis succeeds but creates an invalid state
    // (This doesn't panic but violates the invariant that granter != grantee)
    suite.Require().NotPanics(func() {
        suite.keeper.InitGenesis(suite.ctx, invalidGenesis)
    })
    
    // The invalid self-grant is now in state
    authorizations := suite.keeper.GetAuthorizations(suite.ctx, granterAddr, granterAddr)
    suite.Require().Len(authorizations, 1, "Self-grant was incorrectly allowed in genesis")
}
```

**Setup:**
- Uses existing test suite infrastructure from `genesis_test.go`
- Reuses test accounts `granterAddr` and `granteeAddr` already defined in the file
- Uses standard `bank.SendAuthorization` as the authorization type

**Trigger:**
1. Create a `GenesisState` with invalid addresses (malformed bech32, empty, or self-grant)
2. Call `ValidateGenesis` - it incorrectly returns nil
3. Call `InitGenesis` - it panics on the invalid address

**Observation:**
- The test observes that `ValidateGenesis` returns no error despite invalid data
- The test observes that `InitGenesis` panics when processing the invalid address
- This confirms the vulnerability: validation passes but initialization fails catastrophically

**Expected Result:** All three test functions should demonstrate the vulnerability by showing that `ValidateGenesis` passes invalid data that causes `InitGenesis` to panic or create invalid state.

### Citations

**File:** x/authz/genesis.go (L14-17)
```go
// ValidateGenesis check the given genesis state has no integrity issues
func ValidateGenesis(data GenesisState) error {
	return nil
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

**File:** x/authz/msgs.go (L54-68)
```go
func (msg MsgGrant) ValidateBasic() error {
	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}

	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
	}
	return msg.Grant.ValidateBasic()
}
```
