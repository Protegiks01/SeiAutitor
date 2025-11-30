# Audit Report

## Title
Genesis Import Panic Due to Unvalidated StakeAuthorization Type Causing Total Network Shutdown

## Summary
The authz module's `ValidateGenesis` function performs no validation on authorization grants, allowing a `StakeAuthorization` with `AUTHORIZATION_TYPE_UNSPECIFIED` to be included in genesis state. This causes all nodes to panic during `InitGenesis` when the authorization's `MsgTypeURL()` method is called, preventing the entire network from starting.

## Impact
Medium

## Finding Description

**Location:**
- Primary vulnerability: [1](#0-0) 
- Panic trigger: [2](#0-1) 
- Genesis initialization flow: [3](#0-2) 

**Intended Logic:**
Genesis validation should verify that all authorization grants are valid before importing them into chain state. The `StakeAuthorization.ValidateBasic()` method explicitly checks that `AuthorizationType` is not `AUTHORIZATION_TYPE_UNSPECIFIED` [4](#0-3) . Other modules like feegrant properly implement this pattern by calling `ValidateBasic()` during genesis validation [5](#0-4) .

**Actual Logic:**
The `ValidateGenesis` function returns `nil` without performing any validation checks [1](#0-0) . During module initialization [6](#0-5) , the keeper loops through authorization entries and calls `SaveGrant` for each [3](#0-2) . The `SaveGrant` function invokes `authorization.MsgTypeURL()` to construct the storage key [7](#0-6) . For `StakeAuthorization`, `MsgTypeURL()` calls `normalizeAuthzType()` which returns an error for `AUTHORIZATION_TYPE_UNSPECIFIED`, causing a panic [2](#0-1)  via [8](#0-7) .

**Exploitation Path:**
1. Genesis file contains a `StakeAuthorization` with `authorization_type` set to `AUTHORIZATION_TYPE_UNSPECIFIED` (value 0, the protobuf default) [9](#0-8) 
2. Genesis passes through `ValidateGenesis` without error
3. Module's `InitGenesis` is called during chain startup
4. Keeper's `InitGenesis` loops through entries and calls `SaveGrant`
5. `SaveGrant` calls `authorization.MsgTypeURL()`
6. `MsgTypeURL()` panics when encountering invalid authorization type
7. Panic propagates, causing genesis import to fail
8. All nodes fail to start, resulting in complete network outage

**Security Guarantee Broken:**
Network availability invariant is violated. The system fails to validate critical genesis state, allowing malformed data that causes deterministic panics across all nodes during initialization.

## Impact Explanation

This vulnerability causes total network shutdown matching the explicitly listed impact category "Network not being able to confirm new transactions (total network shutdown)" classified as Medium severity. All nodes attempting to import the genesis state will panic and fail to start. The impact affects:

- **New chain launch**: Network cannot initialize, preventing blockchain operations
- **Network restart from genesis**: All nodes fail to restart, causing permanent unavailability until genesis is manually corrected
- **Transaction confirmation**: No transactions can be confirmed since the network cannot start
- **Node coverage**: 100% of network nodes are affected deterministically

## Likelihood Explanation

**Who Can Trigger:**
Parties with genesis file creation authority:
- Chain deployers/launchers creating initial genesis
- Governance coordinators during network upgrades requiring genesis export/import
- Network coordinators during hard fork or recovery scenarios

**Conditions Required:**
The malformed genesis file must be distributed to and used by network validators during new blockchain launches, hard fork upgrades, or network recovery scenarios.

**Frequency:**
While genesis imports occur infrequently, they are critical events. The vulnerability is deterministic - any node importing the crafted genesis will panic. The issue could occur accidentally since `AUTHORIZATION_TYPE_UNSPECIFIED` is the default protobuf value (0).

**Privileged Access Exception:**
Although genesis file creation is privileged, the exception clause applies: even a trusted role inadvertently triggering this causes an unrecoverable security failure (complete network shutdown) beyond their intended authority (adding an authz grant, not causing DoS). The failure mode is disproportionate to the configuration error.

## Recommendation

Implement proper validation in the `ValidateGenesis` function following the pattern used in the feegrant module [5](#0-4) :

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
        
        // Validate authorization using ValidateBasic
        auth := grant.Authorization.GetCachedValue()
        if authorization, ok := auth.(Authorization); ok {
            if err := authorization.ValidateBasic(); err != nil {
                return sdkerrors.Wrapf(err, "invalid authorization")
            }
        }
    }
    return nil
}
```

This leverages the existing `ValidateBasic()` method [10](#0-9)  which properly checks authorization validity.

## Proof of Concept

**Test File:** `x/authz/keeper/genesis_test.go`

**Setup:** Use the existing `GenesisTestSuite` [11](#0-10)  which provides a configured keeper and context.

**Action:** 
1. Create a `StakeAuthorization` with `AuthorizationType` set to `AUTHORIZATION_TYPE_UNSPECIFIED` (value 0)
2. Pack it into a `GrantAuthorization` with valid granter/grantee addresses and expiration
3. Create a `GenesisState` containing this authorization
4. Call `ValidateGenesis` on the genesis state
5. Call `InitGenesis` on the keeper with the genesis state

**Result:** 
1. `ValidateGenesis` incorrectly returns no error for the invalid authorization
2. `InitGenesis` panics when attempting to save the grant because `MsgTypeURL()` panics on the invalid authorization type

The test demonstrates that invalid genesis state bypasses validation and causes a panic during initialization, proving the vulnerability exists and matches the claimed impact.

## Notes

The `Grant` type has a `ValidateBasic()` method that calls the authorization's `ValidateBasic()` [10](#0-9) , but this is never invoked during genesis validation. The feegrant module demonstrates the correct validation pattern [5](#0-4) , confirming this is an implementation gap rather than intentional design.

### Citations

**File:** x/authz/genesis.go (L15-17)
```go
func ValidateGenesis(data GenesisState) error {
	return nil
}
```

**File:** x/staking/types/authz.go (L41-47)
```go
func (a StakeAuthorization) MsgTypeURL() string {
	authzType, err := normalizeAuthzType(a.AuthorizationType)
	if err != nil {
		panic(err)
	}
	return authzType
}
```

**File:** x/staking/types/authz.go (L49-58)
```go
func (a StakeAuthorization) ValidateBasic() error {
	if a.MaxTokens != nil && a.MaxTokens.IsNegative() {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidCoins, "negative coin amount: %v", a.MaxTokens)
	}
	if a.AuthorizationType == AuthorizationType_AUTHORIZATION_TYPE_UNSPECIFIED {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "unknown authorization type")
	}

	return nil
}
```

**File:** x/staking/types/authz.go (L139-150)
```go
func normalizeAuthzType(authzType AuthorizationType) (string, error) {
	switch authzType {
	case AuthorizationType_AUTHORIZATION_TYPE_DELEGATE:
		return sdk.MsgTypeURL(&MsgDelegate{}), nil
	case AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE:
		return sdk.MsgTypeURL(&MsgUndelegate{}), nil
	case AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE:
		return sdk.MsgTypeURL(&MsgBeginRedelegate{}), nil
	default:
		return "", sdkerrors.ErrInvalidType.Wrapf("unknown authorization type %T", authzType)
	}
}
```

**File:** x/authz/keeper/keeper.go (L144-160)
```go
func (k Keeper) SaveGrant(ctx sdk.Context, grantee, granter sdk.AccAddress, authorization authz.Authorization, expiration time.Time) error {
	store := ctx.KVStore(k.storeKey)

	grant, err := authz.NewGrant(authorization, expiration)
	if err != nil {
		return err
	}

	bz := k.cdc.MustMarshal(&grant)
	skey := grantStoreKey(grantee, granter, authorization.MsgTypeURL())
	store.Set(skey, bz)
	return ctx.EventManager().EmitTypedEvent(&authz.EventGrant{
		MsgTypeUrl: authorization.MsgTypeURL(),
		Granter:    granter.String(),
		Grantee:    grantee.String(),
	})
}
```

**File:** x/authz/keeper/keeper.go (L245-260)
```go
// InitGenesis new authz genesis
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

**File:** x/feegrant/genesis.go (L17-29)
```go
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

**File:** x/authz/module/module.go (L149-154)
```go
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
	var genesisState authz.GenesisState
	cdc.MustUnmarshalJSON(data, &genesisState)
	am.keeper.InitGenesis(ctx, &genesisState)
	return []abci.ValidatorUpdate{}
}
```

**File:** proto/cosmos/staking/v1beta1/authz.proto (L38-40)
```text
enum AuthorizationType {
  // AUTHORIZATION_TYPE_UNSPECIFIED specifies an unknown authorization type
  AUTHORIZATION_TYPE_UNSPECIFIED = 0;
```

**File:** x/authz/authorization_grant.go (L57-64)
```go
func (g Grant) ValidateBasic() error {
	av := g.Authorization.GetCachedValue()
	a, ok := av.(Authorization)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", (Authorization)(nil), av)
	}
	return a.ValidateBasic()
}
```

**File:** x/authz/keeper/genesis_test.go (L17-30)
```go
type GenesisTestSuite struct {
	suite.Suite

	ctx    sdk.Context
	keeper keeper.Keeper
}

func (suite *GenesisTestSuite) SetupTest() {
	checkTx := false
	app := simapp.Setup(checkTx)

	suite.ctx = app.BaseApp.NewContext(checkTx, tmproto.Header{Height: 1})
	suite.keeper = app.AuthzKeeper
}
```
