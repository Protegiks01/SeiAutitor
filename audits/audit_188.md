# Audit Report

## Title
Expiration Time Validation Bypass Allowing Permanent Storage Bloat Through Expired Authorization Grants

## Summary
The authz module allows creation of authorization grants with past expiration times due to commented-out validation logic, violating the documented specification and causing permanent blockchain state bloat.

## Impact
**Medium**

## Finding Description

**Location:** 
The vulnerability exists in the authz module across multiple files:
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:**
According to the specification, MsgGrant message handling should fail if the provided expiration time is less than the current unix timestamp: [4](#0-3) 

An error is defined specifically for this validation: [5](#0-4) 

**Actual Logic:**
The validation code that checks expiration against block time is commented out with a TODO note for version 0.45: [6](#0-5) 

The `MsgGrant.ValidateBasic()` method calls `Grant.ValidateBasic()` which only validates the authorization itself, not the expiration time: [7](#0-6) 

When `SaveGrant` is called from the message server, it accepts any expiration time without validation: [8](#0-7) 

**Exploit Scenario:**
1. An attacker creates a `MsgGrant` transaction with expiration time set to a past date (e.g., Unix epoch 0 or any time before current block time)
2. The message passes `ValidateBasic()` validation since expiration time is not checked
3. The message handler stores the grant in blockchain state permanently
4. The expired grant remains in storage and appears in query results from methods like `GranterGrants` and `GranteeGrants`: [9](#0-8) 

5. While `GetCleanAuthorization` filters expired grants during execution attempts, the grants persist in storage: [10](#0-9) 

**Security Failure:**
This breaks the specification invariant and causes unintended protocol behavior. The system stores authorization grants that should have been rejected, causing permanent state bloat that affects all network nodes.

## Impact Explanation

**Affected Components:**
- Blockchain state storage on all network nodes
- Query RPC endpoints that return grant information
- Network resource consumption (storage and query processing)

**Severity of Damage:**
This is a bug in layer 1 network code that results in unintended behavior, fitting the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

While no funds are directly at risk (expired grants cannot be executed), the vulnerability:
1. Violates the documented specification
2. Causes permanent blockchain state pollution
3. Increases storage requirements for all network nodes
4. Pollutes query results with useless expired grants
5. Can be exploited by any user without special privileges

**System Reliability Impact:**
Every expired grant created consumes storage permanently on every network node. While individual grants are small, accumulated over time this represents unnecessary state bloat that increases synchronization time for new nodes and query processing overhead.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can trigger this vulnerability - it requires no special privileges, only the ability to submit a `MsgGrant` transaction.

**Conditions Required:**
- Standard transaction submission capability
- Gas fees to pay for the transaction
- No special timing or state conditions needed

**Frequency:**
This can be exploited at will during normal network operation. The test suite even demonstrates this behavior as expected: [11](#0-10) [12](#0-11) 

The test shows that grants with past expiration times are created successfully and stored, only to be filtered out later during retrieval via `GetCleanAuthorization`.

## Recommendation

Uncomment and implement the validation logic in `NewGrant` function to check expiration against block time:

```go
func NewGrant(blockTime time.Time, a Authorization, expiration time.Time) (Grant, error) {
    if !expiration.After(blockTime) {
        return Grant{}, sdkerrors.ErrInvalidRequest.Wrapf("expiration must be after the current block time (%v), got %v", blockTime.Format(time.RFC3339), expiration.Format(time.RFC3339))
    }
    // ... rest of the function
}
```

Update `SaveGrant` in the keeper to pass block time:
```go
func (k Keeper) SaveGrant(ctx sdk.Context, grantee, granter sdk.AccAddress, authorization authz.Authorization, expiration time.Time) error {
    grant, err := authz.NewGrant(ctx.BlockTime(), authorization, expiration)
    // ... rest of the function
}
```

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add this test to demonstrate the vulnerability:

```go
func (s *TestSuite) TestPastExpirationGrantCreationVulnerability() {
    app, ctx, addrs := s.app, s.ctx, s.addrs
    
    granterAddr := addrs[0]
    granteeAddr := addrs[1]
    now := s.ctx.BlockHeader().Time
    
    // SETUP: Create a grant with expiration time 1 year in the past
    pastTime := now.AddDate(-1, 0, 0)
    s.T().Logf("Current block time: %v", now)
    s.T().Logf("Attempting to create grant with expiration: %v", pastTime)
    
    newCoins := sdk.NewCoins(sdk.NewInt64Coin("steak", 100))
    authorization := &banktypes.SendAuthorization{SpendLimit: newCoins}
    
    // TRIGGER: SaveGrant should reject past expiration but doesn't
    err := app.AuthzKeeper.SaveGrant(ctx, granteeAddr, granterAddr, authorization, pastTime)
    
    // OBSERVATION 1: Grant creation succeeds when it should fail per spec
    s.Require().NoError(err, "Grant with past expiration was accepted (spec violation)")
    
    // OBSERVATION 2: The grant persists in storage
    var foundExpiredGrant bool
    app.AuthzKeeper.IterateGrants(ctx, func(granter, grantee sdk.AccAddress, grant authz.Grant) bool {
        if granter.Equals(granterAddr) && grantee.Equals(granteeAddr) {
            foundExpiredGrant = true
            s.T().Logf("Found expired grant in storage with expiration: %v", grant.Expiration)
        }
        return false
    })
    s.Require().True(foundExpiredGrant, "Expired grant not found in storage via iteration")
    
    // OBSERVATION 3: The grant appears in query results
    store := ctx.KVStore(app.GetKey("authz"))
    key := keeper.GrantStoreKey(granteeAddr, granterAddr, authorization.MsgTypeURL())
    bz := store.Get(key)
    s.Require().NotNil(bz, "Expired grant permanently stored in KVStore")
    
    s.T().Log("VULNERABILITY CONFIRMED: Grant with past expiration stored permanently")
    s.T().Log("- Violates specification requirement at x/authz/spec/03_messages.md:19")
    s.T().Log("- Causes permanent state bloat across all network nodes")
    s.T().Log("- Grant remains queryable but cannot be executed")
}
```

**Expected Behavior:** The test demonstrates that:
1. A grant with expiration time in the past is successfully created (violates spec)
2. The expired grant is permanently stored in blockchain state
3. The grant can be retrieved through iteration and direct storage access
4. This creates permanent storage bloat that affects all network nodes

**Observation:** Run this test to see it pass, confirming that expired grants are accepted and stored when they should be rejected according to the specification.

### Citations

**File:** x/authz/authorization_grant.go (L13-20)
```go
func NewGrant( /*blockTime time.Time, */ a Authorization, expiration time.Time) (Grant, error) {
	// TODO: add this for 0.45
	// if !expiration.After(blockTime) {
	// 	return Grant{}, sdkerrors.ErrInvalidRequest.Wrapf("expiration must be after the current block time (%v), got %v", blockTime.Format(time.RFC3339), expiration.Format(time.RFC3339))
	// }
	g := Grant{
		Expiration: expiration,
	}
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

**File:** x/authz/keeper/msg_server.go (L14-41)
```go
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	authorization := msg.GetAuthorization()
	if authorization == nil {
		return nil, sdkerrors.ErrUnpackAny.Wrap("Authorization is not present in the msg")
	}

	t := authorization.MsgTypeURL()
	if k.router.HandlerByTypeURL(t) == nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
	}

	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration)
	if err != nil {
		return nil, err
	}

	return &authz.MsgGrantResponse{}, nil
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

**File:** x/authz/spec/03_messages.md (L16-21)
```markdown
The message handling should fail if:

- both granter and grantee have the same address.
- provided `Expiration` time is less than current unix timestamp.
- provided `Grant.Authorization` is not implemented.
- `Authorization.MsgTypeURL()` is not defined in the router (there is no defined handler in the app router to handle that Msg types).
```

**File:** x/authz/errors.go (L9-9)
```go
	ErrInvalidExpirationTime = sdkerrors.Register(ModuleName, 3, "expiration time of authorization should be more than current time")
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

**File:** x/authz/keeper/keeper.go (L196-207)
```go
func (k Keeper) GetCleanAuthorization(ctx sdk.Context, grantee sdk.AccAddress, granter sdk.AccAddress, msgType string) (cap authz.Authorization, expiration time.Time) {
	grant, found := k.getGrant(ctx, grantStoreKey(grantee, granter, msgType))
	if !found {
		return nil, time.Time{}
	}
	if grant.Expiration.Before(ctx.BlockHeader().Time) {
		k.DeleteGrant(ctx, grantee, granter, msgType)
		return nil, time.Time{}
	}

	return grant.GetAuthorization(), grant.Expiration
}
```

**File:** x/authz/keeper/grpc_query.go (L84-128)
```go
func (k Keeper) GranterGrants(c context.Context, req *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	granter, err := sdk.AccAddressFromBech32(req.Granter)
	if err != nil {
		return nil, err
	}

	ctx := sdk.UnwrapSDKContext(c)
	store := ctx.KVStore(k.storeKey)
	authzStore := prefix.NewStore(store, grantStoreKey(nil, granter, ""))

	grants, pageRes, err := query.GenericFilteredPaginate(k.cdc, authzStore, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
		auth1 := auth.GetAuthorization()
		if err != nil {
			return nil, err
		}

		any, err := codectypes.NewAnyWithValue(auth1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		grantee := firstAddressFromGrantStoreKey(key)
		return &authz.GrantAuthorization{
			Granter:       granter.String(),
			Grantee:       grantee.String(),
			Authorization: any,
			Expiration:    auth.Expiration,
		}, nil

	}, func() *authz.Grant {
		return &authz.Grant{}
	})

	if err != nil {
		return nil, err
	}

	return &authz.QueryGranterGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
```

**File:** x/authz/msgs_test.go (L83-83)
```go
		{"past time", granter, grantee, &banktypes.SendAuthorization{SpendLimit: coinsPos}, time.Now().AddDate(0, 0, -1), false, true}, // TODO need 0.45
```

**File:** x/authz/keeper/keeper_test.go (L60-65)
```go
	s.T().Log("verify if expired authorization is rejected")
	x := &banktypes.SendAuthorization{SpendLimit: newCoins}
	err := app.AuthzKeeper.SaveGrant(ctx, granterAddr, granteeAddr, x, now.Add(-1*time.Hour))
	s.Require().NoError(err)
	authorization, _ = app.AuthzKeeper.GetCleanAuthorization(ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().Nil(authorization)
```
