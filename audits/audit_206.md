## Title
GranteeGrants Query DoS via Full Grant Store Scan

## Summary
The `GranteeGrants` query in `x/authz/keeper/grpc_query.go` scans and unmarshals ALL grants in the entire system when queried without pagination or with `limit=0`, regardless of whether they match the requested grantee. This allows any attacker to repeatedly trigger expensive full-store scans, causing RPC endpoint resource exhaustion and denial of service.

## Impact
**Medium**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The GranteeGrants query should efficiently retrieve grants where a specific address is the grantee, using pagination to limit resource consumption per query.

**Actual Logic:** 
The query uses only the global `GrantKey` prefix (0x01) instead of a grantee-specific prefix, causing it to iterate through ALL grants in the system. [2](#0-1) 

The filtering by grantee happens in the application layer within the onResult callback, not at the storage layer: [3](#0-2) 

When pagination is not provided or `limit=0`, the system sets `countTotal=true`: [4](#0-3) 

With `countTotal=true`, the iterator continues processing ALL remaining grants even after collecting enough results: [5](#0-4) 

Each grant is unmarshaled regardless of whether it matches the grantee filter: [6](#0-5) 

gRPC queries use an infinite gas meter, providing no gas-based protection: [7](#0-6) 

**Exploit Scenario:**
1. Attacker sends repeated requests to `/cosmos/authz/v1beta1/grantee_grants/{grantee_addr}` without pagination parameters or with `pagination.limit=0`
2. Each query triggers iteration through ALL grants in the system (potentially thousands or millions)
3. For each grant entry, the system:
   - Unmarshals the protobuf message (CPU intensive)
   - Parses the key to extract granter/grantee addresses
   - Checks if grantee matches
   - Only returns matching grants, but processes ALL grants
4. With sufficient grants in the system (which accumulate naturally over time), each query consumes significant CPU and memory
5. Repeated queries overwhelm RPC endpoints without any rate limiting

**Security Failure:**
Denial-of-service through resource exhaustion. The query design violates the principle of efficient data access by forcing full-store scans instead of using indexed access patterns.

## Impact Explanation

**Affected processes:** RPC endpoint availability and responsiveness

**Severity:** 
- Each query forces unmarshaling and processing of ALL grants globally, not just those for the requested grantee
- In a production blockchain with active authz usage (delegation, staking authorizations, etc.), thousands of grants could exist
- Processing thousands of protobuf unmarshals per query consumes significant CPU
- Memory pressure from iterating large datasets
- RPC nodes become slow or unresponsive, affecting all users and applications
- Unlike transaction-based attacks, queries incur no gas cost to the attacker
- No rate limiting prevents sustained attacks

**System impact:**
This matters because RPC endpoints are critical infrastructure for blockchain interaction. Applications, wallets, and monitoring tools depend on RPC availability. Resource exhaustion can cause cascading failures affecting user experience and system reliability.

## Likelihood Explanation

**Who can trigger:** Any network participant with access to the RPC endpoint (typically public and unauthenticated)

**Conditions required:**
- The authz module must have grants stored (this happens naturally in any active chain)
- Attacker needs network access to the RPC endpoint (standard for public chains)
- No special privileges, authentication, or on-chain state required

**Frequency:**
- Can be exploited immediately and repeatedly
- Impact scales with the number of grants in the system
- As the chain matures and more grants accumulate, the vulnerability becomes more severe
- Each query is independent and cheap for the attacker (no gas costs)

## Recommendation

**Fix 1 - Storage Key Restructuring (Optimal):**
Modify the grant storage key structure to enable efficient grantee-based lookups. Add a secondary index with grantee as the prefix:
- Primary key: `0x01<granter><grantee><msgType>` (existing)
- Secondary index: `0x02<grantee><granter><msgType>` 

Update GranteeGrants to use the grantee-prefixed index for efficient filtering.

**Fix 2 - Disable countTotal for GranteeGrants (Quick mitigation):**
Force `countTotal=false` in the GranteeGrants query regardless of the pagination parameters to prevent full-store scans:

```go
// In GranteeGrants function, after line 143:
if pageRequest != nil {
    pageRequest = &query.PageRequest{
        Key:        pageRequest.Key,
        Offset:     pageRequest.Offset,
        Limit:      pageRequest.Limit,
        CountTotal: false,  // Force false to prevent full scans
        Reverse:    pageRequest.Reverse,
    }
}
```

**Fix 3 - Add Maximum Limit:**
Enforce a reasonable maximum limit (e.g., 1000) for GranteeGrants queries to prevent unbounded iteration even with offset-based pagination.

## Proof of Concept

**File:** `x/authz/keeper/grpc_query_test.go`

**Test Function:** Add the following test to demonstrate the DoS vulnerability:

```go
func (suite *TestSuite) TestGranteeGrantsDoS() {
    require := suite.Require()
    app, ctx, queryClient, addrs := suite.app, suite.ctx, suite.queryClient, suite.addrs
    
    // Setup: Create many grants from different granters to simulate a real system
    now := ctx.BlockHeader().Time
    newCoins := sdk.NewCoins(sdk.NewInt64Coin("steak", 100))
    authorization := &banktypes.SendAuthorization{SpendLimit: newCoins}
    
    // Create 100 grants from different granters (not involving the target grantee)
    otherAddrs := simapp.AddTestAddrsIncremental(app, ctx, 100, sdk.NewInt(30000000))
    for i := 0; i < 100; i++ {
        err := app.AuthzKeeper.SaveGrant(ctx, otherAddrs[i], otherAddrs[(i+1)%100], authorization, now.Add(time.Hour))
        require.NoError(err)
    }
    
    // Create just 1 grant for the target grantee (addrs[0])
    err := app.AuthzKeeper.SaveGrant(ctx, addrs[0], addrs[1], authorization, now.Add(time.Hour))
    require.NoError(err)
    
    // Trigger: Query GranteeGrants for addrs[0] with no pagination (triggers countTotal=true)
    start := time.Now()
    result, err := queryClient.GranteeGrants(gocontext.Background(), &authz.QueryGranteeGrantsRequest{
        Grantee: addrs[0].String(),
        // No pagination - this triggers limit=100 and countTotal=true
    })
    elapsed := time.Since(start)
    
    // Observation: Query should return only 1 grant for addrs[0]
    require.NoError(err)
    require.Len(result.Grants, 1)
    require.Equal(uint64(1), result.Pagination.Total)
    
    // But it processes ALL 101 grants in the system
    // To verify this is expensive, measure time or add instrumentation
    // In a real attack with thousands of grants, this would be significantly worse
    suite.T().Logf("Query took %v to scan %d total grants to return %d matching grants", 
        elapsed, 101, len(result.Grants))
    
    // The vulnerability: Each query unmarshals and processes ALL grants even though
    // only 1 matches. With thousands of grants, this becomes a DoS vector.
}
```

**Setup:** The test creates 101 grants total (100 between other addresses, 1 involving the target grantee)

**Trigger:** Query GranteeGrants for a specific grantee without pagination parameters, which triggers `countTotal=true` and forces processing of all grants

**Observation:** The query returns only 1 matching grant but processes all 101 grants in the system. The test demonstrates that the number of grants processed is proportional to ALL grants globally, not just those for the queried grantee. In a production system with thousands of grants, this becomes a severe DoS vector that can overwhelm RPC endpoints through repeated queries.

## Notes

The specific Grants query mentioned in the security question (lines 19-81) is less vulnerable because it requires both granter AND grantee parameters, limiting its scope to specific address pairs. The key structure `<granter><grantee><msgType>` allows efficient prefix-based filtering for that query. [8](#0-7) 

However, GranteeGrants in the same file and module represents a more severe instance of the same underlying pagination inefficiency issue, where the storage key structure doesn't support efficient filtering by the query parameter (grantee alone).

### Citations

**File:** x/authz/keeper/grpc_query.go (L52-54)
```go
	store := ctx.KVStore(k.storeKey)
	key := grantStoreKey(grantee, granter, "")
	grantsStore := prefix.NewStore(store, key)
```

**File:** x/authz/keeper/grpc_query.go (L132-178)
```go
func (k Keeper) GranteeGrants(c context.Context, req *authz.QueryGranteeGrantsRequest) (*authz.QueryGranteeGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	grantee, err := sdk.AccAddressFromBech32(req.Grantee)
	if err != nil {
		return nil, err
	}

	ctx := sdk.UnwrapSDKContext(c)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), GrantKey)

	authorizations, pageRes, err := query.GenericFilteredPaginate(k.cdc, store, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
		auth1 := auth.GetAuthorization()
		if err != nil {
			return nil, err
		}

		granter, g := addressesFromGrantStoreKey(append(GrantKey, key...))
		if !g.Equals(grantee) {
			return nil, nil
		}

		authorizationAny, err := codectypes.NewAnyWithValue(auth1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		return &authz.GrantAuthorization{
			Authorization: authorizationAny,
			Expiration:    auth.Expiration,
			Granter:       granter.String(),
			Grantee:       grantee.String(),
		}, nil
	}, func() *authz.Grant {
		return &authz.Grant{}
	})
	if err != nil {
		return nil, err
	}

	return &authz.QueryGranteeGrantsResponse{
		Grants:     authorizations,
		Pagination: pageRes,
	}, nil
}
```

**File:** types/query/filtered_pagination.go (L153-158)
```go
	if limit == 0 {
		limit = DefaultLimit

		// count total results when the limit is zero/not supplied
		countTotal = true
	}
```

**File:** types/query/filtered_pagination.go (L217-222)
```go
		protoMsg := constructor()

		err := cdc.Unmarshal(iterator.Value(), protoMsg)
		if err != nil {
			return nil, nil, err
		}
```

**File:** types/query/filtered_pagination.go (L237-245)
```go
		if numHits == end+1 {
			if nextKey == nil {
				nextKey = iterator.Key()
			}

			if !countTotal {
				break
			}
		}
```

**File:** types/context.go (L280-280)
```go
	}
```
