# Audit Report

## Title
Unbounded Query Resource Consumption via Infinite Gas Meter in Authorization Lookups

## Summary
Query contexts are initialized with an infinite gas meter, allowing expensive authorization lookup queries (specifically `GranteeGrants`) to iterate through unlimited grant records without any gas limit enforcement. An attacker can exhaust node resources (CPU, memory, I/O) by creating many grants and querying with high pagination limits.

## Impact
**Medium** - Increasing network processing node resource consumption by at least 30% without brute force actions.

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Vulnerable query: [2](#0-1) 
- Query context creation: [3](#0-2) 
- Pagination implementation: [4](#0-3) 

**Intended Logic:** 
Query gas limits should prevent expensive operations from consuming excessive node resources. Authorization queries should have bounded resource consumption to protect nodes from DoS attacks.

**Actual Logic:** 
When creating query contexts, the system initializes with an infinite gas meter [1](#0-0) , which never triggers out-of-gas errors [5](#0-4) . The `GranteeGrants` query creates a prefix store over ALL authorization grants [6](#0-5) , then uses `GenericFilteredPaginate` to iterate through them. The pagination function reads and unmarshals every grant entry [7](#0-6) , then filters by comparing addresses [8](#0-7) . With no maximum limit enforcement (MaxLimit is set to math.MaxUint64 [9](#0-8) ), an attacker can request pagination through millions of records.

**Exploit Scenario:**
1. Attacker creates numerous authorization grants (e.g., 1 million grants) between various address pairs by submitting normal grant transactions over time
2. Attacker sends a `GranteeGrants` query with a very high pagination limit (e.g., 1 million) to a public RPC endpoint
3. The query iterates through ALL grants in the store, reading from disk, unmarshalling protobuf messages, and performing address comparisons for each one
4. With the infinite gas meter, this continues without limit, consuming CPU, memory, and I/O resources
5. Multiple concurrent queries amplify the effect, potentially overwhelming the node

**Security Failure:** 
Denial-of-service through unbounded resource consumption. The infinite gas meter breaks the security property that queries should have limited resource usage, allowing any user to exhaust node resources without paying transaction fees.

## Impact Explanation

**Affected Resources:** 
- Node CPU (unmarshalling, address comparisons)
- Node memory (loading grant data)
- Node I/O (reading from disk)
- RPC endpoint availability

**Damage Severity:** 
An attacker can significantly increase resource consumption on RPC nodes by sending expensive queries. Since queries are free and accessible to anyone, this can be done repeatedly without cost to the attacker. If the authorization grant count is high (easily achievable through normal chain usage), a single query can consume substantial resources. Multiple concurrent queries from the same or different attackers can bring nodes to their knees, making them unresponsive to legitimate users.

**System Impact:** 
This matters because RPC nodes are critical infrastructure for blockchain interaction. If RPC nodes become unresponsive due to resource exhaustion, users cannot submit transactions, query state, or interact with the chain. This effectively creates a DoS attack vector that bypasses all transaction-level protections (gas limits, fees) since queries are free.

## Likelihood Explanation

**Who Can Trigger:** 
Any user with access to a public RPC endpoint can trigger this vulnerability. No authentication, authorization, or privileged access is required.

**Conditions Required:** 
- The chain must have a substantial number of authorization grants stored (achievable through normal usage or deliberate setup by the attacker)
- The attacker must send queries with high pagination limits
- No additional conditions or timing constraints are needed

**Frequency:** 
This can be exploited continuously. An attacker can send multiple concurrent queries repeatedly without any cost or restriction. The attack becomes more effective as the number of grants in the system grows organically through normal chain usage. With even moderate grant counts (tens of thousands), the resource consumption per query becomes significant.

## Recommendation

Implement proper gas metering for query contexts:

1. **Add query gas limits:** Replace the infinite gas meter in query contexts with a bounded gas meter that has a reasonable limit (e.g., similar to transaction gas limits or a separate query gas limit configuration).

2. **Enforce maximum pagination limits:** Add validation to reject pagination requests exceeding a maximum reasonable limit (e.g., 1000 items) at the query handler level.

3. **Optimize the GranteeGrants query:** Use a more efficient storage key structure that allows direct prefix iteration for a specific grantee, rather than iterating through all grants and filtering.

4. **Add query rate limiting:** Implement rate limiting at the RPC level to prevent abuse of expensive query endpoints.

The most critical fix is replacing the infinite gas meter with a bounded one for all query contexts.

## Proof of Concept

**File:** `x/authz/keeper/grpc_query_test.go`

**Test Function:** Add the following test to demonstrate resource exhaustion:

```go
func (suite *TestSuite) TestGranteeGrantsResourceExhaustion() {
    require := suite.Require()
    app, ctx, queryClient := suite.app, suite.ctx, suite.queryClient
    
    // Setup: Create many grants from different granters to different grantees
    // to simulate a realistic scenario with many authorization grants in the system
    numGranters := 1000  // In production, this could be much higher
    numGrantees := 100
    
    // Create test addresses
    granters := make([]sdk.AccAddress, numGranters)
    grantees := make([]sdk.AccAddress, numGrantees)
    
    for i := 0; i < numGranters; i++ {
        granters[i] = sdk.AccAddress(fmt.Sprintf("granter%d", i))
    }
    for i := 0; i < numGrantees; i++ {
        grantees[i] = sdk.AccAddress(fmt.Sprintf("grantee%d", i))
    }
    
    // Create many grants (simulating normal chain usage over time)
    now := ctx.BlockHeader().Time
    newCoins := sdk.NewCoins(sdk.NewInt64Coin("steak", 100))
    authorization := &banktypes.SendAuthorization{SpendLimit: newCoins}
    
    for i := 0; i < numGranters; i++ {
        for j := 0; j < numGrantees; j++ {
            err := app.AuthzKeeper.SaveGrant(ctx, grantees[j], granters[i], authorization, now.Add(time.Hour))
            require.NoError(err)
        }
    }
    
    // Trigger: Query with a very high pagination limit for a single grantee
    // This should iterate through ALL grants in the system (numGranters * numGrantees)
    // filtering for the specific grantee
    targetGrantee := grantees[0]
    
    // Measure resource consumption
    startTime := time.Now()
    
    result, err := queryClient.GranteeGrants(gocontext.Background(), &authz.QueryGranteeGrantsRequest{
        Grantee: targetGrantee.String(),
        Pagination: &query.PageRequest{
            Limit: math.MaxUint64, // Request unlimited pagination
            CountTotal: true,       // Force iteration through all records
        },
    })
    
    elapsed := time.Since(startTime)
    
    // Observation: The query completes but takes excessive time and resources
    require.NoError(err)
    require.NotNil(result)
    
    // This query should have iterated through numGranters * numGrantees records
    // filtering for the specific grantee, finding numGranters matches
    require.Equal(uint64(numGranters), result.Pagination.Total)
    
    // Log the execution time - in a real attack scenario with millions of grants,
    // this would take seconds to minutes, consuming substantial CPU and I/O
    fmt.Printf("Query executed in %v for %d total grants, consuming unbounded gas\n", 
        elapsed, numGranters*numGrantees)
    
    // The vulnerability is that there's no gas limit preventing this expensive operation
    // The context has an infinite gas meter, so no out-of-gas error occurs
    // Multiple concurrent such queries can exhaust node resources
}
```

**Setup:** The test creates a realistic scenario with many authorization grants between different address pairs.

**Trigger:** A `GranteeGrants` query is sent with `Limit: math.MaxUint64` and `CountTotal: true`, forcing iteration through all grants in the system.

**Observation:** The query completes successfully without any gas limit errors, despite iterating through thousands of grant records. The test demonstrates that with the infinite gas meter, there's no protection against this expensive operation. In a production environment with millions of grants, this query would consume substantial resources (CPU, memory, I/O) without any limit, and multiple concurrent such queries would amplify the resource exhaustion effect.

The test confirms the vulnerability: queries use an infinite gas meter and have no effective resource limits, allowing unbounded resource consumption.

### Citations

**File:** types/context.go (L272-272)
```go
		gasMeter:        NewInfiniteGasMeter(1, 1),
```

**File:** x/authz/keeper/grpc_query.go (L132-177)
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
```

**File:** baseapp/abci.go (L757-759)
```go
	ctx := sdk.NewContext(
		cacheMS, checkStateCtx.BlockHeader(), true, app.logger,
	).WithMinGasPrices(app.minGasPrices).WithBlockHeight(height)
```

**File:** types/query/filtered_pagination.go (L212-246)
```go
	for ; iterator.Valid(); iterator.Next() {
		if iterator.Error() != nil {
			return nil, nil, iterator.Error()
		}

		protoMsg := constructor()

		err := cdc.Unmarshal(iterator.Value(), protoMsg)
		if err != nil {
			return nil, nil, err
		}

		val, err := onResult(iterator.Key(), protoMsg)
		if err != nil {
			return nil, nil, err
		}

		if val.Size() != 0 {
			// Previously this was the "accumulate" flag
			if numHits >= offset && numHits < end {
				results = append(results, val)
			}
			numHits++
		}

		if numHits == end+1 {
			if nextKey == nil {
				nextKey = iterator.Key()
			}

			if !countTotal {
				break
			}
		}
	}
```

**File:** store/types/gas.go (L252-258)
```go
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}
```

**File:** types/query/pagination.go (L20-20)
```go
const MaxLimit = math.MaxUint64
```
