## Audit Report

## Title
Unmetered Expensive Iteration in GenericFilteredPaginate Allows Query-Based DoS Attack

## Summary
The `GenericFilteredPaginate` function in `x/authz/keeper/grpc_query.go` can iterate through significantly more records than the specified pagination limit when filters reject many results. Combined with infinite gas meters used for gRPC queries, this enables unprivileged attackers to force expensive operations on query nodes without gas protection, leading to resource exhaustion.

## Impact
**Medium**

## Finding Description

**Location:** 
- Primary: `types/query/filtered_pagination.go`, lines 122-254 (`GenericFilteredPaginate` function)
- Usage: `x/authz/keeper/grpc_query.go`, line 145 (`GranteeGrants` query)
- Context creation: `baseapp/abci.go`, line 712 (`CreateQueryContext` function)
- Gas meter: `types/context.go`, line 272 (infinite gas meter initialization) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The pagination system should limit query operations to iterate through approximately `limit` number of records, with gas metering providing protection against expensive operations. Filters should efficiently narrow results without causing excessive iteration.

**Actual Logic:** 
In `GenericFilteredPaginate`, the loop only increments `numHits` when `val.Size() != 0` (line 229-235). When filtering callbacks return nil or empty results (Size() == 0), the iteration continues without incrementing `numHits`. This means if many records are filtered out, the function iterates through far more than `limit` records to find enough matching results. [4](#0-3) 

In the `GranteeGrants` query, the store prefix is only `GrantKey` (0x01), causing iteration over ALL grants system-wide. The filter checks if the grantee matches, returning nil for non-matches (line 152-154). [5](#0-4) 

Furthermore, gRPC queries use contexts created with infinite gas meters that never enforce limits: [6](#0-5) [7](#0-6) 

**Exploit Scenario:**
1. Attacker creates many authorization grants (e.g., 10,000 grants) between various granter/grantee pairs via standard transactions
2. Attacker repeatedly queries `GranteeGrants` for a target grantee address that has very few matching grants (e.g., only 10 grants)
3. With `limit=10` in the pagination request, the intended behavior would iterate ~10-20 records
4. Actual behavior: the function iterates through all 10,000 grants to find the 10 matches
5. Each iteration consumes CPU for: iterator operations, protobuf unmarshaling, callback execution
6. With no gas limit (infinite gas meter), there's no automatic termination
7. Repeated queries cause sustained resource consumption on query nodes

**Security Failure:** 
This breaks the resource accounting and DoS protection mechanisms. The infinite gas meter for queries, combined with unbound iteration in filtered pagination, allows unprivileged users to trigger expensive operations without cost or limit.

## Impact Explanation

**Affected Resources:**
- Query node CPU and memory resources
- Network RPC endpoint availability
- Node responsiveness to legitimate queries

**Severity:**
An attacker can force query nodes to perform 100-1000x more iterations than the pagination limit suggests. For example:
- With 100,000 total grants and a query for a grantee with 10 grants
- Pagination limit of 10 causes ~100,000 iterations instead of ~10-20
- Each iteration: ~30 gas flat + 3 gas/byte for keys/values + unmarshaling cost + callback cost
- Even with gas tracking (but no limit), this represents 10,000x resource consumption

This enables:
- Sustained resource exhaustion attacks on query endpoints
- Degraded service for legitimate users querying the same endpoints
- Potential node crashes under memory pressure from large iterations
- Economic attack with minimal attacker cost (just gRPC requests)

**Why This Matters:**
Query endpoints are critical infrastructure for applications, wallets, and explorers. Their availability directly impacts user experience and protocol usability. This vulnerability allows cheap attacks (no transaction fees) to degrade or deny service.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with the ability to:
1. Create authorization grants (requires normal transaction fees to setup)
2. Send gRPC queries (no authentication or cost required)

**Conditions Required:**
- Moderate number of existing grants in the system (realistic in production)
- Target grantee with sparse grant distribution (attacker-controllable)
- No special privileges or timing requirements

**Frequency:**
- Can be triggered immediately and repeatedly
- Each query request triggers the vulnerability
- Attacker can automate continuous queries
- More effective as the total number of grants grows over time

**Likelihood Assessment:** High
The attack is trivial to execute, requires no special privileges, has no direct cost to the attacker (gRPC queries are free), and becomes more effective as the system grows naturally with usage.

## Recommendation

**Immediate Mitigation:**
1. Add a configurable gas limit for gRPC query contexts to replace the infinite gas meter
2. Add a hard iteration limit (e.g., 10x the pagination limit) in `GenericFilteredPaginate` to prevent excessive iteration regardless of filter results

**Long-term Fix:**
Redesign the storage key structure for grants to enable efficient prefix filtering by grantee. For `GranteeGrants` queries, create a secondary index with key format: `0x02<granteeAddressLen><granteeAddress><granterAddressLen><granterAddress><msgType>` to enable direct iteration over a specific grantee's grants without scanning the entire grant space.

**Specific Code Changes:**
In `types/query/filtered_pagination.go`, add an iteration counter:
```go
maxIterations := limit * 10 // configurable multiplier
iterationCount := uint64(0)
for ; iterator.Valid(); iterator.Next() {
    iterationCount++
    if iterationCount > maxIterations {
        return results, &PageResponse{NextKey: iterator.Key()}, 
            fmt.Errorf("exceeded maximum iterations")
    }
    // ... rest of logic
}
```

## Proof of Concept

**File:** `x/authz/keeper/grpc_query_test.go`

**Test Function:** Add the following test to demonstrate the excessive iteration issue:

```go
func (suite *TestSuite) TestGranteeGrantsExcessiveIteration() {
    require := suite.Require()
    app, ctx, queryClient := suite.app, suite.ctx, suite.queryClient
    
    // Setup: Create many grants to various grantees
    now := ctx.BlockHeader().Time
    newCoins := sdk.NewCoins(sdk.NewInt64Coin("steak", 100))
    authorization := &banktypes.SendAuthorization{SpendLimit: newCoins}
    
    // Create 1000 grants with different granters/grantees
    // but only 5 grants for our target grantee (addrs[0])
    numNoiseGrants := 1000
    numTargetGrants := 5
    
    // Create noise grants (not matching our target grantee)
    for i := 0; i < numNoiseGrants; i++ {
        // Create fake addresses for granters and grantees
        granter := sdk.AccAddress([]byte(fmt.Sprintf("granter%d", i)))
        grantee := sdk.AccAddress([]byte(fmt.Sprintf("grantee%d", i)))
        err := app.AuthzKeeper.SaveGrant(ctx, grantee, granter, authorization, now.Add(time.Hour))
        require.NoError(err)
    }
    
    // Create target grants (matching our target grantee addrs[0])
    for i := 0; i < numTargetGrants; i++ {
        granter := sdk.AccAddress([]byte(fmt.Sprintf("target_granter%d", i)))
        err := app.AuthzKeeper.SaveGrant(ctx, suite.addrs[0], granter, authorization, now.Add(time.Hour))
        require.NoError(err)
    }
    
    // Track gas before query
    gasBefore := ctx.GasMeter().GasConsumed()
    
    // Query for grants to addrs[0] with pagination limit of 10
    // Expected: iterate ~10-20 records
    // Actual: iterates through ALL 1005 grants to find the 5 matches
    result, err := queryClient.GranteeGrants(gocontext.Background(), &authz.QueryGranteeGrantsRequest{
        Grantee: suite.addrs[0].String(),
        Pagination: &query.PageRequest{
            Limit: 10,
        },
    })
    
    require.NoError(err)
    require.Len(result.Grants, numTargetGrants)
    
    // Measure gas consumed
    gasAfter := ctx.GasMeter().GasConsumed()
    gasConsumed := gasAfter - gasBefore
    
    // With infinite gas meter, this won't panic, but gas is still tracked
    // The gas consumed will be proportional to the total iterations (~1005)
    // not the pagination limit (10)
    
    // Expected gas: ~10 iterations * (30 + 3*keysize + 3*valuesize)
    // Actual gas: ~1005 iterations * (30 + 3*keysize + 3*valuesize)
    expectedGasPerIteration := uint64(30 + 3*50 + 3*100) // rough estimate
    expectedReasonableGas := expectedGasPerIteration * 20 // 2x pagination limit
    
    // This assertion will fail, demonstrating excessive iteration
    require.Less(gasConsumed, expectedReasonableGas,
        "Gas consumed (%d) indicates iteration through all grants, not just limit", gasConsumed)
}
```

**Setup:**
The test uses the existing `TestSuite` infrastructure in `x/authz/keeper/grpc_query_test.go`.

**Trigger:**
The test creates 1000 "noise" grants with random grantees, plus 5 grants for the target grantee. Then queries with `limit=10` for the target grantee.

**Observation:**
The gas consumed will be proportional to ~1005 iterations (all grants) rather than ~10-20 iterations (pagination limit). The test assertion will fail, proving that the function iterates through far more records than the pagination limit, exposing the vulnerability. In a production environment with an infinite gas meter (as used in gRPC queries), this would cause unbounded resource consumption.

### Citations

**File:** types/query/filtered_pagination.go (L122-254)
```go
// GenericFilteredPaginate does pagination of all the results in the PrefixStore based on the
// provided PageRequest. `onResult` should be used to filter or transform the results.
// `c` is a constructor function that needs to return a new instance of the type T (this is to
// workaround some generic pitfalls in which we can't instantiate a T struct inside the function).
// If key is provided, the pagination uses the optimized querying.
// If offset is used, the pagination uses lazy filtering i.e., searches through all the records.
// The resulting slice (of type F) can be of a different type than the one being iterated through
// (type T), so it's possible to do any necessary transformation inside the onResult function.
func GenericFilteredPaginate[T codec.ProtoMarshaler, F codec.ProtoMarshaler](
	cdc codec.BinaryCodec,
	prefixStore types.KVStore,
	pageRequest *PageRequest,
	onResult func(key []byte, value T) (F, error),
	constructor func() T,
) ([]F, *PageResponse, error) {
	// if the PageRequest is nil, use default PageRequest
	if pageRequest == nil {
		pageRequest = &PageRequest{}
	}

	offset := pageRequest.Offset
	key := pageRequest.Key
	limit := pageRequest.Limit
	countTotal := pageRequest.CountTotal
	reverse := pageRequest.Reverse
	results := []F{}

	if offset > 0 && key != nil {
		return results, nil, fmt.Errorf("invalid request, either offset or key is expected, got both")
	}

	if limit == 0 {
		limit = DefaultLimit

		// count total results when the limit is zero/not supplied
		countTotal = true
	}

	if len(key) != 0 {
		iterator := getIterator(prefixStore, key, reverse)
		defer iterator.Close()

		var (
			numHits uint64
			nextKey []byte
		)

		for ; iterator.Valid(); iterator.Next() {
			if numHits == limit {
				nextKey = iterator.Key()
				break
			}

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
				results = append(results, val)
				numHits++
			}
		}

		return results, &PageResponse{
			NextKey: nextKey,
		}, nil
	}

	iterator := getIterator(prefixStore, nil, reverse)
	defer iterator.Close()

	end := offset + limit

	var (
		numHits uint64
		nextKey []byte
	)

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

	res := &PageResponse{NextKey: nextKey}
	if countTotal {
		res.Total = numHits
	}

	return results, res, nil
}
```

**File:** x/authz/keeper/grpc_query.go (L143-169)
```go
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
```

**File:** types/context.go (L261-272)
```go
// create a new context
func NewContext(ms MultiStore, header tmproto.Header, isCheckTx bool, logger log.Logger) Context {
	// https://github.com/gogo/protobuf/issues/519
	header.Time = header.Time.UTC()
	return Context{
		ctx:             context.Background(),
		ms:              ms,
		header:          header,
		chainID:         header.ChainID,
		checkTx:         isCheckTx,
		logger:          logger,
		gasMeter:        NewInfiniteGasMeter(1, 1),
```

**File:** baseapp/abci.go (L712-761)
```go
func (app *BaseApp) CreateQueryContext(height int64, prove bool) (sdk.Context, error) {
	err := checkNegativeHeight(height)
	if err != nil {
		return sdk.Context{}, err
	}

	lastBlockHeight := app.LastBlockHeight()
	if height > lastBlockHeight {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidHeight,
				"cannot query with height in the future; please provide a valid height",
			)
	}

	// when a client did not provide a query height, manually inject the latest
	if height == 0 {
		height = lastBlockHeight
	}

	if height <= 1 && prove {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidRequest,
				"cannot query with proof when height <= 1; please provide a valid height",
			)
	}

	var cacheMS types.CacheMultiStore
	if height < app.migrationHeight && app.qms != nil {
		cacheMS, err = app.qms.CacheMultiStoreWithVersion(height)
	} else {
		cacheMS, err = app.cms.CacheMultiStoreWithVersion(height)
	}

	if err != nil {
		return sdk.Context{},
			sdkerrors.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"failed to load state at height %d; %s (latest height: %d)", height, err, lastBlockHeight,
			)
	}

	checkStateCtx := app.checkState.Context()
	// branch the commit-multistore for safety
	ctx := sdk.NewContext(
		cacheMS, checkStateCtx.BlockHeader(), true, app.logger,
	).WithMinGasPrices(app.minGasPrices).WithBlockHeight(height)

	return ctx, nil
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
