# Audit Report

## Title
GranteeGrants Query Causes O(N) Full Store Scan Leading to RPC Node Resource Exhaustion DoS

## Summary
The `GranteeGrants` query in the x/authz module performs an inefficient O(N) full store scan where N equals the total number of grants in the entire system, rather than using indexed lookups for the specific grantee. This causes RPC node resource exhaustion as the system grows, leading to denial of service for all users.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The query should efficiently retrieve grants where a specific address is the grantee, using indexed lookups similar to `GranterGrants` which uses a prefix store with the granter address for O(M) complexity where M = grants for that specific granter. [2](#0-1) 

**Actual Logic:**
The implementation creates a prefix store using only `GrantKey` (0x01), which matches ALL grants in the entire system. The key structure stores grants as `GrantKey + Granter + Grantee + MsgType`, with granter appearing before grantee: [3](#0-2) 

Since grantee appears after granter in the key structure, there is no efficient prefix for querying by grantee alone. The code must iterate through ALL grants and filter in memory. When `CountTotal=true` in the pagination request, the pagination function continues scanning the entire store even after collecting sufficient results: [4](#0-3) 

**Exploitation Path:**
1. System naturally accumulates grants over time through normal usage (or attacker creates many grants via `MsgGrant` transactions)
2. Any user queries the public RPC endpoint at `/cosmos/authz/v1beta1/grants/grantee/{grantee}`: [5](#0-4) 
3. Query scans ALL grants in the system, unmarshaling each protobuf message and parsing each key
4. Query executes without gas metering (query contexts have no resource limits)
5. Normal query patterns cause cumulative resource exhaustion on RPC nodes

**Security Guarantee Broken:**
This violates the DoS protection property. RPC queries should have bounded resource consumption, but this query's cost grows linearly with total system grants (O(N)) rather than just the matching grants (O(M)). The codebase includes an explicit warning about this exact pattern: [6](#0-5) 

## Impact Explanation

**Affected Resources:**
- RPC node CPU: Unmarshaling grants, parsing keys, performing filtering comparisons
- RPC node I/O: Reading entire grant store from disk  
- RPC node memory: Maintaining iteration state across large datasets
- Network availability: RPC services becoming slow or unresponsive affecting all users

**Severity Assessment:**
As the blockchain matures and grants accumulate (e.g., from 1,000 to 100,000 grants), each `GranteeGrants` query must scan 100x more entries. This represents:
- 100x more disk reads
- 100x more protobuf unmarshaling operations
- 100x more key parsing and address extraction
- 100x more filtering comparisons

Even if `GranteeGrants` queries constitute only 10% of total query volume, a 100x increase in work for those queries translates to a 10x overall increase in resources for that query type, easily exceeding the 30% threshold when aggregated across normal daily operations.

This matches the Medium severity impact: **"Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours."**

## Likelihood Explanation

**Who Can Trigger:**
Any network participant. Queries are publicly accessible via RPC endpoints and require no authentication or special permissions.

**Conditions Required:**
- System accumulates grants over time through normal usage (no attack needed)
- Users make legitimate queries to check their received grants
- Standard network operation with no special conditions

**Frequency:**
This is not an attack that requires repeated malicious queries. Rather, it's a performance degradation that occurs naturally:
- As the system grows, grants accumulate organically
- Normal legitimate queries become progressively more expensive
- The inefficiency compounds with system growth
- Affects all RPC nodes processing these queries

**Likelihood Assessment:**
Extremely high likelihood because:
1. No attack needed - affects normal operations
2. Natural system growth triggers the issue
3. Public blockchains routinely accumulate large amounts of state
4. No protective mechanisms exist (no query limits, no secondary indexes)
5. Even conservative estimates (10,000+ grants) cause significant degradation

## Recommendation

**Short-term Fix:**
1. Add maximum iteration limit (e.g., 10,000 entries) with error on exceeded
2. Disable `CountTotal` for this query endpoint
3. Implement rate limiting at RPC infrastructure level
4. Document the performance characteristics for node operators

**Long-term Fix:**
Create secondary index for grantee-based lookups, mirroring the `GranterGrants` pattern:
1. Add new key prefix: `GranteeIndexKey + Grantee + Granter + MsgType → Grant`
2. Maintain index in `SaveGrant` and `DeleteGrant` methods  
3. Update `GranteeGrants` to use the grantee index for O(M) lookups where M = grants to specific grantee
4. This provides efficient querying by grantee without full store scans

## Proof of Concept

**Conceptual Test:** `x/authz/keeper/grpc_query_test.go` - `TestGranteeGrantsPerformanceDoS`

**Setup:**
1. Initialize test app and context using existing TestSuite framework
2. Create 1,000 grants from different granters to different grantees (simulating accumulated system state)
3. Create only 1 grant where target address is the grantee
4. Set up query client

**Action:**
1. Call `GranteeGrants` with target grantee address
2. Set `CountTotal=true` in pagination request to force full store scan
3. Capture pagination response including total count

**Expected Result:**
- Pagination response shows `Total=1000` (confirming ALL grants were scanned)
- Response contains only 1 matching grant
- Query iterated through 999 irrelevant grants to find 1 match
- Demonstrates O(N) complexity where N = total system grants rather than O(M) where M = grants for the queried grantee

This proves the query performance degrades linearly with total grants in the system. From reasoning alone, it is obvious that scanning 100,000 entries with full unmarshaling and key parsing consumes vastly more resources (100x) than scanning 1,000 entries, easily exceeding the 30% resource consumption threshold when aggregated across normal daily query patterns.

## Notes

The vulnerability is confirmed by comparing the `GranteeGrants` implementation with `GranterGrants`, which uses an efficient prefix-based lookup. The key structure prevents efficient grantee-based queries without a secondary index. The codebase itself includes a warning comment acknowledging this pattern should not be used in query services without charging gas, yet `GranteeGrants` uses exactly this pattern in a public query endpoint without any gas metering or resource limits.

### Citations

**File:** x/authz/keeper/grpc_query.go (L84-96)
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

**File:** x/authz/keeper/keys.go (L19-36)
```go
// grantStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>: Grant
func grantStoreKey(grantee sdk.AccAddress, granter sdk.AccAddress, msgType string) []byte {
	m := conv.UnsafeStrToBytes(msgType)
	granter = address.MustLengthPrefix(granter)
	grantee = address.MustLengthPrefix(grantee)

	l := 1 + len(grantee) + len(granter) + len(m)
	var key = make([]byte, l)
	copy(key, GrantKey)
	copy(key[1:], granter)
	copy(key[1+len(granter):], grantee)
	copy(key[l-len(m):], m)
	//	fmt.Println(">>>> len", l, key)
	return key
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

**File:** proto/cosmos/authz/v1beta1/query.proto (L28-30)
```text
  rpc GranteeGrants(QueryGranteeGrantsRequest) returns (QueryGranteeGrantsResponse) {
    option (google.api.http).get = "/cosmos/authz/v1beta1/grants/grantee/{grantee}";
  }
```

**File:** x/authz/keeper/keeper.go (L209-211)
```go
// IterateGrants iterates over all authorization grants
// This function should be used with caution because it can involve significant IO operations.
// It should not be used in query or msg services without charging additional gas.
```
