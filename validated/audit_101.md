# Audit Report

## Title
Unvalidated Pagination Limit Causing Resource Exhaustion in GranteeGrants Query

## Summary
The `GranteeGrants` gRPC query in the authz module allows unprivileged attackers to cause significant resource exhaustion by exploiting inefficient store iteration combined with unbounded pagination limits. The query iterates over ALL grants in the system with expensive unmarshaling operations occurring before filtering, and no upper bound validation prevents arbitrarily large pagination limits.

## Impact
**Medium**

## Finding Description

**Location:** `x/authz/keeper/grpc_query.go` lines 132-178 (GranteeGrants function) and `types/query/filtered_pagination.go` lines 130-254 (GenericFilteredPaginate function)

**Intended Logic:** The pagination mechanism should efficiently query only grants relevant to the specified grantee with reasonable resource limits. Queries should process only the minimum necessary data and enforce bounds to prevent abuse.

**Actual Logic:** 

The `GranteeGrants` function creates a prefix store using only `GrantKey` (0x01) which includes ALL grants in the system, not just grantee-specific grants. [1](#0-0) 

This occurs because the grant key structure places granter before grantee, making grantee-specific prefixes impossible. [2](#0-1) [3](#0-2) 

The `GenericFilteredPaginate` function unmarshals every grant entry BEFORE applying the grantee filter. [4](#0-3) 

The filtering happens in the `onResult` callback, which returns nil for non-matching entries, but the expensive unmarshal has already occurred. [5](#0-4) 

While `MaxLimit = math.MaxUint64` is defined, there is no enforcement preventing users from requesting arbitrarily large limits. [6](#0-5) 

The pagination logic only sets a default when limit is 0, but accepts any non-zero value without validation. [7](#0-6) 

Query contexts are created with infinite gas meters, providing no resource protection. [8](#0-7) 

**Exploitation Path:**
1. Attacker calls the publicly accessible `GranteeGrants` gRPC endpoint with any address (including one with zero grants)
2. Attacker sets pagination `Limit` to a very large value (e.g., 10,000,000)
3. Node creates prefix store that includes entire grant store (all grants with prefix 0x01)
4. Pagination iterates through the store, unmarshaling each grant via expensive protobuf deserialization
5. After unmarshaling, the filter checks if grantee matches and returns nil for non-matching entries
6. Loop continues trying to find `limit` matching entries, processing the entire store when insufficient matches exist [9](#0-8) 
7. Attacker repeats with multiple concurrent queries to amplify impact

**Security Guarantee Broken:** Resource limitation and DoS protection. The system fails to enforce reasonable bounds on query resource consumption, allowing unprivileged users to exhaust node resources.

## Impact Explanation

On a mature blockchain with substantial authz usage (thousands to millions of grants), this vulnerability allows attackers to force nodes to:
- Perform expensive protobuf unmarshaling operations on every grant in the system
- Allocate memory for each unmarshaled grant object
- Consume significant CPU and memory resources per query

Multiple concurrent malicious queries amplify the effect. Nodes experience degraded performance and become unable to process legitimate transactions promptly. This meets the Medium severity threshold of "Increasing network processing node resource consumption by at least 30% without brute force actions" because:
- A single query with a large limit can force processing of the entire grant store
- No brute force is required (legitimate gRPC call with large pagination limit)
- Public RPC nodes are accessible to any network participant
- Impact scales with the number of grants in the system

## Likelihood Explanation

**Trigger Conditions:**
- Any network participant with gRPC endpoint access (standard for public RPC nodes)
- No authentication, authorization, or on-chain resources required
- Authz module contains grants (normal operational state for active chains)
- No special timing or race conditions needed

**Frequency:** Can be exploited continuously with multiple concurrent queries. The attack is trivial (single gRPC call with large limit parameter) and works against any public RPC endpoint. Likelihood is high in production environments where chains accumulate grants over time through normal authz usage.

## Recommendation

**Immediate Fixes:**

1. Add upper bound validation for pagination limits:
```go
const MaxQueryLimit = 1000

if req.Pagination != nil && req.Pagination.Limit > MaxQueryLimit {
    req.Pagination.Limit = MaxQueryLimit
}
```

2. Optimize store iteration by restructuring the grant key schema to enable efficient grantee-based lookups, or implement a secondary index for grantee queries.

**Long-term Improvements:**
- Implement rate limiting on expensive query endpoints
- Add query gas metering for read operations to limit resource consumption
- Consider caching mechanisms for frequently accessed grant data
- Add monitoring and alerting for excessive query resource consumption

## Proof of Concept

**Setup:** In `x/authz/keeper/grpc_query_test.go`, create a test with 10,000 grants between various granter-grantee pairs to simulate a populated authz store on a production chain.

**Action:** Call `GranteeGrants` with an address that has zero grants and a pagination limit of 1,000,000:
```go
queryClient.GranteeGrants(context.Background(), &authz.QueryGranteeGrantsRequest{
    Grantee: victimAddr.String(),
    Pagination: &query.PageRequest{Limit: 1000000},
})
```

**Result:** Despite returning zero grants (no matches), the query iterates through and unmarshals all 10,000 grants in the store. Profiling would show significant CPU time spent in protobuf unmarshaling. The elapsed time and resource consumption demonstrate the vulnerability. In production with millions of grants, this causes severe resource exhaustion that can affect 30% or more of network processing nodes.

## Notes

The comparison with `GranterGrants` is instructive - it uses `grantStoreKey(nil, granter, "")` which creates an efficient granter-specific prefix. [10](#0-9) 

In contrast, `GranteeGrants` cannot use a grantee-specific prefix due to the key structure placing granter before grantee in the composite key. This architectural limitation makes grantee queries inherently inefficient, which when combined with unbounded pagination limits and infinite gas meters for queries, creates a significant DoS vector for unprivileged attackers targeting public RPC infrastructure.

### Citations

**File:** x/authz/keeper/grpc_query.go (L96-96)
```go
	authzStore := prefix.NewStore(store, grantStoreKey(nil, granter, ""))
```

**File:** x/authz/keeper/grpc_query.go (L143-143)
```go
	store := prefix.NewStore(ctx.KVStore(k.storeKey), GrantKey)
```

**File:** x/authz/keeper/grpc_query.go (L151-154)
```go
		granter, g := addressesFromGrantStoreKey(append(GrantKey, key...))
		if !g.Equals(grantee) {
			return nil, nil
		}
```

**File:** x/authz/keeper/keys.go (L22-22)
```go
// - 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>: Grant
```

**File:** x/authz/keeper/keys.go (L30-32)
```go
	copy(key, GrantKey)
	copy(key[1:], granter)
	copy(key[1+len(granter):], grantee)
```

**File:** types/query/filtered_pagination.go (L153-158)
```go
	if limit == 0 {
		limit = DefaultLimit

		// count total results when the limit is zero/not supplied
		countTotal = true
	}
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

**File:** types/query/pagination.go (L18-20)
```go
// MaxLimit is the maximum limit the paginate function can handle
// which equals the maximum value that can be stored in uint64
const MaxLimit = math.MaxUint64
```

**File:** types/context.go (L272-272)
```go
		gasMeter:        NewInfiniteGasMeter(1, 1),
```
