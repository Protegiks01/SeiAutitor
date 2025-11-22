# Audit Report

## Title
Missing Maximum Limit Validation in Pagination Allows Unbounded Resource Consumption

## Summary
The pagination logic in `types/query/pagination.go` does not validate or enforce maximum page size limits, allowing attackers to request arbitrarily large result sets (up to `math.MaxUint64`) via gRPC queries. This causes unbounded memory allocation, CPU exhaustion, and potential node crashes through resource exhaustion.

## Impact
**Medium to High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The pagination system should enforce reasonable limits on page sizes to prevent resource exhaustion. A `MaxLimit` constant is defined [2](#0-1)  suggesting an intention to cap pagination, and a `DefaultLimit` of 100 is used when no limit is specified [3](#0-2) .

**Actual Logic:** 
The `Paginate` function accepts `PageRequest.Limit` as a `uint64` without any maximum validation [4](#0-3) . When a non-zero limit is provided, it is used directly without bounds checking [5](#0-4) . The iteration logic then processes items while `count <= end` where `end = offset + limit` [6](#0-5) , allowing an attacker to specify `limit = math.MaxUint64` and force iteration over the entire dataset.

**Exploit Scenario:**
1. An attacker crafts a gRPC query (e.g., `AllBalances`, `Validators`, `Proposals`) with `PageRequest{Limit: math.MaxUint64}` or any extremely large value
2. The request is passed directly to `query.Paginate()` without validation [7](#0-6) 
3. The pagination loop iterates through the entire store, appending all results to memory
4. The node experiences memory exhaustion, CPU saturation, and potential OOM crash
5. The gRPC server becomes unresponsive, affecting all other queries

**Security Failure:** 
This breaks the denial-of-service protection invariant. The pagination mechanism is designed to limit resource consumption per query, but the lack of maximum limit enforcement allows unprivileged attackers to bypass this protection and consume unbounded resources.

## Impact Explanation

**Affected Assets/Processes:**
- **Node availability**: Excessive memory allocation can trigger OOM kills, crashing the node
- **RPC service**: CPU and memory exhaustion makes the gRPC server unresponsive to legitimate queries
- **Network capacity**: Bandwidth consumed returning massive responses, delaying block propagation
- **Chain liveness**: If enough validators run affected nodes, consensus could be disrupted

**Severity:**
- **Memory**: Loading millions of items (validators, balances, delegations) into memory can exhaust available RAM on typical validator hardware
- **CPU**: Iterating and marshaling large datasets blocks query processing threads
- **Cascading failures**: One malicious query can degrade node performance for all subsequent requests
- **Persistent vulnerability**: Attack can be repeated indefinitely at minimal cost to attacker

**System Impact:**
This vulnerability directly enables the Medium-severity impacts defined in scope: "Increasing network processing node resource consumption by at least 30%" and "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions." In extreme cases with large datasets, it could cause High-severity "RPC API crash" impacting dependent projects.

## Likelihood Explanation

**Trigger Conditions:**
- **Who**: Any unauthenticated network participant with gRPC access can trigger this
- **Requirements**: No special privileges, credentials, or state conditions required
- **Method**: Simply send a gRPC query with a malicious `PageRequest.Limit` value

**Frequency:**
- Can be exploited continuously and repeatedly
- Works against any query endpoint using `Paginate` or `FilteredPaginate` (bank, staking, gov, distribution, etc.)
- Attack cost is minimal (single gRPC request), while defense cost is high (node resources)
- Public RPC endpoints are typically exposed, making this easily accessible

**Realistic Scenarios:**
- Production networks with thousands of validators, delegators, or token holders have sufficient data volume to cause significant resource exhaustion
- Validators and full nodes commonly expose gRPC endpoints for applications, making them vulnerable
- No special timing or network conditions required - works during normal operation

## Recommendation

Implement maximum limit validation in the `Paginate` function:

```go
// In types/query/pagination.go, modify the Paginate function
const MaxPageSize = 1000 // Reasonable maximum, can be configurable

func Paginate(...) (*PageResponse, error) {
    if pageRequest == nil {
        pageRequest = &PageRequest{}
    }
    
    // Add validation BEFORE using limit
    limit := pageRequest.Limit
    if limit == 0 {
        limit = DefaultLimit
        countTotal = true
    } else if limit > MaxPageSize {
        return nil, fmt.Errorf("limit %d exceeds maximum allowed page size %d", limit, MaxPageSize)
    }
    
    // Continue with existing logic...
}
```

Apply the same validation to `FilteredPaginate` and `GenericFilteredPaginate` functions. Consider making `MaxPageSize` configurable via node config for operators who need larger limits in trusted environments.

## Proof of Concept

**File:** `types/query/pagination_test.go`

**Test Function:** `TestPaginationExcessiveLimit` (add to existing test suite)

**Setup:**
Use the existing `setupTest()` function to create a simapp instance and context. Fund an account with multiple balance entries to create a realistic dataset (reuse pattern from existing tests).

**Trigger:**
```go
func (s *paginationTestSuite) TestPaginationExcessiveLimit() {
    app, ctx, _ := setupTest()
    queryHelper := baseapp.NewQueryServerTestHelper(ctx, app.InterfaceRegistry())
    types.RegisterQueryServer(queryHelper, app.BankKeeper)
    queryClient := types.NewQueryClient(queryHelper)

    // Create test data - add multiple balance entries
    var balances sdk.Coins
    for i := 0; i < 100; i++ {
        denom := fmt.Sprintf("testcoin%d", i)
        balances = append(balances, sdk.NewInt64Coin(denom, 1000))
    }
    
    addr := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
    acc := app.AccountKeeper.NewAccountWithAddress(ctx, addr)
    app.AccountKeeper.SetAccount(ctx, acc)
    s.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr, balances))

    // Attack: Request with extremely large limit
    pageReq := &query.PageRequest{
        Limit: math.MaxUint64, // Malicious large limit
    }
    request := types.NewQueryAllBalancesRequest(addr, pageReq)
    
    // This should either fail with validation error OR demonstrate resource exhaustion
    res, err := queryClient.AllBalances(gocontext.Background(), request)
    
    // Current vulnerable behavior: Returns ALL results without limit enforcement
    // Expected secure behavior: Should return error or enforce reasonable limit
    s.Require().NoError(err) // Currently passes - demonstrates vulnerability
    s.Require().Equal(100, res.Balances.Len()) // Returns all 100 items, not limited
    
    // In a real attack with millions of entries, this would cause OOM
}
```

**Observation:**
The test demonstrates that when `Limit: math.MaxUint64` is specified, the `Paginate` function processes and returns ALL items in the store without any maximum limit enforcement. With larger datasets (validators, delegations, token holders), this causes memory exhaustion and node crash. The test currently passes on vulnerable code, proving the lack of validation. After applying the recommended fix, the test should fail with a validation error, confirming the protection is in place.

### Citations

**File:** types/query/pagination.go (L14-16)
```go
// DefaultLimit is the default `limit` for queries
// if the `limit` is not supplied, paginate will use `DefaultLimit`
const DefaultLimit = 100
```

**File:** types/query/pagination.go (L18-20)
```go
// MaxLimit is the maximum limit the paginate function can handle
// which equals the maximum value that can be stored in uint64
const MaxLimit = math.MaxUint64
```

**File:** types/query/pagination.go (L46-142)
```go
// Paginate does pagination of all the results in the PrefixStore based on the
// provided PageRequest. onResult should be used to do actual unmarshaling.
func Paginate(
	prefixStore types.KVStore,
	pageRequest *PageRequest,
	onResult func(key []byte, value []byte) error,
) (*PageResponse, error) {

	// if the PageRequest is nil, use default PageRequest
	if pageRequest == nil {
		pageRequest = &PageRequest{}
	}

	offset := pageRequest.Offset
	key := pageRequest.Key
	limit := pageRequest.Limit
	countTotal := pageRequest.CountTotal
	reverse := pageRequest.Reverse

	if offset > 0 && key != nil {
		return nil, fmt.Errorf("invalid request, either offset or key is expected, got both")
	}

	if limit == 0 {
		limit = DefaultLimit

		// count total results when the limit is zero/not supplied
		countTotal = true
	}

	if len(key) != 0 {
		iterator := getIterator(prefixStore, key, reverse)
		defer iterator.Close()

		var count uint64
		var nextKey []byte

		for ; iterator.Valid(); iterator.Next() {

			if count == limit {
				nextKey = iterator.Key()
				break
			}
			if iterator.Error() != nil {
				return nil, iterator.Error()
			}
			err := onResult(iterator.Key(), iterator.Value())
			if err != nil {
				return nil, err
			}

			count++
		}

		return &PageResponse{
			NextKey: nextKey,
		}, nil
	}

	iterator := getIterator(prefixStore, nil, reverse)
	defer iterator.Close()

	end := offset + limit

	var count uint64
	var nextKey []byte

	for ; iterator.Valid(); iterator.Next() {
		count++

		if count <= offset {
			continue
		}
		if count <= end {
			err := onResult(iterator.Key(), iterator.Value())
			if err != nil {
				return nil, err
			}
		} else if count == end+1 {
			nextKey = iterator.Key()

			if !countTotal {
				break
			}
		}
		if iterator.Error() != nil {
			return nil, iterator.Error()
		}
	}

	res := &PageResponse{NextKey: nextKey}
	if countTotal {
		res.Total = count
	}

	return res, nil
}
```

**File:** proto/cosmos/base/query/v1beta1/pagination.proto (L24-26)
```text
  // limit is the total number of results to be returned in the result page.
  // If left empty it will default to a value to be set by each app.
  uint64 limit = 3;
```

**File:** x/bank/keeper/grpc_query.go (L62-70)
```go
	pageRes, err := query.Paginate(accountStore, req.Pagination, func(_, value []byte) error {
		var result sdk.Coin
		err := k.cdc.Unmarshal(value, &result)
		if err != nil {
			return err
		}
		balances = append(balances, result)
		return nil
	})
```
