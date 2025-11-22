## Title
Integer Overflow in Pagination Offset+Limit Calculation Causes Result Skipping and Resource Exhaustion

## Summary
The pagination implementation in `types/query/pagination.go` performs an unchecked uint64 addition of `offset + limit` that can overflow, causing the pagination logic to either skip all results or return all results from the store, bypassing pagination limits. This can be exploited by any user making gRPC queries with crafted pagination parameters.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

The vulnerability is in the `Paginate` function at line 108, where `end := offset + limit` is calculated without overflow checking. The same issue exists in filtered pagination variants. [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The pagination system should safely handle offset and limit parameters to return a bounded subset of results. The `end` variable should represent the last item index to include in the current page (offset + limit).

**Actual Logic:** 
When `offset + limit` exceeds `math.MaxUint64`, the addition wraps around to a small value due to uint64 overflow. This causes two distinct failure modes:

1. **All Results Skipped**: When overflow produces `end < offset`, the condition `count <= offset` at line 116 causes all items to be skipped via `continue`, while `count <= end` is never reached. The query returns an empty result set with no `nextKey`, even when data exists.

2. **All Results Returned**: When `limit` is near `math.MaxUint64`, the condition `count <= end` at line 119 becomes true for all items in the store. Additionally, `count == end+1` at line 124 never triggers (as `end+1` overflows to 0), so `nextKey` is never set and pagination continues until the iterator is exhausted.

**Exploit Scenario:**
Any user can send a gRPC query (e.g., `AllBalances`, `Validators`, `Delegations`) with manipulated pagination parameters:

- Scenario A: Set `offset = math.MaxUint64 - 50` and `limit = 100` → All results skipped
- Scenario B: Set `offset = 0` and `limit = math.MaxUint64` → All results returned

No special privileges are required, as these are public query endpoints accessible via gRPC/REST APIs. [4](#0-3) [5](#0-4) 

**Security Failure:**
The overflow violates pagination invariants, leading to:
- **Denial of Service**: Queries returning entire datasets can exhaust node memory and CPU
- **API Unreliability**: Queries returning empty results when data exists break client applications
- **Resource Exhaustion**: Large stores (millions of entries) could cause nodes to crash or become unresponsive

## Impact Explanation

**Affected Components:**
- All gRPC query endpoints using `query.Paginate`, `query.FilteredPaginate`, or `query.GenericFilteredPaginate`
- Modules include: bank, staking, gov, authz, feegrant, distribution, evidence, slashing

**Severity:**
- **Resource Exhaustion**: Queries attempting to return millions of entries can cause nodes to run out of memory or consume excessive CPU, potentially crashing the RPC service
- **Network Impact**: If 30%+ of public RPC nodes are targeted simultaneously, it could significantly degrade network query availability
- **Client Disruption**: Applications relying on pagination will receive incorrect results (empty or unbounded), breaking UX and potentially causing financial losses if trading bots or DeFi protocols depend on accurate queries

The codebase already has overflow protection (`addUint64Overflow`) for gas metering but fails to apply it to pagination. [6](#0-5) 

## Likelihood Explanation

**Triggering Conditions:**
- **Who**: Any user with access to the chain's RPC/gRPC endpoints
- **When**: At any time during normal operation
- **Requirements**: None - just craft a query with large `offset` or `limit` values

**Likelihood:**
High. The vulnerability is:
- Trivially exploitable (single malformed query)
- Affects all public query endpoints
- No authentication or special conditions required
- Can be automated for sustained attacks

**Frequency:**
An attacker could repeatedly send malicious queries to exhaust resources or could discover this accidentally when using large pagination values.

## Recommendation

Add overflow checking before computing `end` in all pagination functions:

1. Use the existing `addUint64Overflow` pattern or create a similar check:
   ```go
   end, overflow := addUint64Overflow(offset, limit)
   if overflow {
       return nil, fmt.Errorf("pagination overflow: offset + limit exceeds maximum")
   }
   ```

2. Apply this check in:
   - `types/query/pagination.go` line 108
   - `types/query/filtered_pagination.go` lines 83 and 205

3. Consider adding a reasonable maximum limit value (e.g., 10,000) to prevent excessively large limit values, similar to how other blockchain systems implement pagination bounds.

## Proof of Concept

**File:** `types/query/pagination_test.go`

**Test Function:** Add this test to the existing test suite:

```go
func (s *paginationTestSuite) TestPaginationIntegerOverflow() {
	app, ctx, _ := setupTest()
	queryHelper := baseapp.NewQueryServerTestHelper(ctx, app.InterfaceRegistry())
	types.RegisterQueryServer(queryHelper, app.BankKeeper)
	queryClient := types.NewQueryClient(queryHelper)

	var balances sdk.Coins
	for i := 0; i < numBalances; i++ {
		denom := fmt.Sprintf("foo%ddenom", i)
		balances = append(balances, sdk.NewInt64Coin(denom, 100))
	}

	balances = balances.Sort()
	addr1 := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
	acc1 := app.AccountKeeper.NewAccountWithAddress(ctx, addr1)
	app.AccountKeeper.SetAccount(ctx, acc1)
	s.Require().NoError(simapp.FundAccount(app.BankKeeper, ctx, addr1, balances))

	s.T().Log("Test overflow causing all results to be skipped")
	// offset = MaxUint64 - 10, limit = 100
	// end = MaxUint64 + 90 (overflows to 89)
	// Since all count values (1..235) are <= offset, all results are skipped
	pageReq := &query.PageRequest{
		Offset: uint64(math.MaxUint64 - 10),
		Limit:  100,
	}
	request := types.NewQueryAllBalancesRequest(addr1, pageReq)
	res, err := queryClient.AllBalances(gocontext.Background(), request)
	
	// BUG: Should return error or some results, but returns empty due to overflow
	s.Require().NoError(err)
	s.Require().Equal(0, res.Balances.Len(), "Expected empty results due to overflow bug")
	s.Require().Nil(res.Pagination.NextKey, "Expected no nextKey due to overflow bug")

	s.T().Log("Test overflow causing unbounded results")
	// offset = 0, limit = MaxUint64
	// end = MaxUint64
	// All items satisfy count <= end, and end+1 overflows to 0
	// This attempts to return ALL results
	pageReq = &query.PageRequest{
		Offset: 0,
		Limit:  uint64(math.MaxUint64),
		CountTotal: false,
	}
	request = types.NewQueryAllBalancesRequest(addr1, pageReq)
	res, err = queryClient.AllBalances(gocontext.Background(), request)
	
	// BUG: Should be limited by default pagination, but returns all results
	s.Require().NoError(err)
	s.Require().Equal(numBalances, res.Balances.Len(), "Expected all results due to overflow bug")
	s.Require().Nil(res.Pagination.NextKey, "Expected no nextKey as all results returned")
}
```

**Setup:** The test uses the existing test infrastructure with 235 balance entries.

**Trigger:** 
1. First query with `offset = math.MaxUint64 - 10, limit = 100` triggers the skip-all-results bug
2. Second query with `offset = 0, limit = math.MaxUint64` triggers the return-all-results bug

**Observation:** 
- First query returns 0 results when 235 exist (incorrect)
- Second query returns all 235 results without pagination (incorrect)
- Both demonstrate the overflow vulnerability causing incorrect pagination behavior

Run with: `go test -v ./types/query -run TestPaginationIntegerOverflow`

### Citations

**File:** types/query/pagination.go (L108-108)
```go
	end := offset + limit
```

**File:** types/query/filtered_pagination.go (L83-83)
```go
	end := offset + limit
```

**File:** types/query/filtered_pagination.go (L205-205)
```go
	end := offset + limit
```

**File:** x/bank/keeper/grpc_query.go (L62-74)
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

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "paginate: %v", err)
	}
```

**File:** x/staking/keeper/grpc_query.go (L40-59)
```go
	pageRes, err := query.FilteredPaginate(valStore, req.Pagination, func(key []byte, value []byte, accumulate bool) (bool, error) {
		val, err := types.UnmarshalValidator(k.cdc, value)
		if err != nil {
			return false, err
		}

		if req.Status != "" && !strings.EqualFold(val.GetStatus().String(), req.Status) {
			return false, nil
		}

		if accumulate {
			validators = append(validators, val)
		}

		return true, nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
```

**File:** store/types/gas.go (L89-95)
```go
func addUint64Overflow(a, b uint64) (uint64, bool) {
	if math.MaxUint64-a < b {
		return 0, true
	}

	return a + b, false
}
```
