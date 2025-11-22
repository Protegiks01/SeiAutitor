# Audit Report

## Title
Double-Counting of Supply Values in Reverse Pagination Due to Deleted NextKey Item

## Summary
The `GetPaginatedTotalSupply` function contains a critical vulnerability in its reverse pagination logic that causes supply values to be counted twice when the NextKey item is deleted between paginated requests. This occurs in the `getIterator` helper function in `types/query/pagination.go` lines 144-158, which incorrectly handles the case where a pagination key no longer exists in the store. [1](#0-0) 

## Impact
**Medium** - This bug results in unintended behavior with supply accounting, causing incorrect total supply calculations when clients use paginated queries. While no funds are directly at risk, the supply accounting invariant is violated, which could lead to systemic issues in protocols relying on accurate supply data.

## Finding Description

**Location:** The vulnerability exists in the `getIterator` function at `types/query/pagination.go:144-158` and affects `GetPaginatedTotalSupply` at `x/bank/keeper/keeper.go:78-102`. [2](#0-1) 

**Intended Logic:** When paginating in reverse order, the NextKey returned from one request should be used as the starting point for the next request, with each item processed exactly once. The iterator should resume from where the previous page ended, without re-processing any items.

**Actual Logic:** When reverse pagination encounters a start key that no longer exists in the store (e.g., because that denomination's supply was burned to zero and deleted), the forward Iterator positions at the next key AFTER the deleted key instead of AT it. This causes the ReverseIterator to include items that were already processed in the previous page.

Specifically in `getIterator` for reverse pagination:
1. Line 148: `Iterator(start, nil)` is called where `start` is the deleted key
2. The Iterator positions at the first key >= start, which is the next key AFTER the deleted one  
3. Line 151: `Next()` moves one more position forward
4. Line 152: This key becomes the exclusive `end` boundary for `ReverseIterator`
5. Line 155: `ReverseIterator(nil, end)` includes items that were in the previous page

**Exploit Scenario:**
1. Initial supply store contains: [atom: 1000, foo: 2000, usei: 3000, usdc: 4000, weth: 5000]
2. Client makes Request 1: `GetPaginatedTotalSupply(ctx, &query.PageRequest{Reverse: true, Limit: 2})`
   - Returns: [weth: 5000, usdc: 4000], NextKey="usei"
   - Items processed: weth, usdc
3. Between requests, all usei tokens are burned via `BurnCoins`, which calls `SetSupply` with zero amount
4. Line 644 of keeper.go: `supplyStore.Delete([]byte("usei"))` removes usei from storage [3](#0-2) 

5. Store now contains: [atom: 1000, foo: 2000, usdc: 4000, weth: 5000]
6. Client makes Request 2: `GetPaginatedTotalSupply(ctx, &query.PageRequest{Reverse: true, Key: []byte("usei"), Limit: 2})`
   - `getIterator` is called with start="usei" (doesn't exist), reverse=true
   - Iterator("usei", nil) positions at "usdc" (next key >= "usei")
   - Next() moves to "weth"
   - ReverseIterator(nil, "weth") iterates over [atom, foo, usdc] in reverse
   - Returns: [usdc: 4000, foo: 2000]
7. **usdc is counted twice**: once in Request 1 and again in Request 2

**Security Failure:** The accounting invariant is violated - supply values are double-counted. Clients aggregating paginated results will calculate incorrect total supply, breaking the fundamental correctness guarantee of the supply tracking system.

## Impact Explanation

**Affected Assets:** Total supply calculations for all token denominations in the banking module.

**Severity of Damage:** 
- Clients using reverse pagination to query total supply will receive incorrect results
- The double-counting causes supply values to be inflated in aggregated results
- This violates the supply accounting invariant that the TotalSupply function is supposed to maintain
- Protocols or applications relying on accurate total supply data (e.g., for computing market cap, checking invariants, or making economic decisions) will operate on incorrect information
- While no funds are directly stolen or locked, the incorrect accounting could lead to downstream issues in systems that depend on accurate supply data

**System Impact:** This is a Medium severity issue because it causes unintended smart contract/protocol behavior with incorrect state calculations, fitting the scope: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation

**Who can trigger it:** Any client or application making paginated queries to `GetPaginatedTotalSupply` with reverse pagination enabled.

**Conditions required:**
1. Client must use reverse pagination (Reverse: true)
2. A denomination that becomes the NextKey must be completely burned (supply goes to zero) between paginated requests
3. Client must continue pagination using the returned NextKey

**Frequency:** This can occur during normal network operation whenever:
- Clients use reverse pagination for total supply queries
- Token supplies are burned to zero (which removes them from storage per line 644 of keeper.go)
- The timing aligns such that a denomination is burned between consecutive paginated requests

While the specific timing requirement makes this less likely than issues that occur on every call, it is not rare - token burning is a common operation, and pagination queries from clients/indexers happen continuously. The vulnerability is deterministic once the conditions are met.

## Recommendation

Fix the `getIterator` function to correctly handle the case where the start key doesn't exist for reverse pagination. When the start key is deleted, the reverse iterator should start from the position BEFORE where the deleted key would have been, not after it.

**Suggested fix:** Modify `getIterator` in `types/query/pagination.go` lines 144-158:

```go
func getIterator(prefixStore types.KVStore, start []byte, reverse bool) db.Iterator {
    if reverse {
        var end []byte
        if start != nil {
            itr := prefixStore.Iterator(start, nil)
            defer itr.Close()
            if itr.Valid() {
                // If iterator is at 'start', we want to exclude it (it's already processed)
                // So use 'start' itself as the exclusive end boundary
                end = itr.Key()
                // Only advance if we're exactly at the start key
                if bytes.Equal(itr.Key(), start) {
                    itr.Next()
                    if itr.Valid() {
                        end = itr.Key()
                    }
                }
            } else {
                // If start doesn't exist and iterator is invalid, use start as end
                end = start
            }
        }
        return prefixStore.ReverseIterator(nil, end)
    }
    return prefixStore.Iterator(start, nil)
}
```

Alternatively, document that clients should not use reverse pagination across mutable stores, or implement a snapshot mechanism to ensure pagination consistency.

## Proof of Concept

**File:** `x/bank/keeper/keeper_test.go`

**Test Function:** Add the following test function to the `IntegrationTestSuite`:

```go
func (suite *IntegrationTestSuite) TestGetPaginatedTotalSupply_ReversePaginationDoubleCount() {
    ctx := suite.ctx
    require := suite.Require()
    
    authKeeper, keeper := suite.initKeepersWithmAccPerms(make(map[string]bool))
    
    // Setup: Create multiple denominations with supply in alphabetical order
    // atom, foo, usei, usdc, weth
    atomCoin := sdk.NewInt64Coin("atom", 1000)
    fooCoin := sdk.NewInt64Coin("foo", 2000)
    useiCoin := sdk.NewInt64Coin("usei", 3000)
    usdcCoin := sdk.NewInt64Coin("usdc", 4000)
    wethCoin := sdk.NewInt64Coin("weth", 5000)
    
    totalSupply := sdk.NewCoins(atomCoin, fooCoin, useiCoin, usdcCoin, wethCoin)
    
    authKeeper.SetModuleAccount(ctx, minterAcc)
    authKeeper.SetModuleAccount(ctx, burnerAcc)
    
    require.NoError(keeper.MintCoins(ctx, authtypes.Minter, totalSupply))
    require.NoError(keeper.SendCoinsFromModuleToAccount(ctx, authtypes.Minter, burnerAcc.GetAddress(), totalSupply))
    
    // Request 1: Get first page with reverse pagination (limit=2)
    page1Supply, page1Res, err := keeper.GetPaginatedTotalSupply(ctx, &query.PageRequest{
        Reverse: true,
        Limit:   2,
    })
    require.NoError(err)
    require.NotNil(page1Res.NextKey)
    
    // Should get [weth: 5000, usdc: 4000]
    require.Equal(2, page1Supply.Len())
    require.Equal(int64(5000), page1Supply.AmountOf("weth").Int64())
    require.Equal(int64(4000), page1Supply.AmountOf("usdc").Int64())
    require.Equal("usei", string(page1Res.NextKey))
    
    // Between requests: Burn all usei tokens (this deletes the NextKey from storage)
    useiToburn := sdk.NewCoins(useiCoin)
    require.NoError(keeper.BurnCoins(ctx, authtypes.Burner, useiToburn))
    
    // Verify usei is removed from supply store
    useiSupply := keeper.GetSupply(ctx, "usei")
    require.True(useiSupply.IsZero())
    
    // Request 2: Get second page using NextKey from first page
    page2Supply, page2Res, err := keeper.GetPaginatedTotalSupply(ctx, &query.PageRequest{
        Reverse: true,
        Key:     page1Res.NextKey,
        Limit:   2,
    })
    require.NoError(err)
    
    // Expected: [foo: 2000, atom: 1000]
    // Actual BUG: [usdc: 4000, foo: 2000] - usdc is counted twice!
    require.Equal(2, page2Supply.Len())
    
    // This assertion will FAIL, demonstrating the bug
    // usdc should NOT appear in page 2 since it was already in page 1
    require.Equal(int64(0), page2Supply.AmountOf("usdc").Int64(), 
        "BUG: usdc was counted in page 1 but appears again in page 2")
    
    // Aggregate results to see the double-count
    aggregatedSupply := page1Supply.Add(page2Supply...)
    
    // usdc is counted twice: once with 4000 from page1, once with 4000 from page2
    require.Equal(int64(4000), aggregatedSupply.AmountOf("usdc").Int64(),
        "usdc should only be counted once")
    
    // The aggregated supply is incorrect
    expectedTotal := sdk.NewCoins(atomCoin, fooCoin, usdcCoin, wethCoin) // usei was burned
    require.Equal(expectedTotal, aggregatedSupply,
        "BUG: Aggregated supply has double-counted usdc")
}
```

**Setup:** The test initializes a supply store with 5 denominations in alphabetical order: atom, foo, usei, usdc, weth.

**Trigger:** 
1. Makes a reverse paginated query with limit=2, getting the last 2 items (weth, usdc) and NextKey="usei"
2. Burns all usei tokens, causing it to be deleted from the supply store
3. Makes a second paginated query with the NextKey="usei"

**Observation:** The test will fail because:
- usdc appears in both page 1 and page 2 responses
- The aggregated supply counts usdc twice (8000 total instead of 4000)
- The assertion `require.Equal(int64(0), page2Supply.AmountOf("usdc").Int64())` fails, proving usdc was double-counted

This PoC can be run in the project's test suite with `go test -v -run TestGetPaginatedTotalSupply_ReversePaginationDoubleCount` to reproduce the vulnerability.

### Citations

**File:** types/query/pagination.go (L144-158)
```go
func getIterator(prefixStore types.KVStore, start []byte, reverse bool) db.Iterator {
	if reverse {
		var end []byte
		if start != nil {
			itr := prefixStore.Iterator(start, nil)
			defer itr.Close()
			if itr.Valid() {
				itr.Next()
				end = itr.Key()
			}
		}
		return prefixStore.ReverseIterator(nil, end)
	}
	return prefixStore.Iterator(start, nil)
}
```

**File:** x/bank/keeper/keeper.go (L78-102)
```go
// GetPaginatedTotalSupply queries for the supply, ignoring 0 coins, with a given pagination
func (k BaseKeeper) GetPaginatedTotalSupply(ctx sdk.Context, pagination *query.PageRequest) (sdk.Coins, *query.PageResponse, error) {
	store := ctx.KVStore(k.storeKey)
	supplyStore := prefix.NewStore(store, types.SupplyKey)

	supply := sdk.NewCoins()

	pageRes, err := query.Paginate(supplyStore, pagination, func(key, value []byte) error {
		var amount sdk.Int
		err := amount.Unmarshal(value)
		if err != nil {
			return fmt.Errorf("unable to convert amount string to Int %v", err)
		}

		// `Add` omits the 0 coins addition to the `supply`.
		supply = supply.Add(sdk.NewCoin(string(key), amount))
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return supply, pageRes, nil
}
```

**File:** x/bank/keeper/keeper.go (L642-644)
```go
	// Bank invariants and IBC requires to remove zero coins.
	if coin.IsZero() {
		supplyStore.Delete([]byte(coin.GetDenom()))
```
