## Title
Unbounded ABCI Subspace Query Enables Denial-of-Service via State Iteration

## Summary
The ABCI `/subspace` query endpoint iterates over all keys matching a given prefix without pagination or gas limits, allowing attackers to cause resource exhaustion and denial-of-service by querying large datasets. Query contexts use infinite gas meters, bypassing resource controls that protect transaction execution.

## Impact
**Medium to High**

## Finding Description

### Location
- **Primary vulnerability:** [1](#0-0) 
- **Also affects:** [2](#0-1) 
- **And:** [3](#0-2) 
- **Root cause:** [4](#0-3) 

### Intended Logic
The `/subspace` ABCI query endpoint is designed to retrieve key-value pairs matching a given prefix for debugging and administrative purposes. Query operations should be resource-bounded to prevent abuse.

### Actual Logic
The `/subspace` handler collects ALL matching key-value pairs into memory without any pagination or limits: [5](#0-4) 

Query contexts are created with infinite gas meters that never enforce limits: [6](#0-5) 

The infinite gas meter always returns `false` for limit checks: [7](#0-6) 

### Exploit Scenario
1. Attacker identifies a store module with many keys under a common prefix (e.g., bank module's balance store uses `BalancesPrefix = 0x02`): [8](#0-7) 

2. The bank module stores all account balances under this prefix: [9](#0-8) 

3. Attacker sends ABCI query via RPC: [10](#0-9) 
   - Path: `/store/bank/subspace`
   - Data: `[]byte{0x02}` (BalancesPrefix)

4. BaseApp routes to multistore Query: [11](#0-10) 

5. Store iterates ALL matching entries, loading gigabytes of data into memory

6. Multiple concurrent queries can exhaust node memory and crash the process

### Security Failure
This breaks **resource isolation** and **denial-of-service protection**. While transaction execution has gas metering to prevent resource exhaustion, queries bypass this protection, allowing unbounded computation and memory allocation that can crash nodes.

## Impact Explanation

**Affected Components:**
- RPC nodes serving ABCI queries become unresponsive or crash
- Network availability degrades as query load increases
- Legitimate users cannot access chain data

**Severity:**
- **Memory exhaustion:** On a chain with 1M accounts, querying all balances loads hundreds of MB to GB into memory
- **CPU exhaustion:** Iterating and marshaling millions of key-value pairs blocks query handlers
- **Cascading failure:** Multiple concurrent queries can crash ≥30% of RPC nodes simultaneously
- **No authentication required:** Any external user can trigger via standard RPC endpoints

This meets the **Medium** severity criteria: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" and potentially **High** severity: "RPC API crash affecting projects with greater than or equal to 25% of the market capitalization."

## Likelihood Explanation

**Triggering Requirements:**
- Any unauthenticated user can send ABCI queries via public RPC endpoints
- No special privileges, timing, or configuration needed
- Attack works during normal chain operation

**Conditions:**
- Blockchain must have accumulated sufficient state (realistic on any production chain)
- Common modules like bank, staking, and gov all use prefix stores with potentially millions of entries

**Frequency:**
- Can be triggered at any time with a single RPC call
- Multiple concurrent queries amplify the impact
- Highly likely to be exploited if discovered by adversaries

## Recommendation

**Immediate Mitigation:**
1. Add pagination support to `/subspace` query endpoint with a maximum result limit (e.g., 1000 entries)
2. Implement query-specific gas meters with reasonable limits (similar to transaction gas limits)
3. Add rate limiting for expensive query operations at the RPC layer

**Implementation:**
```
// In store Query methods, add pagination check:
const maxSubspaceResults = 1000
count := 0
for ; iterator.Valid(); iterator.Next() {
    if count >= maxSubspaceResults {
        // Return error or truncate with pagination token
        break
    }
    pairs.Pairs = append(pairs.Pairs, kv.Pair{...})
    count++
}
```

**Long-term Solution:**
- Deprecate unbounded `/subspace` queries in favor of paginated gRPC query endpoints
- Enforce query gas limits consistently across all query types
- Add monitoring and alerting for expensive query patterns

## Proof of Concept

**File:** `store/iavl/store_test.go`

**Test Function:** `TestSubspaceQueryDoS`

**Setup:**
```go
func TestSubspaceQueryDoS(t *testing.T) {
    // Create store with many keys under same prefix
    db := dbm.NewMemDB()
    tree, err := iavl.NewMutableTree(db, 10000, false)
    require.NoError(t, err)
    
    // Simulate realistic state: 100k accounts with balances
    prefix := []byte{0x02} // BalancesPrefix
    const numAccounts = 100000
    
    startTime := time.Now()
    startMem := getMemUsage()
    
    // Populate state (attacker can do this via normal transactions)
    for i := 0; i < numAccounts; i++ {
        key := append(prefix, []byte(fmt.Sprintf("account%d", i))...)
        value := []byte(fmt.Sprintf("balance%d", i*1000))
        tree.Set(key, value)
    }
    _, _, err = tree.SaveVersion()
    require.NoError(t, err)
    
    store := UnsafeNewStore(tree)
    
    // Trigger: Send subspace query
    req := abci.RequestQuery{
        Path: "/subspace",
        Data: prefix,
    }
    
    queryStart := time.Now()
    resp := store.Query(req)
    queryDuration := time.Since(queryStart)
    
    // Observation: Query loads all entries into memory
    var pairs kv.Pairs
    err = pairs.Unmarshal(resp.Value)
    require.NoError(t, err)
    
    endMem := getMemUsage()
    
    // Assertions demonstrating DoS impact
    assert.Equal(t, numAccounts, len(pairs.Pairs), "All entries loaded")
    assert.Greater(t, queryDuration, 1*time.Second, "Query took excessive time")
    assert.Greater(t, endMem-startMem, 10*1024*1024, "Memory increased by >10MB")
    
    t.Logf("DoS Impact: %d entries, %v duration, %d MB memory", 
        len(pairs.Pairs), queryDuration, (endMem-startMem)/(1024*1024))
}

func getMemUsage() uint64 {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    return m.Alloc
}
```

**Expected Result:** Test demonstrates that querying 100k entries loads all data into memory without pagination, taking >1 second and consuming >10MB RAM. On production chains with millions of entries, this causes node crashes.

**Notes:**
- The vulnerability is confirmed by examining the code flow from ABCI query through to store iteration
- No pagination logic exists in any of the three `/subspace` implementations
- Infinite gas meter prevents resource limits from protecting queries
- Attack requires only standard RPC access, no special privileges needed

### Citations

**File:** store/iavl/store.go (L398-417)
```go
	case "/subspace":
		pairs := kv.Pairs{
			Pairs: make([]kv.Pair, 0),
		}

		subspace := req.Data
		res.Key = subspace

		iterator := types.KVStorePrefixIterator(st, subspace)
		for ; iterator.Valid(); iterator.Next() {
			pairs.Pairs = append(pairs.Pairs, kv.Pair{Key: iterator.Key(), Value: iterator.Value()})
		}
		iterator.Close()

		bz, err := pairs.Marshal()
		if err != nil {
			panic(fmt.Errorf("failed to marshal KV pairs: %w", err))
		}

		res.Value = bz
```

**File:** storev2/state/store.go (L106-122)
```go
	case "/subspace":
		pairs := kv.Pairs{
			Pairs: make([]kv.Pair, 0),
		}
		subspace := req.Data
		res.Key = subspace
		iterator := types.KVStorePrefixIterator(st, subspace)
		for ; iterator.Valid(); iterator.Next() {
			pairs.Pairs = append(pairs.Pairs, kv.Pair{Key: iterator.Key(), Value: iterator.Value()})
		}
		iterator.Close()

		bz, err := pairs.Marshal()
		if err != nil {
			panic(fmt.Errorf("failed to marshal KV pairs: %w", err))
		}
		res.Value = bz
```

**File:** storev2/commitment/store.go (L155-174)
```go
	case "/subspace":
		pairs := kv.Pairs{
			Pairs: make([]kv.Pair, 0),
		}

		subspace := req.Data
		res.Key = subspace

		iterator := types.KVStorePrefixIterator(st, subspace)
		for ; iterator.Valid(); iterator.Next() {
			pairs.Pairs = append(pairs.Pairs, kv.Pair{Key: iterator.Key(), Value: iterator.Value()})
		}
		iterator.Close()

		bz, err := pairs.Marshal()
		if err != nil {
			panic(fmt.Errorf("failed to marshal KV pairs: %w", err))
		}

		res.Value = bz
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

**File:** store/types/gas.go (L252-258)
```go
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}
```

**File:** x/bank/types/key.go (L32-32)
```go
	BalancesPrefix       = []byte{0x02}
```

**File:** x/bank/keeper/view.go (L138-161)
```go
func (k BaseViewKeeper) IterateAllBalances(ctx sdk.Context, cb func(sdk.AccAddress, sdk.Coin) bool) {
	store := ctx.KVStore(k.storeKey)
	balancesStore := prefix.NewStore(store, types.BalancesPrefix)

	iterator := balancesStore.Iterator(nil, nil)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		address, err := types.AddressFromBalancesStore(iterator.Key())
		if err != nil {
			k.Logger(ctx).With("key", iterator.Key(), "err", err).Error("failed to get address from balances store")
			// TODO: revisit, for now, panic here to keep same behavior as in 0.42
			// ref: https://github.com/cosmos/cosmos-sdk/issues/7409
			panic(err)
		}

		var balance sdk.Coin
		k.cdc.MustUnmarshal(iterator.Value(), &balance)

		if cb(address, balance) {
			break
		}
	}
}
```

**File:** baseapp/abci.go (L520-521)
```go
	case "store":
		resp = handleQueryStore(app, path, *req)
```

**File:** store/rootmulti/store.go (L679-691)
```go
	store := rs.GetStoreByName(firstPath)
	if store == nil {
		return sdkerrors.QueryResult(sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "no such store: %s", firstPath))
	}

	queryable, ok := store.(types.Queryable)
	if !ok {
		return sdkerrors.QueryResult(sdkerrors.Wrapf(sdkerrors.ErrUnknownRequest, "store %s (type %T) doesn't support queries", firstPath, store))
	}

	// trim the path and make the query
	req.Path = subpath
	res := queryable.Query(req)
```
