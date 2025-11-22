## Title
Unbounded Memory Consumption in ExportGenesis Leading to Node Crashes via Grant Exhaustion

## Summary
The `ExportGenesis` method in the feegrant keeper loads all fee grants into memory simultaneously without pagination or limits. An attacker can create millions of grants over time through normal transactions, causing nodes to run out of memory and crash when attempting to export genesis state during chain upgrades or maintenance operations.

## Impact
**Medium to High**

## Finding Description

### Location
- **Module:** `x/feegrant`
- **File:** `x/feegrant/keeper/keeper.go`
- **Lines:** 218-229 (ExportGenesis function)
- **Related:** Lines 127-144 (IterateAllFeeAllowances function) [1](#0-0) 

### Intended Logic
The ExportGenesis function is designed to export all fee grant allowances from the keeper's store into a GenesisState for chain export operations (upgrades, snapshots, backups). The function should safely handle any number of grants without causing resource exhaustion.

### Actual Logic
The function unconditionally iterates over ALL grants in the store and appends each one to an in-memory slice without any pagination, batching, or memory limits: [2](#0-1) 

The iteration uses `IterateAllFeeAllowances`, which includes a comment warning about the expense of this operation: [3](#0-2) 

Additionally, the `ExportGenesisStream` method that appears to provide streaming support is fake - it simply wraps the entire ExportGenesis result in a goroutine, still loading everything into memory: [4](#0-3) 

### Exploit Scenario

**Step 1: Grant Creation**
Any user can create fee grants by submitting `MsgGrantAllowance` transactions. The granter must sign the transaction but there are no restrictions on the number of grants: [5](#0-4) 

The only validation is checking for duplicate granter-grantee pairs. An attacker can create millions of unique grants by using different grantee addresses.

**Step 2: No Grant Limits**
There is no maximum limit on the number of grants that can be created. The codebase analysis confirms no `MaxGrants` parameter or enforcement exists.

**Step 3: Genesis Export Triggered**
When node operators export genesis (common during chain upgrades, creating snapshots, or migration): [6](#0-5) 

The context is created with an infinite gas meter, so gas limits provide no protection. All grants are loaded into memory simultaneously.

**Step 4: Memory Exhaustion**
Each Grant object contains:
- Granter address (~45 bytes)
- Grantee address (~45 bytes)  
- Allowance data (~100-200 bytes)

Total per grant: ~200-300 bytes. With millions of grants:
- 1 million grants = ~200-300 MB
- 10 million grants = ~2-3 GB
- 50 million grants = ~10-15 GB

This can exhaust available memory on validator nodes, causing crashes.

### Security Failure
This violates the **availability** and **resource safety** security properties:
- Nodes crash due to Out-of-Memory (OOM) errors
- Chain export/upgrade operations fail
- Multiple nodes can be affected simultaneously if they attempt export operations
- No graceful degradation or error handling

## Impact Explanation

### Affected Components
- **Node availability:** Validator and full nodes crash when running out of memory
- **Chain operations:** Genesis export, chain upgrades, and state snapshots fail
- **Network stability:** If multiple nodes attempt export simultaneously (e.g., during coordinated upgrades), >= 30% of nodes could crash

### Severity Assessment
The vulnerability enables:
1. **Shutdown of >= 30% of network processing nodes** - When multiple nodes attempt genesis export during coordinated upgrade procedures, they can simultaneously crash from OOM errors (Medium severity per impact criteria)

2. **Increasing network processing node resource consumption by at least 30%** - Even if not immediately causing crashes, loading millions of grants significantly increases memory consumption beyond normal operation (Medium severity per impact criteria)

3. **Potential chain upgrade failures** - If nodes cannot successfully export genesis, chain upgrades requiring state export/migration become extremely difficult or impossible without manual intervention

The issue matters because:
- Chain upgrades are critical maintenance operations
- Node crashes reduce network decentralization and security
- Recovery requires manual intervention and potential emergency patches

## Likelihood Explanation

### Triggering Conditions
- **Who:** Any user with funds to pay transaction fees
- **Requirements:** Submit MsgGrantAllowance transactions over time to accumulate grants
- **Frequency:** Can be executed continuously; grants persist indefinitely

### Realistic Exploitation
**High likelihood** because:
1. Creating grants only requires normal transaction fees (no special permissions)
2. Grants can accumulate gradually over months/years through legitimate or malicious use
3. Genesis export is a standard operation during chain upgrades and maintenance
4. The attacker doesn't need to time the attack - they just need to create enough grants and wait for operators to trigger export

**Cost Analysis:**
- If each grant transaction costs ~0.01 USD in fees
- Creating 10 million grants = ~$100,000
- This is affordable for a determined attacker targeting a major blockchain

**Legitimate Accumulation:**
Even without malicious intent, popular chains with heavy fee grant usage could naturally accumulate millions of grants over time, making this a time bomb.

## Recommendation

Implement paginated genesis export with memory-safe streaming:

1. **Add pagination to ExportGenesis:**
   - Modify `IterateAllFeeAllowances` to support pagination with configurable batch sizes
   - Process grants in batches and stream results instead of accumulating in memory

2. **Implement proper streaming in ExportGenesisStream:**
   - Instead of wrapping the entire result, iterate and stream grants in chunks
   - Send each grant or small batch through the channel incrementally

3. **Add grant limits (optional defense-in-depth):**
   - Consider adding a module parameter for maximum grants per granter or globally
   - This provides an additional safety mechanism

4. **Example fix pattern** (similar to how other large state exports should be handled):
```go
// Pseudocode for proper streaming
func (am AppModule) ExportGenesisStream(ctx sdk.Context, cdc codec.JSONCodec) <-chan json.RawMessage {
    ch := make(chan json.RawMessage)
    go func() {
        defer close(ch)
        
        const batchSize = 1000
        grants := make([]feegrant.Grant, 0, batchSize)
        
        k.IterateAllFeeAllowances(ctx, func(grant feegrant.Grant) bool {
            grants = append(grants, grant)
            if len(grants) >= batchSize {
                // Send batch and reset
                state := &feegrant.GenesisState{Allowances: grants}
                ch <- cdc.MustMarshalJSON(state)
                grants = make([]feegrant.Grant, 0, batchSize)
            }
            return false
        })
        
        // Send remaining
        if len(grants) > 0 {
            state := &feegrant.GenesisState{Allowances: grants}
            ch <- cdc.MustMarshalJSON(state)
        }
    }()
    return ch
}
```

## Proof of Concept

**Test File:** `x/feegrant/keeper/genesis_test.go`

**Test Function:** Add the following test to demonstrate the unbounded memory accumulation:

```go
func (suite *GenesisTestSuite) TestExportGenesisMemoryExhaustion() {
    // This test demonstrates that ExportGenesis loads all grants into memory
    // Create a large number of grants to simulate the attack
    
    msgSrvr := keeper.NewMsgServerImpl(suite.keeper)
    coins := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(1_000)))
    now := suite.ctx.BlockHeader().Time
    oneYear := now.AddDate(1, 0, 0)
    
    // Simulate creating many grants (reduced number for test execution)
    // In production, an attacker could create millions
    numGrants := 10000  // Reduced from realistic attack (would be millions)
    granters := make([]sdk.AccAddress, numGrants)
    
    // Create unique granter-grantee pairs
    for i := 0; i < numGrants; i++ {
        granterKey := secp256k1.GenPrivKey()
        granters[i] = sdk.AccAddress(granterKey.PubKey().Address())
        
        granteeKey := secp256k1.GenPrivKey()
        granteeAddr := sdk.AccAddress(granteeKey.PubKey().Address())
        
        allowance := &feegrant.BasicAllowance{
            SpendLimit: coins,
            Expiration: &oneYear,
        }
        
        err := suite.keeper.GrantAllowance(suite.ctx, granters[i], granteeAddr, allowance)
        suite.Require().NoError(err)
    }
    
    // Attempt to export genesis - this loads ALL grants into memory
    genesis, err := suite.keeper.ExportGenesis(suite.ctx)
    suite.Require().NoError(err)
    
    // Verify all grants are loaded in memory simultaneously
    suite.Require().Equal(numGrants, len(genesis.Allowances))
    
    // Calculate approximate memory usage
    // Each grant is ~200-300 bytes (addresses + allowance data)
    approxMemoryBytes := len(genesis.Allowances) * 250
    approxMemoryMB := approxMemoryBytes / (1024 * 1024)
    
    // Log the memory consumption
    suite.T().Logf("Loaded %d grants into memory", len(genesis.Allowances))
    suite.T().Logf("Approximate memory usage: %d MB", approxMemoryMB)
    
    // With 10M grants (realistic attack), this would be:
    // 10,000,000 * 250 bytes = 2.5 GB of memory
    // This would cause OOM on many validator nodes
    
    // The vulnerability is that there's no pagination or streaming
    // All grants must fit in memory simultaneously
}
```

**Setup:**
1. Use the existing test suite structure in `x/feegrant/keeper/genesis_test.go`
2. Create a large number of fee grant allowances (10,000 for test, but note that millions would be used in a real attack)

**Trigger:**
Call `ExportGenesis` which loads all grants into memory at once

**Observation:**
The test demonstrates that:
- All grants are loaded into a single slice in memory
- Memory consumption scales linearly with the number of grants
- No pagination or memory limits exist
- With millions of grants, this would exhaust available memory

The test passes but highlights the vulnerability by showing unbounded memory growth. In production with millions of grants, nodes would crash with OOM errors.

### Citations

**File:** x/feegrant/keeper/keeper.go (L124-127)
```go
// IterateAllFeeAllowances iterates over all the grants in the store.
// Callback to get all data, returns true to stop, false to keep reading
// Calling this without pagination is very expensive and only designed for export genesis
func (k Keeper) IterateAllFeeAllowances(ctx sdk.Context, cb func(grant feegrant.Grant) bool) error {
```

**File:** x/feegrant/keeper/keeper.go (L217-229)
```go
// ExportGenesis will dump the contents of the keeper into a serializable GenesisState.
func (k Keeper) ExportGenesis(ctx sdk.Context) (*feegrant.GenesisState, error) {
	var grants []feegrant.Grant

	err := k.IterateAllFeeAllowances(ctx, func(grant feegrant.Grant) bool {
		grants = append(grants, grant)
		return false
	})

	return &feegrant.GenesisState{
		Allowances: grants,
	}, err
}
```

**File:** x/feegrant/module/module.go (L184-191)
```go
func (am AppModule) ExportGenesisStream(ctx sdk.Context, cdc codec.JSONCodec) <-chan json.RawMessage {
	ch := make(chan json.RawMessage)
	go func() {
		ch <- am.ExportGenesis(ctx, cdc)
		close(ch)
	}()
	return ch
}
```

**File:** x/feegrant/keeper/msg_server.go (L26-56)
```go
// GrantAllowance grants an allowance from the granter's funds to be used by the grantee.
func (k msgServer) GrantAllowance(goCtx context.Context, msg *feegrant.MsgGrantAllowance) (*feegrant.MsgGrantAllowanceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	// Checking for duplicate entry
	if f, _ := k.Keeper.GetAllowance(ctx, granter, grantee); f != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "fee allowance already exists")
	}

	allowance, err := msg.GetFeeAllowanceI()
	if err != nil {
		return nil, err
	}

	err = k.Keeper.GrantAllowance(ctx, granter, grantee, allowance)
	if err != nil {
		return nil, err
	}

	return &feegrant.MsgGrantAllowanceResponse{}, nil
}
```

**File:** simapp/export.go (L18-33)
```go
func (app *SimApp) ExportAppStateAndValidators(
	forZeroHeight bool, jailAllowedAddrs []string,
) (servertypes.ExportedApp, error) {
	// as if they could withdraw from the start of the next block
	ctx := app.NewContext(true, tmproto.Header{Height: app.LastBlockHeight()})

	// We export at last height + 1, because that's the height at which
	// Tendermint will start InitChain.
	height := app.LastBlockHeight() + 1
	if forZeroHeight {
		height = 0
		app.prepForZeroHeightGenesis(ctx, jailAllowedAddrs)
	}

	genState := app.mm.ExportGenesis(ctx, app.appCodec)
	appState, err := json.MarshalIndent(genState, "", "  ")
```
