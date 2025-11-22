Audit Report

## Title
Unbounded Memory Consumption in ExportGenesis Leading to Node Crashes During Chain Upgrades

## Summary
The `ExportGenesis` method in the feegrant keeper loads all fee grants into memory simultaneously without pagination or limits, causing nodes to crash with out-of-memory (OOM) errors when millions of grants exist. This can be triggered during mandatory chain upgrade operations, potentially affecting >= 30% of network nodes simultaneously.

## Impact
Medium

## Finding Description

**Location**: 
- `x/feegrant/keeper/keeper.go` lines 217-229 (ExportGenesis function)
- `x/feegrant/keeper/keeper.go` lines 124-144 (IterateAllFeeAllowances function)
- `x/feegrant/module/module.go` lines 184-191 (ExportGenesisStream function) [1](#0-0) 

**Intended logic**: The ExportGenesis function should safely export all fee grant allowances from the keeper's store into a GenesisState, handling any number of grants without resource exhaustion.

**Actual logic**: The function unconditionally iterates over ALL grants and appends each one to an in-memory slice without pagination, batching, or memory limits. [1](#0-0)  The iteration function itself contains a warning comment: "Calling this without pagination is very expensive and only designed for export genesis" [2](#0-1) 

The `ExportGenesisStream` method that appears to provide streaming support is ineffective - it simply wraps the entire ExportGenesis result in a goroutine, still loading everything into memory: [3](#0-2) 

**Exploitation path**:

1. **Grant Accumulation**: Any user can create fee grants by submitting `MsgGrantAllowance` transactions. The only validation is checking for duplicate granter-grantee pairs, allowing an attacker to create millions of unique grants by using different grantee addresses. [4](#0-3) 

2. **No Limits**: The codebase has no `MaxGrants` parameter or enforcement limiting the total number of grants that can be created.

3. **Export Triggered**: During chain upgrades, validators call `ExportAppStateAndValidators` which invokes `app.mm.ExportGenesis(ctx, app.appCodec)` [5](#0-4) , triggering the feegrant module's ExportGenesis.

4. **Memory Exhaustion**: With millions of grants (~250 bytes each), the memory requirements become:
   - 10 million grants = ~2.5 GB
   - 50 million grants = ~12.5 GB
   
   When nodes exceed available memory, the Go runtime panics or the OS OOM killer terminates the process, crashing the node.

**Security guarantee broken**: This violates the availability security property. Chain upgrades are mandatory critical operations, and node crashes during these operations disrupt network stability and upgrade coordination.

## Impact Explanation

When >= 30% of network nodes attempt genesis export during coordinated chain upgrades and sufficient grants exist in state, these nodes will simultaneously crash with OOM errors. This meets the Medium severity impact criterion: **"Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network."**

Consequences:
- Validator and full nodes crash and stop processing blocks until manually restarted
- Chain upgrades requiring state export become extremely difficult or impossible without emergency intervention
- Network decentralization and security are reduced during the recovery period
- Recovery requires manual intervention and potential emergency patches

The network continues operating with remaining nodes (doesn't violate the 67% Byzantine threshold), but upgrade operations are severely disrupted.

## Likelihood Explanation

**High likelihood** of exploitation or natural occurrence:

1. **Accessibility**: Creating grants requires only normal transaction fees (~$0.01 per grant), no special permissions
2. **Cost feasibility**: Creating 10 million grants costs approximately $100,000-$1,000,000 - affordable for a determined attacker targeting a valuable blockchain
3. **Persistence**: Grants persist indefinitely and accumulate over time
4. **Natural accumulation**: Popular chains with heavy feegrant usage could naturally accumulate millions of grants over months/years, making this a time bomb even without malicious intent
5. **Trigger frequency**: Chain upgrades are standard periodic operations that all validators must perform

The attacker needs only to create grants gradually over time, then wait for the inevitable chain upgrade to trigger the vulnerability.

## Recommendation

1. **Implement paginated export with batching**:
   - Modify `IterateAllFeeAllowances` to support pagination with configurable batch sizes (e.g., 1000-10000 grants per batch)
   - Process and stream grants in batches instead of accumulating all in memory

2. **Fix ExportGenesisStream to properly stream**:
   - Instead of wrapping the entire result, iterate and send grants through the channel in chunks
   - Example pattern:
     ```go
     func (am AppModule) ExportGenesisStream(ctx sdk.Context, cdc codec.JSONCodec) <-chan json.RawMessage {
         ch := make(chan json.RawMessage)
         go func() {
             defer close(ch)
             const batchSize = 1000
             grants := make([]feegrant.Grant, 0, batchSize)
             
             k.IterateAllFeeAllowances(ctx, func(grant feegrant.Grant) bool {
                 grants = append(grants, grant)
                 if len(grants) >= batchSize {
                     state := &feegrant.GenesisState{Allowances: grants}
                     ch <- cdc.MustMarshalJSON(state)
                     grants = make([]feegrant.Grant, 0, batchSize)
                 }
                 return false
             })
             
             if len(grants) > 0 {
                 state := &feegrant.GenesisState{Allowances: grants}
                 ch <- cdc.MustMarshalJSON(state)
             }
         }()
         return ch
     }
     ```

3. **Add grant limits (defense-in-depth)**:
   - Consider adding a module parameter for maximum grants per granter or globally
   - Provides an additional safety mechanism against accumulation

## Proof of Concept

**Test scenario**: The following demonstrates unbounded memory accumulation in ExportGenesis:

**Setup**:
- Create a large number of fee grant allowances (10,000+ for demonstration; millions in realistic attack)
- Each grant uses unique granter-grantee pairs to bypass duplicate checking

**Action**:
- Call `keeper.ExportGenesis(ctx)` which triggers the vulnerable code path [1](#0-0) 

**Result**:
- All grants are loaded into a single in-memory slice
- Memory consumption scales linearly: `len(grants) * ~250 bytes`
- With 10M grants: ~2.5 GB memory required
- With 50M grants: ~12.5 GB memory required
- On nodes with insufficient memory, this causes OOM crashes

**Demonstration code structure** (for `x/feegrant/keeper/genesis_test.go`):
```go
func TestExportGenesisMemoryExhaustion() {
    // Setup: Create many grants with unique granter-grantee pairs
    for i := 0; i < largeNumber; i++ {
        granter := generateUniqueAddress(i)
        grantee := generateUniqueAddress(i + largeNumber)
        keeper.GrantAllowance(ctx, granter, grantee, allowance)
    }
    
    // Action: Export genesis - loads all into memory
    genesis, err := keeper.ExportGenesis(ctx)
    
    // Result: All grants in memory, no pagination
    assert.Equal(t, largeNumber, len(genesis.Allowances))
    // Memory usage: largeNumber * 250 bytes
}
```

The vulnerability is confirmed by code inspection showing no pagination or memory limits in the export path.

## Notes

The gRPC query endpoints (`Allowances` and `AllowancesByGranter` in `x/feegrant/keeper/grpc_query.go`) DO implement proper pagination for queries, confirming that the developers understood pagination is necessary for scalability. However, this pagination was not applied to the critical ExportGenesis function, creating this vulnerability during chain upgrade operations.

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

**File:** x/feegrant/keeper/msg_server.go (L40-42)
```go
	// Checking for duplicate entry
	if f, _ := k.Keeper.GetAllowance(ctx, granter, grantee); f != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "fee allowance already exists")
```

**File:** simapp/export.go (L32-32)
```go
	genState := app.mm.ExportGenesis(ctx, app.appCodec)
```
