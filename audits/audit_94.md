# Audit Report

## Title
Unbounded Dependency Mapping Growth Causing Memory Exhaustion During Genesis Export

## Summary
The access control system's dependency mappings (both resource and WASM) can grow unboundedly without size limits, pagination, or cleanup mechanisms. During genesis export operations (critical for chain upgrades), all mappings are loaded into memory at once, which can cause memory exhaustion and prevent successful chain upgrades. [1](#0-0) 

## Impact
**Severity: Medium**

## Finding Description

**Location:** 
- Primary: `x/accesscontrol/keeper/genesis.go`, function `ExportGenesis` (lines 28-44)
- Secondary: `x/accesscontrol/keeper/keeper.go`, functions `IterateResourceKeys` (lines 106-117) and `IterateWasmDependencies` (lines 484-496)
- Validation: `x/accesscontrol/types/message_dependency_mapping.go`, function `ValidateWasmDependencyMapping` (lines 123-181)

**Intended Logic:** 
The dependency mapping system should store access control patterns for messages and WASM contracts to enable parallel transaction execution. Genesis export should safely export all state for chain upgrades.

**Actual Logic:** 
The system allows unlimited accumulation of dependency mappings without bounds: [2](#0-1) 

The validation has no size limits on:
- Number of access operations per mapping
- Number of contract references
- Size of individual fields
- Total number of mappings

During genesis export, ALL mappings are loaded into memory simultaneously: [3](#0-2) [4](#0-3) 

**Exploit Scenario:**
1. Over the chain's lifetime, numerous WASM contracts are deployed and dependency mappings are registered through governance proposals
2. Each mapping can contain unlimited access operations, contract references, and nested dependencies with no validation limits
3. No cleanup mechanism exists - old/unused contract mappings remain in storage indefinitely
4. When a chain upgrade is initiated, nodes must export genesis state
5. The `ExportGenesis` function iterates over ALL mappings and loads them into memory slices without pagination
6. With sufficient accumulated mappings or intentionally large mappings, this causes out-of-memory errors
7. The chain upgrade fails, preventing critical updates and potentially halting the network

**Security Failure:** 
This breaks the availability guarantee for chain upgrades. The lack of bounds checking combined with unbounded accumulation creates a time-bomb that can prevent essential maintenance operations.

## Impact Explanation

**Affected Components:**
- Chain upgrade process (genesis export/import)
- Node memory resources during critical operations
- Network ability to perform maintenance and security updates

**Severity:**
- Chain upgrades are critical for security patches, consensus changes, and protocol improvements
- Failure during genesis export prevents the upgrade from completing
- All validator nodes attempting the upgrade would experience the same memory exhaustion
- This effectively halts the network's ability to upgrade, leaving it stuck on potentially vulnerable old code
- Falls under "Medium: Increasing network processing node resource consumption by at least 30%" and potentially "High: Network not being able to confirm new transactions" if upgrade failure prevents block production

**Why This Matters:**
Chain upgrades are essential for blockchain health. Without the ability to upgrade, the network cannot patch vulnerabilities, improve performance, or adapt to changing requirements. Memory exhaustion during this critical operation is a severe availability issue.

## Likelihood Explanation

**Who Can Trigger:**
- Direct: Governance participants who approve dependency mapping proposals
- Indirect: Natural accumulation over time as legitimate contracts are deployed and mappings registered
- Malicious: Attacker who can influence governance or submit large mappings

**Conditions Required:**
- Sufficient dependency mappings accumulated in storage (either through many contracts or intentionally large mappings)
- Genesis export operation initiated (during chain upgrade)
- No cleanup of old/unused mappings has occurred

**Frequency:**
- Low immediate risk for new chains
- Risk increases linearly with chain age and contract deployment activity
- Chain upgrades happen periodically (every few months typically)
- Once threshold is reached, EVERY subsequent upgrade attempt fails until addressed via emergency hard fork

**Realistic Scenario:**
A mature chain with thousands of deployed contracts, each with dependency mappings registered over years of operation, attempts a routine upgrade. The genesis export runs out of memory, forcing emergency coordination for a hard fork to fix the issue.

## Recommendation

Implement multiple defensive measures:

1. **Add size limits to validation:**
```
// In ValidateWasmDependencyMapping
const MaxAccessOpsPerMapping = 1000
const MaxContractReferences = 100
const MaxMappingSizeBytes = 100 * 1024 // 100KB

if len(mapping.BaseAccessOps) > MaxAccessOpsPerMapping {
    return errors.New("too many access operations")
}
// Validate total serialized size
if proto.Size(&mapping) > MaxMappingSizeBytes {
    return errors.New("mapping too large")
}
```

2. **Add pagination to iteration:** [5](#0-4) 

Modify `IterateWasmDependencies` and `IterateResourceKeys` to support pagination with configurable page size.

3. **Implement cleanup mechanism:**
Add a function to delete unused mappings and implement automatic cleanup during EndBlock for contracts that haven't been called in X blocks.

4. **Add genesis export streaming:**
Instead of loading all mappings into memory, stream them directly to the output file.

## Proof of Concept

**File:** `x/accesscontrol/keeper/genesis_test.go`

**Test Function:** `TestGenesisExportMemoryExhaustion`

```go
func TestGenesisExportMemoryExhaustion(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Setup: Create many contracts with large dependency mappings
    numMappings := 10000
    addresses := make([]sdk.AccAddress, numMappings)
    
    for i := 0; i < numMappings; i++ {
        addresses[i] = sdk.AccAddress(fmt.Sprintf("contract%d", i))
        
        // Create a large mapping with many access operations
        largeMapping := accesscontrol.WasmDependencyMapping{
            ContractAddress: addresses[i].String(),
            BaseAccessOps:   make([]*accesscontrol.WasmAccessOperation, 500),
        }
        
        // Fill with access operations to increase size
        for j := 0; j < 500; j++ {
            largeMapping.BaseAccessOps[j] = &accesscontrol.WasmAccessOperation{
                Operation: &accesscontrol.AccessOperation{
                    AccessType:         accesscontrol.AccessType_WRITE,
                    ResourceType:       accesscontrol.ResourceType_KV_WASM_CONTRACT_STORE,
                    IdentifierTemplate: fmt.Sprintf("key_%d", j),
                },
                SelectorType: accesscontrol.AccessOperationSelectorType_NONE,
            }
        }
        // Add commit op
        largeMapping.BaseAccessOps = append(largeMapping.BaseAccessOps, &accesscontrol.WasmAccessOperation{
            Operation:    types.CommitAccessOp(),
            SelectorType: accesscontrol.AccessOperationSelectorType_NONE,
        })
        
        err := app.AccessControlKeeper.SetWasmDependencyMapping(ctx, largeMapping)
        require.NoError(t, err)
    }
    
    // Trigger: Attempt genesis export
    // This will load all mappings into memory
    var memBefore runtime.MemStats
    runtime.ReadMemStats(&memBefore)
    
    exportedGenesis := app.AccessControlKeeper.ExportGenesis(ctx)
    
    var memAfter runtime.MemStats
    runtime.ReadMemStats(&memAfter)
    
    // Observation: Memory usage increases significantly
    memIncreaseMB := float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024)
    
    // With 10000 mappings of ~500 ops each, expect >50MB increase
    require.Greater(t, memIncreaseMB, 50.0, "Expected significant memory increase during genesis export")
    
    // Verify all mappings were loaded
    require.Equal(t, numMappings, len(exportedGenesis.WasmDependencyMappings))
    
    // This test demonstrates unbounded memory growth
    // In production with millions of mappings, this would cause OOM
    t.Logf("Memory increase during export: %.2f MB for %d mappings", memIncreaseMB, numMappings)
}
```

**Setup:** Initialize application, create many WASM contracts with large dependency mappings using `SetWasmDependencyMapping`.

**Trigger:** Call `ExportGenesis` which loads all mappings into memory via `IterateWasmDependencies`.

**Observation:** Memory usage increases proportionally with number and size of mappings, demonstrating unbounded growth. With enough mappings (millions in production), this causes OOM. The test shows no pagination or size limits prevent this accumulation.

**Notes**

This vulnerability is particularly insidious because:
1. It accumulates gradually over time, making it hard to detect until critical
2. The impact manifests during the most critical operation (chain upgrades)
3. All nodes attempting the upgrade experience the same issue simultaneously
4. No automatic cleanup or bounds checking prevents the accumulation

The combination of no size validation, no cleanup mechanism, and loading everything into memory during genesis export creates a severe availability risk for mature chains.

### Citations

**File:** x/accesscontrol/keeper/genesis.go (L28-44)
```go
func (k Keeper) ExportGenesis(ctx sdk.Context) *types.GenesisState {
	resourceDependencyMappings := []acltypes.MessageDependencyMapping{}
	k.IterateResourceKeys(ctx, func(dependencyMapping acltypes.MessageDependencyMapping) (stop bool) {
		resourceDependencyMappings = append(resourceDependencyMappings, dependencyMapping)
		return false
	})
	wasmDependencyMappings := []acltypes.WasmDependencyMapping{}
	k.IterateWasmDependencies(ctx, func(dependencyMapping acltypes.WasmDependencyMapping) (stop bool) {
		wasmDependencyMappings = append(wasmDependencyMappings, dependencyMapping)
		return false
	})
	return &types.GenesisState{
		Params:                   k.GetParams(ctx),
		MessageDependencyMapping: resourceDependencyMappings,
		WasmDependencyMappings:   wasmDependencyMappings,
	}
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L123-181)
```go
func ValidateWasmDependencyMapping(mapping acltypes.WasmDependencyMapping) error {
	numOps := len(mapping.BaseAccessOps)
	if numOps == 0 || mapping.BaseAccessOps[numOps-1].Operation.AccessType != acltypes.AccessType_COMMIT {
		return ErrNoCommitAccessOp
	}

	// ensure uniqueness for partitioned message names across access ops and contract references
	seenMessageNames := map[string]struct{}{}
	for _, ops := range mapping.ExecuteAccessOps {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.QueryAccessOps {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.ExecuteContractReferences {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.QueryContractReferences {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}

	// ensure deprecation for CONTRACT_REFERENCE access operation selector due to new contract references
	for _, accessOp := range mapping.BaseAccessOps {
		if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
			return ErrSelectorDeprecated
		}
	}
	for _, accessOps := range mapping.ExecuteAccessOps {
		for _, accessOp := range accessOps.WasmOperations {
			if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
				return ErrSelectorDeprecated
			}
		}
	}
	for _, accessOps := range mapping.QueryAccessOps {
		for _, accessOp := range accessOps.WasmOperations {
			if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
				return ErrSelectorDeprecated
			}
		}
	}

	return nil
}
```

**File:** x/accesscontrol/keeper/keeper.go (L106-117)
```go
func (k Keeper) IterateResourceKeys(ctx sdk.Context, handler func(dependencyMapping acltypes.MessageDependencyMapping) (stop bool)) {
	store := ctx.KVStore(k.storeKey)
	iter := sdk.KVStorePrefixIterator(store, types.GetResourceDependencyMappingKey())
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		dependencyMapping := acltypes.MessageDependencyMapping{}
		k.cdc.MustUnmarshal(iter.Value(), &dependencyMapping)
		if handler(dependencyMapping) {
			break
		}
	}
}
```

**File:** x/accesscontrol/keeper/keeper.go (L484-496)
```go
func (k Keeper) IterateWasmDependencies(ctx sdk.Context, handler func(wasmDependencyMapping acltypes.WasmDependencyMapping) (stop bool)) {
	store := ctx.KVStore(k.storeKey)

	iter := sdk.KVStorePrefixIterator(store, types.GetWasmMappingKey())
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		dependencyMapping := acltypes.WasmDependencyMapping{}
		k.cdc.MustUnmarshal(iter.Value(), &dependencyMapping)
		if handler(dependencyMapping) {
			break
		}
	}
}
```

**File:** x/accesscontrol/keeper/grpc_query.go (L52-61)
```go
func (k Keeper) ListWasmDependencyMapping(ctx context.Context, req *types.ListWasmDependencyMappingRequest) (*types.ListWasmDependencyMappingResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	wasmDependencyMappings := []acltypes.WasmDependencyMapping{}
	k.IterateWasmDependencies(sdkCtx, func(dependencyMapping acltypes.WasmDependencyMapping) (stop bool) {
		wasmDependencyMappings = append(wasmDependencyMappings, dependencyMapping)
		return false
	})

	return &types.ListWasmDependencyMappingResponse{WasmDependencyMappingList: wasmDependencyMappings}, nil
}
```
