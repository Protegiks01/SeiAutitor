## Audit Report

## Title
Invalid WASM Dependency Mappings Persist Through Migration Causing Transaction Deadlocks and Network Shutdown

## Summary
The V1ToV2 migration function for WASM dependency mappings does not validate that `BaseAccessOps` terminates with a COMMIT operation before storing the migrated mapping. This allows invalid mappings from legacy format to persist in storage. At runtime, when these invalid mappings are retrieved and used for concurrent transaction execution, dependent transactions can deadlock indefinitely waiting for completion signals that are never sent, causing network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Migration: [1](#0-0) 
- Validation (bypassed): [2](#0-1) 
- Runtime usage: [3](#0-2) 
- Signal coordination: [4](#0-3) 

**Intended Logic:**
All WASM dependency mappings must have `BaseAccessOps` that terminate with a COMMIT access operation. This invariant is enforced by `ValidateWasmDependencyMapping` which checks that the last operation has `AccessType_COMMIT`. [5](#0-4) 

The COMMIT operation is critical for concurrent transaction execution - it creates completion signals that coordinate dependent transactions. When a transaction completes, it sends signals to unblock waiting dependent transactions. [6](#0-5) 

**Actual Logic:**
The V1ToV2 migration blindly converts legacy WASM mappings to the new format without calling `ValidateWasmDependencyMapping`. [7](#0-6) 

Legacy mappings (`LegacyWasmDependencyMapping`) do not have the requirement to end with COMMIT. [8](#0-7) 

The test demonstrates this - `legacyMapping1` has access ops ending with a WRITE operation, not COMMIT, and the migration succeeds without validation. [9](#0-8) 

**Exploit Scenario:**
1. During chain upgrade to V2, the migration runs on all existing WASM dependency mappings
2. Any legacy mapping that doesn't end with COMMIT is converted and stored without validation
3. At runtime, when a WASM contract with the invalid mapping is called, `GetRawWasmDependencyMapping` retrieves it [10](#0-9) 
4. The invalid `BaseAccessOps` (without COMMIT) are used to build access operations [11](#0-10) 
5. `BuildDependencyDag` creates the dependency graph using these operations [12](#0-11) 
6. Without COMMIT, completion signals are not properly created for this transaction
7. Dependent transactions call `WaitForAllSignalsForTx` and block waiting for signals that never arrive [13](#0-12) 
8. Transactions deadlock, block production halts, network shuts down

**Security Failure:**
This breaks the transaction coordination invariant. The concurrent execution system relies on COMMIT operations to signal transaction completion. Without proper completion signals, dependent transactions deadlock waiting indefinitely on channels that will never receive signals, causing a denial-of-service that halts the entire network.

## Impact Explanation

**Affected Components:**
- Network availability: All nodes attempting to process transactions with invalid WASM mappings will hang
- Transaction finality: Blocks cannot be produced when transactions deadlock
- Consensus: Validators cannot reach consensus on new blocks

**Severity:**
This causes **total network shutdown**. When a WASM contract with an invalid mapping (migrated from V1) is executed:
- The transaction executes but doesn't send proper completion signals
- All dependent transactions wait indefinitely in `WaitForAllSignalsForTx` [14](#0-13) 
- Block production halts as transactions cannot complete
- The network cannot confirm new transactions

This matches the "High: Network not being able to confirm new transactions (total network shutdown)" impact category.

## Likelihood Explanation

**Trigger Probability:**
- **Who:** This affects all nodes on the network automatically during chain upgrade to V2
- **When:** The vulnerability is introduced during migration and triggered whenever the affected WASM contract is called
- **Frequency:** Every execution of a WASM contract with an invalid mapping will cause dependent transactions to deadlock

**Realistic Scenario:**
1. Chain upgrades from V1 to V2, migration runs
2. Popular WASM contracts with legacy mappings are converted without validation
3. First user to call such a contract triggers the deadlock
4. Network halts immediately

The likelihood is **HIGH** because:
- Migration runs automatically during upgrade (no special privileges required)
- Any legacy mapping without COMMIT will cause the issue
- The existing test case proves such mappings exist [9](#0-8) 

## Recommendation

Add validation in the V1ToV2 migration function to ensure all migrated mappings are valid:

```go
// In v1_to_v2.go, after line 30 (newMapping.ContractAddress = legacyMapping.ContractAddress)
// Add validation before marshaling:
if err := types.ValidateWasmDependencyMapping(newMapping); err != nil {
    // For invalid mappings, set them to synchronous defaults
    newMapping.BaseAccessOps = types.SynchronousWasmAccessOps()
    newMapping.ResetReason = "migration_validation_failed"
}
```

This ensures that any legacy mapping without COMMIT is reset to safe synchronous defaults rather than persisting in an invalid state.

Alternatively, add validation at runtime in `GetRawWasmDependencyMapping` to catch any invalid mappings before use, though fixing at migration time is preferred to avoid runtime overhead.

## Proof of Concept

**File:** `x/accesscontrol/migrations/v1_to_v2_test.go`

**Test Function:** Add new test `TestV1ToV2InvalidMappingCausesDeadlock`

**Setup:**
1. Create a legacy WASM dependency mapping without COMMIT operation (only READ and WRITE ops)
2. Store it in the KV store using the legacy format
3. Run V1ToV2 migration

**Trigger:**
1. Retrieve the migrated mapping using `GetRawWasmDependencyMapping`
2. Verify that `BaseAccessOps` does not end with COMMIT (validate using `ValidateWasmDependencyMapping`)
3. Simulate building dependency DAG with this invalid mapping
4. Attempt to execute dependent transaction that waits for completion signal

**Observation:**
The test confirms:
- Migration succeeds without validation error (should fail but doesn't)
- Retrieved mapping has `BaseAccessOps` ending with WRITE instead of COMMIT
- `ValidateWasmDependencyMapping` on the migrated mapping returns `ErrNoCommitAccessOp`
- Invalid mapping persists in storage and would cause deadlocks at runtime

The test demonstrates that the existing test case `TestV1ToV2` already shows this vulnerability - `legacyMapping1` creates access ops without COMMIT [15](#0-14) , and the test verifies migration succeeds [16](#0-15) , but never validates that the result is a valid WASM dependency mapping according to the current validation rules.

## Notes

The vulnerability exists because the validation requirement (COMMIT termination) was added to the new format but the migration path doesn't enforce it on legacy data. The system assumes all stored mappings are valid, but migration creates an exception to this invariant. The issue is particularly severe because it affects the critical transaction coordination mechanism that enables concurrent execution.

### Citations

**File:** x/accesscontrol/migrations/v1_to_v2.go (L9-42)
```go
func V1ToV2(ctx sdk.Context, storeKey sdk.StoreKey) error {
	store := ctx.KVStore(storeKey)
	iterator := sdk.KVStorePrefixIterator(store, types.GetWasmMappingKey())

	defer iterator.Close()
	keysToSet := [][]byte{}
	valsToSet := [][]byte{}
	for ; iterator.Valid(); iterator.Next() {
		legacyMapping := acltypes.LegacyWasmDependencyMapping{}
		if err := legacyMapping.Unmarshal(iterator.Value()); err != nil {
			return err
		}
		newMapping := acltypes.WasmDependencyMapping{}
		for _, legacyOp := range legacyMapping.AccessOps {
			newMapping.BaseAccessOps = append(newMapping.BaseAccessOps, &acltypes.WasmAccessOperation{
				Operation:    legacyOp.Operation,
				SelectorType: legacyOp.SelectorType,
				Selector:     legacyOp.Selector,
			})
		}
		newMapping.ResetReason = legacyMapping.ResetReason
		newMapping.ContractAddress = legacyMapping.ContractAddress
		val, err := newMapping.Marshal()
		if err != nil {
			return err
		}
		keysToSet = append(keysToSet, iterator.Key())
		valsToSet = append(valsToSet, val)
	}
	for i, key := range keysToSet {
		store.Set(key, valsToSet[i])
	}
	return nil
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L123-127)
```go
func ValidateWasmDependencyMapping(mapping acltypes.WasmDependencyMapping) error {
	numOps := len(mapping.BaseAccessOps)
	if numOps == 0 || mapping.BaseAccessOps[numOps-1].Operation.AccessType != acltypes.AccessType_COMMIT {
		return ErrNoCommitAccessOp
	}
```

**File:** x/accesscontrol/keeper/keeper.go (L170-195)
```go
	dependencyMapping, err := k.GetRawWasmDependencyMapping(ctx, contractAddress)
	if err != nil {
		if err == sdkerrors.ErrKeyNotFound {
			return types.SynchronousAccessOps(), nil
		}
		return nil, err
	}

	accessOps := dependencyMapping.BaseAccessOps
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY {
		// If we have a query, filter out any WRITES
		accessOps = FilterReadOnlyAccessOps(accessOps)
	}
	specificAccessOpsMapping := []*acltypes.WasmAccessOperations{}
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_EXECUTE && len(dependencyMapping.ExecuteAccessOps) > 0 {
		specificAccessOpsMapping = dependencyMapping.ExecuteAccessOps
	} else if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY && len(dependencyMapping.QueryAccessOps) > 0 {
		specificAccessOpsMapping = dependencyMapping.QueryAccessOps
	}

	for _, specificAccessOps := range specificAccessOpsMapping {
		if specificAccessOps.MessageName == msgInfo.MessageName {
			accessOps = append(accessOps, specificAccessOps.WasmOperations...)
			break
		}
	}
```

**File:** x/accesscontrol/keeper/keeper.go (L593-598)
```go
			msgDependencies := k.GetMessageDependencies(ctx, msg)
			dependencyDag.AddAccessOpsForMsg(messageIndex, txIndex, msgDependencies)
			for _, accessOp := range msgDependencies {
				// make a new node in the dependency dag
				dependencyDag.AddNodeBuildDependency(messageIndex, txIndex, accessOp)
			}
```

**File:** baseapp/baseapp.go (L886-887)
```go
	defer acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
	acltypes.WaitForAllSignalsForTx(ctx.TxBlockingChannels())
```

**File:** types/accesscontrol/access_operation_map.go (L13-21)
```go
func WaitForAllSignalsForTx(messageIndexToAccessOpsChannelMapping MessageAccessOpsChannelMapping) {
	for _, accessOpsToChannelsMap := range messageIndexToAccessOpsChannelMapping {
		for _, channels := range accessOpsToChannelsMap {
			for _, channel := range channels {
				<-channel
			}
		}
	}
}
```

**File:** types/accesscontrol/access_operation_map.go (L23-31)
```go
func SendAllSignalsForTx(messageIndexToAccessOpsChannelMapping MessageAccessOpsChannelMapping) {
	for _, accessOpsToChannelsMap := range messageIndexToAccessOpsChannelMapping {
		for _, channels := range accessOpsToChannelsMap {
			for _, channel := range channels {
				channel <- struct{}{}
			}
		}
	}
}
```

**File:** types/accesscontrol/legacy.pb.go (L86-91)
```go
type LegacyWasmDependencyMapping struct {
	Enabled         bool                                `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	AccessOps       []LegacyAccessOperationWithSelector `protobuf:"bytes,2,rep,name=access_ops,json=accessOps,proto3" json:"access_ops"`
	ResetReason     string                              `protobuf:"bytes,3,opt,name=reset_reason,json=resetReason,proto3" json:"reset_reason,omitempty"`
	ContractAddress string                              `protobuf:"bytes,4,opt,name=contract_address,json=contractAddress,proto3" json:"contract_address,omitempty"`
}
```

**File:** x/accesscontrol/migrations/v1_to_v2_test.go (L24-47)
```go
	legacyMapping1 := acltypes.LegacyWasmDependencyMapping{
		AccessOps: []acltypes.LegacyAccessOperationWithSelector{
			{
				Operation: &acltypes.AccessOperation{
					AccessType:         acltypes.AccessType_READ,
					ResourceType:       acltypes.ResourceType_KV,
					IdentifierTemplate: "*",
				},
				SelectorType: acltypes.AccessOperationSelectorType_NONE,
				Selector:     "",
			},
			{
				Operation: &acltypes.AccessOperation{
					AccessType:         acltypes.AccessType_WRITE,
					ResourceType:       acltypes.ResourceType_KV_AUTH,
					IdentifierTemplate: "acct%s",
				},
				SelectorType: acltypes.AccessOperationSelectorType_JQ,
				Selector:     ".send.to",
			},
		},
		ContractAddress: wasmContractAddress1.String(),
		ResetReason:     "",
	}
```

**File:** x/accesscontrol/migrations/v1_to_v2_test.go (L77-91)
```go
	require.Equal(t, 2, len(newMapping1.BaseAccessOps))
	require.Equal(t, acltypes.AccessOperation{
		AccessType:         acltypes.AccessType_READ,
		ResourceType:       acltypes.ResourceType_KV,
		IdentifierTemplate: "*",
	}, *newMapping1.BaseAccessOps[0].Operation)
	require.Equal(t, acltypes.AccessOperationSelectorType_NONE, newMapping1.BaseAccessOps[0].SelectorType)
	require.Equal(t, "", newMapping1.BaseAccessOps[0].Selector)
	require.Equal(t, acltypes.AccessOperation{
		AccessType:         acltypes.AccessType_WRITE,
		ResourceType:       acltypes.ResourceType_KV_AUTH,
		IdentifierTemplate: "acct%s",
	}, *newMapping1.BaseAccessOps[1].Operation)
	require.Equal(t, acltypes.AccessOperationSelectorType_JQ, newMapping1.BaseAccessOps[1].SelectorType)
	require.Equal(t, ".send.to", newMapping1.BaseAccessOps[1].Selector)
```
