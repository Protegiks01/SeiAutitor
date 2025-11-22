# Audit Report

## Title
WASM Dependency Mappings Bypass Non-Leaf Resource Type Validation Allowing Incorrect Concurrent Execution

## Summary
The `ValidateWasmDependencyMapping` function does not call `ValidateAccessOp` to validate individual access operations within WASM dependency mappings. This allows WASM contracts to register access operations with non-leaf resource types (parent resources with children) using specific identifiers instead of the required wildcard "*", bypassing critical validation that prevents state corruption during concurrent transaction execution. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in `x/accesscontrol/types/message_dependency_mapping.go` in the `ValidateWasmDependencyMapping` function (lines 123-181), which is called by `SetWasmDependencyMapping` in `x/accesscontrol/keeper/keeper.go` (line 447). [2](#0-1) 

**Intended Logic:**
All access operations should be validated using `ValidateAccessOp` to enforce that non-leaf resource types (resources with children in the resource hierarchy) must use "*" as their `IdentifierTemplate`. This ensures proper dependency tracking in the DAG construction for concurrent transaction execution. The validation check is: [3](#0-2) 

**Actual Logic:**
`ValidateWasmDependencyMapping` only validates:
1. That base access operations end with `AccessType_COMMIT`
2. No duplicate message names exist
3. Deprecated selector types are not used

It never calls `ValidateAccessOp` for any of the access operations in `BaseAccessOps`, `ExecuteAccessOps`, or `QueryAccessOps`. In contrast, regular message dependency mappings are properly validated through `ValidateMessageDependencyMapping` which calls `ValidateAccessOps`: [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. An attacker deploys a WASM contract and registers a `WasmDependencyMapping` with an invalid access operation, for example:
   - `ResourceType: ResourceType_KV_BANK` (a parent resource with children like `KV_BANK_BALANCES`, `KV_BANK_SUPPLY`)
   - `IdentifierTemplate: "account_address_1"`
   - `AccessType: WRITE`

2. The validation in `SetWasmDependencyMapping` calls `ValidateWasmDependencyMapping` which passes without error since it doesn't check individual access operations.

3. When the contract executes, `GetWasmDependencyAccessOps` retrieves these operations and they are added to the dependency DAG via `AddNodeBuildDependency`: [6](#0-5) 

4. Two concurrent transactions execute the contract with different identifiers (e.g., "account_address_1" and "account_address_2"). In the DAG dependency resolution logic in `getDependencyWrites`, when checking for conflicts between operations on the same resource type: [7](#0-6) 

The logic at lines 212-217 only looks for matching identifiers or wildcards. Since the identifiers differ ("account_address_1" vs "account_address_2") and neither is "*", no dependency edge is created.

5. Both transactions execute concurrently despite accessing the same parent resource scope, leading to potential race conditions and state corruption.

**Security Failure:**
The dependency DAG construction fails to correctly identify conflicts between operations accessing the same parent resource with different identifiers, violating the invariant that parent resource accesses must be serialized. This breaks the concurrent execution safety guarantees of the access control system.

## Impact Explanation

The vulnerability affects the integrity of the blockchain state during concurrent transaction execution:

- **State Corruption Risk**: Transactions that should be serialized (because they access the same parent resource scope) can execute concurrently, leading to race conditions and inconsistent state updates.

- **Consensus Disagreement**: Different nodes might execute transactions in different orders or with different concurrency, potentially leading to state divergence between validators.

- **Smart Contract Behavior**: WASM contracts relying on the access control system for safe concurrent execution may experience unexpected behavior, including incorrect state transitions that could affect user funds or contract logic.

The severity is Medium because while it requires a WASM contract deployment (which may have some barriers), once deployed, the misconfigured access operations would consistently cause incorrect concurrent execution, potentially affecting all users interacting with that contract.

## Likelihood Explanation

**Who can trigger it:** Any user who can deploy a WASM contract can register a `WasmDependencyMapping` with invalid access operations. This could be done:
- Intentionally by a malicious actor
- Accidentally by a developer who misconfigures their contract's access patterns

**Conditions required:** 
- A WASM contract must be deployed with a dependency mapping containing invalid access operations
- Multiple transactions must be submitted in the same block that execute this contract with different identifiers
- The transactions must actually access overlapping state despite having different identifiers

**Frequency:** Once a contract with invalid access operations is deployed, every block containing multiple transactions to that contract could potentially trigger the concurrent execution issue. Given that WASM contracts are a core feature of the Sei protocol, this is likely to occur in normal operation.

## Recommendation

Modify `ValidateWasmDependencyMapping` to validate all individual access operations by calling `ValidateAccessOp`:

1. Add validation for `BaseAccessOps`:
```
for _, wasmOp := range mapping.BaseAccessOps {
    if err := ValidateAccessOp(*wasmOp.Operation); err != nil {
        return err
    }
}
```

2. Add validation for `ExecuteAccessOps` and `QueryAccessOps`:
```
for _, execOps := range mapping.ExecuteAccessOps {
    for _, wasmOp := range execOps.WasmOperations {
        if err := ValidateAccessOp(*wasmOp.Operation); err != nil {
            return err
        }
    }
}
```

3. Similarly validate operations in `QueryAccessOps`.

This ensures that all WASM access operations are subject to the same validation as regular message access operations, enforcing the non-leaf resource type constraint.

## Proof of Concept

**File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** `TestWasmDependencyMappingBypassesValidation`

**Setup:**
1. Initialize a test app with the access control keeper
2. Create a test contract address
3. Create a `WasmDependencyMapping` with an invalid access operation using a non-leaf resource type (`ResourceType_KV_BANK`) with a specific identifier instead of "*"

**Trigger:**
1. Call `SetWasmDependencyMapping` with the invalid mapping
2. Verify that the call succeeds (demonstrating the validation bypass)
3. Build a dependency DAG with two transactions that would conflict if validation were correct
4. Verify that no dependency edge is created between the transactions (demonstrating incorrect concurrent execution)

**Observation:**
The test demonstrates that:
1. `SetWasmDependencyMapping` accepts an invalid access operation (it should reject it)
2. The DAG construction allows concurrent execution of transactions that should be serialized
3. This violates the invariant that operations on the same parent resource must create dependency edges

**Test Code Structure:**
```
func TestWasmDependencyMappingBypassesValidation(t *testing.T) {
    // Setup: Create app and context
    // Create invalid WASM dependency mapping with non-leaf resource + specific identifier
    // Verify SetWasmDependencyMapping succeeds (SHOULD FAIL but doesn't)
    // Build DAG with conflicting transactions
    // Verify incorrect lack of dependency edge
}
```

The test would demonstrate that a WASM dependency mapping with `ResourceType_KV_BANK` (which has children) and `IdentifierTemplate: "specific_address"` passes validation when it should fail with `ErrNonLeafResourceTypeWithIdentifier`.

### Citations

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-45)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
	}
	for _, accessOp := range accessOps {
		err := ValidateAccessOp(accessOp)
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L47-55)
```go
func ValidateAccessOp(accessOp acltypes.AccessOperation) error {
	if accessOp.IdentifierTemplate == "" {
		return ErrEmptyIdentifierString
	}
	if accessOp.ResourceType.HasChildren() && accessOp.IdentifierTemplate != "*" {
		return ErrNonLeafResourceTypeWithIdentifier
	}
	return nil
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L57-59)
```go
func ValidateMessageDependencyMapping(mapping acltypes.MessageDependencyMapping) error {
	return ValidateAccessOps(mapping.AccessOps)
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

**File:** x/accesscontrol/keeper/keeper.go (L160-224)
```go
func (k Keeper) GetWasmDependencyAccessOps(ctx sdk.Context, contractAddress sdk.AccAddress, senderBech string, msgInfo *types.WasmMessageInfo, circularDepLookup ContractReferenceLookupMap) ([]acltypes.AccessOperation, error) {
	uniqueIdentifier := GetCircularDependencyIdentifier(contractAddress, msgInfo)
	if _, ok := circularDepLookup[uniqueIdentifier]; ok {
		// we've already seen this identifier, we should simply return synchronous access Ops
		ctx.Logger().Error("Circular dependency encountered, using synchronous access ops instead")
		return types.SynchronousAccessOps(), nil
	}
	// add to our lookup so we know we've seen this identifier
	circularDepLookup[uniqueIdentifier] = struct{}{}

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

	selectedAccessOps, err := k.BuildSelectorOps(ctx, contractAddress, accessOps, senderBech, msgInfo, circularDepLookup)
	if err != nil {
		return nil, err
	}

	// imports base contract references
	contractRefs := dependencyMapping.BaseContractReferences
	// add the specific execute or query contract references based on message type + name
	specificContractRefs := []*acltypes.WasmContractReferences{}
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_EXECUTE && len(dependencyMapping.ExecuteContractReferences) > 0 {
		specificContractRefs = dependencyMapping.ExecuteContractReferences
	} else if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY && len(dependencyMapping.QueryContractReferences) > 0 {
		specificContractRefs = dependencyMapping.QueryContractReferences
	}
	for _, specificContractRef := range specificContractRefs {
		if specificContractRef.MessageName == msgInfo.MessageName {
			contractRefs = append(contractRefs, specificContractRef.ContractReferences...)
			break
		}
	}
	importedAccessOps, err := k.ImportContractReferences(ctx, contractAddress, contractRefs, senderBech, msgInfo, circularDepLookup)
	if err != nil {
		return nil, err
	}
	// combine the access ops to get the definitive list of access ops for the contract
	selectedAccessOps.Merge(importedAccessOps)

	return selectedAccessOps.ToSlice(), nil
```

**File:** x/accesscontrol/keeper/keeper.go (L443-460)
```go
func (k Keeper) SetWasmDependencyMapping(
	ctx sdk.Context,
	dependencyMapping acltypes.WasmDependencyMapping,
) error {
	err := types.ValidateWasmDependencyMapping(dependencyMapping)
	if err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	b := k.cdc.MustMarshal(&dependencyMapping)

	contractAddr, err := sdk.AccAddressFromBech32(dependencyMapping.ContractAddress)
	if err != nil {
		return err
	}
	resourceKey := types.GetWasmContractAddressKey(contractAddr)
	store.Set(resourceKey, b)
	return nil
```

**File:** x/accesscontrol/types/graph.go (L200-231)
```go
func (dag *Dag) getDependencyWrites(node DagNode, dependentResource acltypes.ResourceType) mapset.Set {
	nodeIDs := mapset.NewSet()
	writeResourceAccess := ResourceAccess{
		dependentResource,
		acltypes.AccessType_WRITE,
	}
	if identifierNodeMapping, ok := dag.ResourceAccessMap[writeResourceAccess]; ok {
		var nodeIDsMaybeDependency []DagNodeID
		if dependentResource != node.AccessOperation.ResourceType {
			// we can add all node IDs as dependencies if applicable
			nodeIDsMaybeDependency = getAllNodeIDsFromIdentifierMapping(identifierNodeMapping)
		} else {
			if node.AccessOperation.IdentifierTemplate != "*" {
				nodeIDsMaybeDependency = identifierNodeMapping[node.AccessOperation.IdentifierTemplate]
				nodeIDsMaybeDependency = append(nodeIDsMaybeDependency, identifierNodeMapping["*"]...)
			} else {
				nodeIDsMaybeDependency = getAllNodeIDsFromIdentifierMapping(identifierNodeMapping)
			}
		}
		for _, wn := range nodeIDsMaybeDependency {
			writeNode := dag.NodeMap[wn]
			// if accessOp exists already (and from a previous transaction), we need to define a dependency on the previous message (and make a edge between the two)
			// if from a previous transaction, we need to create an edge
			if writeNode.TxIndex < node.TxIndex {
				// this should be the COMMIT access op for the tx
				lastTxNode := dag.NodeMap[dag.TxIndexMap[writeNode.TxIndex]]
				nodeIDs.Add(lastTxNode.NodeID)
			}
		}
	}
	return nodeIDs
}
```
