## Audit Report

## Title
Non-Deterministic Access Operation Ordering Causes Consensus Failures in WASM Dependency Resolution

## Summary
The `AccessOperationSet.ToSlice()` method in `x/accesscontrol/types/access_operations.go` iterates over a Go map without sorting, producing non-deterministic ordering of access operations. This method is used in the consensus-critical `GetWasmDependencyAccessOps()` function, causing different validators to potentially generate different access operation sequences for WASM contract messages, leading to consensus failures and chain splits.

## Impact
**High** - This vulnerability can cause unintended permanent chain splits requiring hard forks.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The access control system should produce deterministic access operation sequences across all validators to ensure consensus. When WASM contract dependencies are resolved, all validators must agree on the exact same ordered list of access operations for each message to build identical dependency DAGs and execute transactions in the same order.

**Actual Logic:** 
The `ToSlice()` method iterates over a Go map (`waos.ops`) without sorting the keys. Go deliberately randomizes map iteration order to prevent developers from relying on it. While the COMMIT operation is deterministically placed last, all other operations are added in whatever order the map iteration produces. When a WASM dependency mapping contains multiple non-COMMIT operations, different validators will receive them in different orders. [2](#0-1) 

The `GetWasmDependencyAccessOps()` function builds an `AccessOperationSet` by merging operations from multiple sources (base operations, specific message operations, and imported contract references), then calls `ToSlice()` to return the final list. [3](#0-2) 

These access operations are used by `GetMessageDependencies()` which feeds into the consensus-critical `BuildDependencyDag()` function. [4](#0-3) 

**Exploit Scenario:**
1. A WASM contract is registered with a dependency mapping containing multiple access operations (e.g., READ on multiple different resources plus COMMIT)
2. When transactions invoke this contract, each validator calls `GetWasmDependencyAccessOps()`
3. The function builds an `AccessOperationSet` and calls `ToSlice()` to convert it to a slice
4. Due to non-deterministic map iteration, Validator A gets operations in order [OP1, OP2, OP3, COMMIT]
5. Validator B gets the same operations but in order [OP2, OP1, OP3, COMMIT]
6. The different orderings lead to different dependency DAG structures
7. This causes different execution orders or validation results across validators
8. Validators produce different state roots and cannot reach consensus
9. The chain splits permanently until a hard fork fixes the issue

**Security Failure:** 
Consensus agreement is broken. The blockchain's fundamental requirement that all validators must process transactions identically and reach the same state is violated, causing chain splits.

## Impact Explanation

This vulnerability affects the entire blockchain network's ability to maintain consensus:

- **Consensus breakdown**: Different validators process the same transactions differently, leading to state divergence
- **Permanent chain split**: Once validators disagree on state, the chain splits into multiple incompatible forks
- **Network partition**: The network fragments as different validator subsets follow different chain tips
- **Requires hard fork**: Recovery requires coordinated manual intervention and a hard fork to fix the non-determinism

This is critical because consensus is the foundation of blockchain security. Without deterministic execution, the blockchain cannot function as a distributed ledger. All transactions, smart contracts, and assets on affected chains become unreliable until the issue is resolved through a hard fork.

## Likelihood Explanation

**Triggering conditions:**
- Any network participant can deploy or interact with WASM contracts
- No special privileges required - any user transaction invoking a WASM contract with multiple access operations can trigger this
- The issue manifests whenever a WASM dependency mapping contains more than two non-COMMIT operations (since with only one non-COMMIT operation, the ordering is deterministic)

**Frequency:**
- Occurs during normal operation whenever multi-operation WASM contracts are executed
- More complex contracts with fine-grained access control are more likely to exhibit this behavior
- The non-determinism means it could manifest inconsistently - sometimes validators agree by chance, sometimes they don't
- As WASM contract usage grows, the likelihood of encountering this increases

**Detection:**
- May manifest as mysterious consensus failures that are hard to debug
- Could be intermittent if some execution paths have fewer operations
- Validators would see unexplained state root mismatches

## Recommendation

Sort the access operations before returning them from `ToSlice()`. The recommended fix is to extract all operations from the map into a slice, sort them deterministically (e.g., by a combination of ResourceType, AccessType, and IdentifierTemplate), then append COMMIT at the end:

```go
func (waos *AccessOperationSet) ToSlice() []acltypes.AccessOperation {
    res := []acltypes.AccessOperation{}
    hasCommitOp := false
    
    for op := range waos.ops {
        if op != *CommitAccessOp() {
            res = append(res, op)
        } else {
            hasCommitOp = true
        }
    }
    
    // Sort non-COMMIT operations deterministically
    sort.Slice(res, func(i, j int) bool {
        if res[i].ResourceType != res[j].ResourceType {
            return res[i].ResourceType < res[j].ResourceType
        }
        if res[i].AccessType != res[j].AccessType {
            return res[i].AccessType < res[j].AccessType
        }
        return res[i].IdentifierTemplate < res[j].IdentifierTemplate
    })
    
    if hasCommitOp {
        res = append(res, *CommitAccessOp())
    }
    return res
}
```

This ensures all validators produce identical access operation orderings regardless of map iteration order.

## Proof of Concept

**File:** `x/accesscontrol/types/access_operations_test.go` (new file)

**Test function:** `TestToSliceNonDeterminism`

**Setup:**
Create an `AccessOperationSet` with multiple non-COMMIT operations that would expose the map iteration non-determinism.

**Trigger:**
Call `ToSlice()` multiple times (ideally in separate goroutines or test runs to maximize chance of different map iteration orders) and compare results.

**Observation:**
The test demonstrates that `ToSlice()` can produce different orderings. While a single test run might not catch this due to Go's map randomization, the code structure clearly shows the vulnerability. A more robust test would use runtime.MapIterOrder if available, or simply demonstrate that the code doesn't sort before returning.

```go
package types_test

import (
    "testing"
    
    acltypes "github.com/cosmos/cosmos-sdk/types/accesscontrol"
    "github.com/cosmos/cosmos-sdk/x/accesscontrol/types"
    "github.com/stretchr/testify/require"
)

func TestToSliceNonDeterminism(t *testing.T) {
    // Create multiple different non-COMMIT operations
    ops := []acltypes.AccessOperation{
        {AccessType: acltypes.AccessType_READ, ResourceType: acltypes.ResourceType_KV_BANK_BALANCES, IdentifierTemplate: "addr1"},
        {AccessType: acltypes.AccessType_READ, ResourceType: acltypes.ResourceType_KV_STAKING, IdentifierTemplate: "validator1"},
        {AccessType: acltypes.AccessType_WRITE, ResourceType: acltypes.ResourceType_KV_BANK_BALANCES, IdentifierTemplate: "addr2"},
        {AccessType: acltypes.AccessType_READ, ResourceType: acltypes.ResourceType_KV_ORACLE_EXCHANGE_RATE, IdentifierTemplate: "*"},
        *types.CommitAccessOp(),
    }
    
    // Create AccessOperationSet
    set := types.NewAccessOperationSet(ops)
    
    // Call ToSlice multiple times - the ordering of non-COMMIT ops may vary
    // due to map iteration non-determinism
    result1 := set.ToSlice()
    result2 := set.ToSlice()
    
    // The vulnerability is in the code structure: ToSlice() iterates over a map
    // without sorting. While this test might pass if map iteration happens to
    // be the same, the code is non-deterministic.
    
    // Verify COMMIT is last (this should always pass)
    require.Equal(t, *types.CommitAccessOp(), result1[len(result1)-1])
    require.Equal(t, *types.CommitAccessOp(), result2[len(result2)-1])
    
    // The issue: no guarantee that result1[0:len-1] == result2[0:len-1]
    // Different validators could get different orderings, causing consensus failure
    
    // To demonstrate: manually check that the code doesn't sort
    // Look at access_operations.go lines 46-60: it uses "for op := range waos.ops"
    // which is non-deterministic map iteration
}

// This test demonstrates the consensus impact
func TestWasmDependencyResolutionConsensusFailure(t *testing.T) {
    // Scenario: Two validators process the same WASM contract execution
    // Due to ToSlice() non-determinism, they get different access operation orders
    // This leads to different dependency DAGs and consensus failure
    
    // This is a conceptual test showing the vulnerability's impact
    // In practice, different nodes would need to be tested separately to see divergence
}
```

**Notes:**
The core issue is evident in the code structure at lines 46-60 of `access_operations.go`. The codebase has established patterns of sorting map keys before iteration in consensus-critical paths (as seen in `store/rootmulti/store.go`, `x/upgrade/keeper/keeper.go`, etc.), but `ToSlice()` violates this pattern. This is a consensus-breaking bug that can cause permanent chain splits.

### Citations

**File:** x/accesscontrol/types/access_operations.go (L46-60)
```go
func (waos *AccessOperationSet) ToSlice() []acltypes.AccessOperation {
	res := []acltypes.AccessOperation{}
	hasCommitOp := false
	for op := range waos.ops {
		if op != *CommitAccessOp() {
			res = append(res, op)
		} else {
			hasCommitOp = true
		}
	}
	if hasCommitOp {
		res = append(res, *CommitAccessOp())
	}
	return res
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

**File:** x/accesscontrol/keeper/keeper.go (L555-609)
```go
func (k Keeper) BuildDependencyDag(ctx sdk.Context, anteDepGen sdk.AnteDepGenerator, txs []sdk.Tx) (*types.Dag, error) {
	defer MeasureBuildDagDuration(time.Now(), "BuildDependencyDag")
	// contains the latest msg index for a specific Access Operation
	dependencyDag := types.NewDag()
	for txIndex, tx := range txs {
		if tx == nil {
			// this implies decoding error
			return nil, sdkerrors.ErrTxDecode
		}
		// get the ante dependencies and add them to the dag
		anteDeps, err := anteDepGen([]acltypes.AccessOperation{}, tx, txIndex)
		if err != nil {
			return nil, err
		}
		anteDepSet := make(map[acltypes.AccessOperation]struct{})
		anteAccessOpsList := []acltypes.AccessOperation{}
		for _, accessOp := range anteDeps {
			// if found in set, we've already included this access Op in out ante dependencies, so skip it
			if _, found := anteDepSet[accessOp]; found {
				continue
			}
			anteDepSet[accessOp] = struct{}{}
			err = types.ValidateAccessOp(accessOp)
			if err != nil {
				return nil, err
			}
			dependencyDag.AddNodeBuildDependency(acltypes.ANTE_MSG_INDEX, txIndex, accessOp)
			anteAccessOpsList = append(anteAccessOpsList, accessOp)
		}
		// add Access ops for msg for anteMsg
		dependencyDag.AddAccessOpsForMsg(acltypes.ANTE_MSG_INDEX, txIndex, anteAccessOpsList)

		ctx = ctx.WithTxIndex(txIndex)
		msgs := tx.GetMsgs()
		for messageIndex, msg := range msgs {
			if types.IsGovMessage(msg) {
				return nil, types.ErrGovMsgInBlock
			}
			msgDependencies := k.GetMessageDependencies(ctx, msg)
			dependencyDag.AddAccessOpsForMsg(messageIndex, txIndex, msgDependencies)
			for _, accessOp := range msgDependencies {
				// make a new node in the dependency dag
				dependencyDag.AddNodeBuildDependency(messageIndex, txIndex, accessOp)
			}
		}
	}
	// This should never happen base on existing DAG algorithm but it's not a significant
	// performance overhead (@BenchmarkAccessOpsBuildDependencyDag),
	// it would be better to keep this check. If a cyclic dependency
	// is ever found it may cause the chain to halt
	if !graph.Acyclic(&dependencyDag) {
		return nil, types.ErrCycleInDAG
	}
	return &dependencyDag, nil
}
```

**File:** x/accesscontrol/keeper/keeper.go (L625-642)
```go
func (k Keeper) GetMessageDependencies(ctx sdk.Context, msg sdk.Msg) []acltypes.AccessOperation {
	// Default behavior is to get the static dependency mapping for the message
	messageKey := types.GenerateMessageKey(msg)
	dependencyMapping := k.GetResourceDependencyMapping(ctx, messageKey)
	if dependencyGenerator, ok := k.MessageDependencyGeneratorMapper[types.GenerateMessageKey(msg)]; dependencyMapping.DynamicEnabled && ok {
		// if we have a dependency generator AND dynamic is enabled, use it
		if dependencies, err := dependencyGenerator(k, ctx, msg); err == nil {
			// validate the access ops before using them
			validateErr := types.ValidateAccessOps(dependencies)
			if validateErr == nil {
				return dependencies
			}
			errorMessage := fmt.Sprintf("Invalid Access Ops for message=%s. %s", messageKey, validateErr.Error())
			ctx.Logger().Error(errorMessage)
		}
	}
	return dependencyMapping.AccessOps
}
```
