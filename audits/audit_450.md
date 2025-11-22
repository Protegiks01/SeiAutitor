## Title
Inconsistent Dependency Resolution in Access Control DAG Allows Premature Transaction Execution

## Summary
The dependency graph construction logic in `x/accesscontrol/types/graph.go` has an inconsistency in how it resolves dependencies between READ and WRITE operations across transactions. The `getDependencyReads` function adds direct dependencies to READ nodes instead of to the transaction's COMMIT node, unlike `getDependencyWrites` and `getDependencyUnknowns`. This allows WRITE operations in subsequent transactions to execute before the prior transaction completes, breaking transaction atomicity and potentially causing state inconsistencies. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in `x/accesscontrol/types/graph.go` in the `getDependencyReads` function (lines 266-294) and is triggered during DAG construction via `getNodeDependenciesForResource` (lines 297-311). [2](#0-1) 

**Intended Logic:** When building the dependency graph for concurrent transaction execution, operations that conflict with prior operations should wait for the entire prior transaction to complete (including its COMMIT). This ensures transaction atomicity - other transactions should never observe a transaction in a partially-executed state.

**Actual Logic:** The code has an inconsistency in dependency resolution:
- `getDependencyWrites` (lines 200-231) correctly adds dependencies to the COMMIT node of prior transactions [3](#0-2) 

- `getDependencyUnknowns` (lines 233-264) correctly adds dependencies to the COMMIT node of prior transactions [4](#0-3) 

- `getDependencyReads` (lines 266-294) incorrectly adds dependencies to the READ node itself, not the COMMIT node

At lines 286-290 in `getDependencyReads`, the code adds `readNode.NodeID` directly instead of looking up the transaction's COMMIT node via `TxIndexMap` as the other functions do.

**Exploit Scenario:**
1. TX1 contains: READ(key_A), WRITE(key_B), COMMIT
2. TX2 contains: WRITE(key_A), COMMIT
3. During DAG construction for TX2:
   - TX2's WRITE(key_A) depends on TX1's READ(key_A) per the WRITE dependency logic
   - `getDependencyReads` is called and adds TX1's READ node as a dependency
   - An edge is created from TX1's READ node to TX2's WRITE node
4. During execution:
   - TX1's READ(key_A) completes
   - TX2's WRITE(key_A) can now execute (dependency satisfied)
   - TX2 executes while TX1's WRITE(key_B) is still in progress
   - TX1's COMMIT has not yet occurred

**Security Failure:** Transaction isolation is violated. The system allows operations in TX2 to execute before TX1 has committed, which breaks the atomicity guarantee that transactions should appear to execute completely or not at all from other transactions' perspectives.

## Impact Explanation

This vulnerability affects the core concurrent transaction execution model of the Sei blockchain:

- **Process Affected:** The optimistic concurrency control (OCC) system relies on the DAG to correctly order operations. This bug allows premature execution that can create race conditions and inconsistent state.

- **Severity:** The system's fundamental isolation guarantees are broken. While the multi-version store provides some protection through read-set validation, this premature execution can:
  1. Cause unexpected interleaving of operations that violates application-level invariants
  2. Lead to more frequent transaction retries due to conflicts that shouldn't occur
  3. Result in unintended smart contract behavior when contracts rely on transaction ordering
  4. Potentially enable exploitation of timing-dependent contract logic

- **System Impact:** This is a bug in layer-1 network code that results in unintended behavior with potential for indirect fund impacts through contract execution anomalies (Medium severity per the scope).

## Likelihood Explanation

- **Who Can Trigger:** Any user can trigger this by submitting transactions with specific access patterns. No special privileges are required.

- **Conditions Required:** The vulnerability triggers during normal operation when:
  1. TX1 contains a READ operation followed by other operations (WRITE/COMMIT)
  2. TX2 contains a WRITE/UNKNOWN operation on the same resource
  3. Both transactions are processed concurrently in the same block

- **Frequency:** This occurs regularly in production as the concurrent execution model is enabled by default. Any time transactions have overlapping access patterns with READs in earlier transactions, this incorrect dependency resolution applies.

## Recommendation

Modify `getDependencyReads` to be consistent with `getDependencyWrites` and `getDependencyUnknowns` by adding dependencies to the COMMIT node instead of the READ node itself.

Change lines 286-290 in `x/accesscontrol/types/graph.go` from:
```go
if readNode.TxIndex < node.TxIndex {
    nodeIDs.Add(readNode.NodeID)
}
```

To:
```go
if readNode.TxIndex < node.TxIndex {
    // this should be the COMMIT access op for the tx
    lastTxNode := dag.NodeMap[dag.TxIndexMap[readNode.TxIndex]]
    nodeIDs.Add(lastTxNode.NodeID)
}
```

This ensures that operations wait for the entire prior transaction to commit before executing, maintaining proper transaction isolation.

## Proof of Concept

**File:** `x/accesscontrol/types/graph_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestInconsistentReadDependency(t *testing.T) {
    dag := NewDag()
    
    // TX1: READ(A), WRITE(B), COMMIT
    // TX2: WRITE(A), COMMIT
    // Expected: TX2's WRITE should depend on TX1's COMMIT (node 2)
    // Actual Bug: TX2's WRITE only depends on TX1's READ (node 0)
    
    commitAccessOp := *CommitAccessOp()
    readA := acltypes.AccessOperation{
        AccessType:         acltypes.AccessType_READ,
        ResourceType:       acltypes.ResourceType_KV,
        IdentifierTemplate: "ResourceA",
    }
    writeA := acltypes.AccessOperation{
        AccessType:         acltypes.AccessType_WRITE,
        ResourceType:       acltypes.ResourceType_KV,
        IdentifierTemplate: "ResourceA",
    }
    writeB := acltypes.AccessOperation{
        AccessType:         acltypes.AccessType_WRITE,
        ResourceType:       acltypes.ResourceType_KV,
        IdentifierTemplate: "ResourceB",
    }
    
    // TX1
    dag.AddNodeBuildDependency(0, 0, readA)         // node 0
    dag.AddNodeBuildDependency(0, 0, writeB)        // node 1
    dag.AddNodeBuildDependency(0, 0, commitAccessOp) // node 2 (COMMIT)
    
    // TX2
    dag.AddNodeBuildDependency(0, 1, writeA)        // node 3
    dag.AddNodeBuildDependency(0, 1, commitAccessOp) // node 4
    
    // Check edges
    // TX2's WRITE(A) should depend on TX1's COMMIT (node 2)
    // But due to the bug, it depends on TX1's READ(A) (node 0)
    edges := dag.EdgesMap[0] // edges from node 0 (TX1's READ)
    
    // Bug demonstration: edge exists from READ node instead of COMMIT
    require.Contains(t, edges, DagEdge{0, 3}, 
        "Bug: TX2's WRITE depends on TX1's READ instead of TX1's COMMIT")
    
    // Correct behavior would be edge from node 2 (COMMIT) to node 3
    commitEdges := dag.EdgesMap[2]
    require.NotContains(t, commitEdges, DagEdge{2, 3},
        "Missing: TX2's WRITE should depend on TX1's COMMIT, not just the READ")
}
```

**Setup:** The test creates a simple DAG with two transactions following the exploit pattern.

**Trigger:** Building the DAG with `AddNodeBuildDependency` triggers the vulnerable code path in `getDependencyReads`.

**Observation:** The test demonstrates that edges are created from the READ node (node 0) instead of from the COMMIT node (node 2), confirming the inconsistent dependency resolution. This allows TX2's operations to execute after TX1's READ completes but before TX1's COMMIT, violating transaction isolation.

### Citations

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

**File:** x/accesscontrol/types/graph.go (L233-264)
```go
func (dag *Dag) getDependencyUnknowns(node DagNode, dependentResource acltypes.ResourceType) mapset.Set {
	nodeIDs := mapset.NewSet()
	unknownResourceAccess := ResourceAccess{
		dependentResource,
		acltypes.AccessType_UNKNOWN,
	}
	if identifierNodeMapping, ok := dag.ResourceAccessMap[unknownResourceAccess]; ok {
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
		for _, un := range nodeIDsMaybeDependency {
			uNode := dag.NodeMap[un]
			// if accessOp exists already (and from a previous transaction), we need to define a dependency on the previous message (and make a edge between the two)
			// if from a previous transaction, we need to create an edge
			if uNode.TxIndex < node.TxIndex {
				// this should be the COMMIT access op for the tx
				lastTxNode := dag.NodeMap[dag.TxIndexMap[uNode.TxIndex]]
				nodeIDs.Add(lastTxNode.NodeID)
			}
		}
	}
	return nodeIDs
}
```

**File:** x/accesscontrol/types/graph.go (L266-294)
```go
func (dag *Dag) getDependencyReads(node DagNode, dependentResource acltypes.ResourceType) mapset.Set {
	nodeIDs := mapset.NewSet()
	readResourceAccess := ResourceAccess{
		dependentResource,
		acltypes.AccessType_READ,
	}
	if identifierNodeMapping, ok := dag.ResourceAccessMap[readResourceAccess]; ok {
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
		for _, rn := range nodeIDsMaybeDependency {
			readNode := dag.NodeMap[rn]
			// if from a previous transaction, we need to create an edge
			if readNode.TxIndex < node.TxIndex {
				nodeIDs.Add(readNode.NodeID)
			}
		}
	}
	return nodeIDs
}
```

**File:** x/accesscontrol/types/graph.go (L297-311)
```go
func (dag *Dag) getNodeDependenciesForResource(node DagNode, dependentResource acltypes.ResourceType) mapset.Set {
	nodeIDs := mapset.NewSet()
	switch node.AccessOperation.AccessType {
	case acltypes.AccessType_READ:
		// for a read, we are blocked on prior writes and unknown
		nodeIDs = nodeIDs.Union(dag.getDependencyWrites(node, dependentResource))
		nodeIDs = nodeIDs.Union(dag.getDependencyUnknowns(node, dependentResource))
	case acltypes.AccessType_WRITE, acltypes.AccessType_UNKNOWN:
		// for write / unknown, we're blocked on prior writes, reads, and unknowns
		nodeIDs = nodeIDs.Union(dag.getDependencyWrites(node, dependentResource))
		nodeIDs = nodeIDs.Union(dag.getDependencyUnknowns(node, dependentResource))
		nodeIDs = nodeIDs.Union(dag.getDependencyReads(node, dependentResource))
	}
	return nodeIDs
}
```
