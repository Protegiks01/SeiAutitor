# Audit Report

## Title
Index Out of Range Panic in ValidateAccessOps Causes Network Shutdown via Governance Proposal

## Summary
The `ValidateAccessOps` function fails to validate that the access operations slice is non-empty before accessing its last element, causing a panic when processing governance proposals with empty `AccessOps`. This vulnerability enables any user to submit a malicious governance proposal that, upon execution, crashes all validator nodes and halts the entire network. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary: `x/accesscontrol/types/message_dependency_mapping.go`, function `ValidateAccessOps`, line 33
- Call sites: `x/accesscontrol/keeper/keeper.go` lines 95, 633

**Intended Logic:** 
The `ValidateAccessOps` function is designed to reject access-op sequences that are missing a final COMMIT operation. It should return `ErrNoCommitAccessOp` error when the last operation is not a COMMIT, and should handle all edge cases including empty sequences gracefully. [2](#0-1) 

**Actual Logic:** 
The function immediately accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. When `accessOps` has length 0, the expression `len(accessOps)-1` evaluates to -1, causing a runtime panic with "index out of range [-1]" instead of returning a validation error. [3](#0-2) 

**Exploit Scenario:**

1. An attacker crafts a `MsgUpdateResourceDependencyMappingProposal` containing a `MessageDependencyMapping` with an empty `AccessOps` array (zero elements)

2. The attacker submits this proposal to the governance module with sufficient deposit

3. The proposal's `ValidateBasic()` method only validates the title and description, NOT the AccessOps content, so the proposal is accepted [4](#0-3) 

4. The proposal goes through the voting period and accumulates enough votes to pass

5. During `EndBlocker` execution, when the proposal passes, the handler is invoked [5](#0-4) 

6. The handler calls `SetResourceDependencyMapping` which calls `ValidateMessageDependencyMapping` [6](#0-5) [7](#0-6) 

7. This calls `ValidateAccessOps` with the empty slice, triggering the panic [8](#0-7) 

8. The panic propagates through the call stack, crashes the node during block execution, and prevents the block from being finalized

9. All validator nodes processing this block experience the same panic, causing total network shutdown

**Security Failure:** 
This is a **denial-of-service vulnerability** that breaks the network's **liveness property**. The panic during governance proposal execution causes all nodes to crash simultaneously when processing the same block, preventing consensus and halting the blockchain indefinitely.

## Impact Explanation

**Affected Components:**
- All validator nodes and full nodes processing blocks
- Network consensus and transaction finality
- Entire blockchain operation

**Severity of Damage:**
- **Complete network halt**: All nodes crash when processing the malicious governance proposal execution
- **Permanent blockchain freeze**: The chain cannot progress past the block containing the proposal execution without manual intervention
- **Loss of network availability**: No new transactions can be confirmed, no blocks can be produced
- **Consensus breakdown**: Validators cannot reach agreement on new blocks due to systematic crashes

**System Impact:**
This vulnerability represents a critical systemic failure because:
1. It can be triggered by any user with governance participation capability (no special privileges required beyond proposal deposit)
2. It affects 100% of network nodes simultaneously
3. Recovery requires manual node operator intervention, potentially including emergency patches or chain rollback
4. The attack surface is a legitimate governance mechanism, making it difficult to prevent through rate limiting or access controls

## Likelihood Explanation

**Attack Feasibility:**
- **Who can trigger**: Any user who can submit a governance proposal (requires only sufficient tokens for minimum deposit, which varies by chain configuration but is typically accessible)
- **Skill requirement**: Low - requires only understanding of governance proposal structure and ability to craft JSON with empty array
- **Detection difficulty**: The malicious proposal would appear valid during submission and voting periods, only manifesting during execution

**Conditions Required:**
- Attacker must acquire minimum deposit amount for governance proposals
- Proposal must receive sufficient votes to pass (this is the main barrier)
- No other validation exists to catch empty AccessOps before execution

**Exploitation Frequency:**
- Can be executed repeatedly if not fixed
- Each successful attack requires waiting through voting period (~2 weeks typical)
- High likelihood if attacker controls sufficient voting power or can coordinate votes
- Could also occur accidentally if legitimate governance proposals are malformed

## Recommendation

Add an empty slice check at the beginning of `ValidateAccessOps` before accessing any elements:

```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
    if len(accessOps) == 0 {
        return ErrNoCommitAccessOp
    }
    lastAccessOp := accessOps[len(accessOps)-1]
    if lastAccessOp != *CommitAccessOp() {
        return ErrNoCommitAccessOp
    }
    // ... rest of function
}
```

Additionally, consider adding validation to `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to reject proposals with empty AccessOps during submission rather than execution:

```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
    err := govtypes.ValidateAbstract(p)
    if err != nil {
        return err
    }
    for _, mapping := range p.MessageDependencyMapping {
        if err := ValidateMessageDependencyMapping(mapping); err != nil {
            return err
        }
    }
    return nil
}
```

## Proof of Concept

**File:** `x/accesscontrol/types/message_dependency_mapping_test.go`

**Test Function:** `TestValidateAccessOpsWithEmptySlice`

**Setup:**
```go
func TestValidateAccessOpsWithEmptySlice(t *testing.T) {
    // Create a MessageDependencyMapping with empty AccessOps
    emptyAccessOpsMapping := acltypes.MessageDependencyMapping{
        MessageKey: "testEmptyOps",
        AccessOps:  []acltypes.AccessOperation{}, // Empty slice
    }
```

**Trigger:**
```go
    // This should return an error but instead will panic
    // Use require.Panics to catch the panic and demonstrate the vulnerability
    require.Panics(t, func() {
        types.ValidateAccessOps(emptyAccessOpsMapping.AccessOps)
    }, "ValidateAccessOps should panic when given empty slice")
    
    // Also test through ValidateMessageDependencyMapping
    require.Panics(t, func() {
        types.ValidateMessageDependencyMapping(emptyAccessOpsMapping)
    }, "ValidateMessageDependencyMapping should panic with empty AccessOps")
```

**Observation:**
The test demonstrates that calling `ValidateAccessOps` or `ValidateMessageDependencyMapping` with an empty `AccessOps` slice triggers a panic with "runtime error: index out of range [-1]" instead of returning the expected `ErrNoCommitAccessOp` error. This confirms the vulnerability.

**Complete test that can be added to the test file:**

```go
func TestValidateAccessOpsWithEmptySlice(t *testing.T) {
    // Test direct call to ValidateAccessOps with empty slice
    emptyOps := []acltypes.AccessOperation{}
    
    // This demonstrates the vulnerability - function panics instead of returning error
    require.Panics(t, func() {
        _ = types.ValidateAccessOps(emptyOps)
    }, "Expected panic when validating empty AccessOps slice")
    
    // Test through ValidateMessageDependencyMapping
    emptyMapping := acltypes.MessageDependencyMapping{
        MessageKey: "test",
        AccessOps:  []acltypes.AccessOperation{},
    }
    
    require.Panics(t, func() {
        _ = types.ValidateMessageDependencyMapping(emptyMapping)
    }, "Expected panic when validating MessageDependencyMapping with empty AccessOps")
}
```

To simulate the full governance proposal attack scenario, add this test to `x/accesscontrol/keeper/keeper_test.go`:

```go
func TestGovernanceProposalWithEmptyAccessOpsCausesNodeCrash(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create a malicious MessageDependencyMapping with empty AccessOps
    maliciousMapping := acltypes.MessageDependencyMapping{
        MessageKey: "malicious",
        AccessOps:  []acltypes.AccessOperation{}, // Empty - will cause panic
    }
    
    // Attempting to set this mapping will panic (simulating governance proposal execution)
    require.Panics(t, func() {
        _ = app.AccessControlKeeper.SetResourceDependencyMapping(ctx, maliciousMapping)
    }, "SetResourceDependencyMapping should panic with empty AccessOps, crashing the node")
}
```

### Citations

**File:** x/accesscontrol/types/message_dependency_mapping.go (L11-12)
```go
var (
	ErrNoCommitAccessOp                  = fmt.Errorf("MessageDependencyMapping doesn't terminate with AccessType_COMMIT")
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-36)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
	}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L57-59)
```go
func ValidateMessageDependencyMapping(mapping acltypes.MessageDependencyMapping) error {
	return ValidateAccessOps(mapping.AccessOps)
}
```

**File:** x/accesscontrol/types/gov.go (L42-44)
```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
	err := govtypes.ValidateAbstract(p)
	return err
```

**File:** x/gov/abci.go (L67-74)
```go
		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
```

**File:** x/accesscontrol/handler.go (L12-17)
```go
func HandleMsgUpdateResourceDependencyMappingProposal(ctx sdk.Context, k *keeper.Keeper, p *types.MsgUpdateResourceDependencyMappingProposal) error {
	for _, resourceDepMapping := range p.MessageDependencyMapping {
		err := k.SetResourceDependencyMapping(ctx, resourceDepMapping)
		if err != nil {
			return err
		}
```

**File:** x/accesscontrol/keeper/keeper.go (L91-98)
```go
func (k Keeper) SetResourceDependencyMapping(
	ctx sdk.Context,
	dependencyMapping acltypes.MessageDependencyMapping,
) error {
	err := types.ValidateMessageDependencyMapping(dependencyMapping)
	if err != nil {
		return err
	}
```
