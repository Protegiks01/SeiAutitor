## Title
Governance Proposal Validation Bypass Allows Node Crash via Empty AccessOps Array

## Summary
The `ValidateBasic()` method for `MsgUpdateResourceDependencyMappingProposal` fails to validate dependency mappings, allowing proposals with empty `AccessOps` arrays to be submitted and voted on. When such a proposal executes, the `ValidateAccessOps()` function attempts to access an out-of-bounds array index, causing a runtime panic that can crash nodes during `EndBlock` execution, where no panic recovery exists.

## Impact
High

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Secondary vulnerability (panic trigger): [2](#0-1) 
- No panic recovery in: [3](#0-2) 

**Intended Logic:** 
The `ValidateBasic()` method is supposed to perform stateless validation on governance proposals before they enter the governance voting process. For dependency mapping proposals, this should include validating that the `MessageDependencyMapping` contains valid `AccessOps` (non-empty, properly formatted, ending with COMMIT operation).

**Actual Logic:** 
The `ValidateBasic()` implementation only calls `govtypes.ValidateAbstract(p)`, which validates title and description fields but does NOT validate the `MessageDependencyMapping` array or its contents. [1](#0-0) 

The validation functions exist but are never called during proposal submission:
- `ValidateMessageDependencyMapping()` is defined [4](#0-3)  but not used in `ValidateBasic()`
- `ValidateAccessOps()` contains a critical bug: it accesses `accessOps[len(accessOps)-1]` without checking if the array is empty [2](#0-1) 

**Exploit Scenario:**
1. Attacker submits a `MsgSubmitProposal` containing a `MsgUpdateResourceDependencyMappingProposal` with a `MessageDependencyMapping` that has an empty `AccessOps` array
2. The `MsgSubmitProposal.ValidateBasic()` calls `content.ValidateBasic()` on the proposal [5](#0-4) 
3. Since the proposal's `ValidateBasic()` only validates title/description, the malformed proposal passes validation and enters governance
4. If the proposal receives enough votes and passes, it executes in `EndBlocker` [6](#0-5) 
5. The handler calls `keeper.SetResourceDependencyMapping()` which calls `ValidateMessageDependencyMapping()` [7](#0-6) 
6. `ValidateAccessOps()` attempts to access `accessOps[len(accessOps)-1]` when length is 0, causing a runtime panic (index out of range)
7. The `EndBlock` function has no panic recovery mechanism [3](#0-2) , so the panic propagates and crashes the node

**Security Failure:**
This breaks the availability and safety properties of the consensus system. A runtime panic during `EndBlock` execution causes the node to crash. If multiple validators execute the approved proposal simultaneously, they will all crash, potentially halting the network or causing a consensus failure.

## Impact Explanation

**Affected Components:**
- Network availability: Nodes crash during block finalization
- Consensus integrity: If >33% of validators crash simultaneously, the network halts
- Transaction finality: Blocks cannot be produced while nodes are recovering

**Severity:**
- If the malicious proposal passes governance and 30%+ of validators execute it, their nodes crash during the same block's `EndBlock`
- This constitutes a "Shutdown of greater than or equal to 30% of network processing nodes" (Medium severity per scope)
- If >67% of validators are affected, it becomes "Network not being able to confirm new transactions" (High severity per scope)
- The network remains halted until manual intervention (node restarts), during which no transactions can be confirmed

**Why This Matters:**
Even though governance approval is required, this represents a critical system failure. Defensive programming principles dictate that validation should occur at the earliest possible stage (proposal submission) and that the system should never crash due to malformed data, even if that data was approved through governance. The combination of missing validation in `ValidateBasic()` and the panic vulnerability creates a critical availability risk.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with sufficient tokens to meet the proposal deposit requirement can submit the malicious proposal.

**Conditions Required:**
1. Attacker submits a proposal with empty `AccessOps` array (requires proposal deposit, typically a modest amount)
2. Proposal must pass governance voting (requires majority approval)
3. All nodes executing `EndBlock` when the proposal passes will crash

**Likelihood Assessment:**
While governance approval is required, several factors increase the likelihood:
- The malicious nature can be disguised (empty array might look like a "reset" or "cleanup" operation)
- Voters may not thoroughly inspect the technical details of dependency mapping proposals
- Automated voting systems may approve without detailed validation
- Social engineering could convince voters this is a legitimate "fix" or "update"
- Once approved, the impact is immediate and affects all nodes simultaneously

The vulnerability is deterministic: once a malformed proposal passes, the crash is guaranteed during execution.

## Recommendation

**Immediate Fix:**
Add proper validation in the `ValidateBasic()` methods:

1. In `x/accesscontrol/types/gov.go`, modify both `ValidateBasic()` methods (lines 42-45 and 79-82) to call the existing validation functions:
   - For `MsgUpdateResourceDependencyMappingProposal`: iterate through `MessageDependencyMapping` array and call `ValidateMessageDependencyMapping()` on each element
   - For `MsgUpdateWasmDependencyMappingProposal`: call `ValidateWasmDependencyMapping()` on the `WasmDependencyMapping` field

2. In `x/accesscontrol/types/message_dependency_mapping.go`, add bounds checking in `ValidateAccessOps()` (line 32):
   - Check `len(accessOps) == 0` before accessing array elements
   - Return `ErrNoCommitAccessOp` if empty

3. Add panic recovery to `EndBlock` in `baseapp/abci.go` as a defense-in-depth measure, following the pattern used in `ProcessProposal`.

## Proof of Concept

**File:** `x/accesscontrol/types/gov_test.go` (new file)

**Test Function:** `TestMsgUpdateResourceDependencyMappingProposal_ValidateBasic_EmptyAccessOps`

**Setup:**
1. Create a `MsgUpdateResourceDependencyMappingProposal` with valid title and description
2. Add a `MessageDependencyMapping` with an empty `AccessOps` array to the proposal

**Trigger:**
1. Call `ValidateBasic()` on the proposal
2. Observe that it returns `nil` (no error), allowing the malformed proposal to pass validation
3. Simulate execution by calling `ValidateMessageDependencyMapping()` directly on the malformed mapping
4. Observe the resulting panic from the index out of bounds error

**Observation:**
The test demonstrates two issues:
1. `ValidateBasic()` incorrectly passes validation for a proposal with empty `AccessOps`
2. Subsequent validation during execution causes a panic

**Expected Test Code Structure:**
```
func TestMsgUpdateResourceDependencyMappingProposal_ValidateBasic_EmptyAccessOps(t *testing.T) {
    // Create malformed mapping with empty AccessOps
    malformedMapping := acltypes.MessageDependencyMapping{
        MessageKey: "test_message",
        AccessOps:  []acltypes.AccessOperation{}, // EMPTY - should be caught by ValidateBasic
    }
    
    // Create proposal
    proposal := NewMsgUpdateResourceDependencyMappingProposal(
        "Test Proposal",
        "This proposal has empty AccessOps",
        []acltypes.MessageDependencyMapping{malformedMapping},
    )
    
    // ValidateBasic should reject this but currently doesn't
    err := proposal.ValidateBasic()
    require.NoError(t, err) // CURRENTLY PASSES - THIS IS THE BUG
    
    // Simulate what happens during execution
    require.Panics(t, func() {
        _ = ValidateMessageDependencyMapping(malformedMapping)
    }) // PANIC occurs during execution, crashing the node
}
```

This test proves that malformed proposals bypass `ValidateBasic()` validation and cause panics during execution, demonstrating the complete attack chain from submission through node crash.

### Citations

**File:** x/accesscontrol/types/gov.go (L42-45)
```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
	err := govtypes.ValidateAbstract(p)
	return err
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-34)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L57-59)
```go
func ValidateMessageDependencyMapping(mapping acltypes.MessageDependencyMapping) error {
	return ValidateAccessOps(mapping.AccessOps)
}
```

**File:** baseapp/abci.go (L178-201)
```go
func (app *BaseApp) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	// Clear DeliverTx Events
	ctx.MultiStore().ResetEvents()

	defer telemetry.MeasureSince(time.Now(), "abci", "end_block")

	if app.endBlocker != nil {
		res = app.endBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	if cp := app.GetConsensusParams(ctx); cp != nil {
		res.ConsensusParamUpdates = legacytm.ABCIToLegacyConsensusParams(cp)
	}

	// call the streaming service hooks with the EndBlock messages
	for _, streamingListener := range app.abciListeners {
		if err := streamingListener.ListenEndBlock(app.deliverState.ctx, req, res); err != nil {
			app.logger.Error("EndBlock listening hook failed", "height", req.Height, "err", err)
		}
	}

	return res
}
```

**File:** x/gov/types/msgs.go (L108-110)
```go
	if err := content.ValidateBasic(); err != nil {
		return err
	}
```

**File:** x/gov/abci.go (L67-92)
```go
		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
			if err == nil {
				proposal.Status = types.StatusPassed
				tagValue = types.AttributeValueProposalPassed
				logMsg = "passed"

				// The cached context is created with a new EventManager. However, since
				// the proposal handler execution was successful, we want to track/keep
				// any events emitted, so we re-emit to "merge" the events into the
				// original Context's EventManager.
				ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())

				// write state to the underlying multi-store
				writeCache()
			} else {
				proposal.Status = types.StatusFailed
				tagValue = types.AttributeValueProposalFailed
				logMsg = fmt.Sprintf("passed, but failed on execution: %s", err)
			}
```

**File:** x/accesscontrol/keeper/keeper.go (L95-98)
```go
	err := types.ValidateMessageDependencyMapping(dependencyMapping)
	if err != nil {
		return err
	}
```
