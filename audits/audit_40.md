# Audit Report

## Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

## Summary
The `ValidateAccessOps` function performs unbounded array access at `accessOps[len(accessOps)-1]` without checking if the array is empty, causing a runtime panic when an empty `AccessOps` array is provided. This vulnerability can be triggered through governance proposals where `ValidateBasic` only validates title and description fields, bypassing validation of `MessageDependencyMapping` contents. During proposal execution in `EndBlock`, the unrecovered panic crashes all validator nodes simultaneously, causing complete network shutdown.

## Impact
High

## Finding Description

- **location**: 
  - Primary vulnerability: [1](#0-0) 
  - Insufficient proposal validation: [2](#0-1) 
  - Proposal execution handler: [3](#0-2) 
  - SetResourceDependencyMapping validation call: [4](#0-3) 
  - EndBlock proposal execution: [5](#0-4) 
  - EndBlock without panic recovery: [6](#0-5) 

- **intended logic**: The `ValidateAccessOps` function should validate that AccessOps arrays are non-empty before accessing elements and verify they terminate with a COMMIT operation. The `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` method should comprehensively validate all proposal contents, including the `MessageDependencyMapping` structure, before allowing proposals to enter the voting process.

- **actual logic**: The function directly accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. When `len(accessOps)` equals 0, the expression `len(accessOps)-1` evaluates to -1 (underflow in unsigned arithmetic context), causing an index out-of-bounds panic. The `ValidateBasic()` method only calls `govtypes.ValidateAbstract(p)`, which validates title and description fields but completely bypasses validation of the `MessageDependencyMapping` contents.

- **exploitation path**:
  1. A governance proposal containing `MessageDependencyMapping` with an empty `AccessOps` array is created (structurally valid per protobuf schema [7](#0-6) )
  2. The proposal passes `MsgSubmitProposal.ValidateBasic` which calls `content.ValidateBasic()` [8](#0-7) 
  3. `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` only validates title/description, allowing the malformed proposal through
  4. The proposal proceeds through the voting period and receives sufficient votes to pass
  5. During `EndBlock` execution, the approved proposal handler is invoked
  6. `HandleMsgUpdateResourceDependencyMappingProposal` calls `k.SetResourceDependencyMapping`
  7. This invokes `types.ValidateMessageDependencyMapping`, which calls `ValidateAccessOps`
  8. The panic occurs when accessing the non-existent array element at index -1
  9. Since `EndBlock` has no panic recovery mechanism (no defer/recover blocks), the node process crashes
  10. All validator nodes execute the same `EndBlock` deterministically at the same block height, causing simultaneous crashes across the entire validator set
  11. The chain halts completely with no nodes remaining operational to produce blocks

- **security guarantee broken**: Network availability and liveness. The blockchain must gracefully handle invalid inputs by returning validation errors, not crashing all nodes through unrecovered panics that terminate the consensus process. The `ValidateBasic` function exists specifically to prevent invalid proposals from entering the governance process, but its incomplete implementation allows structurally valid but semantically invalid data to crash the system during execution.

## Impact Explanation

When the malformed governance proposal executes during `EndBlock`, all validator nodes crash simultaneously because they deterministically process the same proposal at the same block height. This results in:

- **Complete network shutdown**: No validator nodes remain operational to produce new blocks, matching the impact category "Network not being able to confirm new transactions (total network shutdown)"
- **Transaction processing halt**: No transactions can be confirmed or executed
- **Consensus failure**: The network cannot reach consensus on new blocks
- **Recovery complexity**: Requires coordinated manual intervention across all validators, potentially requiring emergency patches and coordinated network restart with modified state or code

The uncontrolled panic propagates through the application layer without being caught by any recovery mechanism, terminating the node process entirely. This represents a complete denial-of-service affecting the entire network infrastructure.

## Likelihood Explanation

**Who can trigger**: Any participant capable of submitting governance proposals and obtaining sufficient voting support from the community.

**Conditions required**:
- Governance proposal with empty `AccessOps` is submitted (requires minimum deposit)
- Proposal receives sufficient votes to pass (requires governance participation)
- Proposal executes after voting period ends

**Likelihood factors**:
1. While governance approval is required, this is fundamentally a **validation bug** not a governance attack scenario
2. Proposals created with buggy tooling, automated scripts, or human error could inadvertently contain empty arrays (valid per protobuf repeated field specification)
3. The validation failure is subtle - validators reviewing proposal JSON may not notice the empty array in the structure
4. No validation occurs at submission or voting time; the crash only manifests during execution in `EndBlock`
5. Once executed, the impact is immediate and deterministic across all nodes
6. The protobuf schema allows empty repeated fields by design, making this a structurally valid input that should be handled gracefully

This represents a critical validation gap where well-intentioned governance participants could accidentally halt the network through programming errors in proposal creation tooling or manual mistakes during proposal preparation. The vulnerability is in the validation logic, not in governance authority itself.

## Recommendation

**Immediate fix**: Add bounds checking in `ValidateAccessOps`:

```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
    if len(accessOps) == 0 {
        return ErrNoCommitAccessOp
    }
    lastAccessOp := accessOps[len(accessOps)-1]
    if lastAccessOp != *CommitAccessOp() {
        return ErrNoCommitAccessOp
    }
    // ... rest of validation
}
```

**Additional improvements**:

1. Enhance `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to validate the full `MessageDependencyMapping` contents before proposals enter the governance voting process:
```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
    err := govtypes.ValidateAbstract(p)
    if err != nil {
        return err
    }
    for _, mapping := range p.MessageDependencyMapping {
        if err := types.ValidateMessageDependencyMapping(mapping); err != nil {
            return err
        }
    }
    return nil
}
```

2. Fix `ValidateGenesis` in [9](#0-8)  to call the comprehensive [10](#0-9)  instead of only `data.Params.Validate()`

3. Consider adding panic recovery in EndBlock execution as a defense-in-depth measure

## Proof of Concept

**Test location**: `x/accesscontrol/types/message_dependency_mapping_test.go`

**Setup**: Import required packages (`testing`, `acltypes`, `types`) and define test function

**Action**: Call `ValidateAccessOps` with empty slice:
```go
func TestValidateAccessOps_EmptyArray_Panic(t *testing.T) {
    emptyAccessOps := []acltypes.AccessOperation{}
    
    defer func() {
        if r := recover(); r == nil {
            t.Errorf("Expected panic but got none")
        }
    }()
    
    types.ValidateAccessOps(emptyAccessOps)
}
```

**Result**: The function panics with "runtime error: index out of range [-1]" instead of returning a proper validation error. The panic occurs because Go interprets `accessOps[len(accessOps)-1]` as `accessOps[-1]` when the slice length is 0, resulting in an invalid memory access that terminates the process. This demonstrates that the validation function fails to handle the empty array case, which is a structurally valid input per the protobuf schema definition.

## Notes

This vulnerability represents a critical validation gap in the access control governance proposal flow. While governance approval is required to trigger the issue, the root cause is a programming error (missing bounds check) in the validation function that allows accidentally malformed proposals to crash the entire network. 

The key distinction is that this is not about malicious governance actors or governance authority abuse - it's about insufficient input validation that transforms routine programming mistakes into catastrophic network failures. Governance participants' intended authority includes approving or rejecting proposals to modify system parameters, but does not extend to accidentally halting the entire network through tooling errors in proposal creation. 

The `ValidateBasic` function exists specifically to prevent invalid proposals from entering the governance process, but its incomplete implementation fails to validate the actual proposal contents. This allows proposals that are structurally valid (per protobuf schema) but semantically invalid (empty AccessOps array) to pass validation and crash the system during execution. The absence of panic recovery in the `EndBlock` execution path means this panic propagates to the node process level, causing immediate termination across all validators simultaneously, resulting in complete network shutdown.

### Citations

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-36)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
	}
```

**File:** x/accesscontrol/types/gov.go (L42-45)
```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
	err := govtypes.ValidateAbstract(p)
	return err
}
```

**File:** x/accesscontrol/handler.go (L12-20)
```go
func HandleMsgUpdateResourceDependencyMappingProposal(ctx sdk.Context, k *keeper.Keeper, p *types.MsgUpdateResourceDependencyMappingProposal) error {
	for _, resourceDepMapping := range p.MessageDependencyMapping {
		err := k.SetResourceDependencyMapping(ctx, resourceDepMapping)
		if err != nil {
			return err
		}
	}
	return nil
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

**File:** proto/cosmos/accesscontrol/accesscontrol.proto (L38-44)
```text
message MessageDependencyMapping {
    string message_key = 1;
    repeated AccessOperation access_ops = 2 [
        (gogoproto.nullable) = false
    ];
    bool dynamic_enabled = 3;
}
```

**File:** x/gov/types/msgs.go (L90-112)
```go
func (m MsgSubmitProposal) ValidateBasic() error {
	if m.Proposer == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, m.Proposer)
	}
	if !m.InitialDeposit.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, m.InitialDeposit.String())
	}
	if m.InitialDeposit.IsAnyNegative() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, m.InitialDeposit.String())
	}

	content := m.GetContent()
	if content == nil {
		return sdkerrors.Wrap(ErrInvalidProposalContent, "missing content")
	}
	if !IsValidProposalType(content.ProposalType()) {
		return sdkerrors.Wrap(ErrInvalidProposalType, content.ProposalType())
	}
	if err := content.ValidateBasic(); err != nil {
		return err
	}

	return nil
```

**File:** x/accesscontrol/module.go (L62-69)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return data.Params.Validate()
}
```

**File:** x/accesscontrol/types/genesis.go (L29-43)
```go
func ValidateGenesis(data GenesisState) error {
	for _, mapping := range data.MessageDependencyMapping {
		err := ValidateMessageDependencyMapping(mapping)
		if err != nil {
			return err
		}
	}
	for _, mapping := range data.WasmDependencyMappings {
		err := ValidateWasmDependencyMapping(mapping)
		if err != nil {
			return err
		}
	}
	return data.Params.Validate()
}
```
