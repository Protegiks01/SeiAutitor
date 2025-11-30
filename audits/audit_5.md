# Audit Report

## Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

## Summary
The `ValidateAccessOps` function performs array access without bounds checking, causing a panic when an empty `AccessOps` array is provided. This vulnerability can be triggered through governance proposals that bypass content validation in `ValidateBasic`, leading to simultaneous crashes of all validator nodes and complete network shutdown during proposal execution in `EndBlock`.

## Impact
High

## Finding Description

- **location**: 
  - Primary vulnerability: [1](#0-0) 
  - Insufficient proposal validation: [2](#0-1) 
  - Proposal execution handler: [3](#0-2) 
  - EndBlock execution without panic recovery: [4](#0-3) 

- **intended logic**: The `ValidateAccessOps` function should validate that AccessOps arrays are non-empty before accessing elements and verify they terminate with a COMMIT operation. Governance proposal validation should comprehensively validate all proposal contents before allowing the voting process to begin.

- **actual logic**: The function directly accesses `accessOps[len(accessOps)-1]` at line 33 without checking if the slice is empty. When `len(accessOps)` equals 0, the expression `len(accessOps)-1` evaluates to -1, causing an index out-of-bounds panic. The `ValidateBasic()` method only validates title and description through `govtypes.ValidateAbstract(p)` [5](#0-4) , completely bypassing validation of the `MessageDependencyMapping` contents.

- **exploitation path**:
  1. A governance proposal containing `MessageDependencyMapping` with an empty `AccessOps` array is created (valid per protobuf schema [6](#0-5) )
  2. The proposal passes `ValidateBasic` validation which only checks title/description fields
  3. The proposal proceeds through the voting period and receives sufficient votes to pass
  4. During `EndBlock` execution [7](#0-6) , the approved proposal handler is invoked
  5. `HandleMsgUpdateResourceDependencyMappingProposal` calls `k.SetResourceDependencyMapping`
  6. This invokes `types.ValidateMessageDependencyMapping` at [8](#0-7) , which calls `ValidateAccessOps`
  7. The panic occurs when accessing the non-existent array element at index -1
  8. Since `EndBlock` has no panic recovery mechanism (confirmed by absence of defer/recover), the node process crashes
  9. All validator nodes execute the same `EndBlock` deterministically at the same block height, causing simultaneous crashes
  10. The chain halts completely with no blocks being produced

- **security guarantee broken**: Network availability and liveness. The blockchain must gracefully handle invalid inputs by returning validation errors, not crashing all nodes through unrecovered panics that terminate the consensus process.

## Impact Explanation

When the malformed governance proposal executes during `EndBlock`, all validator nodes crash simultaneously because they deterministically process the same proposal at the same block height. This results in:

- **Complete network shutdown**: No validator nodes remain operational to produce new blocks
- **Transaction processing halt**: No transactions can be confirmed or executed  
- **Consensus failure**: The network cannot reach consensus on new blocks
- **Recovery complexity**: Requires coordinated manual intervention across all validators, potentially requiring emergency patches and coordinated network restart

The uncontrolled panic propagates through the application layer without being caught by any recovery mechanism, terminating the node process entirely. This represents a complete denial-of-service affecting the entire network.

## Likelihood Explanation

**Who can trigger**: Any participant capable of submitting governance proposals and obtaining sufficient voting support from the community.

**Conditions required**:
- Governance proposal with empty `AccessOps` is submitted (requires minimum deposit)
- Proposal receives sufficient votes to pass (requires governance participation)
- Proposal executes after voting period ends

**Likelihood factors**:
1. While governance approval is required, this is fundamentally a **validation bug** not a governance attack scenario
2. Proposals created with buggy tooling, automated scripts, or human error could inadvertently contain empty arrays (valid per protobuf schema)
3. The validation failure is subtle - validators reviewing proposals may not notice the empty array in the JSON structure
4. No validation occurs at submission or voting time; the crash only manifests during execution
5. Once executed, the impact is immediate and deterministic across all nodes
6. The protobuf schema allows empty repeated fields, making this a valid input structure

This represents a critical validation gap where well-intentioned governance participants could accidentally halt the network through programming errors in proposal creation tooling or manual mistakes during proposal preparation.

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

1. Enhance `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to validate mapping contents before governance voting begins
2. Fix `ValidateGenesis` in module.go [9](#0-8)  to call the comprehensive `types.ValidateGenesis(data)` [10](#0-9)  instead of only `data.Params.Validate()`
3. Consider adding panic recovery in EndBlock execution as a defense-in-depth measure

## Proof of Concept

**Test location**: `x/accesscontrol/types/message_dependency_mapping_test.go`

**Setup**: Import required packages and define test function

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

**Result**: The function panics with "runtime error: index out of range [-1]" instead of returning a proper validation error. The panic occurs because Go interprets `accessOps[len(accessOps)-1]` as `accessOps[-1]` when the slice length is 0, resulting in an invalid memory access that terminates the process.

## Notes

This vulnerability represents a critical validation gap in the access control governance proposal flow. While governance approval is required, the issue stems from insufficient input validation that allows accidentally malformed proposals to crash the entire network. 

The key distinction is that this is not about malicious governance actors - it's about a programming error (missing bounds check) that transforms routine validation mistakes into catastrophic network failures. Governance participants' intended authority includes approving or rejecting proposals, but does not extend to accidentally halting the entire network through tooling errors. The absence of panic recovery in the `EndBlock` execution path [11](#0-10)  means this panic propagates to the node process level, causing immediate termination across all validators simultaneously.

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

**File:** x/gov/types/content.go (L37-54)
```go
func ValidateAbstract(c Content) error {
	title := c.GetTitle()
	if len(strings.TrimSpace(title)) == 0 {
		return sdkerrors.Wrap(ErrInvalidProposalContent, "proposal title cannot be blank")
	}
	if len(title) > MaxTitleLength {
		return sdkerrors.Wrapf(ErrInvalidProposalContent, "proposal title is longer than max length of %d", MaxTitleLength)
	}

	description := c.GetDescription()
	if len(description) == 0 {
		return sdkerrors.Wrap(ErrInvalidProposalContent, "proposal description cannot be blank")
	}
	if len(description) > MaxDescriptionLength {
		return sdkerrors.Wrapf(ErrInvalidProposalContent, "proposal description is longer than max length of %d", MaxDescriptionLength)
	}

	return nil
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
