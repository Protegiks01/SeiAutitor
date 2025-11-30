# Audit Report

## Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

## Summary
The `ValidateAccessOps` function in the access control module lacks bounds checking before accessing array elements, causing a runtime panic when an empty `AccessOps` array is provided through governance proposals. Since `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` only validates title and description fields without validating the `MessageDependencyMapping` contents, malformed proposals can pass validation and enter the voting process. When executed during `EndBlock` without panic recovery, this causes simultaneous crashes across all validator nodes, resulting in complete network shutdown. [1](#0-0) 

## Impact
Medium

## Finding Description

- **location**: Primary vulnerability in `ValidateAccessOps` function at x/accesscontrol/types/message_dependency_mapping.go:32-36; insufficient validation in `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` at x/accesscontrol/types/gov.go:42-45

- **intended logic**: The `ValidateAccessOps` function should validate that AccessOps arrays are non-empty before accessing elements. The `ValidateBasic()` method should comprehensively validate all proposal contents, including the `MessageDependencyMapping` structure, before allowing proposals to enter the governance voting process.

- **actual logic**: The function directly accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. When `len(accessOps)` equals 0, attempting to access index -1 causes an index out-of-bounds panic. The `ValidateBasic()` method only calls `govtypes.ValidateAbstract(p)`, which validates title and description but bypasses validation of `MessageDependencyMapping` contents. [2](#0-1) [3](#0-2) 

- **exploitation path**:
  1. A governance proposal containing `MessageDependencyMapping` with an empty `AccessOps` array is created (structurally valid per protobuf repeated field specification)
  2. The proposal passes `MsgSubmitProposal.ValidateBasic` which calls `content.ValidateBasic()`
  3. `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` only validates title/description, allowing the malformed proposal through
  4. The proposal proceeds through voting and receives sufficient votes to pass
  5. During `EndBlock` execution, the approved proposal handler is invoked
  6. `HandleMsgUpdateResourceDependencyMappingProposal` calls `k.SetResourceDependencyMapping`
  7. This invokes `types.ValidateMessageDependencyMapping`, which calls `ValidateAccessOps`
  8. The panic occurs when accessing the non-existent array element
  9. Since `EndBlock` has no panic recovery mechanism, the node process crashes
  10. All validator nodes execute the same `EndBlock` deterministically, causing simultaneous crashes across the entire validator set
  11. The chain halts completely with no nodes remaining operational [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

- **security guarantee broken**: Network availability and liveness. The blockchain must gracefully handle invalid inputs by returning validation errors rather than crashing all nodes through unrecovered panics that terminate consensus. [9](#0-8) 

## Impact Explanation

When the malformed governance proposal executes during `EndBlock`, all validator nodes crash simultaneously because they deterministically process the same proposal at the same block height. This results in complete network shutdown where no validator nodes remain operational to produce new blocks, no transactions can be confirmed or executed, and the network cannot reach consensus. Recovery requires coordinated manual intervention across all validators, potentially requiring emergency patches and coordinated network restart with modified state or code. The uncontrolled panic propagates through the application layer without being caught by any recovery mechanism, terminating the node process entirely.

## Likelihood Explanation

**Who can trigger**: Any participant capable of submitting governance proposals and obtaining sufficient voting support from the community.

**Conditions required**:
- Governance proposal with empty `AccessOps` is submitted (requires minimum deposit)
- Proposal receives sufficient votes to pass (requires governance participation)
- Proposal executes after voting period ends

While governance approval is required, this is fundamentally a **validation bug** rather than a governance attack scenario. Proposals created with buggy tooling, automated scripts, or human error could inadvertently contain empty arrays (valid per protobuf repeated field specification). The validation failure is subtle - validators reviewing proposal JSON may not notice the empty array. No validation occurs at submission or voting time; the crash only manifests during execution in `EndBlock`. The protobuf schema allows empty repeated fields by design, making this structurally valid input that should be handled gracefully. [10](#0-9) 

This represents a critical validation gap where well-intentioned governance participants could accidentally halt the network through programming errors in proposal creation tooling. Governance participants' intended authority includes approving parameter changes but does not extend to accidentally halting the entire network, making this an unrecoverable security failure beyond their intended authority.

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

1. Enhance `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to validate the full `MessageDependencyMapping` contents:
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

2. Fix `ValidateGenesis` in x/accesscontrol/module.go to call the comprehensive validation function instead of only `data.Params.Validate()` [11](#0-10) [12](#0-11) 

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

**Result**: The function panics with "runtime error: index out of range [-1]" instead of returning a proper validation error, demonstrating that the validation function fails to handle the empty array case gracefully.

## Notes

This vulnerability represents a critical validation gap in the access control governance proposal flow. The root cause is a programming error (missing bounds check) in the validation function combined with incomplete proposal validation that allows accidentally malformed proposals to crash the entire network. The `ValidateBasic` function exists specifically to prevent invalid proposals from entering the governance process, but its incomplete implementation fails to validate actual proposal contents. This allows proposals that are structurally valid (per protobuf schema) but semantically invalid (empty AccessOps array) to pass validation and crash the system during execution. The absence of panic recovery in the `EndBlock` execution path means this panic propagates to the node process level, causing immediate termination across all validators simultaneously, resulting in complete network shutdown.

### Citations

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

**File:** x/accesscontrol/types/gov.go (L42-45)
```go
func (p *MsgUpdateResourceDependencyMappingProposal) ValidateBasic() error {
	err := govtypes.ValidateAbstract(p)
	return err
}
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
