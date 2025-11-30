# Audit Report

## Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

## Summary
The `ValidateAccessOps` function accesses an array element without bounds checking, causing a panic when an empty `AccessOps` array is provided. This can be triggered through governance proposals due to insufficient validation in `ValidateBasic`, leading to simultaneous node crashes and complete network shutdown during proposal execution.

## Impact
High

## Finding Description

- **location**: 
  - Primary vulnerability: [1](#0-0) 
  - Insufficient validation: [2](#0-1) 
  - Execution handler: [3](#0-2) 

- **intended logic**: The `ValidateAccessOps` function should validate that AccessOps arrays are non-empty before accessing elements and verify they end with a COMMIT operation. Governance proposal validation should ensure all proposal contents are valid before allowing voting.

- **actual logic**: The function directly accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. When `len(accessOps)` is 0, the expression `len(accessOps)-1` wraps to a large unsigned value, causing an index out-of-bounds panic. The `ValidateBasic()` method only validates title and description via `govtypes.ValidateAbstract(p)` [4](#0-3) , completely bypassing validation of the `MessageDependencyMapping` contents.

- **exploitation path**:
  1. A governance proposal containing `MessageDependencyMapping` with an empty `AccessOps` array is submitted
  2. The proposal passes `ValidateBasic` validation (only checks title/description fields)
  3. The proposal proceeds through the voting period and is approved by governance
  4. During `EndBlock` execution [5](#0-4) , the approved proposal handler is invoked at line 74
  5. `HandleMsgUpdateResourceDependencyMappingProposal` calls `k.SetResourceDependencyMapping` [6](#0-5) 
  6. This invokes `types.ValidateMessageDependencyMapping` at line 95, which calls `ValidateAccessOps`
  7. The panic occurs when accessing the non-existent array element
  8. Since `EndBlock` has no panic recovery mechanism, the node crashes
  9. All validator nodes execute the same `EndBlock` at the same block height, causing simultaneous crashes across the network
  10. The chain halts completely with no blocks being produced

- **security guarantee broken**: Network availability and liveness. The blockchain should gracefully handle invalid inputs by returning validation errors, not crashing all nodes through unrecovered panics.

## Impact Explanation

When the malformed governance proposal executes during `EndBlock`, all validator nodes crash simultaneously because they deterministically process the same proposal at the same block height. This results in:

- **Complete network shutdown**: No validator nodes are running to produce new blocks
- **Transaction processing halt**: No transactions can be confirmed or executed
- **Consensus failure**: The network cannot reach consensus on new blocks
- **Recovery complexity**: Requires coordinated manual intervention across all validators, potentially requiring a coordinated restart or software patch deployment

The uncontrolled panic propagates through the application layer without being caught, terminating the node process entirely. This is a complete denial-of-service affecting the entire network.

## Likelihood Explanation

**Who can trigger**: Any participant who can submit and get governance proposals passed (requires community/validator support for voting).

**Conditions required**:
- Governance proposal with empty `AccessOps` is submitted (requires deposit)
- Proposal receives sufficient votes to pass (requires governance participation)
- Proposal executes after voting period ends

**Likelihood factors**:
1. While governance approval is required, this is fundamentally a **validation bug** not a governance attack
2. Proposals created with buggy tooling, scripts, or simple human error could inadvertently contain empty arrays
3. The validation failure is subtle - validators reviewing proposals may not notice the empty array
4. No validation at submission or voting time prevents this; the crash only occurs at execution
5. Once executed, the impact is immediate and deterministic across all nodes

This represents a critical validation gap where well-intentioned governance participants could accidentally halt the network through a programming error in proposal creation tooling or manual mistakes.

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

1. Enhance `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to validate mapping contents before governance voting:
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

2. Fix `ValidateGenesis` in module.go to use the full validation: [7](#0-6)  should call `types.ValidateGenesis(data)` [8](#0-7)  instead of only `data.Params.Validate()`.

## Proof of Concept

**Test location**: Can be added to `x/accesscontrol/types/message_dependency_mapping_test.go`

**Setup**: 
```go
import (
    "testing"
    acltypes "github.com/cosmos/cosmos-sdk/types/accesscontrol"
    "github.com/cosmos/cosmos-sdk/x/accesscontrol/types"
)
```

**Action**: Call `ValidateAccessOps` with empty slice:
```go
func TestValidateAccessOps_EmptyArray_ShouldPanic(t *testing.T) {
    emptyAccessOps := []acltypes.AccessOperation{}
    
    // This will panic with "runtime error: index out of range [-1]"
    defer func() {
        if r := recover(); r == nil {
            t.Errorf("Expected panic but got none")
        }
    }()
    
    types.ValidateAccessOps(emptyAccessOps)
}
```

**Result**: The function panics with "runtime error: index out of range" instead of returning a proper error. The panic occurs because accessing `accessOps[len(accessOps)-1]` when the slice is empty attempts to access an invalid memory location.

**Complete execution path verification**: A governance proposal test demonstrating the full exploit path would iterate through proposal submission, voting, and execution in EndBlock, confirming the node crash occurs during execution phase.

## Notes

This vulnerability represents a critical validation gap in the access control governance proposal flow. While governance approval is required, the issue stems from insufficient input validation that allows accidentally malformed proposals to crash the entire network. The lack of panic recovery in the `EndBlock` execution path ( [5](#0-4) ) means this panic propagates to the node process level, causing immediate termination. This is not about malicious governance but about a programming error that transforms routine validation mistakes into catastrophic network failures.

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

**File:** x/accesscontrol/keeper/keeper.go (L91-104)
```go
func (k Keeper) SetResourceDependencyMapping(
	ctx sdk.Context,
	dependencyMapping acltypes.MessageDependencyMapping,
) error {
	err := types.ValidateMessageDependencyMapping(dependencyMapping)
	if err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	b := k.cdc.MustMarshal(&dependencyMapping)
	resourceKey := types.GetResourceDependencyKey(types.MessageKey(dependencyMapping.GetMessageKey()))
	store.Set(resourceKey, b)
	return nil
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

**File:** x/accesscontrol/types/genesis.go (L28-43)
```go
// ValidateGenesis validates the oracle genesis state
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
