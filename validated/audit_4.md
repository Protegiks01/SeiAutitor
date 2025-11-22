# Audit Report

## Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

## Summary
The `ValidateAccessOps` function in the access control module accesses the last element of an `AccessOps` array without bounds checking, causing a panic when the array is empty. This can be triggered through a governance proposal because `ValidateBasic` only validates abstract fields (title, description) and not the `MessageDependencyMapping` contents, allowing malformed proposals to pass validation and crash all nodes upon execution.

## Impact
High - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location**: 
- Primary vulnerability: `x/accesscontrol/types/message_dependency_mapping.go`, line 33
- Insufficient validation: `x/accesscontrol/types/gov.go`, lines 42-45
- Execution path: `x/accesscontrol/handler.go`, lines 12-20 [1](#0-0) 

**Intended logic**: The `ValidateAccessOps` function should validate that AccessOps arrays are non-empty and end with a COMMIT operation. The governance proposal's `ValidateBasic` should ensure proposals contain valid mappings before they can be voted on.

**Actual logic**: The function directly accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. When an empty array is provided, `len(accessOps)-1` evaluates to `-1`, causing an index out-of-bounds panic that crashes the node. Additionally, `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` only validates title and description through `govtypes.ValidateAbstract(p)`. [2](#0-1) [3](#0-2) 

**Exploitation path**:
1. A governance proposal with `MessageDependencyMapping` containing an empty `AccessOps` array is submitted
2. The proposal passes `ValidateBasic` validation (only checks title/description)
3. The proposal goes through voting and is approved
4. Upon execution, `HandleMsgUpdateResourceDependencyMappingProposal` is invoked [4](#0-3) 

5. The handler calls `k.SetResourceDependencyMapping` which validates the mapping [5](#0-4) 

6. This triggers `ValidateAccessOps` with the empty array, causing a panic
7. All nodes executing the proposal panic simultaneously at the same block height
8. The chain halts completely with no blocks being produced

**Security guarantee broken**: Network availability and liveness guarantee. The blockchain should gracefully handle invalid inputs by returning errors, not panicking and crashing all nodes.

## Impact Explanation

When the malformed governance proposal executes, all validator nodes crash simultaneously because they all process the same proposal at the same block height. This results in:
- **Complete network shutdown**: No new blocks can be produced
- **Transaction finality loss**: No transactions can be confirmed
- **Unrecoverable halt**: Requires manual intervention and potentially a hard fork to recover

The uncontrolled panic propagates through the consensus layer, causing all nodes to terminate unexpectedly. This is a complete denial-of-service that affects the entire network.

## Likelihood Explanation

**Who can trigger**: Any participant who can submit governance proposals (typically any token holder). The proposal must pass the voting process requiring validator/token holder approval.

**Conditions required**:
- Governance proposal with empty `AccessOps` is submitted
- Proposal receives sufficient votes to pass
- Proposal executes after voting period

**Likelihood factors**:
1. The validation failure is subtle and could be missed during proposal review
2. Proposals created with buggy tooling or human error could inadvertently contain empty arrays
3. Once executed, impact is immediate and affects all nodes simultaneously
4. No validation at submission time prevents this

While governance approval is required, this is a **validation bug** that allows invalid data to crash the network. Even well-intentioned validators approving what appears to be a legitimate proposal could trigger this accidentally. The lack of proper validation transforms an accidental programming error into a network-halting vulnerability.

## Recommendation

**Immediate fix**: Add bounds checking in `ValidateAccessOps`:

```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
    if len(accessOps) == 0 {
        return ErrNoCommitAccessOp
    }
    lastAccessOp := accessOps[len(accessOps)-1]
    // ... rest of validation
}
```

**Additional improvements**:
1. Update `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to validate the `MessageDependencyMapping` contents:

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

2. Update `module.go`'s `ValidateGenesis` to call the full validation function: [6](#0-5) 

Should call `types.ValidateGenesis(data)` instead of just `data.Params.Validate()`: [7](#0-6) 

## Proof of Concept

**Test File**: `x/accesscontrol/types/message_dependency_mapping_test.go`

**Setup**: Initialize test environment

**Action**: Call `ValidateAccessOps` with an empty slice:
```go
emptyAccessOps := []acltypes.AccessOperation{}
err := types.ValidateAccessOps(emptyAccessOps)
```

**Result**: The function panics with "index out of range [-1]" instead of returning an error. This can be verified by adding a test with `defer recover()` to catch the panic.

The vulnerability is confirmed by the code structure where no bounds check exists before array access, and the governance proposal validation path does not validate the mapping contents, allowing invalid data to reach the panic-triggering code during proposal execution.

## Notes

This is a critical validation vulnerability that breaks the availability guarantee of the blockchain. While it requires governance approval, the key issue is the **missing validation** that allows buggy or malformed data to halt the entire network. This is not about malicious governance actors but about a programming error that transforms accidental invalid inputs into catastrophic network failures.

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
