## Audit Report

### Title
Unvalidated Empty AccessOps Array Causes Chain Halt via Governance Proposals

### Summary
The `ValidateAccessOps` function in the access control module attempts to access the last element of an `AccessOps` array without first checking if the array is empty, causing an index out-of-bounds panic. [1](#0-0) 

This vulnerability can be triggered through a governance proposal (`MsgUpdateResourceDependencyMappingProposal`) because the proposal's `ValidateBasic` method only validates abstract proposal fields and does not validate the `MessageDependencyMapping` contents. [2](#0-1) 

When such a proposal is executed, the chain panics and halts, causing a network-wide denial of service.

### Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

### Finding Description

**Location:** 
- Primary vulnerability: `x/accesscontrol/types/message_dependency_mapping.go`, line 33 in `ValidateAccessOps` function
- Exploitable attack path: `x/accesscontrol/types/gov.go`, lines 42-45 in `ValidateBasic` method
- Execution handler: `x/accesscontrol/handler.go`, lines 12-20 in `HandleMsgUpdateResourceDependencyMappingProposal`

**Intended Logic:**
The `ValidateAccessOps` function should validate that all `MessageDependencyMapping` entries end with a COMMIT operation and contain valid access operations. The governance proposal's `ValidateBasic` should ensure that proposals contain valid mappings before they can be voted on and executed.

**Actual Logic:**
The `ValidateAccessOps` function directly accesses `accessOps[len(accessOps)-1]` without checking if the slice is empty. [3](#0-2) 

When an empty `AccessOps` array is provided, `len(accessOps)-1` evaluates to `-1`, causing an index out-of-bounds panic. This panic is not caught and propagates to crash the node.

The `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` only calls `govtypes.ValidateAbstract(p)`, which validates title and description but does not validate the `MessageDependencyMapping` array contents. [2](#0-1) 

**Exploit Scenario:**
1. An attacker (or inadvertently, an operator) submits a governance proposal containing a `MessageDependencyMapping` with an empty `AccessOps` array
2. The proposal passes `ValidateBasic` validation since it only checks abstract fields
3. The proposal goes through the governance voting process and is approved
4. Upon execution, `HandleMsgUpdateResourceDependencyMappingProposal` is invoked [4](#0-3) 
5. The handler calls `k.SetResourceDependencyMapping` which validates the mapping [5](#0-4) 
6. This triggers `ValidateAccessOps` with the empty array
7. The function panics with index out-of-bounds
8. All nodes executing the proposal panic simultaneously
9. The chain halts completely

**Security Failure:**
This breaks the availability guarantee of the blockchain. The uncontrolled panic causes all nodes to crash when processing the governance proposal, resulting in a complete network shutdown.

### Impact Explanation

**Affected Assets/Processes:**
- Network availability: All nodes crash and cannot process transactions
- Transaction finality: No new blocks can be produced
- Network liveness: The chain halts until manual intervention

**Severity:**
The entire network stops functioning when the malformed governance proposal is executed. All validators crash simultaneously, preventing block production and transaction processing. This is a complete denial-of-service attack on the network.

**Significance:**
While governance proposals require approval from validators, the lack of proper validation in `ValidateBasic` means that well-intentioned operators may unknowingly approve a buggy or malformed proposal. The uncontrolled panic makes this a critical availability issue, as it immediately halts the entire network without any graceful degradation or recovery mechanism.

### Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit a governance proposal (typically any token holder). However, the proposal must pass the governance voting process, which requires approval from validators/token holders.

**Conditions Required:**
- A governance proposal with empty `AccessOps` must be submitted
- The proposal must receive sufficient votes to pass
- The proposal must be executed (automatic after the voting period ends)

**Frequency:**
While this requires governance approval, the risk is significant because:
1. The validation failure is subtle and could be missed during review
2. Proposals with programming errors or malformed data structures could be inadvertently approved
3. Once executed, the impact is immediate and affects all nodes simultaneously
4. There is no defense mechanism or validation to prevent this at proposal submission time

The vulnerability could be triggered accidentally by operators using buggy tooling or through social engineering if an attacker convinces validators to approve a malformed proposal.

### Recommendation

**Immediate Fix:**
Add bounds checking in `ValidateAccessOps` before accessing the last element:

```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
    if len(accessOps) == 0 {
        return ErrNoCommitAccessOp
    }
    lastAccessOp := accessOps[len(accessOps)-1]
    // ... rest of validation
}
```

**Additional Improvements:**
1. Update `MsgUpdateResourceDependencyMappingProposal.ValidateBasic()` to call the full `ValidateGenesis` function that validates all mappings [6](#0-5) 

2. Similarly, update the accesscontrol module's `ValidateGenesis` to call the complete validation function instead of only validating params [7](#0-6) 

### Proof of Concept

**Test File:** `x/accesscontrol/types/message_dependency_mapping_test.go`

**Test Function:**
```go
func TestValidateAccessOpsEmptySlice(t *testing.T) {
    // This test demonstrates the panic when ValidateAccessOps receives an empty slice
    defer func() {
        if r := recover(); r != nil {
            // Expected panic: index out of range
            require.Contains(t, fmt.Sprintf("%v", r), "index out of range")
        } else {
            t.Fatal("Expected panic but none occurred")
        }
    }()
    
    // Create empty AccessOps slice
    emptyAccessOps := []acltypes.AccessOperation{}
    
    // This should panic with index out of range instead of returning an error
    _ = types.ValidateAccessOps(emptyAccessOps)
}
```

**Alternative Integration Test File:** `x/accesscontrol/keeper/genesis_test.go`

**Test Function:**
```go
func TestInitGenesisWithEmptyAccessOps(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create a MessageDependencyMapping with empty AccessOps
    invalidMapping := acltypes.MessageDependencyMapping{
        MessageKey:     "test.message.type",
        AccessOps:      []acltypes.AccessOperation{}, // Empty slice
        DynamicEnabled: false,
    }
    
    genState := types.GenesisState{
        Params:                   types.DefaultParams(),
        MessageDependencyMapping: []acltypes.MessageDependencyMapping{invalidMapping},
        WasmDependencyMappings:   []acltypes.WasmDependencyMapping{},
    }
    
    // This should panic with index out of range when InitGenesis is called
    defer func() {
        if r := recover(); r != nil {
            require.Contains(t, fmt.Sprintf("%v", r), "index out of range")
        } else {
            t.Fatal("Expected panic during InitGenesis but none occurred")
        }
    }()
    
    app.AccessControlKeeper.InitGenesis(ctx, genState)
}
```

**Setup:** Initialize a test blockchain context and keeper.

**Trigger:** Call `InitGenesis` or execute a governance proposal with a `MessageDependencyMapping` containing an empty `AccessOps` array.

**Observation:** The test should catch a panic with "index out of range" error, confirming that the validation function crashes instead of returning a proper validation error. This demonstrates that the chain would halt when processing such invalid data.

### Citations

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-35)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
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
