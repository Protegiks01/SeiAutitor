## Audit Report

### Title
Incomplete Genesis Validation in Access Control Module Allows Malformed Dependency Mappings to Bypass Validation and Cause Network Initialization Failure

### Summary
The access control module's `ValidateGenesis` method in `AppModuleBasic` only validates parameters but skips validation of `MessageDependencyMapping` and `WasmDependencyMappings` arrays. This allows malformed genesis data with invalid dependency mappings to bypass the genesis validation phase, only to cause a panic during `InitGenesis`, resulting in total network initialization failure.

### Impact
**High** - Network not being able to confirm new transactions (total network shutdown). All nodes will fail to initialize and the network cannot start.

### Finding Description

**Location:** 
The vulnerability exists in the `ValidateGenesis` method of `AppModuleBasic` in the access control module. [1](#0-0) 

**Intended Logic:** 
The genesis validation flow should validate all genesis state before chain initialization. The access control module has a comprehensive validation function that checks both parameters and dependency mappings. [2](#0-1) 

**Actual Logic:** 
The module's `ValidateGenesis` method only validates parameters (`data.Params.Validate()`) and completely skips validation of `MessageDependencyMapping` and `WasmDependencyMappings` arrays. It does not call the comprehensive `types.ValidateGenesis(data)` function that validates dependency mappings.

In contrast, other modules like the auth module correctly call their comprehensive validation function: [3](#0-2) 

**Exploit Scenario:**
1. A genesis file is created with invalid dependency mappings (e.g., missing commit operations, empty identifier templates, deprecated selectors, or duplicate message names in WASM mappings)
2. The genesis file is validated through `BasicManager.ValidateGenesis`, which calls each module's validation [4](#0-3) 
3. The invalid dependency mappings pass validation because the module only checks parameters
4. All network nodes attempt to initialize with this genesis data
5. During `InitGenesis`, the keeper validates and panics when setting invalid mappings [5](#0-4) 
6. All nodes fail to initialize, preventing network startup

**Security Failure:** 
The two-phase validation pattern (ValidateGenesis → InitGenesis) is broken. Invalid data that should be caught during file validation bypasses checks and causes runtime panics during initialization, resulting in a denial-of-service at the network level.

### Impact Explanation

**Affected Processes:**
- Network initialization and startup
- All validator and node operations
- Network availability and transaction processing

**Severity of Damage:**
- Complete network failure to initialize
- All nodes panic during genesis initialization
- Network cannot start or process any transactions
- Requires genesis file correction and complete network restart

**System Reliability:**
This breaks the fundamental assumption that genesis validation prevents initialization failures. Invalid configuration passes validation silently, only to cause catastrophic failure during actual initialization. This could affect mainnet launches, testnets, or any chain initialization scenario.

### Likelihood Explanation

**Who Can Trigger:**
- Chain operators creating genesis files
- Anyone distributing or modifying genesis configurations
- Accidental misconfiguration during genesis creation

**Conditions Required:**
- Genesis file contains invalid dependency mappings with any of these issues:
  - Missing commit access operation (validated by `ValidateAccessOps`)
  - Empty identifier templates (validated by `ValidateAccessOp`)
  - Non-leaf resource types with specific identifiers
  - Deprecated CONTRACT_REFERENCE selectors
  - Duplicate message names in WASM mappings [6](#0-5) [7](#0-6) 

**Frequency:**
- Can occur during any chain initialization with malformed genesis
- Affects all nodes attempting to start with the invalid genesis
- Testing confirms the issue is present in the current codebase [8](#0-7) 

### Recommendation

Update the `ValidateGenesis` method in `x/accesscontrol/module.go` to call the comprehensive validation function:

```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return types.ValidateGenesis(data) // Call comprehensive validation instead of just data.Params.Validate()
}
```

This aligns with the pattern used by other modules and ensures all genesis state is validated before initialization.

### Proof of Concept

**File:** `x/accesscontrol/module_test.go` (new test file)

**Test Function:** `TestValidateGenesis_InvalidDependencyMappingsBypassValidation`

**Setup:**
1. Create a genesis state with invalid MessageDependencyMapping (missing commit operation)
2. Marshal it to JSON
3. Call the module's ValidateGenesis method

**Trigger:**
```go
package accesscontrol_test

import (
	"encoding/json"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/x/accesscontrol"
	"github.com/cosmos/cosmos-sdk/x/accesscontrol/types"
	acltypes "github.com/cosmos/cosmos-sdk/types/accesscontrol"
	"github.com/stretchr/testify/require"
)

func TestValidateGenesis_InvalidDependencyMappingsBypassValidation(t *testing.T) {
	// Setup codec
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(interfaceRegistry)
	
	// Create invalid MessageDependencyMapping (missing commit operation)
	invalidMapping := acltypes.MessageDependencyMapping{
		MessageKey: "TestMessage",
		AccessOps: []acltypes.AccessOperation{
			{
				AccessType:         acltypes.AccessType_UNKNOWN,
				ResourceType:       acltypes.ResourceType_ANY,
				IdentifierTemplate: "*",
			},
			// Missing commit operation - should fail validation
		},
	}
	
	// Create genesis state with invalid mapping
	genState := types.GenesisState{
		Params:                   types.DefaultParams(),
		MessageDependencyMapping: []acltypes.MessageDependencyMapping{invalidMapping},
	}
	
	// This should fail types.ValidateGenesis
	err := types.ValidateGenesis(genState)
	require.Error(t, err, "types.ValidateGenesis should catch invalid mapping")
	require.Contains(t, err.Error(), "COMMIT", "should fail due to missing commit operation")
	
	// Marshal to JSON
	genStateJSON, err := cdc.MarshalJSON(&genState)
	require.NoError(t, err)
	
	// Call module's ValidateGenesis - THIS IS THE BUG
	moduleBasic := accesscontrol.AppModuleBasic{cdc}
	err = moduleBasic.ValidateGenesis(cdc, nil, genStateJSON)
	
	// BUG: This should fail but it doesn't because module.ValidateGenesis only checks params
	require.NoError(t, err, "BUG: Invalid dependency mapping bypasses module ValidateGenesis")
}

func TestValidateGenesis_InvalidWasmMappingBypassValidation(t *testing.T) {
	// Setup codec
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(interfaceRegistry)
	
	// Create invalid WasmDependencyMapping (empty BaseAccessOps)
	invalidWasmMapping := acltypes.WasmDependencyMapping{
		ContractAddress: "sei1invalidaddress",
		BaseAccessOps:   []*acltypes.WasmAccessOperation{}, // Empty - should fail validation
	}
	
	// Create genesis state with invalid WASM mapping
	genState := types.GenesisState{
		Params:                 types.DefaultParams(),
		WasmDependencyMappings: []acltypes.WasmDependencyMapping{invalidWasmMapping},
	}
	
	// This should fail types.ValidateGenesis
	err := types.ValidateGenesis(genState)
	require.Error(t, err, "types.ValidateGenesis should catch invalid WASM mapping")
	
	// Marshal to JSON
	genStateJSON, err := cdc.MarshalJSON(&genState)
	require.NoError(t, err)
	
	// Call module's ValidateGenesis
	moduleBasic := accesscontrol.AppModuleBasic{cdc}
	err = moduleBasic.ValidateGenesis(cdc, nil, genStateJSON)
	
	// BUG: This should fail but it doesn't
	require.NoError(t, err, "BUG: Invalid WASM mapping bypasses module ValidateGenesis")
}
```

**Observation:**
The test demonstrates that invalid dependency mappings fail `types.ValidateGenesis` (comprehensive validation) but pass through the module's `ValidateGenesis` method. This confirms that malformed genesis data bypasses the intended validation phase. Subsequently, when `InitGenesis` is called with this data, it will panic as shown in existing tests. [9](#0-8)

### Citations

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

**File:** x/auth/module.go (L54-61)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return types.ValidateGenesis(data)
}
```

**File:** types/module/module.go (L105-112)
```go
func (bm BasicManager) ValidateGenesis(cdc codec.JSONCodec, txEncCfg client.TxEncodingConfig, genesis map[string]json.RawMessage) error {
	for _, b := range bm {
		if err := b.ValidateGenesis(cdc, txEncCfg, genesis[b.Name()]); err != nil {
			return err
		}
	}

	return nil
```

**File:** x/accesscontrol/keeper/genesis.go (L11-26)
```go
func (k Keeper) InitGenesis(ctx sdk.Context, genState types.GenesisState) {
	k.SetParams(ctx, genState.Params)
	for _, resourceDependencyMapping := range genState.GetMessageDependencyMapping() {
		err := k.SetResourceDependencyMapping(ctx, resourceDependencyMapping)
		if err != nil {
			panic(fmt.Errorf("invalid MessageDependencyMapping %s", err))
		}
	}
	for _, wasmDependencyMapping := range genState.GetWasmDependencyMappings() {
		err := k.SetWasmDependencyMapping(ctx, wasmDependencyMapping)
		if err != nil {
			panic(fmt.Errorf("invalid WasmDependencyMapping %s", err))
		}

	}
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L11-19)
```go
var (
	ErrNoCommitAccessOp                  = fmt.Errorf("MessageDependencyMapping doesn't terminate with AccessType_COMMIT")
	ErrEmptyIdentifierString             = fmt.Errorf("IdentifierTemplate cannot be an empty string")
	ErrNonLeafResourceTypeWithIdentifier = fmt.Errorf("IdentifierTemplate must be '*' for non leaf resource types")
	ErrDuplicateWasmMethodName           = fmt.Errorf("a method name is defined multiple times in specific access operation list")
	ErrQueryRefNonQueryMessageType       = fmt.Errorf("query contract references can only have query message types")
	ErrSelectorDeprecated                = fmt.Errorf("this selector type is deprecated")
	ErrInvalidMsgInfo                    = fmt.Errorf("msg info cannot be nil")
)
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-54)
```go
func ValidateAccessOps(accessOps []acltypes.AccessOperation) error {
	lastAccessOp := accessOps[len(accessOps)-1]
	if lastAccessOp != *CommitAccessOp() {
		return ErrNoCommitAccessOp
	}
	for _, accessOp := range accessOps {
		err := ValidateAccessOp(accessOp)
		if err != nil {
			return err
		}
	}

	return nil
}

func ValidateAccessOp(accessOp acltypes.AccessOperation) error {
	if accessOp.IdentifierTemplate == "" {
		return ErrEmptyIdentifierString
	}
	if accessOp.ResourceType.HasChildren() && accessOp.IdentifierTemplate != "*" {
		return ErrNonLeafResourceTypeWithIdentifier
	}
	return nil
```

**File:** x/accesscontrol/keeper/genesis_test.go (L71-102)
```go
func TestKeeper_InitGenesis_InvalidDependencies(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	invalidAccessOp := types.SynchronousMessageDependencyMapping("Test1")
	invalidAccessOp.AccessOps[0].IdentifierTemplate = ""
	invalidAccessOp.AccessOps = []accesscontrol.AccessOperation{
		invalidAccessOp.AccessOps[0],
	}

	invalidMessageGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		MessageDependencyMapping: []accesscontrol.MessageDependencyMapping{
			invalidAccessOp,
		},
	}

	require.Panics(t, func() {
		app.AccessControlKeeper.InitGenesis(ctx, invalidMessageGenesis)
	})

	invalidWasmGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		WasmDependencyMappings: []accesscontrol.WasmDependencyMapping{
			types.SynchronousWasmDependencyMapping("Test"),
		},
	}
	require.Panics(t, func() {
		app.AccessControlKeeper.InitGenesis(ctx, invalidWasmGenesis)
	})

}
```
