## Audit Report

## Title
Incomplete Genesis Validation in AccessControl Module Allows Chain Initialization Failure

## Summary
The `ValidateGenesis` function in the accesscontrol module only validates parameters but skips validation of `MessageDependencyMapping` and `WasmDependencyMappings` fields. This allows invalid genesis state to pass validation checks, causing the chain to panic during initialization when these invalid mappings are actually applied, resulting in total network shutdown. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Vulnerable function: `x/accesscontrol/module.go`, lines 62-68 (`ValidateGenesis`)
- Related validation code: `x/accesscontrol/types/genesis.go`, lines 29-43 (proper validation)
- Panic location: `x/accesscontrol/keeper/genesis.go`, lines 14-16 and 20-23

**Intended Logic:**
Genesis state validation should verify all fields in the GenesisState structure before chain initialization to ensure no invalid data can cause initialization failures. The module's `ValidateGenesis` function should call the comprehensive validation in `types.ValidateGenesis()` which checks MessageDependencyMapping, WasmDependencyMappings, and Params. [2](#0-1) 

**Actual Logic:**
The module's `ValidateGenesis` function only validates `data.Params.Validate()`, which returns `nil` since the Params struct is empty. It does not call `types.ValidateGenesis(data)` which would validate the dependency mappings. As a result:
1. Invalid MessageDependencyMapping entries (missing COMMIT operations, empty identifiers, etc.) pass validation
2. Invalid WasmDependencyMappings (duplicate message names, deprecated selectors, missing COMMIT) pass validation [1](#0-0) 

During `InitGenesis`, these invalid mappings are validated when calling `SetResourceDependencyMapping` and `SetWasmDependencyMapping`: [3](#0-2) [4](#0-3) 

If validation fails at this stage, the code panics: [5](#0-4) 

**Exploit Scenario:**
1. An invalid genesis file is created (intentionally or accidentally) with malformed MessageDependencyMapping or WasmDependencyMappings, such as:
   - MessageDependencyMapping without COMMIT access operation
   - WasmDependencyMapping with duplicate message names
   - Access operations with empty identifier templates
   - Deprecated CONTRACT_REFERENCE selector types
2. The genesis file passes CLI validation (`validate-genesis` command) because `ValidateGenesis` only checks params
3. Validators/nodes attempt to start the chain with this genesis file
4. During `InitChain` → `InitGenesis`, the invalid mappings are passed to `SetResourceDependencyMapping` or `SetWasmDependencyMapping`
5. These functions detect the invalid data and trigger validation errors
6. The error causes a panic in InitGenesis
7. All nodes crash simultaneously at genesis initialization
8. The chain cannot start until the genesis file is fixed

**Security Failure:**
This breaks the **availability** and **initialization safety** guarantees. The genesis validation system is meant to catch invalid configuration before chain initialization to prevent runtime failures. By allowing invalid dependency mappings to bypass validation, the system becomes vulnerable to denial-of-service at the most critical phase - chain initialization.

## Impact Explanation

**Affected Process:** Chain initialization and network availability

**Severity of Damage:**
- **Total Network Shutdown:** All validator nodes fail simultaneously during InitChain, preventing the blockchain from starting
- **No Transaction Processing:** The network cannot confirm any transactions since initialization never completes
- **Requires Manual Intervention:** Recovery requires identifying the invalid genesis data, fixing it, and redistributing the corrected genesis file to all nodes
- **Chain-Wide Impact:** Unlike runtime errors that might affect individual nodes, genesis initialization failures affect the entire network uniformly

**Why This Matters:**
This vulnerability directly maps to the "High - Network not being able to confirm new transactions (total network shutdown)" impact category. Unlike transient failures or partial node crashes, genesis initialization failures prevent the blockchain from ever becoming operational. This could occur during:
- Initial chain launch with incorrect configuration
- Chain restarts after upgrades where exported genesis state contains invalid mappings
- Network forks where genesis export/import is used

## Likelihood Explanation

**Who Can Trigger:**
- Chain operators who generate genesis files
- Governance proposals that export/modify genesis state
- Anyone with the ability to propose genesis configuration (though typically privileged, the issue is in the validation logic itself, not malicious intent)
- Accidental misconfiguration during chain setup or upgrades

**Conditions Required:**
- A genesis file containing invalid MessageDependencyMapping or WasmDependencyMappings
- The invalid data must pass the incomplete `ValidateGenesis` check (which it will, since only params are validated)
- Nodes attempting to initialize with this genesis file

**Frequency:**
- High likelihood during chain initialization events (new chain launches, major upgrades with genesis export/import)
- Can occur unintentionally due to software bugs, migration errors, or manual configuration mistakes
- Once triggered, affects all nodes uniformly

The validation functions can fail for multiple reasons as documented in the validation code: [6](#0-5) 

## Recommendation

Modify the `ValidateGenesis` function in `x/accesscontrol/module.go` to call the comprehensive validation function from the types package instead of only validating params:

```go
// ValidateGenesis performs genesis state validation for the accesscontrol module.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
    var data types.GenesisState
    if err := cdc.UnmarshalJSON(bz, &data); err != nil {
        return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
    }

    return types.ValidateGenesis(data)  // Use comprehensive validation
}
```

This aligns the module's ValidateGenesis with the pattern used in other modules like auth: [7](#0-6) 

## Proof of Concept

**File:** `x/accesscontrol/keeper/genesis_test.go`

**Test Function:** Add the following test to demonstrate that invalid genesis state passes module-level validation but causes panic during InitGenesis:

```go
func TestKeeper_InvalidGenesisPassesModuleValidation(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create invalid MessageDependencyMapping without COMMIT operation
    invalidMapping := accesscontrol.MessageDependencyMapping{
        MessageKey: "InvalidMessage",
        AccessOps: []accesscontrol.AccessOperation{
            {
                AccessType: accesscontrol.AccessType_UNKNOWN,
                ResourceType: accesscontrol.ResourceType_ANY,
                IdentifierTemplate: "*",
            },
            // Missing COMMIT operation - this is invalid
        },
    }
    
    // Create genesis state with invalid mapping
    invalidGenesis := types.GenesisState{
        Params: types.DefaultParams(),
        MessageDependencyMapping: []accesscontrol.MessageDependencyMapping{
            invalidMapping,
        },
    }
    
    // Marshal to JSON as it would be in genesis file
    bz, err := app.AppCodec().MarshalJSON(&invalidGenesis)
    require.NoError(t, err)
    
    // Module-level ValidateGenesis should catch this but doesn't
    moduleBasic := accesscontrol.AppModuleBasic{}
    err = moduleBasic.ValidateGenesis(app.AppCodec(), simapp.MakeTestEncodingConfig().TxConfig, bz)
    
    // BUG: This passes validation even though it's invalid!
    require.NoError(t, err, "Invalid genesis passed module validation - this is the vulnerability")
    
    // However, types.ValidateGenesis properly detects the error
    err = types.ValidateGenesis(invalidGenesis)
    require.Error(t, err, "types.ValidateGenesis should catch the invalid mapping")
    require.Equal(t, types.ErrNoCommitAccessOp, err)
    
    // InitGenesis will panic when trying to set this invalid mapping
    require.Panics(t, func() {
        app.AccessControlKeeper.InitGenesis(ctx, invalidGenesis)
    }, "InitGenesis panics with invalid mapping, causing chain initialization failure")
}
```

**Setup:** Uses the standard `simapp.Setup(false)` to initialize a test application with all modules.

**Trigger:** 
1. Creates an invalid `MessageDependencyMapping` without the required COMMIT operation
2. Marshals it into JSON as it would appear in a genesis file
3. Calls the module's `ValidateGenesis` function (simulating CLI validation or pre-initialization checks)
4. Calls `types.ValidateGenesis` to show the proper validation catches it
5. Calls `InitGenesis` to demonstrate the panic that causes chain initialization failure

**Observation:** 
- The module's `ValidateGenesis` incorrectly returns no error for invalid data
- The proper `types.ValidateGenesis` correctly returns `ErrNoCommitAccessOp`
- `InitGenesis` panics when attempting to set the invalid mapping via `SetResourceDependencyMapping`
- This confirms that invalid genesis state can bypass validation and cause chain initialization failure

The existing test at lines 71-101 already demonstrates the panic behavior, but this new test explicitly shows the validation bypass that enables the vulnerability: [8](#0-7)

### Citations

**File:** x/accesscontrol/module.go (L62-68)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return data.Params.Validate()
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

**File:** x/accesscontrol/keeper/keeper.go (L443-461)
```go
func (k Keeper) SetWasmDependencyMapping(
	ctx sdk.Context,
	dependencyMapping acltypes.WasmDependencyMapping,
) error {
	err := types.ValidateWasmDependencyMapping(dependencyMapping)
	if err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	b := k.cdc.MustMarshal(&dependencyMapping)

	contractAddr, err := sdk.AccAddressFromBech32(dependencyMapping.ContractAddress)
	if err != nil {
		return err
	}
	resourceKey := types.GetWasmContractAddressKey(contractAddr)
	store.Set(resourceKey, b)
	return nil
}
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

**File:** x/auth/module.go (L53-61)
```go
// ValidateGenesis performs genesis state validation for the auth module.
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return types.ValidateGenesis(data)
}
```

**File:** x/accesscontrol/keeper/genesis_test.go (L71-101)
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

```
