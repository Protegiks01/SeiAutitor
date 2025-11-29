# Audit Report

## Title
Incomplete Genesis Validation in AccessControl Module Allows Chain Initialization Failure

## Summary
The `ValidateGenesis` function in the accesscontrol module bypasses comprehensive validation of `MessageDependencyMapping` and `WasmDependencyMappings` fields, only validating an empty Params structure. This allows invalid genesis state to pass validation checks, causing chain initialization to panic when the invalid mappings are applied during `InitGenesis`, resulting in total network shutdown.

## Impact
Medium

## Finding Description

**Location:**
- Vulnerable function: [1](#0-0) 
- Proper validation function: [2](#0-1) 
- Panic locations: [3](#0-2)  and [4](#0-3) 

**Intended logic:**
Genesis state validation should comprehensively verify all fields in the GenesisState structure before chain initialization. The module's `ValidateGenesis` should call `types.ValidateGenesis()` which validates MessageDependencyMapping, WasmDependencyMappings, and Params to prevent invalid data from causing initialization failures.

**Actual logic:**
The module's `ValidateGenesis` only calls `data.Params.Validate()` which returns `nil` as confirmed in [5](#0-4) . It does not invoke `types.ValidateGenesis(data)` which would validate dependency mappings. Invalid MessageDependencyMapping entries (missing COMMIT operations, empty identifiers) and invalid WasmDependencyMappings (duplicate message names, deprecated selectors) pass validation unchecked.

**Exploitation path:**
1. Genesis file created with invalid MessageDependencyMapping or WasmDependencyMappings (accidentally during chain upgrades or genesis export/import operations)
2. File passes CLI `validate-genesis` command because module's ValidateGenesis only checks params
3. Nodes attempt chain initialization with this genesis file
4. During `InitChain` → `InitGenesis`, invalid mappings passed to setter functions [6](#0-5)  and [7](#0-6) 
5. These functions detect invalid data through validation calls
6. Validation failures trigger panics in InitGenesis
7. All nodes crash simultaneously during genesis initialization
8. Chain cannot start until genesis file manually corrected and redistributed

**Security guarantee broken:**
The genesis validation safety mechanism is defeated. The system's availability guarantee is violated as the validation system fails to prevent initialization failures from invalid configuration, despite that being its core purpose.

## Impact Explanation

**Affected process:** Chain initialization and network availability

**Consequences:**
- **Total network shutdown:** All validator nodes fail simultaneously during `InitChain`, preventing blockchain from starting
- **No transaction processing:** Network cannot confirm any transactions since initialization never completes  
- **Manual intervention required:** Recovery demands identifying invalid genesis data, correcting it, and redistributing to all nodes
- **Network-wide impact:** Unlike runtime errors affecting individual nodes, genesis failures impact entire network uniformly

This vulnerability maps to "Network not being able to confirm new transactions (total network shutdown)" - Medium severity impact. Genesis initialization failures prevent the blockchain from becoming operational during initial chain launch, chain restarts after upgrades where exported genesis contains invalid mappings, or network forks using genesis export/import.

## Likelihood Explanation

**Trigger conditions:**
- Chain operators generating genesis files during setup or upgrades
- Genesis export/import operations during network forks or migrations
- Automated genesis generation with bugs producing invalid mappings

**Realistic scenarios:**
Genesis operations are critical but infrequent events where the validation system serves as the primary safety mechanism. The bug defeats this protection during chain upgrades with genesis export/import (a common operational pattern in Cosmos chains), making accidental triggering plausible. While requiring privileged access to genesis creation, the validation system exists specifically to catch errors by these trusted operators - the bug breaks this safety net.

**Validation errors documented in:** [8](#0-7) 

## Recommendation

Modify `ValidateGenesis` in `x/accesscontrol/module.go` to call the comprehensive validation:

```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
    var data types.GenesisState
    if err := cdc.UnmarshalJSON(bz, &data); err != nil {
        return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
    }
    return types.ValidateGenesis(data)  // Call comprehensive validation
}
```

This aligns with the pattern used in other modules such as: [9](#0-8) 

## Proof of Concept

**Existing test evidence:** [10](#0-9) 

This existing test demonstrates that `InitGenesis` panics when provided invalid dependencies (empty IdentifierTemplate or invalid contract address). The vulnerability is that such invalid data would pass the module's `ValidateGenesis` check, allowing it to reach `InitGenesis` where it causes the panic.

**Setup:** Standard simapp.Setup(false) initializes test application with all modules

**Action:** 
1. Create invalid MessageDependencyMapping without required COMMIT operation or with empty IdentifierTemplate
2. Marshal to JSON as would appear in genesis file
3. Module's ValidateGenesis called (simulating CLI validation) - incorrectly passes
4. InitGenesis called - panics on validation failure

**Result:** Invalid genesis state bypasses module-level validation but causes panic during chain initialization, confirming validation bypass enables total network shutdown

**Notes:**
The severity is Medium (not High as claimed) per the provided impact categories where "Network not being able to confirm new transactions (total network shutdown)" is classified as Medium severity. The vulnerability is valid despite requiring privileged access because it represents a failure of the validation safety mechanism designed to protect against operator errors during critical chain operations.

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

**File:** x/accesscontrol/keeper/genesis.go (L14-16)
```go
		err := k.SetResourceDependencyMapping(ctx, resourceDependencyMapping)
		if err != nil {
			panic(fmt.Errorf("invalid MessageDependencyMapping %s", err))
```

**File:** x/accesscontrol/keeper/genesis.go (L20-23)
```go
		err := k.SetWasmDependencyMapping(ctx, wasmDependencyMapping)
		if err != nil {
			panic(fmt.Errorf("invalid WasmDependencyMapping %s", err))
		}
```

**File:** x/accesscontrol/types/params.go (L30-32)
```go
func (p Params) Validate() error {
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
