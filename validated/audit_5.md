Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**.

# Audit Report

## Title
Incomplete Genesis Validation in Access Control Module Allows Malformed Dependency Mappings to Bypass Validation and Cause Network Initialization Failure

## Summary
The access control module's `ValidateGenesis` method only validates parameters but skips validation of dependency mappings. This allows malformed genesis data to bypass the validation phase and cause a panic during `InitGenesis`, resulting in total network initialization failure.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
Genesis validation should validate all genesis state before chain initialization. The access control module has a comprehensive validation function that checks both parameters and dependency mappings. [2](#0-1) 

**Actual Logic:** 
The module's `ValidateGenesis` method only validates parameters and does not call the comprehensive `types.ValidateGenesis(data)` function. In contrast, other modules like auth correctly implement full validation: [3](#0-2) 

**Exploitation Path:**
1. A genesis file is created with invalid dependency mappings (missing commit operations, empty identifier templates, deprecated selectors, or duplicate message names)
2. The genesis file is validated through `BasicManager.ValidateGenesis`: [4](#0-3) 
3. Invalid dependency mappings pass validation because the module only checks parameters
4. All network nodes attempt to initialize with this genesis data
5. During `InitGenesis`, the keeper validates and panics when setting invalid mappings: [5](#0-4) 
6. All nodes fail to initialize, preventing network startup

**Security Guarantee Broken:** 
The two-phase validation pattern (ValidateGenesis → InitGenesis) is broken. Invalid data that should be caught during genesis validation bypasses checks and causes runtime panics during initialization.

## Impact Explanation

This vulnerability results in complete network initialization failure. When a genesis file contains invalid dependency mappings:
- All validator and full nodes fail to initialize
- The network cannot start or process any transactions
- Requires genesis file correction and coordinated network restart
- Affects mainnet launches, testnets, or any chain initialization scenario

The broken validation allows errors such as:
- Missing commit access operations [6](#0-5) 
- Empty identifier templates or invalid resource type configurations [7](#0-6) 
- Duplicate message names in WASM mappings or deprecated selectors [8](#0-7) 

## Likelihood Explanation

**Who Can Trigger:**
- Chain operators creating genesis files
- Anyone distributing or modifying genesis configurations during network initialization

**Conditions Required:**
Genesis file contains invalid dependency mappings that fail validation checks defined in the comprehensive `ValidateGenesis` function.

**Frequency:**
Can occur during any chain initialization with malformed genesis data. While genesis files are typically carefully reviewed, the absence of proper validation creates a critical gap in the defense-in-depth strategy. The existing test suite confirms this behavior: [9](#0-8) 

## Recommendation

Update the `ValidateGenesis` method in `x/accesscontrol/module.go` to call the comprehensive validation function:

```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return types.ValidateGenesis(data)
}
```

This aligns with the pattern used by other modules and ensures all genesis state is validated before initialization.

## Proof of Concept

The provided PoC demonstrates that:
1. Invalid dependency mappings fail `types.ValidateGenesis` (comprehensive validation)
2. The same invalid mappings pass through the module's `ValidateGenesis` method
3. Subsequently, `InitGenesis` panics when attempting to set these invalid mappings

The keeper methods validate mappings before storing them: [10](#0-9) [11](#0-10) 

When validation errors occur during `InitGenesis`, the keeper panics, causing total node initialization failure as confirmed by existing tests.

## Notes

This vulnerability represents a defense-in-depth failure where genesis validation—a critical security control designed to catch configuration errors before they cause operational failures—is incomplete. While it requires genesis file creation privileges, the validation layer exists specifically to protect against inadvertent mistakes by trusted operators. The inconsistency with other modules' implementations confirms this is unintended behavior rather than a design choice.

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

**File:** x/accesscontrol/types/message_dependency_mapping.go (L32-45)
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
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L47-55)
```go
func ValidateAccessOp(accessOp acltypes.AccessOperation) error {
	if accessOp.IdentifierTemplate == "" {
		return ErrEmptyIdentifierString
	}
	if accessOp.ResourceType.HasChildren() && accessOp.IdentifierTemplate != "*" {
		return ErrNonLeafResourceTypeWithIdentifier
	}
	return nil
}
```

**File:** x/accesscontrol/types/message_dependency_mapping.go (L123-181)
```go
func ValidateWasmDependencyMapping(mapping acltypes.WasmDependencyMapping) error {
	numOps := len(mapping.BaseAccessOps)
	if numOps == 0 || mapping.BaseAccessOps[numOps-1].Operation.AccessType != acltypes.AccessType_COMMIT {
		return ErrNoCommitAccessOp
	}

	// ensure uniqueness for partitioned message names across access ops and contract references
	seenMessageNames := map[string]struct{}{}
	for _, ops := range mapping.ExecuteAccessOps {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.QueryAccessOps {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.ExecuteContractReferences {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}
	seenMessageNames = map[string]struct{}{}
	for _, ops := range mapping.QueryContractReferences {
		if _, ok := seenMessageNames[ops.MessageName]; ok {
			return ErrDuplicateWasmMethodName
		}
		seenMessageNames[ops.MessageName] = struct{}{}
	}

	// ensure deprecation for CONTRACT_REFERENCE access operation selector due to new contract references
	for _, accessOp := range mapping.BaseAccessOps {
		if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
			return ErrSelectorDeprecated
		}
	}
	for _, accessOps := range mapping.ExecuteAccessOps {
		for _, accessOp := range accessOps.WasmOperations {
			if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
				return ErrSelectorDeprecated
			}
		}
	}
	for _, accessOps := range mapping.QueryAccessOps {
		for _, accessOp := range accessOps.WasmOperations {
			if accessOp.SelectorType == acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE {
				return ErrSelectorDeprecated
			}
		}
	}

	return nil
}
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
