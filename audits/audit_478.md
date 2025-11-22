# Audit Report

## Title
Consensus Parameters Bypass Validation at Genesis Leading to Permanent Chain Halt

## Summary
The `InitChain` ABCI method stores consensus parameters without validation, allowing invalid parameters (e.g., `MaxBytes = 0`, `MaxGas < -1`, `MaxAgeNumBlocks ≤ 0`) to be set at genesis. This bypasses the validation functions registered in the parameter store, enabling configurations that cause immediate and permanent chain halt requiring a hard fork to fix. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown) and permanent freezing requiring hard fork.

## Finding Description

**Location:** 
- `baseapp/abci.go` - `InitChain` method at lines 60-65
- `baseapp/baseapp.go` - `StoreConsensusParams` method at lines 741-758
- `x/params/types/subspace.go` - `Set` method at lines 171-180

**Intended Logic:** 
Consensus parameters should be validated before being stored to ensure they meet critical invariants. Validation functions are defined for each parameter type:
- `ValidateBlockParams` requires `MaxBytes > 0` and `MaxGas >= -1` [2](#0-1) 
- `ValidateEvidenceParams` requires `MaxAgeNumBlocks > 0` and `MaxAgeDuration > 0` [3](#0-2) 

These validators are registered in the `ConsensusParamsKeyTable`: [4](#0-3) 

**Actual Logic:** 
During `InitChain`, consensus parameters from the genesis request are stored using `StoreConsensusParams`, which calls `paramStore.Set()` directly for each parameter. The `Set()` method only performs type checking but does NOT invoke the registered validation functions. [5](#0-4) 

Only `SetParamSet()` and `Update()` methods call validation functions: [6](#0-5) 

**Exploit Scenario:**
1. A genesis file is created (either through misconfiguration or malicious intent) with `ConsensusParams.Block.MaxBytes = 0` or negative value
2. During chain initialization, `InitChain` receives this invalid parameter
3. `StoreConsensusParams` stores the parameter using `Set()`, bypassing `ValidateBlockParams`
4. The invalid `MaxBytes = 0` is persisted in the parameter store
5. When the first block after genesis is proposed, Tendermint's block validation layer attempts to validate against `MaxBytes = 0`
6. Block proposal/validation fails because zero-byte blocks are invalid
7. Chain cannot produce or accept any blocks, resulting in permanent halt
8. Requires hard fork to modify stored consensus parameters

**Security Failure:** 
The validation invariant for consensus parameters is violated. The system fails to prevent invalid configurations during the critical genesis initialization phase, leading to denial-of-service through chain halt.

## Impact Explanation
- **Affected Assets/Processes:** The entire blockchain network's ability to produce and validate blocks
- **Severity:** With `MaxBytes = 0`, no valid blocks can be proposed or accepted. The chain is permanently halted from genesis. All network participants are unable to transact. 
- **Critical Impact:** This requires a hard fork to fix - the chain must be restarted with corrected genesis parameters. All existing state must be migrated. This is a **High** severity issue as defined in scope: "Network not being able to confirm new transactions (total network shutdown)" and "Critical Permanent freezing requiring hard fork."

Similar issues exist for:
- `MaxGas < -1`: Violates validation but bypassed at genesis
- `MaxAgeNumBlocks ≤ 0`: Causes incorrect block retention logic potentially corrupting state: [7](#0-6) 

## Likelihood Explanation
**Moderate Likelihood:**
- **Trigger:** Requires control over genesis file creation, which is a privileged operation typically performed by chain operators
- **Accidental Trigger:** High risk of accidental misconfiguration during genesis setup, as no validation alerts operators to invalid parameters
- **Malicious Trigger:** Compromised or malicious genesis creator could intentionally set invalid parameters
- **Frequency:** Once at chain launch, but consequences are permanent and catastrophic

The code vulnerability is that validation exists but isn't called. This violates defense-in-depth principles - even privileged operations should validate inputs to prevent catastrophic failures from human error or compromise.

## Recommendation
Modify `StoreConsensusParams` to validate parameters before storing them:

```go
func (app *BaseApp) StoreConsensusParams(ctx sdk.Context, cp *tmproto.ConsensusParams) {
    if app.paramStore == nil {
        panic("cannot store consensus params with no params store set")
    }
    if cp == nil {
        return
    }
    
    // Validate all parameters before storing
    if cp.Block != nil {
        if err := ValidateBlockParams(*cp.Block); err != nil {
            panic(fmt.Sprintf("invalid block params: %s", err))
        }
    }
    if cp.Evidence != nil {
        if err := ValidateEvidenceParams(*cp.Evidence); err != nil {
            panic(fmt.Sprintf("invalid evidence params: %s", err))
        }
    }
    if cp.Validator != nil {
        if err := ValidateValidatorParams(*cp.Validator); err != nil {
            panic(fmt.Sprintf("invalid validator params: %s", err))
        }
    }
    // ... validate other param types
    
    // Store after validation
    app.paramStore.Set(ctx, ParamStoreKeyBlockParams, cp.Block)
    app.paramStore.Set(ctx, ParamStoreKeyEvidenceParams, cp.Evidence)
    // ... rest of storage
}
```

Alternatively, use `SetParamSet()` which automatically calls validation functions, or add explicit validation in `InitChain` before calling `StoreConsensusParams`.

## Proof of Concept

**File:** `baseapp/abci_test.go` (new test)

**Test Function:** `TestInitChainInvalidConsensusParamsNotValidated`

**Setup:**
1. Create a new BaseApp with parameter store configured
2. Set up the ConsensusParamsKeyTable with validation functions
3. Create a genesis request with invalid consensus parameters (`MaxBytes = 0`)

**Trigger:**
1. Call `InitChain` with the invalid consensus parameters
2. The invalid parameters are stored without validation errors

**Observation:**
```go
func TestInitChainInvalidConsensusParamsNotValidated(t *testing.T) {
    db := dbm.NewMemDB()
    name := t.Name()
    app := NewBaseApp(name, defaultLogger(), db, nil, nil, &testutil.TestAppOpts{})
    
    capKey := sdk.NewKVStoreKey("params")
    app.MountStores(capKey)
    
    // Set up param store with validation
    paramsKeeper := paramskeeper.NewKeeper(
        codec.NewProtoCodec(codectypes.NewInterfaceRegistry()),
        codec.NewLegacyAmino(),
        capKey,
        sdk.NewKVStoreKey("tparams"),
    )
    app.SetParamStore(paramsKeeper.Subspace(Paramspace).WithKeyTable(paramskeeper.ConsensusParamsKeyTable()))
    
    require.NoError(t, app.LoadLatestVersion())
    
    // Create invalid consensus params - MaxBytes = 0 should fail validation
    invalidParams := &tmproto.ConsensusParams{
        Block: &tmproto.BlockParams{
            MaxBytes: 0,  // Invalid: must be > 0
            MaxGas:   -1,
        },
    }
    
    // Manually test that validation would reject this
    err := ValidateBlockParams(*invalidParams.Block)
    require.Error(t, err, "MaxBytes=0 should fail ValidateBlockParams")
    
    // But InitChain accepts it without error!
    req := &abci.RequestInitChain{
        ConsensusParams: invalidParams,
        AppStateBytes:   []byte("{}"),
        ChainId:         "test-chain",
    }
    
    // This should panic or error but doesn't - vulnerability
    res, err := app.InitChain(context.Background(), req)
    require.NoError(t, err)
    require.NotNil(t, res)
    
    // Verify the invalid params were actually stored
    ctx := app.deliverState.ctx
    storedParams := app.GetConsensusParams(ctx)
    require.Equal(t, int64(0), storedParams.Block.MaxBytes, "Invalid MaxBytes=0 was stored")
    
    // This demonstrates the validation bypass
    t.Logf("VULNERABILITY: Invalid MaxBytes=0 was stored without validation")
}
```

The test demonstrates that:
1. `ValidateBlockParams` correctly rejects `MaxBytes = 0`
2. However, `InitChain` stores these invalid parameters without calling validation
3. The invalid configuration persists in the parameter store
4. In production, this would cause immediate chain halt when block production begins

### Citations

**File:** baseapp/abci.go (L60-65)
```go
	if req.ConsensusParams != nil {
		app.StoreConsensusParams(app.deliverState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.prepareProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.processProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.checkState.ctx, req.ConsensusParams)
	}
```

**File:** baseapp/abci.go (L814-817)
```go
	cp := app.GetConsensusParams(app.deliverState.ctx)
	if cp != nil && cp.Evidence != nil && cp.Evidence.MaxAgeNumBlocks > 0 {
		retentionHeight = commitHeight - cp.Evidence.MaxAgeNumBlocks
	}
```

**File:** baseapp/params.go (L37-60)
```go
func ValidateBlockParams(i interface{}) error {
	v, ok := i.(tmproto.BlockParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.MaxBytes <= 0 {
		return fmt.Errorf("block maximum bytes must be positive: %d", v.MaxBytes)
	}

	if v.MaxGas < -1 {
		return fmt.Errorf("block maximum gas must be greater than or equal to -1: %d", v.MaxGas)
	}

	if v.MinTxsInBlock < 0 {
		return fmt.Errorf("block min txs in block must be non-negative: %d", v.MinTxsInBlock)
	}

	if v.MaxGasWanted < -1 {
		return fmt.Errorf("block maximum gas wanted must be greater than or equal to -1: %d", v.MaxGasWanted)
	}

	return nil
}
```

**File:** baseapp/params.go (L64-83)
```go
func ValidateEvidenceParams(i interface{}) error {
	v, ok := i.(tmproto.EvidenceParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.MaxAgeNumBlocks <= 0 {
		return fmt.Errorf("evidence maximum age in blocks must be positive: %d", v.MaxAgeNumBlocks)
	}

	if v.MaxAgeDuration <= 0 {
		return fmt.Errorf("evidence maximum age time duration must be positive: %v", v.MaxAgeDuration)
	}

	if v.MaxBytes < 0 {
		return fmt.Errorf("maximum evidence bytes must be non-negative: %v", v.MaxBytes)
	}

	return nil
}
```

**File:** x/params/keeper/consensus_params.go (L15-39)
```go
func ConsensusParamsKeyTable() types.KeyTable {
	return types.NewKeyTable(
		types.NewParamSetPair(
			baseapp.ParamStoreKeyBlockParams, tmproto.BlockParams{}, baseapp.ValidateBlockParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeyEvidenceParams, tmproto.EvidenceParams{}, baseapp.ValidateEvidenceParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeyValidatorParams, tmproto.ValidatorParams{}, baseapp.ValidateValidatorParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeyVersionParams, tmproto.VersionParams{}, baseapp.ValidateVersionParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeySynchronyParams, tmproto.SynchronyParams{}, baseapp.ValidateSynchronyParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeyTimeoutParams, tmproto.TimeoutParams{}, baseapp.ValidateTimeoutParams,
		),
		types.NewParamSetPair(
			baseapp.ParamStoreKeyABCIParams, tmproto.ABCIParams{}, baseapp.ValidateABCIParams,
		),
	)
}
```

**File:** x/params/types/subspace.go (L171-180)
```go
func (s Subspace) Set(ctx sdk.Context, key []byte, value interface{}) {
	s.checkType(key, value)

	bz, err := s.legacyAmino.MarshalJSON(value)
	if err != nil {
		panic(err)
	}

	s.SetRaw(ctx, key, bz)
}
```

**File:** x/params/types/subspace.go (L241-255)
```go
func (s Subspace) SetParamSet(ctx sdk.Context, ps ParamSet) {
	for _, pair := range ps.ParamSetPairs() {
		// pair.Field is a pointer to the field, so indirecting the ptr.
		// go-amino automatically handles it but just for sure,
		// since SetStruct is meant to be used in InitGenesis
		// so this method will not be called frequently
		v := reflect.Indirect(reflect.ValueOf(pair.Value)).Interface()

		if err := pair.ValidatorFn(v); err != nil {
			panic(fmt.Sprintf("value from ParamSetPair is invalid: %s", err))
		}

		s.Set(ctx, pair.Key, v)
	}
}
```
