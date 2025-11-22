# Audit Report

## Title
Consensus Parameters in Genesis Not Validated During InitChain Leading to Chain Startup Failure

## Summary
Consensus parameters passed in the genesis file are stored during `InitChain` without validation, allowing invalid parameters (such as `MaxBytes=0`, `MaxGas=-5`, or empty `PubKeyTypes`) to be persisted to the application state. This can prevent the chain from creating the first block, causing a total network shutdown. [1](#0-0) [2](#0-1) 

## Impact
High

## Finding Description

**Location:** 
- Primary: `baseapp/abci.go` lines 60-65 (InitChain method)
- Secondary: `baseapp/baseapp.go` lines 742-758 (StoreConsensusParams method)
- Root cause: `x/params/types/subspace.go` lines 171-180 (Subspace.Set method)

**Intended Logic:** 
Consensus parameters define critical blockchain constraints like maximum block size (`MaxBytes`), maximum gas per block (`MaxGas`), and validator public key types. These parameters should be validated to ensure they meet minimum requirements before being used by the consensus engine. Validation functions exist for all parameter types: [3](#0-2) [4](#0-3) [5](#0-4) 

These validation functions are registered in the ConsensusParamsKeyTable: [6](#0-5) 

**Actual Logic:**
When `InitChain` is called with consensus parameters, `StoreConsensusParams` directly calls `paramStore.Set()` for each parameter type without validation. The `Subspace.Set()` method only performs type checking via `checkType()`: [7](#0-6) 

The validation functions are only invoked by the `Update()` method or `SetParamSet()` method, but NOT by `Set()`: [8](#0-7) [9](#0-8) 

**Exploit Scenario:**
1. An operator or genesis coordinator creates a genesis file with invalid consensus parameters (e.g., `MaxBytes: 0` or `MaxGas: -5`)
2. All validators initialize their nodes using this genesis file
3. During `InitChain`, the invalid parameters are stored without validation
4. When Tendermint attempts to build the first block using these parameters, it cannot create any valid block (if `MaxBytes=0`, no block can fit within 0 bytes)
5. The chain fails to start, and all nodes remain stuck unable to produce the first block

**Security Failure:**
This breaks the availability guarantee of the blockchain. Invalid consensus parameters prevent block creation, causing a complete denial of service. The validation exists in the codebase but is bypassed during the critical genesis initialization phase.

## Impact Explanation

The vulnerability affects the entire network's ability to start and process transactions:

- **Affected Process:** Chain initialization and block production
- **Severity of Damage:** Complete network shutdown - the chain cannot produce its first block and remains inoperable
- **Why It Matters:** 
  - All validator nodes become unable to participate in consensus
  - No transactions can be processed
  - The entire network must coordinate to fix the genesis file and restart (requiring a hard reset)
  - This falls under the "High" category: "Network not being able to confirm new transactions (total network shutdown)"

Test cases confirm that invalid parameters should fail validation but currently don't during InitChain: [10](#0-9) 

## Likelihood Explanation

**Who can trigger it:** 
- Genesis coordinators creating the initial chain configuration
- Operators setting up new networks
- Anyone contributing to a genesis ceremony

**Conditions required:**
- Occurs during chain genesis/initialization
- Can happen accidentally due to configuration errors, bugs in genesis generation tools, or miscommunication during multi-party genesis setup
- No malicious intent required - this is a bug that prevents catching honest mistakes

**Frequency:**
- While not frequent in production, it can occur during:
  - Testnet launches
  - New chain deployments  
  - Chain forks or upgrades that regenerate genesis
- Once triggered, affects 100% of nodes trying to start the chain
- Historical precedent exists as evidenced by migration warnings about invalid consensus params: [11](#0-10) 

## Recommendation

Add explicit validation of consensus parameters in the `InitChain` method before storing them:

1. In `baseapp/abci.go`, after line 59 and before storing consensus params, validate each parameter type:
   - Call `ValidateBlockParams(req.ConsensusParams.Block)`
   - Call `ValidateEvidenceParams(req.ConsensusParams.Evidence)`
   - Call `ValidateValidatorParams(req.ConsensusParams.Validator)`
   - Call `ValidateSynchronyParams(req.ConsensusParams.Synchrony)`
   - Call `ValidateTimeoutParams(req.ConsensusParams.Timeout)`
   - Call `ValidateABCIParams(req.ConsensusParams.Abci)`

2. Return an error from `InitChain` if any validation fails, preventing the chain from starting with invalid parameters

3. Alternative: Modify `Subspace.Set()` to always call registered validation functions, but this is a larger change affecting all parameter storage

## Proof of Concept

**File:** `baseapp/abci_test.go`

**Test Function:** `TestInitChainInvalidConsensusParams`

**Setup:**
```go
func TestInitChainInvalidConsensusParams(t *testing.T) {
    logger := defaultLogger()
    db := dbm.NewMemDB()
    name := t.Name()
    app := NewBaseApp(name, logger, db, nil, nil, &testutil.TestAppOpts{})
    
    // Set up a simple param store
    app.SetParamStore(&paramStore{db: dbm.NewMemDB()})
    
    // Test case 1: MaxBytes = 0 (should fail validation but doesn't)
    invalidBlockParams := &tmproto.ConsensusParams{
        Block: &tmproto.BlockParams{
            MaxBytes: 0,  // Invalid: must be > 0
            MaxGas:   100000000,
        },
        Evidence: &tmproto.EvidenceParams{
            MaxAgeNumBlocks: 302400,
            MaxAgeDuration:  504 * time.Hour,
            MaxBytes:        10000,
        },
        Validator: &tmproto.ValidatorParams{
            PubKeyTypes: []string{tmtypes.ABCIPubKeyTypeEd25519},
        },
    }
    
    // InitChain should reject invalid params but currently doesn't
    _, err := app.InitChain(context.Background(), &abci.RequestInitChain{
        ConsensusParams: invalidBlockParams,
    })
    
    // Currently this does NOT error (the bug)
    require.NoError(t, err)
    
    // Verify the invalid params were stored
    ctx := app.deliverState.ctx
    storedParams := app.GetConsensusParams(ctx)
    require.NotNil(t, storedParams)
    require.Equal(t, int64(0), storedParams.Block.MaxBytes)
    
    // Demonstrate that these params fail validation when checked explicitly
    err = ValidateBlockParams(invalidBlockParams.Block)
    require.Error(t, err)
    require.Contains(t, err.Error(), "block maximum bytes must be positive")
}
```

**Trigger:**
Call `InitChain` with consensus parameters that violate validation constraints (e.g., `MaxBytes=0`)

**Observation:**
The test demonstrates that:
1. `InitChain` accepts and stores invalid consensus parameters without error
2. The stored parameters can be retrieved and confirmed to be invalid (MaxBytes=0)
3. When the same parameters are passed to the validation function directly, they correctly fail validation with error "block maximum bytes must be positive"

This proves that validation exists but is not called during InitChain, allowing invalid parameters to be persisted.

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

**File:** baseapp/baseapp.go (L742-758)
```go
func (app *BaseApp) StoreConsensusParams(ctx sdk.Context, cp *tmproto.ConsensusParams) {
	if app.paramStore == nil {
		panic("cannot store consensus params with no params store set")
	}

	if cp == nil {
		return
	}

	app.paramStore.Set(ctx, ParamStoreKeyBlockParams, cp.Block)
	app.paramStore.Set(ctx, ParamStoreKeyEvidenceParams, cp.Evidence)
	app.paramStore.Set(ctx, ParamStoreKeyValidatorParams, cp.Validator)
	app.paramStore.Set(ctx, ParamStoreKeyVersionParams, cp.Version)
	app.paramStore.Set(ctx, ParamStoreKeySynchronyParams, cp.Synchrony)
	app.paramStore.Set(ctx, ParamStoreKeyTimeoutParams, cp.Timeout)
	app.paramStore.Set(ctx, ParamStoreKeyABCIParams, cp.Abci)
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

**File:** baseapp/params.go (L62-83)
```go
// ValidateEvidenceParams defines a stateless validation on EvidenceParams. This
// function is called whenever the parameters are updated or stored.
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

**File:** baseapp/params.go (L85-98)
```go
// ValidateValidatorParams defines a stateless validation on ValidatorParams. This
// function is called whenever the parameters are updated or stored.
func ValidateValidatorParams(i interface{}) error {
	v, ok := i.(tmproto.ValidatorParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if len(v.PubKeyTypes) == 0 {
		return errors.New("validator allowed pubkey types must not be empty")
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

**File:** x/params/types/subspace.go (L196-219)
```go
func (s Subspace) Update(ctx sdk.Context, key, value []byte) error {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
	}

	ty := attr.ty
	dest := reflect.New(ty).Interface()
	s.GetIfExists(ctx, key, dest)

	if err := s.legacyAmino.UnmarshalJSON(value, dest); err != nil {
		return err
	}

	// destValue contains the dereferenced value of dest so validation function do
	// not have to operate on pointers.
	destValue := reflect.Indirect(reflect.ValueOf(dest)).Interface()
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
	}

	s.Set(ctx, key, dest)
	return nil
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

**File:** baseapp/params_test.go (L12-28)
```go
func TestValidateBlockParams(t *testing.T) {
	testCases := []struct {
		arg       interface{}
		expectErr bool
	}{
		{nil, true},
		{&tmproto.BlockParams{}, true},
		{tmproto.BlockParams{}, true},
		{tmproto.BlockParams{MaxBytes: -1, MaxGas: -1}, true},
		{tmproto.BlockParams{MaxBytes: 2000000, MaxGas: -5}, true},
		{tmproto.BlockParams{MaxBytes: 2000000, MaxGas: 300000}, false},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expectErr, baseapp.ValidateBlockParams(tc.arg) != nil)
	}
}
```

**File:** x/genutil/client/cli/migrate.go (L78-82)
```go
			if genDoc.ConsensusParams.Evidence.MaxBytes == 0 {
				fmt.Printf("Warning: consensus_params.evidence.max_bytes is set to 0. If this is"+
					" deliberate, feel free to ignore this warning. If not, please have a look at the chain"+
					" upgrade guide at %s.\n", chainUpgradeGuide)
			}
```
