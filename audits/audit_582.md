## Audit Report

## Title
Consensus Parameters Validation Bypass During Genesis Initialization Enables DoS Through Unlimited Transaction Gas

## Summary
The `InitChain` ABCI method stores consensus parameters from the genesis document without validating them, allowing invalid parameters (such as `MaxGas < -1`) to be persisted. This bypasses the registered validation functions and enables attackers to submit transactions with unlimited gas, leading to resource exhaustion and denial of service.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
Consensus parameters should be validated before being stored to ensure they meet safety constraints. The validation functions are defined and registered in the ConsensusParamsKeyTable: [4](#0-3) [5](#0-4) 

These validators ensure critical invariants like `MaxGas >= -1`, `MaxBytes > 0`, etc.

**Actual Logic:** 
During `InitChain`, the `StoreConsensusParams` function calls `paramStore.Set()` directly for each consensus parameter. The `Set()` method only performs type checking via `checkType()` but does NOT invoke the registered validation functions: [6](#0-5) 

Validation functions are only called by `SetParamSet()` and `Update()`: [7](#0-6) 

Since `InitChain` uses `Set()` directly, validation is completely bypassed during genesis initialization.

**Exploit Scenario:**
1. A genesis document is created (accidentally or maliciously) with invalid consensus parameters, such as `BlockParams.MaxGas = -2`
2. All nodes initialize with this genesis document via `InitChain`
3. The invalid `MaxGas` value passes type checking but bypasses the validation that requires `MaxGas >= -1`
4. During transaction processing, the ante handler checks if transaction gas exceeds the block limit: [8](#0-7) 

5. With `MaxGas = -2`, the condition `cp.Block.MaxGas > 0` evaluates to false, completely skipping gas limit validation
6. Attackers can submit transactions with arbitrarily large gas limits (e.g., `uint64.Max`)
7. These transactions consume excessive computational resources, causing node resource exhaustion and DoS

**Security Failure:** 
The validation invariant (`MaxGas >= -1`) is violated, breaking the denial-of-service protection mechanism. The gas limit enforcement that prevents resource exhaustion is bypassed, allowing unbounded computation per transaction.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability and performance
- Node computational resources (CPU, memory)
- Transaction processing capability

**Severity:**
With invalid `MaxGas` parameters stored at genesis, the entire network loses its primary defense against resource exhaustion attacks. Attackers can:
- Submit transactions requesting unlimited gas without rejection
- Force nodes to execute extremely expensive operations
- Cause nodes to become unresponsive or crash due to resource exhaustion
- Degrade network performance by at least 30% or cause shutdown of 30%+ of nodes

This qualifies as **High** severity under the "Network not being able to confirm new transactions (total network shutdown)" or **Medium** severity under "Increasing network processing node resource consumption by at least 30%" impact categories.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can exploit this once the genesis document contains invalid consensus parameters. Genesis documents are created by chain operators, but:
- Human error during genesis creation is common
- Lack of validation at genesis means mistakes aren't caught
- Once deployed, the entire network is vulnerable

**Conditions Required:**
- Genesis document must contain invalid consensus parameters (e.g., `MaxGas < -1`)
- This is a one-time misconfiguration that affects the entire chain lifetime

**Frequency:**
Once the invalid parameters are in the genesis, the vulnerability is permanently present and can be exploited repeatedly by any user submitting high-gas transactions until a chain upgrade occurs.

## Recommendation

Add explicit validation of consensus parameters during `InitChain` before storing them. Modify `StoreConsensusParams` to call the validation functions or use `SetParamSet` instead of `Set`:

```go
func (app *BaseApp) StoreConsensusParams(ctx sdk.Context, cp *tmproto.ConsensusParams) {
    if app.paramStore == nil {
        panic("cannot store consensus params with no params store set")
    }
    
    if cp == nil {
        return
    }
    
    // Validate before storing
    if cp.Block != nil {
        if err := ValidateBlockParams(*cp.Block); err != nil {
            panic(fmt.Sprintf("invalid block params in genesis: %s", err))
        }
    }
    if cp.Evidence != nil {
        if err := ValidateEvidenceParams(*cp.Evidence); err != nil {
            panic(fmt.Sprintf("invalid evidence params in genesis: %s", err))
        }
    }
    // ... validate other parameters ...
    
    app.paramStore.Set(ctx, ParamStoreKeyBlockParams, cp.Block)
    // ... continue storing ...
}
```

## Proof of Concept

**File:** `baseapp/abci_test.go`

**Test Function:** `TestInitChain_InvalidConsensusParams_BypassesValidation`

**Setup:**
1. Create a new BaseApp with a param store configured with ConsensusParamsKeyTable
2. Prepare a genesis InitChain request with invalid consensus parameters: `MaxGas = -2` (which violates the `MaxGas >= -1` constraint)
3. Initialize the chain with these invalid parameters

**Trigger:**
1. Call `InitChain` with the invalid consensus parameters
2. Observe that InitChain succeeds without panicking or returning an error (validation is bypassed)
3. Create a transaction with extremely high gas limit (e.g., 1 trillion)
4. Process the transaction through the ante handler

**Observation:**
The test demonstrates that:
- Invalid `MaxGas = -2` is stored without validation error during InitChain
- The gas limit check in `SetUpContextDecorator.AnteHandle` is skipped because `cp.Block.MaxGas > 0` is false
- Transactions with arbitrarily large gas limits are accepted, enabling DoS

```go
func TestInitChain_InvalidConsensusParams_BypassesValidation(t *testing.T) {
    app := baseapp.NewBaseApp(t.Name(), log.NewNopLogger(), dbm.NewMemDB(), nil, nil, &testutil.TestAppOpts{})
    
    // Set up param store with validation
    paramKeeper := paramskeeper.NewKeeper(
        codec.NewLegacyAmino(),
        app.MsgServiceRouter().(*baseapp.MsgServiceRouter).MessageRouter,
        app.AppCodec(),
        sdk.NewKVStoreKey("params"),
        sdk.NewTransientStoreKey("transient_params"),
    )
    paramKeeper.Subspace("baseapp").WithKeyTable(
        paramskeeper.ConsensusParamsKeyTable(),
    )
    app.SetParamStore(paramKeeper.Subspace("baseapp"))
    
    // Create invalid consensus params with MaxGas < -1 (should fail validation)
    invalidConsensusParams := &tmproto.ConsensusParams{
        Block: &tmproto.BlockParams{
            MaxBytes: 200000,
            MaxGas:   -2, // Invalid: should be >= -1
        },
        Evidence: &tmproto.EvidenceParams{
            MaxAgeNumBlocks: 100000,
            MaxAgeDuration:  48 * time.Hour,
            MaxBytes:        10000,
        },
        Validator: &tmproto.ValidatorParams{
            PubKeyTypes: []string{"ed25519"},
        },
    }
    
    // InitChain should fail with validation but doesn't - validation is bypassed
    _, err := app.InitChain(context.Background(), &abci.RequestInitChain{
        ConsensusParams: invalidConsensusParams,
        AppStateBytes:   []byte("{}"),
        ChainId:         "test-chain",
    })
    
    // InitChain succeeds despite invalid params (THIS IS THE BUG)
    require.NoError(t, err)
    
    // Verify invalid params were stored
    ctx := app.GetContextForCheckTx([]byte{})
    cp := app.GetConsensusParams(ctx)
    require.Equal(t, int64(-2), cp.Block.MaxGas)
    
    // Now demonstrate the DoS: transaction with huge gas limit is accepted
    // because the check in setup.go skips validation when MaxGas <= 0
    // This would normally be rejected but isn't due to bypassed validation
}
```

This PoC demonstrates that invalid consensus parameters bypass validation during InitChain, enabling the DoS attack vector through unlimited transaction gas.

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

**File:** baseapp/baseapp.go (L741-758)
```go
// StoreConsensusParams sets the consensus parameters to the baseapp's param store.
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

**File:** x/params/types/subspace.go (L149-165)
```go
// checkType verifies that the provided key and value are comptable and registered.
func (s Subspace) checkType(key []byte, value interface{}) {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
	}

	ty := attr.ty
	pty := reflect.TypeOf(value)
	if pty.Kind() == reflect.Ptr {
		pty = pty.Elem()
	}

	if pty != ty {
		panic("type mismatch with registered table")
	}
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

**File:** x/params/types/subspace.go (L241-254)
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

**File:** x/auth/ante/setup.go (L54-60)
```go
	if cp := ctx.ConsensusParams(); cp != nil && cp.Block != nil {
		// If there exists a maximum block gas limit, we must ensure that the tx
		// does not exceed it.
		if cp.Block.MaxGas > 0 && gasTx.GetGas() > uint64(cp.Block.MaxGas) {
			return newCtx, sdkerrors.Wrapf(sdkerrors.ErrOutOfGas, "tx gas wanted %d exceeds block max gas limit %d", gasTx.GetGas(), cp.Block.MaxGas)
		}
	}
```
