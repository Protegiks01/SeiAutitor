# Audit Report

## Title
Genesis Consensus Parameters Bypass Validation During InitChain Leading to Potential Chain Halt

## Summary
During genesis initialization, consensus parameters are stored without validation by the sei-cosmos validation functions. The `InitChain` ABCI method stores consensus parameters using `paramStore.Set()`, which bypasses the registered validation functions in `ConsensusParamsKeyTable()`. This allows invalid parameters (such as MaxBytes ≤ 0 or MaxGas < -1) to be stored in the genesis state, potentially causing a complete chain halt. [1](#0-0) [2](#0-1) 

## Impact
**High** - This vulnerability can cause a total network shutdown where no transactions can be confirmed.

## Finding Description

**Location:** 
- Primary issue: `baseapp/baseapp.go` in the `StoreConsensusParams` function
- Validation bypass: `x/params/types/subspace.go` in the `Set` method
- Genesis initialization: `baseapp/abci.go` in the `InitChain` method

**Intended Logic:** 
Consensus parameters should be validated for reasonable values before being stored. The codebase defines validation functions like `ValidateBlockParams` that check:
- MaxBytes must be > 0
- MaxGas must be >= -1
- MinTxsInBlock must be >= 0
- MaxGasWanted must be >= -1 [3](#0-2) 

These validators are registered in the `ConsensusParamsKeyTable()` to be called when parameters are stored or updated. [4](#0-3) 

**Actual Logic:** 
During `InitChain`, the `StoreConsensusParams` method directly calls `paramStore.Set()` for each consensus parameter. However, the `Subspace.Set()` implementation only performs type checking via `checkType()` and does NOT invoke the validation functions registered in the KeyTable. [5](#0-4) 

The validation functions are only called by `Subspace.SetParamSet()` and `Subspace.Update()`, neither of which are used during genesis initialization. [6](#0-5) 

**Exploit Scenario:**
1. An operator creates a genesis file with invalid consensus parameters (e.g., `MaxBytes: 0` or `MaxGas: -2`)
2. The genesis file passes through Tendermint's `ValidateAndComplete()` (external validation that may not enforce sei-cosmos specific rules)
3. During chain initialization, `InitChain` is called with these parameters
4. `StoreConsensusParams` stores the invalid parameters without triggering sei-cosmos validation
5. The chain starts with broken consensus parameters
6. When attempting to produce blocks:
   - If MaxBytes = 0: No transactions can fit in blocks, causing permanent chain halt
   - If MaxGas < -1: Gas calculations may fail or behave unexpectedly

**Security Failure:** 
This is a consensus-critical configuration validation bypass. The system fails to enforce its own documented parameter constraints during the most critical phase - genesis initialization. This breaks the invariant that consensus parameters must always satisfy safety constraints.

## Impact Explanation

**Affected Components:**
- Block production and validation
- Transaction inclusion in blocks
- Network consensus and finality

**Severity of Damage:**
- **Complete Chain Halt:** If MaxBytes is set to 0 or a negative value, no blocks can be produced because no transactions (or even empty blocks) can satisfy the size constraint
- **Consensus Failure:** Invalid MaxGas values can cause gas calculation errors, node crashes, or consensus disagreements
- **Permanent Network Shutdown:** The chain cannot recover without a hard fork to fix the genesis state

This directly impacts network availability and transaction finality, making it impossible for the blockchain to function.

## Likelihood Explanation

**Who Can Trigger:**
- Network operators during genesis creation/export
- Anyone involved in chain initialization or network upgrades that regenerate genesis files

**Conditions Required:**
- Occurs during genesis file creation or chain initialization
- Can happen accidentally through configuration errors or tooling bugs
- Does not require malicious intent - honest mistakes in genesis configuration can trigger this

**Frequency:**
- High likelihood during network launches, testnets, or upgrades
- The validation gap exists for ALL genesis initializations
- Genesis files are often created programmatically or via export tools, increasing risk of configuration errors [7](#0-6) 

## Recommendation

Add explicit validation of consensus parameters during `StoreConsensusParams` by calling the registered validation functions before storing values. Modify the `StoreConsensusParams` function to:

1. Retrieve the validation function for each parameter type from the KeyTable
2. Call the validation function before storing each parameter
3. Return an error if validation fails, preventing chain initialization with invalid parameters

Alternatively, use `Subspace.SetParamSet()` instead of `Subspace.Set()` in `StoreConsensusParams`, as `SetParamSet` already calls the validation functions. [8](#0-7) 

## Proof of Concept

**Test File:** `baseapp/abci_test.go`

**Test Function:** Add a new test `TestInitChain_InvalidConsensusParams`

**Setup:**
```
// Create a BaseApp with a properly configured param store
app := NewBaseApp(name, logger, db, nil, nil, &testutil.TestAppOpts{})
app.MountStores(capKey1, capKey2)
app.SetParamStore(&paramStore{db: dbm.NewMemDB()})
err := app.LoadLatestVersion()
require.Nil(t, err)
```

**Trigger:**
```
// Call InitChain with invalid consensus parameters (MaxBytes = 0)
_, err := app.InitChain(context.Background(), &abci.RequestInitChain{
    ConsensusParams: &tmproto.ConsensusParams{
        Block: &tmproto.BlockParams{
            MaxBytes: 0,  // Invalid: must be > 0
            MaxGas:   100000000,
        },
    },
})
```

**Observation:**
The current code will NOT return an error - the invalid parameters will be stored successfully. This test demonstrates the validation bypass. The expected behavior would be to return an error preventing chain initialization with invalid parameters.

To verify the issue exists, add this test and observe that:
1. InitChain succeeds (no error returned)
2. The stored MaxBytes value is 0 (retrievable via GetConsensusParams)
3. This violates the constraint defined in ValidateBlockParams that MaxBytes must be > 0

The test should fail (return an error) after the fix is applied, confirming that validation is now properly enforced during genesis initialization.

### Citations

**File:** baseapp/abci.go (L60-64)
```go
	if req.ConsensusParams != nil {
		app.StoreConsensusParams(app.deliverState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.prepareProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.processProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.checkState.ctx, req.ConsensusParams)
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

**File:** x/params/keeper/consensus_params.go (L15-38)
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

**File:** x/genutil/utils.go (L23-28)
```go
func ExportGenesisFile(genDoc *tmtypes.GenesisDoc, genFile string) error {
	if err := genDoc.ValidateAndComplete(); err != nil {
		return err
	}

	return genDoc.SaveAs(genFile)
```
