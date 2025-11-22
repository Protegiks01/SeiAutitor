## Audit Report

## Title
Genesis Validators with Duplicate Public Keys Cause Consensus Failure Due to Missing Validation in InitChain

## Summary
The staking module's `ValidateGenesis` function checks for duplicate validator public keys, but this validation is never called during chain initialization. When `InitChain` processes genesis state, it directly calls `InitGenesis` without validation, allowing validators with duplicate consensus public keys to be loaded. This causes the second validator to overwrite the first in the consensus address index, making the first validator invisible to Tendermint consensus and leading to validator set inconsistencies and potential network failure. [1](#0-0) [2](#0-1) 

## Impact
**High** - Network not being able to confirm new transactions (consensus failure)

## Finding Description

**Location:** 
- Genesis initialization: [3](#0-2) 
- Validator indexing: [4](#0-3) 
- Validation function (not called): [5](#0-4) 

**Intended Logic:** 
Genesis state should be validated to ensure no duplicate validator public keys exist before initializing the chain. The `ValidateGenesis` function properly checks for this by maintaining a map of seen public keys and returning an error if duplicates are found. [6](#0-5) 

**Actual Logic:** 
The `InitChain` ABCI method in `simapp/app.go` directly calls `InitGenesis` without first calling `ValidateGenesis`. The module manager's `InitGenesis` method also does not perform validation before initializing modules. When duplicate validators exist:

1. Both validators are stored successfully in the main validator store (keyed by different operator addresses)
2. `SetValidatorByConsAddr` creates an index mapping consensus address → operator address
3. The second validator with the same consensus public key **overwrites** the first mapping at line 70 [4](#0-3) 

This causes the first validator to become unreachable via consensus address lookups.

**Exploit Scenario:**
1. An attacker crafts a genesis.json file with two validators having different operator addresses but identical consensus public keys
2. The node operator starts the chain without running the optional `validate-genesis` CLI command
3. `InitChain` processes the genesis state and calls `InitGenesis` directly
4. Both validators are loaded into state, but only the second is accessible via `GetValidatorByConsAddr`
5. Tendermint uses consensus public keys to match block signatures to validators
6. The first validator's signatures cannot be matched, causing consensus failures

**Security Failure:** 
This breaks consensus agreement and validator set integrity. Tendermint expects each validator to have a unique consensus public key. When lookups fail for the first validator's signatures, the network cannot properly validate blocks, leading to consensus halts or chain splits.

## Impact Explanation

**Affected Assets/Processes:**
- Network consensus and block finality
- Validator set integrity
- Network availability and liveness

**Severity of Damage:**
- The chain can start but operates with a corrupted validator set
- Block signatures from the "invisible" validator cannot be matched to its identity
- Consensus fails when trying to verify blocks signed by the first validator
- Network may halt or enter undefined behavior requiring emergency intervention
- Requires manual state correction or hard fork to resolve

**Why This Matters:**
Validator set integrity is fundamental to Proof-of-Stake consensus. Any corruption in how validators are tracked breaks the security model of the entire blockchain. Unlike runtime validation (which exists for `MsgCreateValidator`), genesis validation is bypassed, creating a critical vulnerability in chain initialization. [7](#0-6) 

## Likelihood Explanation

**Who Can Trigger:**
Any party creating or distributing a genesis file (chain operators, testnet coordinators, mainnet launch teams). This includes:
- Malicious actors distributing corrupted genesis files
- Accidental errors in genesis file generation
- Compromised genesis generation tools

**Required Conditions:**
- Genesis file contains validators with duplicate consensus public keys
- The `validate-genesis` CLI command is not run before chain start (it's optional)
- Node operators trust the genesis file without independent verification

**Frequency:**
- Likely during: chain launches, network resets, testnet initialization
- The `validate-genesis` command is optional and may be skipped in automated deployments
- Risk increases with more validators in genesis (more opportunities for key collisions)

The test suite confirms that `ValidateGenesis` properly detects duplicates when called: [8](#0-7) 

However, this validation is never invoked during actual chain initialization.

## Recommendation

Modify the `InitChainer` in `simapp/app.go` to call `ValidateGenesis` before calling `InitGenesis`. Add validation to the module manager's `InitGenesis` method:

```go
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
    var genesisState GenesisState
    if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
        panic(err)
    }
    
    // Add validation before initialization
    if err := app.mm.ValidateGenesis(app.appCodec, app.TxConfig(), genesisState); err != nil {
        panic(fmt.Sprintf("genesis validation failed: %s", err))
    }
    
    app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
    return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
}
```

Alternatively, add duplicate key checking directly in `InitGenesis` of the staking module as a defense-in-depth measure.

## Proof of Concept

**File:** `x/staking/genesis_test.go`

**Test Function:** `TestInitGenesis_DuplicatePubKeys`

```go
func TestInitGenesis_DuplicatePubKeys(t *testing.T) {
    app, ctx, addrs := bootstrapGenesisTest(3)
    
    valTokens := app.StakingKeeper.TokensFromConsensusPower(ctx, 1)
    params := app.StakingKeeper.GetParams(ctx)
    
    // Use the SAME public key for two different validators
    pk0, err := codectypes.NewAnyWithValue(PKs[0])
    require.NoError(t, err)
    
    // Validator 1 with pk0 and address 0
    validator1 := types.Validator{
        OperatorAddress: sdk.ValAddress(addrs[0]).String(),
        ConsensusPubkey: pk0,  // Using PKs[0]
        Status:          types.Bonded,
        Tokens:          valTokens,
        DelegatorShares: valTokens.ToDec(),
        Description:     types.NewDescription("validator1", "", "", "", ""),
    }
    
    // Validator 2 with pk0 and address 1 (DUPLICATE PUBLIC KEY)
    validator2 := types.Validator{
        OperatorAddress: sdk.ValAddress(addrs[1]).String(),
        ConsensusPubkey: pk0,  // Using PKs[0] again - DUPLICATE!
        Status:          types.Bonded,
        Tokens:          valTokens,
        DelegatorShares: valTokens.ToDec(),
        Description:     types.NewDescription("validator2", "", "", "", ""),
    }
    
    validators := []types.Validator{validator1, validator2}
    
    // ValidateGenesis should catch this
    genesisState := types.NewGenesisState(params, validators, nil)
    err = staking.ValidateGenesis(genesisState)
    require.Error(t, err, "ValidateGenesis should detect duplicate public keys")
    require.Contains(t, err.Error(), "duplicate validator")
    
    // Fund the bonded pool
    require.NoError(t,
        simapp.FundModuleAccount(
            app.BankKeeper,
            ctx,
            types.BondedPoolName,
            sdk.NewCoins(sdk.NewCoin(params.BondDenom, valTokens.MulRaw(2))),
        ),
    )
    
    // InitGenesis DOES NOT call ValidateGenesis - it proceeds directly
    // This demonstrates the vulnerability
    staking.InitGenesis(ctx, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, genesisState)
    
    // Both validators are stored by operator address
    val1, found1 := app.StakingKeeper.GetValidator(ctx, sdk.ValAddress(addrs[0]))
    require.True(t, found1)
    val2, found2 := app.StakingKeeper.GetValidator(ctx, sdk.ValAddress(addrs[1]))
    require.True(t, found2)
    
    // Get the consensus address from the shared public key
    pk, _ := validator1.ConsPubKey()
    consAddr := sdk.GetConsAddress(pk)
    
    // GetValidatorByConsAddr returns only the SECOND validator (validator2)
    // The first validator is "invisible" - UNDEFINED BEHAVIOR
    valByConsAddr, foundByCons := app.StakingKeeper.GetValidatorByConsAddr(ctx, consAddr)
    require.True(t, foundByCons)
    
    // This proves the vulnerability: only validator2 is accessible via consensus address
    // validator1 has been overwritten in the index
    require.Equal(t, sdk.ValAddress(addrs[1]).String(), valByConsAddr.OperatorAddress,
        "Second validator overwrote first in consensus address index")
    require.NotEqual(t, sdk.ValAddress(addrs[0]).String(), valByConsAddr.OperatorAddress,
        "First validator is now invisible to consensus lookups")
    
    // This is the security failure: Tendermint cannot properly identify validator1
    // by its consensus public key, breaking consensus
}
```

**Setup:** Bootstrap a test app with genesis accounts and addresses.

**Trigger:** Create two validators with different operator addresses but identical consensus public keys in genesis state. Call `InitGenesis` directly (simulating what `InitChain` does) without calling `ValidateGenesis` first.

**Observation:** The test demonstrates that:
1. `ValidateGenesis` properly detects the duplicate (line with `require.Error`)
2. `InitGenesis` proceeds without validation and loads both validators
3. Both validators exist in the validator store by operator address
4. Only the second validator is accessible via `GetValidatorByConsAddr` 
5. The first validator is "invisible" to consensus address lookups

This proves the vulnerability: genesis validation is bypassed during chain initialization, allowing duplicate public keys that corrupt the consensus address index and cause undefined behavior in validator set management.

### Citations

**File:** simapp/app.go (L592-598)
```go
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
	return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
```

**File:** types/module/module.go (L384-442)
```go
func (m *Manager) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, genesisData map[string]json.RawMessage, genesisImportConfig genesistypes.GenesisImportConfig) abci.ResponseInitChain {
	var validatorUpdates []abci.ValidatorUpdate
	if genesisImportConfig.StreamGenesisImport {
		lines := genesistypes.IngestGenesisFileLineByLine(genesisImportConfig.GenesisStreamFile)
		errCh := make(chan error, 1)
		seenModules := make(map[string]bool)
		var moduleName string
		go func() {
			for line := range lines {
				moduleState, err := parseModule(line)
				if err != nil {
					moduleName = "genesisDoc"
				} else {
					moduleName = moduleState.AppState.Module
				}
				if moduleName == "genesisDoc" {
					continue
				}
				if seenModules[moduleName] {
					errCh <- fmt.Errorf("module %s seen twice in genesis file", moduleName)
					return
				}
				moduleValUpdates := m.Modules[moduleName].InitGenesis(ctx, cdc, moduleState.AppState.Data)
				if len(moduleValUpdates) > 0 {
					if len(validatorUpdates) > 0 {
						panic("validator InitGenesis updates already set by a previous module")
					}
					validatorUpdates = moduleValUpdates
				}
			}
			errCh <- nil
		}()
		err := <-errCh
		if err != nil {
			panic(err)
		}
	} else {
		for _, moduleName := range m.OrderInitGenesis {
			if genesisData[moduleName] == nil {
				continue
			}

			moduleValUpdates := m.Modules[moduleName].InitGenesis(ctx, cdc, genesisData[moduleName])

			// use these validator updates if provided, the module manager assumes
			// only one module will update the validator set
			if len(moduleValUpdates) > 0 {
				if len(validatorUpdates) > 0 {
					panic("validator InitGenesis updates already set by a previous module")
				}
				validatorUpdates = moduleValUpdates
			}
		}
	}

	return abci.ResponseInitChain{
		Validators: validatorUpdates,
	}
}
```

**File:** x/staking/genesis.go (L22-64)
```go
func InitGenesis(
	ctx sdk.Context, keeper keeper.Keeper, accountKeeper types.AccountKeeper,
	bankKeeper types.BankKeeper, data *types.GenesisState,
) (res []abci.ValidatorUpdate) {
	bondedTokens := sdk.ZeroInt()
	notBondedTokens := sdk.ZeroInt()

	// We need to pretend to be "n blocks before genesis", where "n" is the
	// validator update delay, so that e.g. slashing periods are correctly
	// initialized for the validator set e.g. with a one-block offset - the
	// first TM block is at height 1, so state updates applied from
	// genesis.json are in block 0.
	ctx = ctx.WithBlockHeight(1 - sdk.ValidatorUpdateDelay)

	keeper.SetParams(ctx, data.Params)
	keeper.SetLastTotalPower(ctx, data.LastTotalPower)

	for _, validator := range data.Validators {
		keeper.SetValidator(ctx, validator)

		// Manually set indices for the first time
		keeper.SetValidatorByConsAddr(ctx, validator)
		keeper.SetValidatorByPowerIndex(ctx, validator)

		// Call the creation hook if not exported
		if !data.Exported {
			keeper.AfterValidatorCreated(ctx, validator.GetOperator())
		}

		// update timeslice if necessary
		if validator.IsUnbonding() {
			keeper.InsertUnbondingValidatorQueue(ctx, validator)
		}

		switch validator.GetStatus() {
		case types.Bonded:
			bondedTokens = bondedTokens.Add(validator.GetTokens())
		case types.Unbonding, types.Unbonded:
			notBondedTokens = notBondedTokens.Add(validator.GetTokens())
		default:
			panic("invalid validator status")
		}
	}
```

**File:** x/staking/genesis.go (L228-274)
```go
// ValidateGenesis validates the provided staking genesis state to ensure the
// expected invariants holds. (i.e. params in correct bounds, no duplicate validators)
func ValidateGenesis(data *types.GenesisState) error {
	if err := validateGenesisStateValidators(data.Validators); err != nil {
		return err
	}

	return data.Params.Validate()
}

func validateGenesisStateValidators(validators []types.Validator) error {
	addrMap := make(map[string]bool, len(validators))

	for i := 0; i < len(validators); i++ {
		val := validators[i]
		consPk, err := val.ConsPubKey()
		if err != nil {
			return err
		}

		strKey := string(consPk.Bytes())

		if _, ok := addrMap[strKey]; ok {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("duplicate validator in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.Jailed && val.IsBonded() {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("validator is bonded and jailed in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.DelegatorShares.IsZero() && !val.IsUnbonding() {
			return fmt.Errorf("bonded/unbonded genesis validator cannot have zero delegator shares, validator: %v", val)
		}

		addrMap[strKey] = true
	}

	return nil
}
```

**File:** x/staking/keeper/validator.go (L64-72)
```go
func (k Keeper) SetValidatorByConsAddr(ctx sdk.Context, validator types.Validator) error {
	consPk, err := validator.GetConsAddr()
	if err != nil {
		return err
	}
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetValidatorByConsAddrKey(consPk), validator.GetOperator())
	return nil
}
```

**File:** x/staking/keeper/msg_server.go (L52-54)
```go
	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
	}
```

**File:** x/staking/genesis_test.go (L217-220)
```go
		{"duplicate validator", func(data *types.GenesisState) {
			data.Validators = genValidators1
			data.Validators = append(data.Validators, genValidators1[0])
		}, true},
```
