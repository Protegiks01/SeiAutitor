# Audit Report

## Title
Missing seenModules Update in Streaming Genesis Import Allows Duplicate Module Initialization

## Summary
The streaming genesis import functionality in `InitGenesis` contains a critical flaw where the duplicate module detection check is non-functional. The code verifies if a module has been processed before but never marks modules as seen, allowing an attacker to craft a genesis file with duplicate module entries that will each be processed, leading to state corruption and potential chain initialization failure. [1](#0-0) 

## Impact
High

## Finding Description

- **Location:** `types/module/module.go`, lines 391-415, specifically the streaming genesis import goroutine in the `Manager.InitGenesis` function.

- **Intended Logic:** The code should prevent duplicate module entries in the genesis file by checking if a module has already been processed and rejecting duplicates to maintain state integrity during chain initialization.

- **Actual Logic:** While the code checks `if seenModules[moduleName]` at line 402 to detect duplicates, it never sets `seenModules[moduleName] = true` after processing a module. This makes the duplicate detection completely ineffective - every module will pass the check regardless of how many times it appears in the genesis file. [2](#0-1) 

- **Exploit Scenario:** 
  1. Attacker crafts a malicious genesis file with duplicate module entries (e.g., "bank" module appearing twice with different or same data)
  2. Chain operators use this genesis file with streaming import enabled (`StreamGenesisImport: true`)
  3. The first "bank" module entry passes the check at line 402 (seenModules is empty) and InitGenesis is called
  4. The second "bank" module entry also passes the check (seenModules was never updated) and InitGenesis is called again
  5. Depending on the module, this causes state corruption, double-crediting of balances, or panics from invariant violations

- **Security Failure:** This breaks fundamental chain initialization integrity and consensus safety. Different modules handle re-initialization differently: some will panic (like staking when validator updates conflict), some will corrupt state (like bank double-crediting balances). This can lead to permanent chain failure, consensus breakdown, or financial loss. [3](#0-2) [4](#0-3) 

## Impact Explanation

**Assets Affected:** All chain state, user balances, validator set, and network consensus.

**Severity of Damage:**
- **State Corruption:** Bank module can double-credit balances if the same accounts appear in both entries with different amounts, creating unbacked tokens
- **Chain Initialization Failure:** Staking module will panic if both entries return validator updates (line 409), preventing chain start
- **Consensus Breakdown:** Different nodes might process the malformed genesis differently depending on timing or implementation details, leading to permanent chain split
- **Financial Loss:** Double-credited balances represent direct theft/creation of unbacked tokens

**System Impact:** This vulnerability compromises the most critical security boundary - chain bootstrapping. A malicious genesis file can render the entire network inoperable or start it in a corrupted state that requires a hard fork to fix. [5](#0-4) 

## Likelihood Explanation

**Who Can Trigger:** Any party involved in genesis file creation or distribution - chain operators, validators, or attackers who can influence genesis file contents.

**Conditions Required:** 
- Streaming genesis import must be enabled (`StreamGenesisImport: true`)
- Genesis file must contain duplicate module entries
- No additional validation occurs before using the genesis file

**Frequency:** This can be triggered on every chain initialization or restart from genesis if a malicious genesis file is used. Since genesis files are typically distributed and used by all validators, a single malicious file affects the entire network.

**Likelihood:** HIGH - Genesis files are commonly shared between validators and chain operators. An attacker targeting a specific chain could distribute a malicious genesis file through community channels, documentation, or by compromising a trusted source.

## Recommendation

Add the missing line to mark modules as seen after processing. Immediately after line 406 where `InitGenesis` is called, add:

```go
seenModules[moduleName] = true
```

This matches the pattern used in the validation function and ensures the duplicate check functions correctly. [6](#0-5) 

Additionally, consider adding a final validation pass to ensure all expected modules appear exactly once, similar to the comprehensive checks in the non-streaming path.

## Proof of Concept

**File:** `types/module/module_test.go`

**Test Function:** `TestManager_InitGenesis_StreamingDuplicateModule`

**Setup:**
```go
func TestManager_InitGenesis_StreamingDuplicateModule(t *testing.T) {
    mockCtrl := gomock.NewController(t)
    t.Cleanup(mockCtrl.Finish)
    
    // Create a temporary genesis file with duplicate bank module entries
    genesisContent := `{"chain_id":"test","genesis_time":"2024-01-01T00:00:00Z"}
{"app_state":{"module":"bank","data":{"params":{},"balances":[{"address":"cosmos1xxx","coins":[{"denom":"stake","amount":"1000"}]}]}}}
{"app_state":{"module":"bank","data":{"params":{},"balances":[{"address":"cosmos1yyy","coins":[{"denom":"stake","amount":"2000"}]}]}}}`
    
    tmpFile, err := os.CreateTemp("", "genesis-*.json")
    require.NoError(t, err)
    defer os.Remove(tmpFile.Name())
    
    _, err = tmpFile.WriteString(genesisContent)
    require.NoError(t, err)
    tmpFile.Close()
    
    // Setup mock module
    mockAppModule := mocks.NewMockAppModule(mockCtrl)
    mockAppModule.EXPECT().Name().AnyTimes().Return("bank")
    
    mm := module.NewManager(mockAppModule)
    ctx := sdk.NewContext(nil, tmproto.Header{}, false, nil)
    interfaceRegistry := types.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(interfaceRegistry)
    
    config := genesis.GenesisImportConfig{
        StreamGenesisImport: true,
        GenesisStreamFile:   tmpFile.Name(),
    }
    
    // Expect InitGenesis to be called exactly once (should fail with current bug)
    mockAppModule.EXPECT().InitGenesis(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil)
    
    // This will currently call InitGenesis twice due to the bug
    mm.InitGenesis(ctx, cdc, nil, config)
}
```

**Trigger:** Run the test with `go test -v -run TestManager_InitGenesis_StreamingDuplicateModule`

**Observation:** The test will FAIL because `InitGenesis` is called twice (once for each "bank" entry), but the mock expects it only once. This confirms that the duplicate module detection is not working. The test will show:
```
unexpected call to *MockAppModule.InitGenesis
```

This demonstrates that the same module is being initialized multiple times, violating the intended security invariant that each module should only be initialized once during genesis. [7](#0-6)

### Citations

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

**File:** x/bank/keeper/genesis.go (L11-59)
```go
// InitGenesis initializes the bank module's state from a given genesis state.
func (k BaseKeeper) InitGenesis(ctx sdk.Context, genState *types.GenesisState) {
	k.SetParams(ctx, genState.Params)

	totalSupply := sdk.Coins{}
	totalWeiBalance := sdk.ZeroInt()

	genState.Balances = types.SanitizeGenesisBalances(genState.Balances)
	for _, balance := range genState.Balances {
		addr := balance.GetAddress()
		coins := balance.Coins
		if err := k.initBalances(ctx, addr, coins); err != nil {
			panic(fmt.Errorf("error on setting balances %w", err))
		}

		totalSupply = totalSupply.Add(coins...)
	}
	for _, weiBalance := range genState.WeiBalances {
		addr := sdk.MustAccAddressFromBech32(weiBalance.Address)
		if err := k.AddWei(ctx, addr, weiBalance.Amount); err != nil {
			panic(fmt.Errorf("error on setting wei balance %w", err))
		}
		totalWeiBalance = totalWeiBalance.Add(weiBalance.Amount)
	}
	weiInUsei, weiRemainder := SplitUseiWeiAmount(totalWeiBalance)
	if !weiRemainder.IsZero() {
		panic(fmt.Errorf("non-zero wei remainder %s", weiRemainder))
	}
	baseDenom, err := sdk.GetBaseDenom()
	if err != nil {
		if !weiInUsei.IsZero() {
			panic(fmt.Errorf("base denom is not registered %s yet there exists wei balance %s", err, weiInUsei))
		}
	} else {
		totalSupply = totalSupply.Add(sdk.NewCoin(baseDenom, weiInUsei))
	}

	if !genState.Supply.Empty() && !genState.Supply.IsEqual(totalSupply) {
		panic(fmt.Errorf("genesis supply is incorrect, expected %v, got %v", genState.Supply, totalSupply))
	}

	for _, supply := range totalSupply {
		k.SetSupply(ctx, supply)
	}

	for _, meta := range genState.DenomMetadata {
		k.SetDenomMetaData(ctx, meta)
	}
}
```

**File:** x/staking/genesis.go (L22-164)
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

	for _, delegation := range data.Delegations {
		delegatorAddress := sdk.MustAccAddressFromBech32(delegation.DelegatorAddress)

		// Call the before-creation hook if not exported
		if !data.Exported {
			keeper.BeforeDelegationCreated(ctx, delegatorAddress, delegation.GetValidatorAddr())
		}

		keeper.SetDelegation(ctx, delegation)
		// Call the after-modification hook if not exported
		if !data.Exported {
			keeper.AfterDelegationModified(ctx, delegatorAddress, delegation.GetValidatorAddr())
		}
	}

	for _, ubd := range data.UnbondingDelegations {
		keeper.SetUnbondingDelegation(ctx, ubd)

		for _, entry := range ubd.Entries {
			keeper.InsertUBDQueue(ctx, ubd, entry.CompletionTime)
			notBondedTokens = notBondedTokens.Add(entry.Balance)
		}
	}

	for _, red := range data.Redelegations {
		keeper.SetRedelegation(ctx, red)

		for _, entry := range red.Entries {
			keeper.InsertRedelegationQueue(ctx, red, entry.CompletionTime)
		}
	}

	bondedCoins := sdk.NewCoins(sdk.NewCoin(data.Params.BondDenom, bondedTokens))
	notBondedCoins := sdk.NewCoins(sdk.NewCoin(data.Params.BondDenom, notBondedTokens))

	// check if the unbonded and bonded pools accounts exists
	bondedPool := keeper.GetBondedPool(ctx)
	if bondedPool == nil {
		panic(fmt.Sprintf("%s module account has not been set", types.BondedPoolName))
	}
	// TODO remove with genesis 2-phases refactor https://github.com/cosmos/cosmos-sdk/issues/2862
	bondedBalance := bankKeeper.GetAllBalances(ctx, bondedPool.GetAddress())
	if bondedBalance.IsZero() {
		accountKeeper.SetModuleAccount(ctx, bondedPool)
	}
	// if balance is different from bonded coins panic because genesis is most likely malformed
	if !bondedBalance.IsEqual(bondedCoins) {
		panic(fmt.Sprintf("bonded pool balance is different from bonded coins: %s <-> %s", bondedBalance, bondedCoins))
	}
	notBondedPool := keeper.GetNotBondedPool(ctx)
	if notBondedPool == nil {
		panic(fmt.Sprintf("%s module account has not been set", types.NotBondedPoolName))
	}

	notBondedBalance := bankKeeper.GetAllBalances(ctx, notBondedPool.GetAddress())
	if notBondedBalance.IsZero() {
		accountKeeper.SetModuleAccount(ctx, notBondedPool)
	}
	// if balance is different from non bonded coins panic because genesis is most likely malformed
	if !notBondedBalance.IsEqual(notBondedCoins) {
		panic(fmt.Sprintf("not bonded pool balance is different from not bonded coins: %s <-> %s", notBondedBalance, notBondedCoins))
	}
	// don't need to run Tendermint updates if we exported
	if data.Exported {
		for _, lv := range data.LastValidatorPowers {
			valAddr, err := sdk.ValAddressFromBech32(lv.Address)
			if err != nil {
				panic(err)
			}
			keeper.SetLastValidatorPower(ctx, valAddr, lv.Power)
			validator, found := keeper.GetValidator(ctx, valAddr)

			if !found {
				panic(fmt.Sprintf("validator %s not found", lv.Address))
			}

			update := validator.ABCIValidatorUpdate(keeper.PowerReduction(ctx))
			update.Power = lv.Power // keep the next-val-set offset, use the last power for the first block
			res = append(res, abci.ValidatorUpdate{
				PubKey: update.PubKey,
				Power:  update.Power,
			})
		}
	} else {
		var err error
		legacyUpdates, err := keeper.ApplyAndReturnValidatorSetUpdates(ctx)
		if err != nil {
			log.Fatal(err)
		}
		res = utils.Map(legacyUpdates, func(v abci.ValidatorUpdate) abci.ValidatorUpdate {
			return abci.ValidatorUpdate{
				PubKey: v.PubKey,
				Power:  v.Power,
			}
		})
	}

	return res
}
```

**File:** x/genutil/client/cli/validate_genesis.go (L134-141)
```go
			if prevModule != moduleName { // new module
				if prevModule != "" && prevModule != "genesisDoc" {
					doneCh <- struct{}{}
				}
				seenModules[prevModule] = true
				if moduleName != "genesisDoc" {
					go mbm.ValidateGenesisStream(cdc, clientCtx.TxConfig, moduleName, genesisCh, doneCh, errCh)
					genesisCh <- moduleState.AppState.Data
```
