## Title
Broken Duplicate Module Detection in Streaming Genesis Import Allows Double-Initialization and Fund Creation

## Summary
The module state parser's duplicate detection mechanism in the streaming genesis initialization path is broken, allowing the same module to be initialized multiple times with different genesis data. This enables direct creation of funds through the bank module's additive Wei balance initialization, bypassing supply constraints and validation checks.

## Impact
**High** - Direct loss/creation of funds

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Parser function: [2](#0-1) 
- Exploitable module: [3](#0-2) 

**Intended Logic:** 
The streaming genesis import should detect and reject duplicate module entries to ensure each module's `InitGenesis` is called exactly once. The `seenModules` map tracks which modules have been processed.

**Actual Logic:** 
The duplicate detection check at line 402 verifies `if seenModules[moduleName]` but never sets `seenModules[moduleName] = true` after processing. This means every duplicate check returns false, allowing unlimited duplicate modules. [4](#0-3) 

Contrast this with the validation path which correctly updates the tracking map: [5](#0-4) 

**Exploit Scenario:**
1. Attacker creates a genesis stream file with duplicate bank module entries:
   - Line 1: GenesisDoc
   - Line 2: `{"app_state": {"module": "bank", "data": {...balances with Wei...}}}`
   - Line 3: `{"app_state": {"module": "bank", "data": {...additional Wei balances...}}}`
2. Attacker configures `StreamImport=true` in config, which skips validation: [6](#0-5) 
3. Chain initialization calls `InitGenesis` in streaming mode
4. First bank entry initializes accounts with Wei balances
5. Second bank entry's `AddWei` calls ADD to existing balances instead of setting: [7](#0-6) 
6. Wei balances are now doubled (or more with additional duplicates), creating funds from nothing

**Security Failure:** 
This breaks accounting invariants and supply integrity. Multiple initializations violate the genesis initialization contract that each module initializes exactly once with deterministic state.

## Impact Explanation

**Affected Assets:** All token balances, particularly Wei balances which use additive operations.

**Severity of Damage:**
- **Direct fund creation**: Wei balances accumulate across duplicate genesis entries, minting tokens without corresponding supply validation
- **Supply corruption**: The total supply validation occurs per-initialization but doesn't account for cumulative effects across duplicates
- **Consensus failure risk**: If different validators process genesis files differently (e.g., some skip duplicates), they end up with divergent initial states

**Why This Matters:**
Genesis state initialization is the foundation of chain security. Allowing arbitrary fund creation at genesis undermines all token economic guarantees. This is especially critical for new chain launches where genesis files are being constructed.

## Likelihood Explanation

**Who Can Trigger:**
Any party involved in genesis file creation for a new chain, or during a coordinated network restart. This includes:
- Chain operators during initial launch
- Coordinating validators during genesis file distribution
- Malicious insider with access to genesis file creation process

**Conditions Required:**
- `StreamImport=true` configuration (explicitly supported feature)
- Access to craft or modify the genesis stream file before distribution
- Network initialization or restart scenario

**Frequency:**
While limited to genesis initialization events (not ongoing operation), this is a critical window. New Sei chain deployments, testnets, or hard fork restarts with genesis export/import all present opportunities. The vulnerability is 100% exploitable whenever conditions are met - no race conditions or probabilistic elements.

## Recommendation

**Immediate Fix:**
Add the missing state update after the duplicate check passes in `types/module/module.go`:

```go
if seenModules[moduleName] {
    errCh <- fmt.Errorf("module %s seen twice in genesis file", moduleName)
    return
}
seenModules[moduleName] = true  // ADD THIS LINE
moduleValUpdates := m.Modules[moduleName].InitGenesis(ctx, cdc, moduleState.AppState.Data)
```

**Additional Safeguards:**
1. Enforce validation even when `StreamImport=true` by removing the validation skip at startup
2. Add integration tests that verify duplicate modules are rejected in streaming mode
3. Consider making the bank module's `InitGenesis` idempotent by using SET operations instead of ADD for Wei balances

## Proof of Concept

**File:** `types/module/module_test.go`

**Test Function:** Add `TestManager_InitGenesis_StreamingDuplicateModule`

**Setup:**
1. Create a mock AppModule that tracks how many times InitGenesis is called
2. Create a temporary genesis stream file with duplicate module entries
3. Configure GenesisImportConfig with StreamGenesisImport=true and the temp file path
4. Initialize a module Manager with the mock module

**Trigger:**
Call `mm.InitGenesis(ctx, cdc, emptyGenesisData, genesisImportConfig)` where the stream file contains:
```
{"chain_id": "test", "genesis_time": "...", ...}
{"app_state": {"module": "testmodule", "data": {"value": 1}}}
{"app_state": {"module": "testmodule", "data": {"value": 2}}}
```

**Observation:**
The mock module's InitGenesis counter should be 1, but will actually be 2, proving the duplicate was not caught. The test should assert the counter equals 1 and fail on the vulnerable code, or assert an error is returned from InitGenesis but none is returned.

**Expected Behavior:** InitGenesis should panic with "module testmodule seen twice in genesis file"

**Actual Behavior:** InitGenesis completes successfully, calling testmodule.InitGenesis twice

This test demonstrates the core vulnerability. A more comprehensive test would use the actual bank module and verify Wei balances are incorrectly doubled, directly proving fund creation.

### Citations

**File:** types/module/module.go (L386-419)
```go
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
```

**File:** x/genutil/client/cli/validate_genesis.go (L81-91)
```go
func parseModule(jsonStr string) (*ModuleState, error) {
	var module ModuleState
	err := json.Unmarshal([]byte(jsonStr), &module)
	if err != nil {
		return nil, err
	}
	if module.AppState.Module == "" {
		return nil, fmt.Errorf("module name is empty")
	}
	return &module, nil
}
```

**File:** x/genutil/client/cli/validate_genesis.go (L130-151)
```go
			if seenModules[moduleName] {
				errCh <- fmt.Errorf("module %s seen twice in genesis file", moduleName)
				return
			}
			if prevModule != moduleName { // new module
				if prevModule != "" && prevModule != "genesisDoc" {
					doneCh <- struct{}{}
				}
				seenModules[prevModule] = true
				if moduleName != "genesisDoc" {
					go mbm.ValidateGenesisStream(cdc, clientCtx.TxConfig, moduleName, genesisCh, doneCh, errCh)
					genesisCh <- moduleState.AppState.Data
				} else {
					err = genDoc.ValidateAndComplete()
					if err != nil {
						errCh <- fmt.Errorf("error validating genesis doc %s: %s", genesis, err.Error())
					}
				}
			} else { // same module
				genesisCh <- moduleState.AppState.Data
			}
			prevModule = moduleName
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

**File:** server/start.go (L196-201)
```go
			if !config.Genesis.StreamImport {
				genesisFile, _ := tmtypes.GenesisDocFromFile(serverCtx.Config.GenesisFile())
				if genesisFile.ChainID != clientCtx.ChainID {
					panic(fmt.Sprintf("genesis file chain-id=%s does not equal config.toml chain-id=%s", genesisFile.ChainID, clientCtx.ChainID))
				}
			}
```

**File:** x/bank/keeper/send.go (L386-405)
```go
func (k BaseSendKeeper) AddWei(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Int) (err error) {
	if !k.CanSendTo(ctx, addr) {
		return sdkerrors.ErrInvalidRecipient
	}
	if amt.Equal(sdk.ZeroInt()) {
		return nil
	}
	defer func() {
		if err == nil {
			ctx.EventManager().EmitEvent(
				types.NewWeiReceivedEvent(addr, amt),
			)
		}
	}()
	currentWeiBalance := k.GetWeiBalance(ctx, addr)
	postWeiBalance := currentWeiBalance.Add(amt)
	if postWeiBalance.LT(OneUseiInWei) {
		// no need to change usei balance
		return k.setWeiBalance(ctx, addr, postWeiBalance)
	}
```
