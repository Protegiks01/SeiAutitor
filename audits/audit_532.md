# Audit Report

## Title
Non-Deterministic Module Initialization Order in Streaming Genesis Import Causes Consensus Failure from Block 0

## Summary
The streaming genesis import path processes modules in file order rather than the configured `OrderInitGenesis`, leading to non-deterministic initialization when validators use genesis files with different module ordering. This breaks consensus from genesis block. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** `types/module/module.go`, `InitGenesis` method, lines 384-442

**Intended Logic:** All validators should initialize modules in a consistent, deterministic order as defined by `OrderInitGenesis`. This order is critical because modules have dependencies—for example, the capability module must initialize first so other modules can claim capabilities, and genutil must initialize after staking for proper pool initialization. [2](#0-1) 

**Actual Logic:** The `InitGenesis` function has two paths:
- Regular path (lines 420-437): Iterates through `m.OrderInitGenesis` and initializes modules in the configured order
- Streaming path (lines 386-419): When `genesisImportConfig.StreamGenesisImport` is true, reads the genesis file line-by-line and processes modules in the order they appear in the file

The streaming path never checks or enforces `OrderInitGenesis`, instead processing modules based solely on their position in the genesis file. [3](#0-2) 

**Exploit Scenario:**
1. Validator A exports genesis using the standard tool, which correctly orders modules according to `OrderInitGenesis` via `ProcessGenesisPerModule`
2. Validator B receives a genesis file where modules are in a different order (due to manual editing, different tooling, or file corruption)
3. Both validators enable streaming import by setting `stream-import = true` in their `app.toml` [4](#0-3) 

4. Validator A initializes modules in one order, Validator B in another order
5. Because module initialization order affects state (e.g., capability claims, pool balances), validators end up with different genesis app hashes
6. Chain fails to achieve consensus from block 0

**Security Failure:** Consensus determinism is broken. The export function explicitly uses `OrderInitGenesis` with a comment stating "the order of importing does due to invariant checks and how we are streaming the genesis file", but the import path ignores this requirement. [5](#0-4) 

## Impact Explanation

This vulnerability causes:
- **Unintended permanent chain split from genesis**: Validators with differently-ordered genesis files will compute different genesis app hashes and never achieve consensus
- **Network unable to start**: All validators must have byte-identical genesis files with modules in the exact same order, but there's no validation enforcing this in streaming mode
- **Hard fork required to fix**: Once validators start with different genesis states, the chain cannot recover without manual coordination

The issue affects the fundamental consensus property that all validators must start from identical state at block 0. This is in-scope as "High Unintended permanent chain split requiring hard fork".

## Likelihood Explanation

**Who can trigger:** Any network participant distributing genesis files, or any validator operator configuring their node.

**Conditions required:** 
- Validators must enable streaming genesis import (`stream-import = true` in config)
- Genesis files must have modules in different orders across validators

**Likelihood:** Medium-to-High. While streaming import is optional, it's designed for large genesis files which are common in production networks. Genesis files can easily end up with different module ordering through:
- Different genesis generation tools or versions
- Manual editing or processing of genesis JSON
- JSON parsers that don't preserve order
- Export from different application versions

## Recommendation

Modify the streaming import path in `InitGenesis` to enforce `OrderInitGenesis`:

1. Read all modules from the genesis file into a map
2. Iterate through `m.OrderInitGenesis` to process modules in the correct order
3. Verify all modules in the file were processed (no extra/missing modules)

Alternatively, add validation that checks the genesis file has modules in the expected order before processing, and fail fast with a clear error message if the order doesn't match `OrderInitGenesis`.

## Proof of Concept

**File:** `types/module/module_test.go`

**Test Function:** Add `TestInitGenesis_StreamingOrderMatters`

**Setup:**
1. Create a module manager with two mock modules: "module1" and "module2"
2. Set `OrderInitGenesis` to `["module1", "module2"]`
3. Create two genesis files in streaming format:
   - File A: module1 first, then module2
   - File B: module2 first, then module1 (reversed order)

**Trigger:**
1. Initialize genesis with streaming import enabled using File A
2. Initialize genesis with streaming import enabled using File B
3. Both should use the same module content, only the order differs

**Observation:**
The test demonstrates that:
- Modules are initialized in different orders (module1→module2 vs module2→module1)
- If modules track initialization order in their state, the final states will differ
- This proves the vulnerability: same genesis content but different file ordering produces non-deterministic results

The test should show that the streaming path processes modules in file order, violating the determinism requirement. In contrast, the regular (non-streaming) path would process both files identically because it uses `OrderInitGenesis`.

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

**File:** types/module/module.go (L454-468)
```go
func (m *Manager) ProcessGenesisPerModule(ctx sdk.Context, cdc codec.JSONCodec, process func(string, json.RawMessage) error) error {
	// It's important that we use OrderInitGenesis here instead of OrderExportGenesis because the order of exporting
	// doesn't matter much but the order of importing does due to invariant checks and how we are streaming the genesis
	// file here
	for _, moduleName := range m.OrderInitGenesis {
		ch := m.Modules[moduleName].ExportGenesisStream(ctx, cdc)
		for msg := range ch {
			err := process(moduleName, msg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
```

**File:** simapp/app.go (L381-392)
```go
	// NOTE: The genutils module must occur after staking so that pools are
	// properly initialized with tokens from genesis accounts.
	// NOTE: Capability module must occur first so that it can initialize any capabilities
	// so that other modules that want to create or claim capabilities afterwards in InitChain
	// can do so safely.
	app.mm.SetOrderInitGenesis(
		capabilitytypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName, distrtypes.ModuleName, stakingtypes.ModuleName,
		slashingtypes.ModuleName, govtypes.ModuleName, minttypes.ModuleName, crisistypes.ModuleName,
		genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName, upgradetypes.ModuleName, vestingtypes.ModuleName, acltypes.ModuleName,
	)
```

**File:** types/genesis/genesis.go (L12-14)
```go
type GenesisImportConfig struct {
	StreamGenesisImport bool
	GenesisStreamFile   string
```

**File:** server/config/config.go (L195-202)
```go
// GenesisConfig defines the genesis export, validation, and import configuration
type GenesisConfig struct {
	// StreamImport defines if the genesis.json is in stream form or not.
	StreamImport bool `mapstructure:"stream-import"`

	// GenesisStreamFile sets the genesis json file from which to stream from
	GenesisStreamFile string `mapstructure:"genesis-stream-file"`
}
```
