## Audit Report

### Title
Missing Duplicate Evidence Hash Validation in Genesis State Allows Network Launch Failure

### Summary
The evidence module's genesis validation function does not check for duplicate evidence entries with identical hashes. While the validation command passes, attempting to initialize the chain with duplicate evidence causes a panic, resulting in total network shutdown. This creates a false sense of security during genesis validation and prevents the network from starting.

### Impact
**High**

### Finding Description

**Location:** 
The vulnerability exists in the evidence module's genesis validation: [1](#0-0) 

**Intended Logic:** 
The genesis validation should detect and reject any duplicate evidence entries before the chain attempts to initialize, similar to how the auth module validates duplicate accounts: [2](#0-1) 

**Actual Logic:** 
The `Validate()` function only calls `ValidateBasic()` on each evidence entry without checking for duplicates. The validation occurs through the module's `ValidateGenesis` method: [3](#0-2) 

The duplicate check only happens during `InitGenesis` at chain startup, where it panics if duplicates are found: [4](#0-3) 

**Exploit Scenario:**
1. A genesis coordinator creates a genesis file for a new network or chain upgrade
2. Due to a bug, manual editing error, or state export corruption, duplicate evidence entries (with identical Hash values) are added to the genesis file
3. The coordinator runs `validate-genesis` CLI command, which calls `ValidateGenesis`: [5](#0-4) 
4. The validation passes because `Validate()` doesn't check for duplicates
5. The genesis file is distributed to all validators
6. When validators attempt to start their nodes, `InitGenesis` panics upon detecting the duplicate
7. All nodes fail to initialize, causing total network shutdown

**Security Failure:** 
This is a denial-of-service vulnerability where the validation phase provides false confidence. The missing duplicate check allows corrupted genesis files to pass validation but prevents the entire network from starting.

### Impact Explanation

- **Affected Process:** The entire blockchain network initialization process is affected
- **Severity:** When duplicate evidence exists in the genesis file, all network nodes panic during `InitGenesis` and cannot start. This results in a complete network failure where no transactions can be processed
- **Why It Matters:** This vulnerability prevents the network from launching or recovering from a genesis-based upgrade. The validation command's false positive creates operational risk, as coordinators believe the genesis file is valid when it will actually cause network-wide failure. This could delay network launches, cause failed upgrades, or be exploited to sabotage network initialization if an attacker can influence genesis file contents

### Likelihood Explanation

- **Who Can Trigger:** Anyone with write access to the genesis file or involved in the genesis creation/export process can introduce duplicate evidence entries. This includes genesis coordinators, validators participating in genesis creation, or automated export/import scripts
- **Conditions Required:** The vulnerability triggers when:
  1. A genesis file contains duplicate evidence entries (same Height, Power, Time, and ConsensusAddress fields, resulting in identical Hash values)
  2. The `validate-genesis` command is run (passes incorrectly)
  3. Nodes attempt to initialize with this genesis file
- **Frequency:** While not common in normal operations, this can occur during:
  - Manual genesis file editing or merging
  - Bugs in genesis export/import tooling
  - State migration errors
  - Intentional sabotage by malicious insiders
  The likelihood increases during network launches and chain upgrades when genesis files are actively manipulated

### Recommendation

Add duplicate hash checking to the `Validate()` function in the evidence module's genesis validation, similar to the auth module's implementation:

1. Modify the `Validate()` function in `x/evidence/types/genesis.go` to include:
   - Create a map to track seen evidence hashes
   - For each evidence entry, compute its hash and check if it already exists in the map
   - Return an error if a duplicate hash is detected
   
2. The implementation should follow the pattern used in the auth module's `ValidateGenAccounts` function: [6](#0-5) 

This ensures the `validate-genesis` CLI command catches duplicate evidence before chain initialization, preventing network launch failures.

### Proof of Concept

**File:** `x/evidence/types/genesis_test.go`

**Test Function:** Add the following test case to demonstrate the vulnerability:

```go
func TestValidateGenesisDuplicateEvidence(t *testing.T) {
    pk := ed25519.GenPrivKey()
    
    // Create duplicate evidence entries with identical fields (same hash)
    duplicateEvidence := &types.Equivocation{
        Height:           100,
        Power:            1000,
        Time:             time.Now().UTC(),
        ConsensusAddress: pk.PubKey().Address().String(),
    }
    
    testEvidence := []exported.Evidence{duplicateEvidence, duplicateEvidence}
    genesisState := types.NewGenesisState(testEvidence)
    
    // Validate() should fail but currently passes
    err := genesisState.Validate()
    require.Error(t, err, "Validate should detect duplicate evidence but doesn't")
    require.Contains(t, err.Error(), "duplicate", "Error should mention duplicate evidence")
}
```

**Setup:** The test creates two identical evidence entries that will produce the same hash value since all fields (Height, Power, Time, ConsensusAddress) are identical.

**Trigger:** The test calls `genesisState.Validate()`, which is the function used by the `validate-genesis` CLI command.

**Observation:** The test currently fails because `Validate()` does NOT detect the duplicates and returns no error. After implementing the recommended fix, this test should pass, confirming that duplicate evidence is properly detected during validation. Additionally, attempting to run `InitGenesis` with this state (as shown in the existing test suite structure) would panic at: [7](#0-6) 

This demonstrates the vulnerability: validation passes but initialization fails, causing network shutdown.

### Citations

**File:** x/evidence/types/genesis.go (L42-54)
```go
func (gs GenesisState) Validate() error {
	for _, e := range gs.Evidence {
		evi, ok := e.GetCachedValue().(exported.Evidence)
		if !ok {
			return fmt.Errorf("expected evidence")
		}
		if err := evi.ValidateBasic(); err != nil {
			return err
		}
	}

	return nil
}
```

**File:** x/auth/types/genesis.go (L85-104)
```go
// ValidateGenAccounts validates an array of GenesisAccounts and checks for duplicates
func ValidateGenAccounts(accounts GenesisAccounts) error {
	addrMap := make(map[string]bool, len(accounts))

	for _, acc := range accounts {
		// check for duplicated accounts
		addrStr := acc.GetAddress().String()
		if _, ok := addrMap[addrStr]; ok {
			return fmt.Errorf("duplicate account found in genesis state; address: %s", addrStr)
		}

		addrMap[addrStr] = true

		// check account specific validation
		if err := acc.Validate(); err != nil {
			return fmt.Errorf("invalid account found in genesis state; address: %s, error: %s", addrStr, err.Error())
		}
	}
	return nil
}
```

**File:** x/evidence/module.go (L68-75)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return gs.Validate()
}
```

**File:** x/evidence/genesis.go (L17-32)
```go
func InitGenesis(ctx sdk.Context, k keeper.Keeper, gs *types.GenesisState) {
	if err := gs.Validate(); err != nil {
		panic(fmt.Sprintf("failed to validate %s genesis state: %s", types.ModuleName, err))
	}

	for _, e := range gs.Evidence {
		evi, ok := e.GetCachedValue().(exported.Evidence)
		if !ok {
			panic("expected evidence")
		}
		if _, ok := k.GetEvidence(ctx, evi.Hash()); ok {
			panic(fmt.Sprintf("evidence with hash %s already exists", evi.Hash()))
		}

		k.SetEvidence(ctx, evi)
	}
```

**File:** x/genutil/client/cli/validate_genesis.go (L60-62)
```go
			if err = mbm.ValidateGenesis(cdc, clientCtx.TxConfig, genState); err != nil {
				return fmt.Errorf("error validating genesis file %s: %s", genesis, err.Error())
			}
```
