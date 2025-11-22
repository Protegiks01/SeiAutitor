## Audit Report

## Title
Evidence Data Loss in v0.40 Genesis Migration Due to Wrong Module Reference

## Summary
The v0.40 genesis migration code contains a critical bug where it reads from the wrong module when migrating evidence data. Line 119 of `x/genutil/legacy/v040/migrate.go` unmarshals evidence genesis state from `appState[v038bank.ModuleName]` instead of `appState[v038evidence.ModuleName]`, causing all validator misbehavior evidence to be permanently lost during chain upgrades from v0.39 to v0.42. [1](#0-0) 

## Impact
High

## Finding Description

**Location:**
- Module: `x/genutil/legacy/v040`
- File: `migrate.go`
- Function: `Migrate`
- Line: 119

**Intended Logic:**
During genesis migration from v0.39 to v0.40/v0.42, the evidence module migration should unmarshal the evidence genesis state from the evidence module's data in `appState[v038evidence.ModuleName]`, then migrate validator equivocation records to the new format.

**Actual Logic:**
The code incorrectly unmarshals from `appState[v038bank.ModuleName]` (bank module) instead of `appState[v038evidence.ModuleName]` (evidence module). Since the bank v038 GenesisState structure is `{SendEnabled: bool}` while evidence expects `{Params: Params, Evidence: []Evidence}`, the unmarshal produces an empty/default evidence genesis state with no records. The original evidence data is then deleted without ever being read. [2](#0-1) 

**Exploit Scenario:**
1. A Cosmos SDK chain running v0.39 has recorded evidence of validator double-signing in its genesis state
2. Chain operators initiate an upgrade to v0.42 using the migration command: `simd migrate v0.42 genesis.json`
3. The migration tool calls `v040.Migrate()` which processes each module
4. When processing the evidence module, line 119 reads bank module data instead of evidence module data
5. The Amino codec unmarshals incompatible data types, producing an empty evidence genesis state
6. Line 122 deletes the original evidence module data
7. Line 126 writes the empty migrated evidence state to the new genesis
8. All validator misbehavior records are permanently lost
9. Malicious validators who should have been slashed escape punishment [3](#0-2) 

**Security Failure:**
- **Data Integrity Loss:** Critical security records (validator double-signing evidence) are permanently deleted without migration
- **Accountability Bypass:** Validators who committed slashable offenses before the upgrade are no longer tracked
- **Security Degradation:** The chain loses its enforcement mechanism for pre-upgrade validator misbehavior

## Impact Explanation

**Affected Assets:**
- All validator equivocation evidence (double-signing records) stored in v0.39 genesis
- Evidence module parameters and historical security data
- Chain security guarantees and validator accountability

**Severity:**
- **Permanent data loss:** Evidence cannot be recovered after migration completes
- **Validator accountability failure:** Malicious validators escape slashing and can continue operating
- **Security policy violation:** The chain's security enforcement for the pre-upgrade period is completely disabled
- **Consensus risk:** If validators knew about this bug, they could intentionally double-sign before an upgrade

**Why This Matters:**
The evidence module is critical for Cosmos SDK chain security. It tracks validator misbehavior (primarily double-signing/equivocation) and ensures validators are slashed for malicious behavior. Losing this data means:
1. Byzantine validators escape punishment for pre-upgrade misbehavior
2. The chain cannot enforce its security policies across upgrades
3. Historical security analysis becomes impossible
4. Trust in the chain's validator accountability is compromised [4](#0-3) 

## Likelihood Explanation

**Who Can Trigger:**
Any chain operator performing a legitimate v0.39→v0.42 genesis migration using the official migration tool. This is not an attack but a critical bug in normal upgrade procedures.

**Conditions:**
- Chain must have evidence module state in v0.39 genesis (standard for all Cosmos SDK chains)
- Must use `simd migrate v0.42` command for genesis upgrade
- Both bank and evidence modules present (standard configuration)

**Frequency:**
- Triggers on **every** v0.39→v0.42 migration where evidence exists
- This was a common upgrade path for Cosmos SDK chains during the v0.40-v0.42 era
- Impact is permanent once migration completes

**Detection Difficulty:**
- Very difficult to detect: Migration completes "successfully" with no errors
- No warnings, panics, or failures occur
- Only detectable by manually comparing evidence counts before/after migration
- Operators typically don't verify evidence preservation during upgrades [5](#0-4) 

## Recommendation

**Immediate Fix:**
Change line 119 to read from the correct module:
```
v039Codec.MustUnmarshalJSON(appState[v038evidence.ModuleName], &evidenceGenState)
```

**Additional Safeguards:**
1. Add integration tests verifying evidence preservation across migrations
2. Add validation comparing record counts before/after migration
3. Log warnings if critical module data is unexpectedly empty
4. Add migration verification steps for data integrity

**For Already-Migrated Chains:**
1. Check if evidence existed in pre-migration genesis backups
2. Assess whether validators should have been slashed based on lost evidence
3. Consider re-importing evidence from backups if available
4. Document the data loss for transparency

## Proof of Concept

**File:** `x/genutil/legacy/v040/migrate_test.go` (new file)

**Test Function:** `TestEvidenceMigrationDataLoss`

**Setup:**
1. Create a v0.39 genesis state with both bank and evidence modules populated
2. Bank module contains: `{send_enabled: true}`
3. Evidence module contains: validator equivocation record with specific height, power, and consensus address
4. Initialize v039 and v040 codecs

**Trigger:**
1. Call `v040.Migrate(appState, clientCtx)` with the populated genesis state
2. The migration will execute the buggy evidence migration code

**Observation:**
1. Check the migrated evidence module state
2. Verify it contains **zero** evidence records (should contain 1)
3. Compare with expected output - the equivocation should be present but will be missing
4. This demonstrates the evidence data is lost during migration

**Test Code:**
```go
func TestEvidenceMigrationDataLoss(t *testing.T) {
    encodingConfig := simapp.MakeTestEncodingConfig()
    clientCtx := client.Context{}.
        WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
        WithCodec(encodingConfig.Marshaler)
    
    v039Codec := codec.NewLegacyAmino()
    v039auth.RegisterLegacyAminoCodec(v039Codec)
    
    // Create v038 genesis with evidence
    addr1, _ := sdk.AccAddressFromBech32("cosmos1xxkueklal9vejv9unqu80w9vptyepfa95pd53u")
    evidenceGenState := v038evidence.GenesisState{
        Params: v038evidence.Params{MaxEvidenceAge: v038evidence.DefaultMaxEvidenceAge},
        Evidence: []v038evidence.Evidence{v038evidence.Equivocation{
            Height:           100,
            Power:            5000,
            ConsensusAddress: addr1.Bytes(),
        }},
    }
    
    bankGenState := v038bank.GenesisState{SendEnabled: true}
    
    appState := types.AppMap{
        v038evidence.ModuleName: v039Codec.MustMarshalJSON(evidenceGenState),
        v038bank.ModuleName:     v039Codec.MustMarshalJSON(bankGenState),
    }
    
    // Run migration
    migratedState := v040.Migrate(appState, clientCtx)
    
    // Check evidence in migrated state
    var migratedEvidence v040evidence.GenesisState
    clientCtx.Codec.MustUnmarshalJSON(migratedState[v040evidence.ModuleName], &migratedEvidence)
    
    // BUG: Evidence should contain 1 record but will be empty
    require.Equal(t, 1, len(migratedEvidence.Evidence), 
        "Evidence data lost during migration - expected 1 equivocation record but got 0")
}
```

**Expected Result:** Test **fails** because `len(migratedEvidence.Evidence)` is 0 instead of 1, proving the evidence data was lost during migration.

This PoC demonstrates that validator misbehavior evidence is completely lost when migrating from v0.39 to v0.42, representing a **High severity** vulnerability affecting chain security and validator accountability.

### Citations

**File:** x/genutil/legacy/v040/migrate.go (L115-127)
```go
	// Migrate x/evidence.
	if appState[v038evidence.ModuleName] != nil {
		// unmarshal relative source genesis application state
		var evidenceGenState v038evidence.GenesisState
		v039Codec.MustUnmarshalJSON(appState[v038bank.ModuleName], &evidenceGenState)

		// delete deprecated x/evidence genesis state
		delete(appState, v038evidence.ModuleName)

		// Migrate relative source genesis application state and marshal it into
		// the respective key.
		appState[v040evidence.ModuleName] = v040Codec.MustMarshalJSON(v040evidence.Migrate(evidenceGenState))
	}
```

**File:** x/evidence/legacy/v038/types.go (L61-77)
```go
// GenesisState defines the evidence module's genesis state.
type GenesisState struct {
	Params   Params     `json:"params" yaml:"params"`
	Evidence []Evidence `json:"evidence" yaml:"evidence"`
}

// Assert interface implementation.
var _ Evidence = Equivocation{}

// Equivocation implements the Evidence interface and defines evidence of double
// signing misbehavior.
type Equivocation struct {
	Height           int64           `json:"height" yaml:"height"`
	Time             time.Time       `json:"time" yaml:"time"`
	Power            int64           `json:"power" yaml:"power"`
	ConsensusAddress sdk.ConsAddress `json:"consensus_address" yaml:"consensus_address"`
}
```

**File:** x/genutil/client/cli/migrate.go (L26-28)
```go
var migrationMap = types.MigrationMap{
	"v0.42": v040.Migrate, // NOTE: v0.40, v0.41 and v0.42 are genesis compatible.
	"v0.43": v043.Migrate,
```
