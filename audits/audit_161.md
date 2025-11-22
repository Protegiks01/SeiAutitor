## Audit Report

## Title
Genesis Validation Allows Duplicate Capability Indices Leading to Silent Owner Overwriting

## Summary
The `Validate()` function in the capability module's genesis validation fails to check for duplicate indices in the `Owners` array. This allows a genesis state with duplicate indices to pass validation and be imported during `InitGenesis`, causing the last entry to silently overwrite previous owners for the same index, resulting in permanent loss of capability ownership for affected modules. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- Validation logic: `x/capability/types/genesis.go`, function `Validate()` (lines 21-49)
- Genesis initialization: `x/capability/genesis.go`, function `InitGenesis()` (lines 11-22)

**Intended Logic:** 
The genesis validation should ensure that all capability indices in the imported genesis state are unique and valid. Each capability index should map to exactly one set of owners. The validation is supposed to catch any malformed genesis data before it gets imported into the chain state.

**Actual Logic:** 
The `Validate()` function only checks that each index falls within the range [1, gs.Index) but does not verify uniqueness of indices across the `Owners` array. [2](#0-1) 

During `InitGenesis`, the code iterates through all `genState.Owners` and calls `SetOwners` for each entry: [3](#0-2) 

The `SetOwners` function unconditionally writes to the store: [4](#0-3) 

If duplicate indices exist, later entries overwrite earlier ones without any warning or error.

**Exploit Scenario:**
1. During a chain upgrade or genesis migration, an operator exports the genesis state
2. A tool bug, manual editing error, or genesis state merge introduces duplicate indices (e.g., two `GenesisOwners` entries both have `Index: 5`)
3. The genesis file is validated using `ValidateGenesis`, which calls `Validate()`
4. The validation passes because each index individually is within range [1, gs.Index)
5. `InitGenesis` is called during chain initialization
6. For the duplicate index 5, `SetOwners` is called twice:
   - First call: stores owners from first entry
   - Second call: overwrites with owners from second entry
7. The first set of owners is permanently lost from the chain state
8. Modules expecting to own that capability can no longer access it

**Security Failure:**
This breaks the **state integrity invariant** - the capability ownership state becomes corrupted and inconsistent with what was intended to be imported. Modules that should have capability ownership lose access, potentially breaking critical functionality like IBC port capabilities or inter-module communication.

## Impact Explanation

**Affected Assets/Processes:**
- Capability ownership mappings in the capability module
- IBC port capabilities (if IBC module loses port ownership)
- Inter-module capability-based permissions and communication

**Severity of Damage:**
- Modules can permanently lose capability ownership without any indication
- IBC connections could become non-functional if IBC port capabilities are affected
- Transactions requiring the lost capabilities would fail
- The chain may not be able to process certain types of transactions
- Recovery would require manual intervention, potentially a coordinated upgrade or hard fork to fix the capability mappings

**System Impact:**
This qualifies as **"A bug in the layer 1 network code that results in unintended smart contract behavior with no concrete funds at direct risk"** (Medium severity). In severe cases where critical capabilities like IBC ports are lost, it could escalate to **"Network not being able to confirm new transactions"** if those capabilities are essential for transaction processing.

## Likelihood Explanation

**Who Can Trigger:**
This can be triggered accidentally by chain operators during:
- Chain upgrades when genesis state is exported and re-imported
- Manual genesis file editing during chain migration
- Tool bugs in genesis generation or manipulation utilities
- Merging genesis states from multiple sources

**Conditions Required:**
- A genesis file with duplicate capability indices must be created (accidentally or through tooling bugs)
- The genesis validation is performed (which incorrectly passes)
- Chain initialization proceeds with the corrupted genesis state

**Frequency:**
While not frequent in normal operation, this is a real risk during:
- Major chain upgrades (happens periodically)
- Network forks or migrations
- Genesis state manipulations for testing or development that accidentally make it to production

The likelihood is **moderate** because it requires genesis manipulation, but the consequences are severe and the validation bug makes it easy for such errors to slip through undetected.

## Recommendation

Add a duplicate index check in the `Validate()` function in `x/capability/types/genesis.go`:

```go
func (gs GenesisState) Validate() error {
	// NOTE: index must be greater than 0
	if gs.Index == 0 {
		return fmt.Errorf("capability index must be non-zero")
	}

	// Track seen indices to detect duplicates
	seenIndices := make(map[uint64]bool)

	for _, genOwner := range gs.Owners {
		if len(genOwner.IndexOwners.Owners) == 0 {
			return fmt.Errorf("empty owners in genesis")
		}

		// Check for duplicate indices
		if seenIndices[genOwner.Index] {
			return fmt.Errorf("duplicate capability index %d in genesis", genOwner.Index)
		}
		seenIndices[genOwner.Index] = true

		// all exported existing indices must be between [1, gs.Index)
		if genOwner.Index == 0 || genOwner.Index >= gs.Index {
			return fmt.Errorf("owners exist for index %d outside of valid range: %d-%d", genOwner.Index, 1, gs.Index-1)
		}

		for _, owner := range genOwner.IndexOwners.Owners {
			if strings.TrimSpace(owner.Module) == "" {
				return fmt.Errorf("owner's module cannot be blank: %s", owner)
			}

			if strings.TrimSpace(owner.Name) == "" {
				return fmt.Errorf("owner's name cannot be blank: %s", owner)
			}
		}
	}

	return nil
}
```

## Proof of Concept

**File:** `x/capability/types/genesis_test.go`

**Test Function:** Add the following test case to the `TestValidateGenesis` function's test cases array:

```go
{
	name: "duplicate indices",
	malleate: func(genState *GenesisState) {
		genState.Index = 10
		genOwner1 := GenesisOwners{
			Index:       5,
			IndexOwners: CapabilityOwners{[]Owner{{Module: "ibc", Name: "port/transfer"}}},
		}
		genOwner2 := GenesisOwners{
			Index:       5,
			IndexOwners: CapabilityOwners{[]Owner{{Module: "bank", Name: "port/bank"}}},
		}
		genState.Owners = append(genState.Owners, genOwner1, genOwner2)
	},
	expPass: false,
},
```

**Setup:** The test uses the existing `TestValidateGenesis` framework which creates a default genesis state and applies malleation functions.

**Trigger:** The test creates a genesis state with two `GenesisOwners` entries that both have `Index: 5`, then calls `genState.Validate()`.

**Observation:** 
- **Current behavior (vulnerable):** The test will **PASS** (expPass: false will fail) because `Validate()` currently returns no error for duplicate indices
- **Expected behavior (after fix):** The test should correctly detect the duplicate and return an error

To demonstrate the state corruption in `InitGenesis`, add this additional test to `x/capability/genesis_test.go`:

```go
func (suite *CapabilityTestSuite) TestInitGenesisDuplicateIndices() {
	// Create genesis state with duplicate indices
	genState := types.GenesisState{
		Index: 10,
		Owners: []types.GenesisOwners{
			{
				Index: 5,
				IndexOwners: types.CapabilityOwners{
					Owners: []types.Owner{{Module: "ibc", Name: "port/transfer"}},
				},
			},
			{
				Index: 5,
				IndexOwners: types.CapabilityOwners{
					Owners: []types.Owner{{Module: "bank", Name: "port/bank"}},
				},
			},
		},
	}

	// Validation incorrectly passes (demonstrates the bug)
	err := genState.Validate()
	suite.Require().NoError(err, "validation should fail but doesn't - this demonstrates the bug")

	// Initialize genesis with duplicate indices
	capability.InitGenesis(suite.ctx, *suite.keeper, genState)

	// Check which owners were actually stored for index 5
	owners, ok := suite.keeper.GetOwners(suite.ctx, 5)
	suite.Require().True(ok)

	// This demonstrates the bug: only the LAST entry's owners are stored
	// The first entry (ibc module) was silently overwritten
	suite.Require().Equal(1, len(owners.Owners), "expected 1 owner")
	suite.Require().Equal("bank", owners.Owners[0].Module, "only the last duplicate entry's owner is stored")
	
	// The IBC module's ownership was lost - this is the security issue
	// In a real scenario, this could break IBC functionality
}
```

This test demonstrates that duplicate indices bypass validation and cause silent state corruption where the last duplicate entry overwrites all previous ones for the same index.

### Citations

**File:** x/capability/types/genesis.go (L21-49)
```go
func (gs GenesisState) Validate() error {
	// NOTE: index must be greater than 0
	if gs.Index == 0 {
		return fmt.Errorf("capability index must be non-zero")
	}

	for _, genOwner := range gs.Owners {
		if len(genOwner.IndexOwners.Owners) == 0 {
			return fmt.Errorf("empty owners in genesis")
		}

		// all exported existing indices must be between [1, gs.Index)
		if genOwner.Index == 0 || genOwner.Index >= gs.Index {
			return fmt.Errorf("owners exist for index %d outside of valid range: %d-%d", genOwner.Index, 1, gs.Index-1)
		}

		for _, owner := range genOwner.IndexOwners.Owners {
			if strings.TrimSpace(owner.Module) == "" {
				return fmt.Errorf("owner's module cannot be blank: %s", owner)
			}

			if strings.TrimSpace(owner.Name) == "" {
				return fmt.Errorf("owner's name cannot be blank: %s", owner)
			}
		}
	}

	return nil
}
```

**File:** x/capability/genesis.go (L16-19)
```go
	// set owners for each index
	for _, genOwner := range genState.Owners {
		k.SetOwners(ctx, genOwner.Index, genOwner.IndexOwners)
	}
```

**File:** x/capability/keeper/keeper.go (L167-174)
```go
// SetOwners set the capability owners to the store
func (k Keeper) SetOwners(ctx sdk.Context, index uint64, owners types.CapabilityOwners) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(index)

	// set owners in persistent store
	prefixStore.Set(indexKey, k.cdc.MustMarshal(&owners))
}
```
