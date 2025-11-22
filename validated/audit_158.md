# Audit Report

## Title
Genesis Validation Bypass Allows Invalid Governance Parameters During Chain Initialization

## Summary
The `ValidateGenesis` function in the governance module fails to check the return value of `validateTallyParams`, allowing invalid tally parameters to be set during chain initialization. This bypasses critical validation that ensures expedited proposals have stricter voting thresholds than regular proposals.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:**
The governance module is designed to enforce that expedited proposals (fast-track urgent proposals) must have equal or stricter requirements than regular proposals. The validation function `validateTallyParams` at [2](#0-1)  explicitly checks that `ExpeditedThreshold` must be strictly greater than `Threshold` to ensure this invariant.

**Actual logic:**
At line 54 of genesis.go, the code calls `validateTallyParams(data.TallyParams)` but ignores its return value. This means even when the validation function returns an error (because `ExpeditedThreshold <= Threshold`), the genesis validation succeeds and accepts invalid parameters. The error is silently discarded.

**Exploitation path:**
1. During chain initialization or genesis migration, a genesis file is created with invalid tally parameters (e.g., `Threshold = 0.67`, `ExpeditedThreshold = 0.50`)
2. The `validate-genesis` CLI command is run to validate the genesis file
3. `ValidateGenesis` is called at [3](#0-2) , which calls the buggy validation
4. Despite `validateTallyParams` returning an error, the validation passes because the return value is not checked
5. The chain initializes via `InitGenesis` at [4](#0-3) 
6. Invalid parameters are set via [5](#0-4)  using [6](#0-5) , which uses [7](#0-6)  that does NOT validate (unlike the `Update` method at [8](#0-7)  which does validate)
7. The tally logic at [9](#0-8)  will use these invalid thresholds, allowing expedited proposals to pass with less consensus than regular proposals

**Security guarantee broken:**
The fundamental governance invariant that expedited proposals require equal or stricter thresholds than regular proposals is violated. This compromises the integrity of the governance mechanism that controls protocol parameters, upgrades, and fund allocations.

## Impact Explanation

This vulnerability affects governance integrity by allowing expedited proposals to be configured with lower voting thresholds than regular proposals, contrary to their design. This could lead to:

- **Governance compromise:** Expedited proposals meant for urgent matters with stricter consensus can be approved with LESS community support than regular proposals
- **Unintended protocol changes:** Proposals can pass more easily through the expedited track without sufficient consensus
- **Persistent invalid state:** Once embedded during chain initialization, these parameters become part of the chain state and persist until changed via governance (which itself may be compromised)

This constitutes a Medium severity issue under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" as it affects the governance layer's behavior and could enable unintended protocol changes.

## Likelihood Explanation

**Who can trigger it:**
- Chain operators during initial chain launch
- Validators coordinating genesis parameters during chain initialization
- Anyone who can influence the genesis file before chain initialization

**Conditions required:**
- Occurs during chain initialization when the genesis file contains invalid tally parameters
- The broken validation in the `validate-genesis` command fails to catch the error
- Once the chain starts, parameters can only be changed via governance proposals (which DO enforce proper validation through the `Update` method)

**Frequency:**
Chain initialization and major upgrades requiring genesis export/import are critical but infrequent events. However, the impact is high when it occurs because the invalid parameters become embedded in the chain state. The broken safety mechanism (validation command) means even careful operators following best practices won't detect this issue.

## Recommendation

Fix the genesis validation by properly checking the return value of `validateTallyParams`:

```go
// In x/gov/types/genesis.go, replace line 54:
if err := validateTallyParams(data.TallyParams); err != nil {
    return err
}
```

This ensures that the same validation logic enforced during parameter updates via governance proposals is also enforced during genesis initialization. Additionally, consider adding integration tests that specifically verify the validation catches invalid tally parameter combinations.

## Proof of Concept

**File:** `x/gov/types/genesis_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestValidateGenesis_InvalidTallyParams(t *testing.T) {
    // Setup: Create genesis state with invalid tally params where
    // expedited threshold is LESS than regular threshold
    invalidTallyParams := TallyParams{
        Quorum:             sdk.NewDecWithPrec(334, 3), // 0.334
        ExpeditedQuorum:    sdk.NewDecWithPrec(667, 3), // 0.667
        Threshold:          sdk.NewDecWithPrec(667, 3), // 0.667
        ExpeditedThreshold: sdk.NewDecWithPrec(500, 3), // 0.500 (INVALID!)
        VetoThreshold:      sdk.NewDecWithPrec(334, 3), // 0.334
    }
    
    genesisState := &GenesisState{
        StartingProposalId: 1,
        DepositParams:      DefaultDepositParams(),
        VotingParams:       DefaultVotingParams(),
        TallyParams:        invalidTallyParams,
    }
    
    // Action: Call ValidateGenesis with invalid params
    err := ValidateGenesis(genesisState)
    
    // Result: Validation incorrectly passes (should fail)
    // On vulnerable code: err == nil (bug demonstrated)
    // After fix: err != nil with message about threshold
    require.Error(t, err) // This will FAIL on current code, PASS after fix
    require.Contains(t, err.Error(), "must be greater than the regular threshold")
}
```

**Setup:** Creates a `GenesisState` with `ExpeditedThreshold` (0.500) less than `Threshold` (0.667), violating the validation rule at [2](#0-1) 

**Action:** Calls `ValidateGenesis` with the invalid genesis state

**Result:** Currently, the test fails because `ValidateGenesis` incorrectly returns nil (no error) instead of returning the validation error. After implementing the fix, this test will pass, properly rejecting invalid genesis parameters.

## Notes

This vulnerability exists specifically in the genesis validation path. The parameter update path via governance proposals correctly enforces validation through the `Update` method in the params subspace. The issue is that the safety mechanism designed to catch operator errors during chain initialization (the `validate-genesis` command) is broken due to the unchecked return value, allowing invalid governance parameters to persist in chain state.

### Citations

**File:** x/gov/types/genesis.go (L54-54)
```go
	validateTallyParams(data.TallyParams)
```

**File:** x/gov/types/params.go (L187-189)
```go
	if v.ExpeditedThreshold.LTE(v.Threshold) {
		return fmt.Errorf("expedited vote threshold %s, must be greater than the regular threshold %s", v.ExpeditedThreshold, v.Threshold)
	}
```

**File:** x/gov/module.go (L72-72)
```go
	return types.ValidateGenesis(&data)
```

**File:** simapp/app.go (L598-598)
```go
	return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
```

**File:** x/gov/genesis.go (L16-16)
```go
	k.SetTallyParams(ctx, data.TallyParams)
```

**File:** x/gov/keeper/params.go (L40-41)
```go
func (keeper Keeper) SetTallyParams(ctx sdk.Context, tallyParams types.TallyParams) {
	keeper.paramSpace.Set(ctx, types.ParamStoreKeyTallyParams, &tallyParams)
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

**File:** x/params/types/subspace.go (L213-214)
```go
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
```

**File:** x/gov/keeper/tally.go (L118-119)
```go
	voteYesThreshold := tallyParams.GetThreshold(proposal.IsExpedited)
	if results[types.OptionYes].Quo(totalVotingPower.Sub(results[types.OptionAbstain])).GT(voteYesThreshold) {
```
