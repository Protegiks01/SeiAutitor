# Audit Report

## Title
Genesis Validation Bypass Allows Expedited Proposals to be Easier to Pass Than Regular Proposals

## Summary
The genesis validation function fails to check the return value of `validateTallyParams`, allowing invalid governance parameters to be set during chain initialization. This bypasses the critical validation at line 187-189 that ensures expedited proposals have stricter voting thresholds than regular proposals, enabling configurations where expedited proposals are easier to pass.

## Impact
High

## Finding Description

**Location:** 
The vulnerability exists in the `ValidateGenesis` function in [1](#0-0) 

**Intended Logic:**
The governance module implements expedited proposals as a fast-track mechanism that should have stricter requirements than regular proposals. The validation function `validateTallyParams` at [2](#0-1)  explicitly checks that `ExpeditedThreshold` must be strictly greater than `Threshold`, ensuring expedited proposals require a higher percentage of YES votes to pass.

**Actual Logic:**
At line 54 of `genesis.go`, the code calls `validateTallyParams(data.TallyParams)` but ignores its return value: [3](#0-2) 

This means even when `validateTallyParams` returns an error (because `ExpeditedThreshold <= Threshold`), the genesis validation passes. The error from the threshold validation check is silently discarded, and invalid parameters are accepted.

**Exploit Scenario:**
1. An entity controlling the genesis file (during chain initialization or genesis migration) creates a `GenesisState` with invalid tally parameters:
   - `Threshold = 0.67` (67% YES votes required for regular proposals)
   - `ExpeditedThreshold = 0.50` (50% YES votes required for expedited proposals)
2. The genesis validation calls `validateTallyParams` which would return an error at line 187-189 because `0.50 <= 0.67`
3. However, since the error is not checked at line 54, the validation succeeds
4. The chain initializes with these invalid parameters via [4](#0-3) 
5. Now expedited proposals only need 50% YES votes while regular proposals need 67%, making expedited proposals easier to pass

**Security Failure:**
This breaks the fundamental security invariant of the governance system that expedited proposals must have equal or stricter requirements than regular proposals. The tally logic at [5](#0-4)  will use these invalid thresholds, allowing expedited proposals to pass with less consensus than intended.

## Impact Explanation

This vulnerability affects the governance mechanism which controls critical protocol parameters, upgrades, and fund allocations. The impacts include:

- **Governance Integrity Compromise:** Expedited proposals, meant for urgent matters with stricter consensus requirements, can be approved with LESS support than regular proposals
- **Unintended Protocol Changes:** Malicious or poorly vetted proposals can pass more easily through the expedited track, potentially leading to protocol parameter changes, upgrades, or fund transfers that lack sufficient community consensus
- **Chain Initialization Risk:** During chain genesis or major upgrades requiring genesis migration, invalid parameters can be embedded permanently into the chain state
- **Violation of Design Principles:** The expedited proposal mechanism is designed with higher deposit requirements [6](#0-5) , higher quorum [7](#0-6) , and higher threshold [8](#0-7)  to ensure urgent proposals still meet strict consensus. This vulnerability defeats that purpose.

This constitutes a **Medium** severity issue under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - as it affects the governance layer's behavior and could lead to unintended protocol changes.

## Likelihood Explanation

**Who can trigger it:**
- Chain operators during initial chain launch
- Validators/governance during chain upgrades that involve genesis export/import
- Anyone who can influence the genesis file before chain initialization

**Conditions required:**
- Occurs during chain initialization via `InitGenesis` 
- Requires the genesis file to contain invalid tally parameters
- After genesis is loaded, parameters can only be changed via governance proposals, which DO enforce validation properly through [9](#0-8) 

**Frequency:**
- One-time during chain initialization or major upgrades
- High impact if exploited, as the invalid parameters become embedded in the chain state
- While not frequent, chain launches and major upgrades are critical moments where this could be exploited

## Recommendation

Fix the genesis validation by properly checking the return value of `validateTallyParams`:

```go
// In x/gov/types/genesis.go, replace line 54:
if err := validateTallyParams(data.TallyParams); err != nil {
    return err
}
```

This ensures that the same validation logic enforced during parameter updates via governance proposals is also enforced during genesis initialization.

## Proof of Concept

**File:** `x/gov/types/genesis_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func TestValidateGenesis_InvalidTallyParams(t *testing.T) {
    // Setup: Create a genesis state with invalid tally params
    // where expedited threshold is LESS than regular threshold
    invalidTallyParams := TallyParams{
        Quorum:             sdk.NewDecWithPrec(334, 3), // 0.334
        ExpeditedQuorum:    sdk.NewDecWithPrec(667, 3), // 0.667 (valid, higher than Quorum)
        Threshold:          sdk.NewDecWithPrec(667, 3), // 0.667
        ExpeditedThreshold: sdk.NewDecWithPrec(500, 3), // 0.500 (INVALID: less than Threshold!)
        VetoThreshold:      sdk.NewDecWithPrec(334, 3), // 0.334
    }
    
    genesisState := &GenesisState{
        StartingProposalId: 1,
        DepositParams:      DefaultDepositParams(),
        VotingParams:       DefaultVotingParams(),
        TallyParams:        invalidTallyParams,
    }
    
    // Trigger: Call ValidateGenesis with invalid params
    err := ValidateGenesis(genesisState)
    
    // Observation: The validation should FAIL but currently PASSES
    // This test will PASS on the vulnerable code (proving the bug exists)
    // because ValidateGenesis incorrectly returns nil for invalid params
    require.Nil(t, err) // This incorrectly passes, demonstrating the vulnerability
    
    // The CORRECT behavior would be:
    // require.Error(t, err)
    // require.Contains(t, err.Error(), "must be greater than the regular threshold")
}
```

**Setup:** The test creates a `GenesisState` with tally parameters where `ExpeditedThreshold` (0.500) is less than `Threshold` (0.667), which violates the validation rule at params.go:187-189.

**Trigger:** The test calls `ValidateGenesis` with this invalid genesis state.

**Observation:** The test currently passes with `require.Nil(t, err)`, demonstrating that ValidateGenesis incorrectly accepts invalid parameters. The correct behavior would be to return an error. This proves that the validation at line 54 of genesis.go is not functioning as intended because it doesn't check the return value of `validateTallyParams`.

To verify the fix works correctly, change the last assertion to `require.Error(t, err)` after implementing the recommendation. The test will then properly fail on the vulnerable code and pass on the fixed code.

### Citations

**File:** x/gov/types/genesis.go (L44-73)
```go
// ValidateGenesis checks if parameters are within valid ranges
func ValidateGenesis(data *GenesisState) error {
	if data == nil {
		return fmt.Errorf("governance genesis state cannot be nil")
	}

	if data.Empty() {
		return fmt.Errorf("governance genesis state cannot be nil")
	}

	validateTallyParams(data.TallyParams)

	if !data.DepositParams.MinDeposit.IsValid() {
		return fmt.Errorf("governance deposit amount must be a valid sdk.Coins amount, is %s",
			data.DepositParams.MinDeposit.String())
	}

	if !data.DepositParams.MinExpeditedDeposit.IsValid() {
		return fmt.Errorf("governance min expedited deposit amount must be a valid sdk.Coins amount, is %s",
			data.DepositParams.MinExpeditedDeposit.String())
	}

	if data.DepositParams.MinExpeditedDeposit.IsAllLTE(data.DepositParams.MinDeposit) {
		return fmt.Errorf("governance min expedited deposit amount %s must be greater than regular min deposit %s",
			data.DepositParams.MinExpeditedDeposit.String(),
			data.DepositParams.MinDeposit.String())
	}

	return nil
}
```

**File:** x/gov/types/params.go (L22-22)
```go
	DefaultMinExpeditedDepositTokens = sdk.NewInt(20000000)
```

**File:** x/gov/types/params.go (L24-24)
```go
	DefaultExpeditedQuorum           = sdk.NewDecWithPrec(667, 3)
```

**File:** x/gov/types/params.go (L26-26)
```go
	DefaultExpeditedThreshold        = sdk.NewDecWithPrec(667, 3)
```

**File:** x/gov/types/params.go (L187-189)
```go
	if v.ExpeditedThreshold.LTE(v.Threshold) {
		return fmt.Errorf("expedited vote threshold %s, must be greater than the regular threshold %s", v.ExpeditedThreshold, v.Threshold)
	}
```

**File:** x/gov/genesis.go (L16-16)
```go
	k.SetTallyParams(ctx, data.TallyParams)
```

**File:** x/gov/keeper/tally.go (L118-121)
```go
	voteYesThreshold := tallyParams.GetThreshold(proposal.IsExpedited)
	if results[types.OptionYes].Quo(totalVotingPower.Sub(results[types.OptionAbstain])).GT(voteYesThreshold) {
		return true, false, tallyResults
	}
```

**File:** x/params/types/subspace.go (L213-214)
```go
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
```
