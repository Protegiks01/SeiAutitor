## Audit Report

## Title
Genesis Validation Bypass Allows Expedited Quorum to be Lower Than Regular Quorum

## Summary
The `ValidateGenesis` function in the governance module fails to check the error returned by `validateTallyParams`, allowing a genesis file with invalid `TallyParams` to be loaded where `ExpeditedQuorum` can be set lower than or equal to the regular `Quorum`. This bypasses the critical validation check at lines 172-174 of params.go and inverts the governance security model. [1](#0-0) 

## Impact
**Medium** - A bug in the layer 1 network code that results in unintended governance behavior with no concrete funds at direct risk, but fundamentally breaks the protocol's governance security assumptions.

## Finding Description

**Location:** 
- Vulnerable code: [1](#0-0) 
- Bypassed validation: [2](#0-1) 
- Governance tally logic: [3](#0-2) 

**Intended Logic:** 
The validation function `validateTallyParams` is designed to enforce that expedited proposals require strictly higher quorum than regular proposals [2](#0-1) . This ensures expedited proposals (which have shorter voting periods) maintain higher security requirements. The function returns an error when `ExpeditedQuorum <= Quorum`.

**Actual Logic:** 
In the genesis validation flow, the code calls `validateTallyParams(data.TallyParams)` but completely ignores the error return value [1](#0-0) . This means all validation errors, including the critical check that expedited quorum must be greater than regular quorum, are silently discarded during chain initialization.

**Exploit Scenario:**
1. A malicious chain operator or attacker who can influence the genesis file creates a `genesis.json` with invalid `TallyParams` where `ExpeditedQuorum < Quorum` (e.g., `ExpeditedQuorum=0.200`, `Quorum=0.334`)
2. The chain is initialized with this genesis file
3. The module's `ValidateGenesis` is called [4](#0-3) , which internally calls `types.ValidateGenesis`
4. The error from `validateTallyParams` is not checked, so validation passes
5. `InitGenesis` is called and loads the invalid parameters into chain state [5](#0-4) 
6. The tally logic now uses the inverted quorum values [3](#0-2) 

**Security Failure:** 
This breaks the governance security invariant that expedited proposals should have stricter requirements than regular proposals. With inverted quorum values, expedited proposals become easier to pass than regular proposals, despite having shorter voting periods. This undermines the protocol's governance security model and community consensus requirements.

## Impact Explanation

**Affected Processes:**
- All governance proposal voting and tallying
- Community consensus mechanisms
- Protocol parameter changes and upgrades

**Severity:**
- Expedited proposals can pass with significantly less community participation than regular proposals
- Since expedited proposals have shorter voting periods (1 day vs 2 days by default) [6](#0-5) , combining this with lower quorum makes them a prime attack vector
- Any governance action (parameter changes, upgrades, fund transfers) can be rushed through with minimal oversight
- Once the chain starts with these invalid parameters, they govern all future proposals, and can only be changed through governance proposals that are themselves subject to the broken rules

**System Impact:**
This inverts the fundamental security assumption of the governance system. Instead of expedited proposals requiring 66.7% participation (default) vs 33.4% for regular proposals [7](#0-6) , an attacker could configure expedited proposals to require only 20% participation while regular proposals require 33.4%, making fast-tracked proposals easier to manipulate.

## Likelihood Explanation

**Who can trigger it:**
Any party that can control or influence the genesis file during chain initialization. This includes:
- Chain operators during initial launch
- Validators coordinating a new network
- Attackers who compromise the genesis file distribution process

**Conditions required:**
- Must occur during chain initialization (genesis)
- Requires the ability to specify custom genesis parameters
- The chain must be starting fresh (not from an existing state)

**Frequency:**
- This occurs during every chain initialization with a maliciously crafted or misconfigured genesis file
- Cannot be exploited after chain start, but the damage persists permanently once the chain is running
- Relatively common scenario for new chains, testnets, or chain forks

**Likelihood:** Medium to High for new chain deployments, as genesis file creation is a common operation and this validation failure is not obvious during setup.

## Recommendation

Fix the validation by capturing and checking the error return value in `ValidateGenesis`:

```go
// In x/gov/types/genesis.go, line 54:
if err := validateTallyParams(data.TallyParams); err != nil {
    return err
}
```

This ensures that the critical invariant check is enforced during genesis initialization, preventing invalid parameter configurations from being loaded into the chain state.

## Proof of Concept

**File:** `x/gov/types/genesis_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestValidateGenesis_ExpeditedQuorumBypass(t *testing.T) {
    // Setup: Create invalid TallyParams where ExpeditedQuorum < Quorum
    // This should fail validation but currently passes due to the bug
    invalidTallyParams := types.NewTallyParams(
        sdk.NewDecWithPrec(334, 3), // Regular Quorum = 0.334 (33.4%)
        sdk.NewDecWithPrec(200, 3), // Expedited Quorum = 0.200 (20%) - INVALID!
        types.DefaultThreshold,
        types.DefaultExpeditedThreshold,
        types.DefaultVetoThreshold,
    )

    genesisState := types.NewGenesisState(
        types.DefaultStartingProposalID,
        types.DefaultDepositParams(),
        types.DefaultVotingParams(),
        invalidTallyParams,
    )

    // Trigger: Call ValidateGenesis with invalid params
    err := types.ValidateGenesis(genesisState)

    // Observation: Currently returns nil (bug), should return error
    // This test will PASS with the bug (demonstrating the vulnerability)
    // and FAIL after the fix (when validation is properly enforced)
    require.Nil(t, err, "BUG DEMONSTRATED: ValidateGenesis accepted invalid params where ExpeditedQuorum < Quorum")
    
    // To verify this is actually invalid, call validateTallyParams directly
    directErr := validateTallyParams(invalidTallyParams)
    require.Error(t, directErr, "Direct validation correctly catches the invalid params")
    require.Contains(t, directErr.Error(), "must be greater than the regular quorum")
}
```

**Setup:** The test creates a `GenesisState` with `TallyParams` where `ExpeditedQuorum` (20%) is less than regular `Quorum` (33.4%), which violates the intended invariant.

**Trigger:** Calls `ValidateGenesis` with the invalid genesis state.

**Observation:** 
- Currently, `ValidateGenesis` returns `nil` (no error), allowing the invalid parameters to pass validation
- Direct call to `validateTallyParams` correctly returns an error
- This proves the validation exists but is being bypassed in the genesis validation flow
- After applying the fix, this test would fail, confirming the validation is properly enforced

The test demonstrates that invalid governance parameters can be loaded at genesis, which would then govern all proposal voting with an inverted security model where expedited proposals require less community participation than regular proposals.

### Citations

**File:** x/gov/types/genesis.go (L54-54)
```go
	validateTallyParams(data.TallyParams)
```

**File:** x/gov/types/params.go (L15-16)
```go
	DefaultPeriod          time.Duration = time.Hour * 24 * 2 // 2 days
	DefaultExpeditedPeriod time.Duration = time.Hour * 24     // 1 day
```

**File:** x/gov/types/params.go (L23-24)
```go
	DefaultQuorum                    = sdk.NewDecWithPrec(334, 3)
	DefaultExpeditedQuorum           = sdk.NewDecWithPrec(667, 3)
```

**File:** x/gov/types/params.go (L172-174)
```go
	if v.ExpeditedQuorum.LTE(v.Quorum) {
		return fmt.Errorf("expedited quorum %s, must be greater than the regular quorum %s", v.ExpeditedQuorum, v.Quorum)
	}
```

**File:** x/gov/keeper/tally.go (L101-103)
```go
	quorumThreshold := tallyParams.GetQuorum(proposal.IsExpedited)
	if percentVoting.LT(quorumThreshold) {
		return false, true, tallyResults
```

**File:** x/gov/module.go (L66-72)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return types.ValidateGenesis(&data)
```

**File:** x/gov/genesis.go (L16-16)
```go
	k.SetTallyParams(ctx, data.TallyParams)
```
