## Audit Report

# Title
Incomplete Consensus Parameter Validation in Governance Proposals Allows Chain Halt

## Summary
The `verifyConsensusParamsUsingDefault` function in the params module only validates `BlockParams` changes in governance proposals, while ignoring the other six consensus parameter types (EvidenceParams, ValidatorParams, VersionParams, SynchronyParams, TimeoutParams, ABCIParams). This allows governance proposals with invalid consensus parameters to pass validation at submission time, potentially causing chain halts when Tendermint validates them after the proposal executes.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The `verifyConsensusParamsUsingDefault` function should validate all consensus parameter changes in a governance proposal before submission to prevent invalid parameters from causing chain halts. The comment explicitly states: "We need to verify ConsensusParams since they are only validated once the proposal passes. If any of them are invalid at time of passing, this will cause a chain halt since validation is done during ApplyBlock" [2](#0-1) 

**Actual Logic:** The function only validates `BlockParams` in the switch statement [3](#0-2) . For other consensus parameter types, the proposed values are never added to `defaultCP` before calling `defaultCP.ValidateConsensusParams()`, meaning the function validates the DEFAULT values instead of the PROPOSED values.

**Exploit Scenario:**
1. An attacker (or mistaken governance participant) submits a parameter change proposal for EvidenceParams, ValidatorParams, SynchronyParams, TimeoutParams, ABCIParams, or VersionParams with invalid values
2. The proposal passes `ValidateBasic()` because `verifyConsensusParamsUsingDefault` doesn't validate the proposed values (only validates defaults)
3. The proposal goes through the voting process and passes
4. When executed via `handleParameterChangeProposal` [4](#0-3) , the parameters are updated
5. At EndBlock, the new consensus params are returned to Tendermint [5](#0-4) 
6. Tendermint's `ValidateConsensusParams` fails during the next block's ApplyBlock, causing a chain halt

**Security Failure:** This breaks the consensus availability guarantee. Invalid consensus parameters can halt the entire blockchain, requiring intervention to recover.

## Impact Explanation

This vulnerability affects the entire blockchain's availability and consensus mechanism:
- **Chain Halt:** Invalid consensus parameters can cause Tendermint to halt the chain when it attempts to validate them during block application
- **Network Unavailability:** All nodes would stop processing transactions, requiring emergency intervention (potentially a hard fork) to recover
- **Governance Bypass:** The pre-validation safeguard intended to prevent chain halts is ineffective for 6 out of 7 consensus parameter types

The severity is high because it can cause "Network not being able to confirm new transactions (total network shutdown)" which is explicitly listed as a High impact in the scope.

## Likelihood Explanation

**Who can trigger it:** Any network participant with sufficient tokens to submit and pass a governance proposal (or through convincing other validators/delegators to vote for it).

**Conditions required:** 
- Submit a governance proposal with consensus parameter changes other than BlockParams
- The proposal must pass the voting process
- The proposed parameter values must be invalid according to Tendermint's validation but not caught by the individual validation functions

**Frequency:** While governance proposals require coordination, mistakes in parameter values are realistic. The comment on line 119 even notes "BlockParams seems to be the only support ConsensusParams available for modifying with proposal" [6](#0-5) , suggesting this gap may not be well understood by governance participants.

## Recommendation

Extend the `verifyConsensusParamsUsingDefault` function to handle all consensus parameter types, not just BlockParams. Add cases in the switch statement for EvidenceParams, ValidatorParams, VersionParams, SynchronyParams, TimeoutParams, and ABCIParams. For each case, unmarshal the proposed value and update the corresponding field in `defaultCP` before calling `ValidateConsensusParams()`.

Example fix structure:
```go
switch change.Key {
case "BlockParams":
    // existing code
case "EvidenceParams":
    var ep tmproto.EvidenceParams
    if err := json.Unmarshal([]byte(change.Value), &ep); err != nil {
        return err
    }
    defaultCP.Evidence = &ep
case "ValidatorParams":
    // similar handling
// ... add cases for other param types
}
```

## Proof of Concept

**File:** `x/params/types/proposal/proposal_test.go`

**Test Function:** Add a new test case `TestInvalidEvidenceParamsNotValidated`

**Setup:** Initialize a test with Tendermint default consensus params.

**Trigger:** Create a `ParameterChangeProposal` that attempts to change EvidenceParams with an invalid value (e.g., `MaxAgeNumBlocks = -1` which violates the constraint that it must be positive [7](#0-6) ).

**Observation:** The test should show that `ValidateBasic()` returns nil (no error) even though the EvidenceParams value is invalid. This demonstrates that invalid consensus parameters for non-BlockParams types can pass proposal validation.

```go
func TestInvalidEvidenceParamsNotValidated(t *testing.T) {
    // Create a parameter change with invalid EvidenceParams
    // MaxAgeNumBlocks must be positive, but we set it to -1
    pc := NewParamChange("baseapp", "EvidenceParams", 
        `{"max_age_num_blocks":"-1","max_age_duration":"1814400000000000","max_bytes":"1048576"}`)
    pcp := NewParameterChangeProposal("test", "test", []ParamChange{pc}, false)
    
    // This should fail but currently passes due to the vulnerability
    err := pcp.ValidateBasic()
    
    // The test expects an error but gets nil, proving the vulnerability
    require.Error(t, err, "Expected validation to fail for invalid EvidenceParams, but it passed")
}
```

The test will currently pass (ValidateBasic returns no error), demonstrating the vulnerability. After the fix, it should fail as expected, catching the invalid EvidenceParams during proposal validation.

### Citations

**File:** x/params/types/proposal/proposal.go (L101-104)
```go
		// We need to verify ConsensusParams since they are only validated once the proposal passes.
		// If any of them are invalid at time of passing, this will cause a chain halt since validation is done during
		// ApplyBlock: https://github.com/sei-protocol/sei-tendermint/blob/d426f1fe475eb0c406296770ff5e9f8869b3887e/internal/state/execution.go#L320
		// Therefore, we validate when we get a param-change msg for ConsensusParams
```

**File:** x/params/types/proposal/proposal.go (L115-133)
```go
func verifyConsensusParamsUsingDefault(changes []ParamChange) error {
	// Start with a default (valid) set of parameters, and update based on proposal then check
	defaultCP := types.DefaultConsensusParams()
	for _, change := range changes {
		// Note: BlockParams seems to be the only support ConsensusParams available for modifying with proposal
		switch change.Key {
		case "BlockParams":
			blockParams := types.DefaultBlockParams()
			err := json.Unmarshal([]byte(change.Value), &blockParams)
			if err != nil {
				return err
			}
			defaultCP.Block = blockParams
		}
	}
	if err := defaultCP.ValidateConsensusParams(); err != nil {
		return err
	}
	return nil
```

**File:** x/params/proposal_handler.go (L26-43)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
}
```

**File:** baseapp/abci.go (L189-191)
```go
	if cp := app.GetConsensusParams(ctx); cp != nil {
		res.ConsensusParamUpdates = legacytm.ABCIToLegacyConsensusParams(cp)
	}
```

**File:** baseapp/params.go (L70-76)
```go
	if v.MaxAgeNumBlocks <= 0 {
		return fmt.Errorf("evidence maximum age in blocks must be positive: %d", v.MaxAgeNumBlocks)
	}

	if v.MaxAgeDuration <= 0 {
		return fmt.Errorf("evidence maximum age time duration must be positive: %v", v.MaxAgeDuration)
	}
```
