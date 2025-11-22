## Audit Report

## Title
Insufficient Minimum Value Validation for Consensus Parameters Allows Governance-Based Denial of Service

## Summary
The consensus parameter validation functions in `baseapp/params.go` do not enforce reasonable minimum bounds for critical block parameters. A malicious governance proposal can set `MaxBytes=1` or `MaxGas=0`, which would pass validation but render the chain unable to produce blocks or process transactions, causing a complete network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `ValidateBlockParams` function should ensure that consensus parameters are set to reasonable values that allow the blockchain to function properly. Block parameters like `MaxBytes` and `MaxGas` should have sufficient capacity to include transactions in blocks.

**Actual Logic:** 
The validation only checks:
- `MaxBytes > 0` - allows any positive value including 1
- `MaxGas >= -1` - allows 0 or any value >= -1
- `MinTxsInBlock >= 0` - no upper bound
- `MaxGasWanted >= -1` - allows 0

There are no minimum reasonable bounds enforced. A value of `MaxBytes=1` is technically positive but far too small for any meaningful transaction (even the smallest transaction requires dozens of bytes). Similarly, `MaxGas=0` is technically valid (>= -1) but prevents any gas-consuming operations.

**Exploit Scenario:**
1. An attacker submits a governance proposal to update block parameters via `ParameterChangeProposal` targeting the baseapp subspace [2](#0-1) 

2. The proposal specifies `MaxBytes=1` or `MaxGas=0` as the new value

3. At submission, the proposal validation only checks if the parameter key exists in the subspace [3](#0-2) 

4. The proposal passes through governance voting

5. When executed, `handleParameterChangeProposal` calls `ss.Update()` which invokes the validation function [4](#0-3) 

6. The validation passes because `1 > 0` and `0 >= -1`

7. The parameters are stored in the baseapp's parameter store [5](#0-4) 

8. Subsequent blocks cannot include transactions because:
   - With `MaxBytes=1`, no transaction can fit (minimum transaction size is much larger)
   - With `MaxGas=0`, no gas-consuming transactions can be included

**Security Failure:** 
This breaks the availability property of the blockchain. The chain becomes unable to process transactions, resulting in a complete denial of service. While technically the consensus layer may continue producing empty blocks, no user transactions can be executed, effectively halting the network.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability and transaction processing capability
- All user transactions and smart contract operations
- Chain liveness and utility

**Severity of Damage:**
- Complete halt of transaction processing network-wide
- No user can execute transactions, transfer funds, or interact with smart contracts
- The chain effectively becomes non-functional for its intended purpose
- Requires a hard fork or emergency governance action to restore functionality
- All validators would be unable to include meaningful transactions in proposed blocks

**System Impact:**
This vulnerability allows an attacker who can pass a governance proposal to permanently disable the blockchain's core functionality. While the consensus mechanism might technically continue, the chain becomes useless as it cannot process any user activity. This is effectively a "soft halt" where blocks are produced but contain no transactions.

## Likelihood Explanation

**Who Can Trigger:**
- Any party that can successfully pass a governance proposal (requires sufficient token holdings or community support to reach quorum and pass the vote)
- Could potentially be exploited through governance manipulation, social engineering, or during periods of low voter participation

**Required Conditions:**
- Submit a `ParameterChangeProposal` targeting baseapp consensus parameters
- Proposal must pass through the deposit period (requires minimum deposit)
- Proposal must achieve quorum and pass the voting period (requires majority yes votes)
- Once passed, the vulnerability is immediately triggered with no additional conditions

**Frequency:**
- Can be triggered as frequently as governance proposals can be submitted and passed
- Once exploited, immediate and persistent impact until fixed via emergency measures
- The attack is deterministic - if a malicious proposal passes, the exploit succeeds with 100% certainty

The likelihood depends on governance participation and vigilance, but the low technical barriers (just submitting a proposal with specific parameter values) and high impact make this a serious vulnerability.

## Recommendation

Add minimum reasonable bounds to the `ValidateBlockParams` function:

```go
func ValidateBlockParams(i interface{}) error {
    v, ok := i.(tmproto.BlockParams)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    // Enforce reasonable minimum for MaxBytes (e.g., 10KB minimum)
    const MinMaxBytes = 10000
    if v.MaxBytes <= 0 {
        return fmt.Errorf("block maximum bytes must be positive: %d", v.MaxBytes)
    }
    if v.MaxBytes < MinMaxBytes {
        return fmt.Errorf("block maximum bytes must be at least %d: %d", MinMaxBytes, v.MaxBytes)
    }

    // Enforce reasonable minimum for MaxGas when not unlimited (-1)
    const MinMaxGas = 10000
    if v.MaxGas < -1 {
        return fmt.Errorf("block maximum gas must be greater than or equal to -1: %d", v.MaxGas)
    }
    if v.MaxGas >= 0 && v.MaxGas < MinMaxGas {
        return fmt.Errorf("block maximum gas must be at least %d or -1 for unlimited: %d", MinMaxGas, v.MaxGas)
    }

    // Enforce reasonable maximum for MinTxsInBlock
    const MaxMinTxsInBlock = 10000
    if v.MinTxsInBlock < 0 {
        return fmt.Errorf("block min txs in block must be non-negative: %d", v.MinTxsInBlock)
    }
    if v.MinTxsInBlock > MaxMinTxsInBlock {
        return fmt.Errorf("block min txs cannot exceed %d: %d", MaxMinTxsInBlock, v.MinTxsInBlock)
    }

    if v.MaxGasWanted < -1 {
        return fmt.Errorf("block maximum gas wanted must be greater than or equal to -1: %d", v.MaxGasWanted)
    }

    return nil
}
```

Consider defining these constants based on actual transaction sizes and gas requirements for the minimum viable block.

## Proof of Concept

**File:** `x/gov/keeper/proposal_test.go`

**Test Function:** Add a new test case to the existing `TestParamChangeProposal` function:

```go
// Add to the testCases map in TestParamChangeProposal (around line 199)
"malicious MaxBytes=1 consensus param": {
    proposal: &proposal.ParameterChangeProposal{
        Title:       "Malicious Block Params",
        Description: "Setting MaxBytes to 1 to DoS the chain",
        Changes: []proposal.ParamChange{
            {
                Subspace: baseapp.Paramspace,
                Key:      string(baseapp.ParamStoreKeyBlockParams),
                Value:    `{"max_bytes": 1, "max_gas": 5000000}`,
            },
        },
        IsExpedited: false,
    },
    expectError: false, // Currently passes validation - THIS IS THE BUG
},
"malicious MaxGas=0 consensus param": {
    proposal: &proposal.ParameterChangeProposal{
        Title:       "Malicious Block Params",  
        Description: "Setting MaxGas to 0 to DoS the chain",
        Changes: []proposal.ParamChange{
            {
                Subspace: baseapp.Paramspace,
                Key:      string(baseapp.ParamStoreKeyBlockParams),
                Value:    `{"max_bytes": 5000000, "max_gas": 0}`,
            },
        },
        IsExpedited: false,
    },
    expectError: false, // Currently passes validation - THIS IS THE BUG
},
```

**Setup:**
1. The test suite initializes a SimApp with default configuration
2. The baseapp subspace is already configured with ConsensusParamsKeyTable

**Trigger:**
1. Submit the governance proposal with malicious parameter values (`MaxBytes=1` or `MaxGas=0`)
2. The proposal passes validation at submission time (only checks key existence)
3. Execute the proposal handler which calls the validation function

**Observation:**
The test demonstrates that these dangerously small values pass validation (`expectError: false`) when they should fail. After fixing the vulnerability by adding minimum bounds, these test cases should be changed to `expectError: true` to verify proper validation.

To verify the DoS impact, add another test that attempts to create a transaction after these parameters are set - it would fail to fit in the block constraints.

**Notes:**
The current tests in [6](#0-5)  only test normal values and don't cover edge cases with dangerously small parameters. The PoC above demonstrates that malicious but technically valid values can be set through governance, which would immediately halt transaction processing network-wide.

### Citations

**File:** baseapp/params.go (L37-60)
```go
func ValidateBlockParams(i interface{}) error {
	v, ok := i.(tmproto.BlockParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.MaxBytes <= 0 {
		return fmt.Errorf("block maximum bytes must be positive: %d", v.MaxBytes)
	}

	if v.MaxGas < -1 {
		return fmt.Errorf("block maximum gas must be greater than or equal to -1: %d", v.MaxGas)
	}

	if v.MinTxsInBlock < 0 {
		return fmt.Errorf("block min txs in block must be non-negative: %d", v.MinTxsInBlock)
	}

	if v.MaxGasWanted < -1 {
		return fmt.Errorf("block maximum gas wanted must be greater than or equal to -1: %d", v.MaxGasWanted)
	}

	return nil
}
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

**File:** x/gov/keeper/proposal.go (L29-39)
```go
		// Validate each parameter change exists
		for _, change := range paramProposal.Changes {
			subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
			if !ok {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
			}
			validKey := subspace.Has(ctx, []byte(change.Key))
			if !validKey {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not found in subspace %s", change.Key, change.Subspace)
			}
		}
```

**File:** x/params/types/subspace.go (L196-219)
```go
func (s Subspace) Update(ctx sdk.Context, key, value []byte) error {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
	}

	ty := attr.ty
	dest := reflect.New(ty).Interface()
	s.GetIfExists(ctx, key, dest)

	if err := s.legacyAmino.UnmarshalJSON(value, dest); err != nil {
		return err
	}

	// destValue contains the dereferenced value of dest so validation function do
	// not have to operate on pointers.
	destValue := reflect.Indirect(reflect.ValueOf(dest)).Interface()
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
	}

	s.Set(ctx, key, dest)
	return nil
}
```

**File:** baseapp/baseapp.go (L741-758)
```go
// StoreConsensusParams sets the consensus parameters to the baseapp's param store.
func (app *BaseApp) StoreConsensusParams(ctx sdk.Context, cp *tmproto.ConsensusParams) {
	if app.paramStore == nil {
		panic("cannot store consensus params with no params store set")
	}

	if cp == nil {
		return
	}

	app.paramStore.Set(ctx, ParamStoreKeyBlockParams, cp.Block)
	app.paramStore.Set(ctx, ParamStoreKeyEvidenceParams, cp.Evidence)
	app.paramStore.Set(ctx, ParamStoreKeyValidatorParams, cp.Validator)
	app.paramStore.Set(ctx, ParamStoreKeyVersionParams, cp.Version)
	app.paramStore.Set(ctx, ParamStoreKeySynchronyParams, cp.Synchrony)
	app.paramStore.Set(ctx, ParamStoreKeyTimeoutParams, cp.Timeout)
	app.paramStore.Set(ctx, ParamStoreKeyABCIParams, cp.Abci)
}
```

**File:** baseapp/params_test.go (L12-28)
```go
func TestValidateBlockParams(t *testing.T) {
	testCases := []struct {
		arg       interface{}
		expectErr bool
	}{
		{nil, true},
		{&tmproto.BlockParams{}, true},
		{tmproto.BlockParams{}, true},
		{tmproto.BlockParams{MaxBytes: -1, MaxGas: -1}, true},
		{tmproto.BlockParams{MaxBytes: 2000000, MaxGas: -5}, true},
		{tmproto.BlockParams{MaxBytes: 2000000, MaxGas: 300000}, false},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expectErr, baseapp.ValidateBlockParams(tc.arg) != nil)
	}
}
```
