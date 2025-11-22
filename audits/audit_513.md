## Title
Parameter Change Proposal Validation Mismatch Causes Chain Halt

## Summary
The parameter change proposal validation in `x/gov/keeper/proposal.go` checks if a parameter key exists in the KVStore during submission, but the execution handler in `x/params/proposal_handler.go` checks if the key is registered in the KeyTable. This mismatch allows proposals for unregistered parameters to pass submission validation but panic during execution, causing a chain halt.

## Impact
**High**

## Finding Description

**Location:** 
- Submission validation: [1](#0-0) 
- Execution handler: [2](#0-1) 
- Update method: [3](#0-2) 

**Intended Logic:** 
Parameter change proposals should only be accepted if the parameter can be safely updated. The validation during proposal submission should verify that the parameter exists and can be modified.

**Actual Logic:** 
The submission validation checks if a parameter key exists in the **KVStore** using `subspace.Has(ctx, []byte(change.Key))` at [4](#0-3) . However, the execution uses `subspace.Update()` which checks if the key is registered in the **KeyTable** and panics if not found at [5](#0-4) .

These are two different checks:
- **KVStore**: Contains the actual key-value pairs stored on chain
- **KeyTable**: Contains the registered parameter schema (type and validator)

A parameter key can exist in the KVStore but not be registered in the KeyTable, particularly after module upgrades where parameters are removed from the schema but remain in storage.

**Exploit Scenario:**
1. A module upgrade removes a parameter from its `ParamSetPairs()` (removing it from KeyTable) but the old value remains in the KVStore
2. An attacker (or any user) submits a `ParameterChangeProposal` targeting this orphaned parameter
3. The submission validation passes because `Has()` finds the key in the KVStore
4. The proposal goes through governance voting and passes
5. During proposal execution in `BeginBlock`/`EndBlock`, the `Update()` method panics because the key is not in the KeyTable
6. The panic occurs during block execution, causing the entire chain to halt

**Security Failure:**
This breaks the consensus safety property. The panic during block execution is unrecoverable and causes all validators to halt at the same block height, resulting in a total network shutdown requiring a hard fork to fix.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability: Total chain halt
- All pending transactions become frozen
- All user funds become inaccessible until hard fork

**Damage Severity:**
- **Chain Halt**: All validators panic during block execution and cannot proceed
- **Hard Fork Required**: The chain cannot recover without coordinated validator action to either skip the block or patch the code
- **Network Downtime**: Complete loss of transaction processing until resolved

**Why This Matters:**
This vulnerability allows any user to halt the entire blockchain network by submitting a specially crafted governance proposal, provided an orphaned parameter exists in storage. This is a critical denial-of-service vector that requires no special privileges beyond the ability to submit a proposal (which requires only a deposit).

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who can submit a governance proposal (requires only having sufficient tokens for the deposit).

**Required Conditions:**
1. A parameter key must exist in the KVStore but not be registered in the KeyTable
2. This condition arises when modules remove parameters from their schema during upgrades but don't clean up storage
3. Examples include deprecated parameters or legacy keys from older versions

**Frequency:**
- Moderate to High likelihood during active protocol development periods
- Each module upgrade that removes or refactors parameters creates potential orphaned keys
- Once an orphaned key exists, exploitation is trivial and can happen at any time
- The validation was only recently added (commit 042ea189, November 2024), suggesting prior incidents

## Recommendation

The submission validation should check KeyTable registration instead of KVStore existence. Replace the `Has()` check with a KeyTable registration check:

```go
// In x/gov/keeper/proposal.go, lines 31-38
subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
if !ok {
    return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
}

// Check KeyTable registration instead of store existence
if !subspace.HasKeyTable() {
    return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "subspace %s has no KeyTable", change.Subspace)
}

// Validate the key is registered in the KeyTable
if err := subspace.Validate(ctx, []byte(change.Key), nil); err != nil {
    if strings.Contains(err.Error(), "not registered") {
        return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not registered in subspace %s", change.Key, change.Subspace)
    }
}
```

Alternatively, perform a dry-run of `Update()` during submission validation to catch any issues before accepting the proposal.

## Proof of Concept

**File:** `x/gov/keeper/proposal_test.go` (add new test function)

```go
func (suite *KeeperTestSuite) TestParameterChangeProposalValidationBypass() {
    // Setup: Create a subspace with a limited KeyTable
    table := paramstypes.NewKeyTable(
        paramstypes.NewParamSetPair([]byte("RegisteredKey"), int64(0), func(_ interface{}) error { return nil }),
    )
    
    // Create test subspace
    testSubspace := suite.app.ParamsKeeper.Subspace("testbypass").WithKeyTable(table)
    
    // Manually write an unregistered key to the store (simulating orphaned parameter)
    store := prefix.NewStore(suite.ctx.KVStore(suite.app.GetKey(paramstypes.StoreKey)), []byte("testbypass/"))
    store.Set([]byte("UnregisteredKey"), []byte(`100`))
    
    // Verify the key exists in store but not in KeyTable
    suite.Require().True(testSubspace.Has(suite.ctx, []byte("UnregisteredKey")), "Key should exist in store")
    
    // Create a parameter change proposal for the unregistered key
    unregisteredParamChange := proposal.ParamChange{
        Subspace: "testbypass",
        Key:      "UnregisteredKey",
        Value:    "200",
    }
    
    proposalContent := &proposal.ParameterChangeProposal{
        Title:       "Change Unregistered Parameter",
        Description: "This should be rejected but passes validation",
        Changes:     []proposal.ParamChange{unregisteredParamChange},
        IsExpedited: false,
    }
    
    // VULNERABILITY: Submission succeeds because Has() finds the key in store
    submittedProposal, err := suite.app.GovKeeper.SubmitProposal(suite.ctx, proposalContent)
    suite.Require().NoError(err, "Proposal submission should pass current validation")
    suite.Require().NotNil(submittedProposal)
    
    // Simulate proposal execution through the handler
    handler := params.NewParamChangeProposalHandler(suite.app.ParamsKeeper)
    
    // CRITICAL: Execution panics because Update() checks KeyTable registration
    suite.Require().Panics(func() {
        handler(suite.ctx, proposalContent)
    }, "Execution should panic when key is not in KeyTable, causing chain halt")
}
```

**Setup:** The test creates a subspace with only one registered parameter, then manually writes an unregistered parameter to the KVStore using direct store access (simulating an orphaned key from a previous upgrade).

**Trigger:** Submits a `ParameterChangeProposal` for the unregistered parameter.

**Observation:** The proposal submission succeeds (vulnerability), but execution panics (chain halt). This demonstrates the validation bypass and its catastrophic impact on chain operation.

### Citations

**File:** x/gov/keeper/proposal.go (L31-38)
```go
			subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
			if !ok {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
			}
			validKey := subspace.Has(ctx, []byte(change.Key))
			if !validKey {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not found in subspace %s", change.Key, change.Subspace)
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
