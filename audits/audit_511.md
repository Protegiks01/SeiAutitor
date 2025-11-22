# Audit Report

## Title
ParameterChangeProposal Validation Bypass Leading to Chain Halt via Panic on Unregistered Parameters

## Summary
A critical mismatch exists between the validation logic for `ParameterChangeProposal` submissions and the execution logic during proposal application. The validation checks if a parameter key exists in the KVStore, while the execution handler checks if the key is registered in the KeyTable and panics if not found. This allows an attacker to craft a proposal that passes validation but causes all nodes to crash during execution, resulting in a total network shutdown. [1](#0-0) [2](#0-1) 

## Impact
High

## Finding Description

**Location:** 
- Validation: `x/gov/keeper/proposal.go`, lines 30-39, specifically line 35
- Execution: `x/params/types/subspace.go`, lines 196-200, specifically line 199
- Handler invocation: `x/gov/abci.go`, line 74

**Intended Logic:** 
The validation during proposal submission is intended to ensure that only valid parameters can be modified through governance proposals. The system should reject proposals targeting non-existent parameters before they enter the voting process.

**Actual Logic:** 
The validation uses `subspace.Has(ctx, []byte(change.Key))` which only checks if a key exists in the KVStore: [3](#0-2) 

However, the execution path calls `Update()` which checks if the key is registered in the `KeyTable` (not the store) and **panics** if not found: [4](#0-3) 

The `Update()` method is invoked by the proposal handler: [5](#0-4) 

**Exploit Scenario:**
1. A key exists in the params KVStore but is NOT registered in the KeyTable. This can occur when:
   - A module removes a parameter from its `ParamSetPairs()` during an upgrade
   - The old value remains in the store (no migration to clean it up)
   - The key is written directly using `SetRaw()` which bypasses KeyTable registration [6](#0-5) 

2. An attacker discovers such a deprecated/unregistered parameter key by querying the params store

3. Attacker submits a `ParameterChangeProposal` targeting this key

4. The validation in `SubmitProposal` passes because `Has()` returns true (key exists in store)

5. The proposal goes through the normal governance process and passes voting

6. During `EndBlocker` execution, the proposal handler is invoked: [7](#0-6) 

7. The handler calls `Update()` which panics at line 199 because the key is not in the KeyTable

8. The panic is NOT caught by the error handling in EndBlocker (which only catches returned errors, not panics)

9. All validator nodes crash when processing this block

10. The chain halts completely as no nodes can process blocks beyond this point

**Security Failure:** 
This breaks the availability and denial-of-service protection of the blockchain. A malicious actor can permanently halt the entire network by exploiting the validation mismatch. The panic during EndBlocker execution is not recovered, causing all nodes to crash.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability: The entire blockchain network becomes unable to process new blocks
- Transaction finality: All pending transactions cannot be confirmed
- Network operations: All validator nodes crash simultaneously

**Severity:**
- This causes a **total network shutdown** - all nodes crash and the chain cannot progress
- Requires emergency intervention and potentially a hard fork to recover
- No transactions can be processed until the issue is resolved
- This is a complete denial-of-service attack on the blockchain

**Why This Matters:**
This is a critical security vulnerability because:
1. Any user can submit a governance proposal (not restricted to privileged actors)
2. The attack only requires discovering a deprecated parameter key, which is deterministic
3. Once the malicious proposal passes governance, the chain halt is guaranteed
4. Recovery requires coordinated off-chain action and potentially a hard fork
5. This falls under the "High - Network not being able to confirm new transactions (total network shutdown)" impact category

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with enough tokens to submit a governance proposal (minimum deposit requirement). The attacker needs the proposal to pass voting, which requires either:
- Convincing other token holders to vote yes (social engineering)
- Controlling enough voting power themselves
- Waiting for voter apathy (proposals can pass with low turnout)

**Required Conditions:**
1. A parameter key must exist in the KVStore but not be registered in the KeyTable
2. This condition naturally occurs during module upgrades when parameters are removed from `ParamSetPairs()` but not deleted from storage
3. The attacker must discover such a key (can be found by iterating the params store)

**Frequency:**
- This can be triggered whenever the required condition exists
- Module upgrades that deprecate parameters without proper migration create this vulnerability
- Once exploited, the impact is immediate and total
- The vulnerability is deterministic - if the conditions exist, the exploit will succeed with certainty

## Recommendation

**Immediate Fix:**
Modify the validation logic in `x/gov/keeper/proposal.go` to check if the key is registered in the KeyTable, not just if it exists in the store. Replace the validation at lines 30-39 with:

```go
for _, change := range paramProposal.Changes {
    subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
    if !ok {
        return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
    }
    
    // Check if key is registered in KeyTable (not just if it exists in store)
    if !subspace.HasKeyTable() {
        return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "subspace %s has no key table", change.Subspace)
    }
    
    // Validate key is registered in the KeyTable
    err := subspace.Validate(ctx, []byte(change.Key), nil)
    if err != nil {
        return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not registered in subspace %s", change.Key, change.Subspace)
    }
}
```

Alternatively, add a method to `Subspace` that checks KeyTable registration:
```go
func (s Subspace) IsKeyRegistered(key []byte) bool {
    _, ok := s.table.m[string(key)]
    return ok
}
```

**Additional Mitigation:**
1. Ensure all module upgrades include proper migration logic to remove deprecated parameters from the store
2. Add panic recovery in the EndBlocker proposal execution path
3. Document the requirement that parameters must be properly migrated when removed from modules

## Proof of Concept

**File:** `x/gov/keeper/proposal_test.go`

**Test Function:** Add the following test to the existing test suite:

```go
func TestParameterChangeProposalPanicOnUnregisteredKey(t *testing.T) {
    // Setup: Create test app and context
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Step 1: Simulate a deprecated parameter by writing directly to the store
    // This mimics what happens when a module removes a parameter from ParamSetPairs
    // but the old value remains in the store from before the upgrade
    
    // Get the staking subspace
    stakingSubspace, ok := app.ParamsKeeper.GetSubspace(stakingtypes.ModuleName)
    require.True(t, ok, "staking subspace should exist")
    
    // Write a "deprecated" key directly to the store using SetRaw
    // This key exists in the store but is NOT registered in the KeyTable
    deprecatedKey := []byte("DeprecatedParameter")
    deprecatedValue := []byte(`"deprecated_value"`)
    stakingSubspace.SetRaw(ctx, deprecatedKey, deprecatedValue)
    
    // Verify the key exists in the store (will pass Has check)
    require.True(t, stakingSubspace.Has(ctx, deprecatedKey), "deprecated key should exist in store")
    
    // Step 2: Create a ParameterChangeProposal targeting this deprecated key
    paramChange := proposal.ParamChange{
        Subspace: stakingtypes.ModuleName,
        Key:      string(deprecatedKey),
        Value:    `"new_value"`,
    }
    
    paramProposal := &proposal.ParameterChangeProposal{
        Title:       "Update Deprecated Parameter",
        Description: "Attempting to update a parameter that exists in store but not in KeyTable",
        Changes:     []proposal.ParamChange{paramChange},
        IsExpedited: false,
    }
    
    // Step 3: Submit the proposal - this PASSES validation incorrectly
    // Validation only checks Has() which looks at the store
    submittedProposal, err := app.GovKeeper.SubmitProposal(ctx, paramProposal)
    require.NoError(t, err, "Proposal submission should succeed (BUG: validation passed)")
    require.NotEqual(t, uint64(0), submittedProposal.ProposalId)
    
    // Step 4: Try to execute the proposal handler - this PANICS
    // The handler calls Update() which checks the KeyTable and panics
    handler := params.NewParamChangeProposalHandler(app.ParamsKeeper)
    
    // This demonstrates the vulnerability: the handler panics when trying to
    // update a parameter that's not registered in the KeyTable
    require.Panics(t, func() {
        _ = handler(ctx, paramProposal)
    }, "Handler should panic with: parameter DeprecatedParameter not registered")
}
```

**Setup:**
- Uses the standard simapp test setup
- Creates a staking subspace with its normal KeyTable registration
- Writes a key directly to the store using `SetRaw()` to bypass KeyTable registration

**Trigger:**
- Submits a `ParameterChangeProposal` targeting the unregistered key
- Shows that validation incorrectly passes
- Invokes the proposal handler directly

**Observation:**
- The test confirms that `SubmitProposal` succeeds (validation bug)
- The test confirms that the handler panics during execution (critical security failure)
- The panic message will be: "parameter DeprecatedParameter not registered"
- This proves that a proposal can pass validation but crash nodes during execution

This PoC can be run with: `go test -v -run TestParameterChangeProposalPanicOnUnregisteredKey ./x/gov/keeper/`

### Citations

**File:** x/gov/keeper/proposal.go (L23-40)
```go
	if content.ProposalType() == proposal.ProposalTypeChange {
		paramProposal, ok := content.(*proposal.ParameterChangeProposal)
		if !ok {
			return types.Proposal{}, sdkerrors.Wrap(types.ErrInvalidProposalContent, "proposal content is not a ParameterChangeProposal")
		}

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
	}
```

**File:** x/params/types/subspace.go (L137-140)
```go
func (s Subspace) Has(ctx sdk.Context, key []byte) bool {
	store := s.kvStore(ctx)
	return store.Has(key)
}
```

**File:** x/params/types/subspace.go (L182-188)
```go
func (s Subspace) SetRaw(ctx sdk.Context, key []byte, value []byte) {
	store := s.kvStore(ctx)
	store.Set(key, value)

	tstore := s.transientStore(ctx)
	tstore.Set(key, []byte{})
}
```

**File:** x/params/types/subspace.go (L196-200)
```go
func (s Subspace) Update(ctx sdk.Context, key, value []byte) error {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
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

**File:** x/gov/abci.go (L67-92)
```go
		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
			if err == nil {
				proposal.Status = types.StatusPassed
				tagValue = types.AttributeValueProposalPassed
				logMsg = "passed"

				// The cached context is created with a new EventManager. However, since
				// the proposal handler execution was successful, we want to track/keep
				// any events emitted, so we re-emit to "merge" the events into the
				// original Context's EventManager.
				ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())

				// write state to the underlying multi-store
				writeCache()
			} else {
				proposal.Status = types.StatusFailed
				tagValue = types.AttributeValueProposalFailed
				logMsg = fmt.Sprintf("passed, but failed on execution: %s", err)
			}
```
