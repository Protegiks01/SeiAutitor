## Audit Report

## Title
Invalid Evidence Stored in State Due to Missing Invariant and Handler Logic Mismatch

## Summary
The evidence module stores invalid evidence (too old, for non-existent validators, or for already-tombstoned validators) in permanent state when submitted via `MsgSubmitEvidence`, despite the evidence handler rejecting it. This occurs because the handler returns without error for invalid evidence, but the caller still stores it. Additionally, the evidence module has no invariants registered to detect this inconsistency. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/evidence/keeper/keeper.go`, function `SubmitEvidence` (lines 78-100)
- Secondary: `x/evidence/keeper/infraction.go`, function `HandleEquivocationEvidence` (lines 25-123)
- Missing invariants: `x/evidence/module.go`, function `RegisterInvariants` (line 168)

**Intended Logic:** 
When evidence is submitted, the handler should validate it and only store evidence that represents valid, actionable misbehavior. Evidence that is too old, references non-existent validators, or targets already-punished validators should be rejected and NOT stored in state. An invariant should verify that all stored evidence is valid.

**Actual Logic:**
The `HandleEquivocationEvidence` handler returns early (without error) when it rejects evidence for various reasons:
- Validator pubkey not found (returns at line 39)
- Evidence too old beyond MaxAgeDuration/MaxAgeNumBlocks (returns at line 62)
- Validator is nil or unbonded (returns at line 70)  
- Validator already tombstoned (returns at line 85) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

However, `keeper.SubmitEvidence` interprets a nil return from the handler as success and proceeds to store the evidence: [6](#0-5) 

**Exploit Scenario:**
1. Attacker creates equivocation evidence with parameters that will cause the handler to reject it (e.g., evidence timestamp older than MaxAgeDuration)
2. Attacker submits via `MsgSubmitEvidence` transaction (no special privileges required)
3. Evidence passes `ValidateBasic` checks (basic field validation)
4. Evidence is checked for duplicates and passes (unique hash)
5. Handler `HandleEquivocationEvidence` is called, determines evidence is too old, returns early without error
6. `SubmitEvidence` stores the evidence at line 98 despite it being invalid
7. Invalid evidence remains in state permanently, included in genesis exports and queries

**Security Failure:**
This violates the state consistency invariant that stored evidence should represent valid, processed misbehavior. The missing invariant check means this inconsistency goes undetected.

## Impact Explanation

This vulnerability affects the protocol's state integrity and resource consumption:

1. **State Bloat:** Invalid evidence is stored permanently in state, consuming storage resources across all network nodes
2. **Genesis Export Corruption:** Invalid evidence is exported in genesis state, propagating the inconsistency
3. **Resource Waste:** Nodes waste storage and processing resources on meaningless data
4. **No Detection Mechanism:** The empty `RegisterInvariants` function means no invariant checks can detect this state inconsistency

While individual evidence submissions are constrained by transaction fees, the accumulation of invalid evidence over time (from legitimate users submitting old evidence or evidence for recently-unbonded validators) would cause state bloat without any mechanism to detect or clean it up.

## Likelihood Explanation

**Who can trigger it:** Any network participant can submit evidence via `MsgSubmitEvidence` - there are no privilege restrictions.

**Conditions required:** This can happen during normal operation when:
- Users submit evidence that's just beyond the MaxAgeDuration/MaxAgeNumBlocks thresholds
- Evidence is submitted for validators that recently unbonded
- Evidence is submitted for validators already tombstoned by previous evidence
- Evidence is submitted for non-existent validator addresses

**Frequency:** This could occur regularly in normal operation as users may legitimately observe old misbehavior and attempt to report it, unaware it's too old to be actionable. The vulnerability would cause this invalid evidence to accumulate in state over time.

## Recommendation

**Option 1 (Preferred):** Modify `HandleEquivocationEvidence` to return an error when evidence is rejected, instead of returning nil:

```go
// In x/evidence/keeper/infraction.go, HandleEquivocationEvidence should return error
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) error {
    // When evidence is rejected, return an error instead of returning nil
    if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
        return fmt.Errorf("evidence is too old")
    }
    // ... similar for other rejection cases
}
```

**Option 2:** Only store evidence within the handler after all validation passes, and never in `SubmitEvidence`. Remove line 98 from `keeper.SubmitEvidence`.

**Option 3:** Add an invariant in `RegisterInvariants` to detect stored invalid evidence:

```go
// In x/evidence/module.go
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {
    keeper.RegisterInvariants(ir, am.keeper)
}

// In x/evidence/keeper/invariants.go (new file)
func RegisterInvariants(ir sdk.InvariantRegistry, k Keeper) {
    ir.RegisterRoute(types.ModuleName, "valid-evidence", ValidEvidenceInvariant(k))
}

func ValidEvidenceInvariant(k Keeper) sdk.Invariant {
    return func(ctx sdk.Context) (string, bool) {
        // Check all stored evidence is valid (not too old, validator exists, etc.)
    }
}
```

## Proof of Concept

**File:** `x/evidence/keeper/keeper_test.go`

**Test Function:** Add this test to the `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestSubmitOldEvidenceStored() {
    // Setup: Create a context with consensus params
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1000).WithBlockTime(time.Now())
    cp := suite.app.BaseApp.GetConsensusParams(ctx)
    ctx = ctx.WithConsensusParams(cp)
    
    pk := ed25519.GenPrivKey()
    
    // Create evidence with old timestamp (beyond MaxAgeDuration)
    oldTime := ctx.BlockTime().Add(-cp.Evidence.MaxAgeDuration).Add(-time.Hour)
    e := &types.Equivocation{
        Height:           1,
        Power:            100,
        Time:             oldTime,
        ConsensusAddress: sdk.ConsAddress(pk.PubKey().Address().Bytes()).String(),
    }
    
    // Trigger: Submit the old evidence
    err := suite.app.EvidenceKeeper.SubmitEvidence(ctx, e)
    
    // Observation: Evidence submission succeeds (no error)
    suite.Nil(err, "Expected no error when submitting old evidence")
    
    // Observation: Evidence is stored in state (THIS IS THE BUG)
    storedEvidence, found := suite.app.EvidenceKeeper.GetEvidence(ctx, e.Hash())
    suite.True(found, "Old evidence should NOT be stored but it is")
    suite.Equal(e, storedEvidence, "Stored evidence matches submitted old evidence")
    
    // Additional verification: Check that no validator was actually punished
    // (If a validator existed with this address, verify they're not jailed/tombstoned)
}
```

**Setup:** The test initializes a blockchain context with consensus parameters including MaxAgeDuration for evidence.

**Trigger:** Submits equivocation evidence with a timestamp older than MaxAgeDuration via `SubmitEvidence`.

**Observation:** The test verifies that:
1. `SubmitEvidence` returns nil (no error) 
2. The invalid evidence IS stored in state via `GetEvidence` (demonstrating the bug)
3. This violates the invariant that only valid, actionable evidence should be stored

The test confirms the vulnerability: old evidence that should be rejected is stored permanently in state.

### Citations

**File:** x/evidence/module.go (L167-168)
```go
// RegisterInvariants registers the evidence module's invariants.
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {}
```

**File:** x/evidence/keeper/infraction.go (L29-40)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
	}
```

**File:** x/evidence/keeper/infraction.go (L52-64)
```go
	if cp != nil && cp.Evidence != nil {
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
			logger.Info(
				"ignored equivocation; evidence too old",
				"validator", consAddr,
				"infraction_height", infractionHeight,
				"max_age_num_blocks", cp.Evidence.MaxAgeNumBlocks,
				"infraction_time", infractionTime,
				"max_age_duration", cp.Evidence.MaxAgeDuration,
			)
			return
		}
	}
```

**File:** x/evidence/keeper/infraction.go (L66-71)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
	if validator == nil || validator.IsUnbonded() {
		// Defensive: Simulation doesn't take unbonding periods into account, and
		// Tendermint might break this assumption at some point.
		return
	}
```

**File:** x/evidence/keeper/infraction.go (L78-86)
```go
	if k.slashingKeeper.IsTombstoned(ctx, consAddr) {
		logger.Info(
			"ignored equivocation; validator already tombstoned",
			"validator", consAddr,
			"infraction_height", infractionHeight,
			"infraction_time", infractionTime,
		)
		return
	}
```

**File:** x/evidence/keeper/keeper.go (L86-100)
```go
	handler := k.router.GetRoute(evidence.Route())
	if err := handler(ctx, evidence); err != nil {
		return sdkerrors.Wrap(types.ErrInvalidEvidence, err.Error())
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSubmitEvidence,
			sdk.NewAttribute(types.AttributeKeyEvidenceHash, evidence.Hash().String()),
		),
	)

	k.SetEvidence(ctx, evidence)
	return nil
}
```
