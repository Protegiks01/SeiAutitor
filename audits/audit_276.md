## Audit Report

## Title
Missing Validation of ABCI-Provided Evidence Allows Excessive Slashing via Invalid Height Values

## Summary
The evidence module's BeginBlocker processes evidence from CometBFT without calling `ValidateBasic()`, allowing malformed evidence with invalid height values (Height < 1) to bypass validation and cause excessive slashing of all unbonding delegations and redelegations for the targeted validator. [1](#0-0) 

## Impact
**Medium** - Direct loss of funds through incorrect slashing of delegator stakes.

## Finding Description

**Location:** 
- Primary vulnerability: `x/evidence/abci.go`, function `BeginBlocker`, lines 19-25
- Validation function exists but unused: `x/evidence/types/evidence.go`, function `ValidateBasic`, lines 46-61
- Contrasting secure path: `x/evidence/types/msgs.go`, function `ValidateBasic`, line 55
- Vulnerable slashing logic: `x/evidence/keeper/infraction.go`, lines 42-64, 101, and `x/staking/keeper/slash.go`, lines 174-177

**Intended Logic:**
Evidence should be validated regardless of source. The `ValidateBasic()` method exists on the `Equivocation` type and checks that:
- Height >= 1
- Power >= 1  
- Time.Unix() > 0
- ConsensusAddress is not empty

User-submitted evidence via `MsgSubmitEvidence` is validated by calling `ValidateBasic()`. [2](#0-1) 

**Actual Logic:**
When evidence arrives from CometBFT via ABCI `BeginBlock`, the code converts it using `FromABCIEvidence` and directly passes it to `HandleEquivocationEvidence` without calling `ValidateBasic()`. This allows evidence with Height=0 or negative values to be processed. [3](#0-2) 

The age check in `HandleEquivocationEvidence` uses AND logic: evidence is only rejected if BOTH `ageDuration > MaxAgeDuration` AND `ageBlocks > MaxAgeNumBlocks`. With Height=0 and recent Time, only one condition is true, so the evidence is NOT rejected. [4](#0-3) 

In `SlashUnbondingDelegation`, the check `if entry.CreationHeight < infractionHeight` determines whether to slash an unbonding delegation. With `infractionHeight=0`, ALL entries with positive `CreationHeight` (which is all normal unbonding delegations) fail this check and get slashed, even if they were created thousands of blocks after the supposed infraction. [5](#0-4) 

**Exploit Scenario:**
1. Due to a bug in CometBFT or a compromised consensus (>1/3 malicious validators), evidence is provided with `Height=0` (or negative), `Power=100`, `Time=<current time>`, and `ConsensusAddress=<target validator>`
2. BeginBlocker processes this evidence without validation
3. `HandleEquivocationEvidence` checks: `ageDuration ≈ 0` (recent time) and `ageBlocks = currentHeight - 0 = currentHeight` (very large)
4. Age check: `(0 > MaxAgeDuration) && (currentHeight > MaxAgeNumBlocks)` = false AND true/false = false → evidence NOT rejected
5. Code proceeds to slash with `infractionHeight=0` and `distributionHeight=-1`
6. In `SlashUnbondingDelegation`, for each unbonding delegation entry created at any positive height (e.g., height 100, 200, 1000), the check `100 < 0` is false, so the entry is NOT skipped and IS slashed
7. Result: ALL unbonding delegations for this validator are slashed, regardless of when they were created [6](#0-5) 

**Security Failure:**
This breaks the fundamental accounting invariant that only stake contributing to the validator's power at the time of the infraction should be slashed. Unbonding delegations created long after block 0 should not be slashed for a supposed infraction at block 0, as that stake was not present during the infraction.

The existing test suite even demonstrates this behavior with Height=0 evidence being processed successfully: [7](#0-6) 

## Impact Explanation

**Assets Affected:** Delegator funds in unbonding delegations and redelegations for the targeted validator.

**Severity:** If CometBFT provides evidence with invalid height (due to bug or compromise), ALL unbonding delegations for a validator would be slashed at the configured slash fraction (typically 5% for double-sign), regardless of when those unbondings occurred. This means:
- Delegators who unbonded weeks or months after block 0 would lose funds for an infraction that occurred before their stake existed
- Potentially hundreds or thousands of delegators could lose funds simultaneously
- The financial loss scales with the total amount in unbonding/redelegating state

**System Impact:** This violates the core security property of slashing: only punish stake that contributed to the validator's misbehavior. This undermines trust in the protocol's fairness and could lead to significant financial losses for innocent delegators.

## Likelihood Explanation

**Trigger Conditions:**
- Requires CometBFT to provide evidence with Height < 1 (either through a bug, network fork, or >1/3 Byzantine validators)
- The evidence must have a recent timestamp to bypass the age check's OR logic
- Does not require any specific actions from unprivileged users

**Likelihood Assessment:**
While requiring malformed evidence from CometBFT makes this moderately unlikely in normal operation, the vulnerability is concerning because:
1. It represents a defense-in-depth failure: the SDK trusts CometBFT completely without validation
2. The existence of `ValidateBasic()` indicates this validation was intended but not implemented for ABCI evidence
3. The test suite demonstrates that Height=0 evidence successfully processes, showing this is a known edge case that wasn't properly secured
4. In network fork or upgrade scenarios, malformed evidence could be propagated
5. A bug in CometBFT's evidence generation could trigger this without malicious intent

## Recommendation

Add validation of ABCI-provided evidence in the BeginBlocker before processing:

```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
    defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

    for _, tmEvidence := range req.ByzantineValidators {
        switch tmEvidence.Type {
        case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
            evidence := types.FromABCIEvidence(tmEvidence)
            
            // Add validation before processing
            if err := evidence.ValidateBasic(); err != nil {
                k.Logger(ctx).Error(fmt.Sprintf("invalid evidence from ABCI: %s", err))
                continue
            }
            
            k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))

        default:
            k.Logger(ctx).Error(fmt.Sprintf("ignored unknown evidence type: %s", tmEvidence.Type))
        }
    }
}
```

This ensures consistent validation regardless of evidence source and prevents malformed evidence from causing excessive slashing.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add a new test `TestInvalidHeightEvidenceExcessiveSlashing` after the existing tests.

**Setup:**
1. Initialize blockchain context at height 1
2. Create a validator with power 100
3. Create multiple unbonding delegations at different heights (e.g., height 50, 100, 150) with 10 tokens each
4. Advance to height 200

**Trigger:**
1. Create evidence with Height=0, Time=current time, Power=100, ConsensusAddress=validator address
2. Call `HandleEquivocationEvidence` directly (simulating BeginBlocker behavior)
3. Verify that ValidateBasic would reject this evidence: `err := evidence.ValidateBasic(); require.Error(t, err)`

**Observation:**
1. Despite ValidateBasic rejecting this evidence, HandleEquivocationEvidence processes it successfully
2. Check unbonding delegation balances: ALL unbonding delegations (created at heights 50, 100, 150) are slashed
3. Expected: Only delegations created at or after the infraction height should be slashed
4. Actual: ALL delegations are slashed because their CreationHeight (50, 100, 150) > infractionHeight (0)
5. Contrast this with proper evidence at height 100: only delegations from height 100+ should be slashed, not those from height 50

The test would demonstrate that:
- Evidence with Height=0 violates ValidateBasic but is still processed
- This causes excessive slashing of unbonding delegations that shouldn't be slashed
- The inconsistency between user-submitted evidence (validated) and ABCI evidence (not validated) creates a security vulnerability

### Citations

**File:** x/evidence/abci.go (L19-25)
```go
	for _, tmEvidence := range req.ByzantineValidators {
		switch tmEvidence.Type {
		// It's still ongoing discussion how should we treat and slash attacks with
		// premeditation. So for now we agree to treat them in the same way.
		case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
			evidence := types.FromABCIEvidence(tmEvidence)
			k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))
```

**File:** x/evidence/types/evidence.go (L46-61)
```go
func (e *Equivocation) ValidateBasic() error {
	if e.Time.Unix() <= 0 {
		return fmt.Errorf("invalid equivocation time: %s", e.Time)
	}
	if e.Height < 1 {
		return fmt.Errorf("invalid equivocation height: %d", e.Height)
	}
	if e.Power < 1 {
		return fmt.Errorf("invalid equivocation validator power: %d", e.Power)
	}
	if e.ConsensusAddress == "" {
		return fmt.Errorf("invalid equivocation validator consensus address: %s", e.ConsensusAddress)
	}

	return nil
}
```

**File:** x/evidence/types/msgs.go (L55-55)
```go
	if err := evi.ValidateBasic(); err != nil {
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

**File:** x/evidence/keeper/infraction.go (L101-101)
```go
	distributionHeight := infractionHeight - sdk.ValidatorUpdateDelay
```

**File:** x/staking/keeper/slash.go (L174-177)
```go
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}
```

**File:** x/evidence/keeper/infraction_test.go (L59-65)
```go
	evidence := &types.Equivocation{
		Height:           0,
		Time:             time.Unix(0, 0),
		Power:            power,
		ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
	}
	suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
```
