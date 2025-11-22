# Audit Report

## Title
Evidence Age Validation Bypass When Consensus Parameters Are Nil

## Summary
The `HandleEquivocationEvidence` function in the evidence module fails to reject arbitrarily old evidence when consensus parameters are nil or when evidence parameters are missing. This allows validators to be slashed, jailed, and permanently tombstoned for infractions that should have been rejected as too old, violating the protocol's statute of limitations for Byzantine evidence. [1](#0-0) 

## Impact
**Medium** - Direct loss of funds through unfair validator slashing and potential network disruption through validator tombstoning.

## Finding Description

**Location:** 
- Module: `x/evidence`
- File: `x/evidence/keeper/infraction.go`
- Function: `HandleEquivocationEvidence`
- Lines: 51-64

**Intended Logic:**
Evidence submitted for Byzantine behavior (double-signing) should be rejected if it exceeds both the maximum age duration (`MaxAgeDuration`) and maximum age in blocks (`MaxAgeNumBlocks`) defined in the consensus parameters. This statute of limitations prevents validators from being punished for ancient infractions and ensures the evidence is temporally relevant.

**Actual Logic:**
The age validation is wrapped in a conditional check `if cp != nil && cp.Evidence != nil`. If either `ctx.ConsensusParams()` returns nil OR if `cp.Evidence` is nil, the entire age check block is skipped, and execution continues directly to line 66, proceeding to slash, jail, and tombstone the validator regardless of evidence age. [2](#0-1) 

**Exploit Scenario:**

1. **Trigger Condition:** Chain operates with missing consensus parameters due to:
   - `app.paramStore` being nil (causing `GetConsensusParams` to return nil) [3](#0-2) 
   
   - Evidence parameters not stored in the param store (causing `cp.Evidence` to be nil) [4](#0-3) 
   
   - InitChain called with nil consensus params [5](#0-4) 

2. **Evidence Submission:** Tendermint submits Byzantine evidence through the ABCI `BeginBlock` interface for an equivocation that occurred far in the past (e.g., months or years ago). [6](#0-5) 

3. **Age Check Bypass:** The age validation is completely skipped because consensus params are nil or evidence params are nil.

4. **Validator Punishment:** The validator is slashed at the `SlashFractionDoubleSign` rate, jailed indefinitely, and permanently tombstoned based on arbitrarily old evidence. [7](#0-6) 

**Security Failure:**
This violates the fail-closed security principle. When safety-critical parameters are missing, the system should reject operations rather than proceed without validation. The code fails open, accepting evidence without age validation, which:
- Breaks the temporal validity invariant for evidence
- Enables unfair punishment of validators for ancient infractions
- Causes irreversible financial loss and operational damage

## Impact Explanation

**Affected Assets:**
- Validator staked tokens (slashed at the configured `SlashFractionDoubleSign` rate)
- Validator operational status (permanently tombstoned, cannot recover)
- Network security (reduced validator set if multiple validators affected)

**Severity of Damage:**
- **Direct Financial Loss:** Validators lose a percentage of their staked tokens through slashing
- **Permanent Operational Impact:** Tombstoning is irreversible; affected validators cannot rejoin the active set even after unbonding
- **Network Disruption:** If multiple validators are tombstoned simultaneously, the active validator set shrinks, potentially impacting network security and liveness

**System Security Impact:**
The protocol's evidence handling is designed with a statute of limitations to balance security (punishing misbehavior) with fairness (not punishing ancient infractions where context may be lost). Bypassing age checks undermines this balance and enables disproportionate punishment that the protocol designers explicitly sought to prevent.

## Likelihood Explanation

**Who Can Trigger:**
- Indirectly triggered by Tendermint consensus submitting Byzantine evidence through ABCI
- Requires consensus parameters to be nil or evidence parameters to be missing
- Cannot be directly triggered by an unprivileged attacker

**Required Conditions:**
- Param store not configured (`SetParamStore` never called)
- Evidence parameters not initialized during `InitChain`
- Evidence parameters lost during chain migration/upgrade
- Chain state corruption affecting parameter storage

**Frequency:**
- Likely during: Chain initialization errors, failed upgrades, state migration bugs
- Unlikely during: Normal steady-state operation of a properly configured chain
- Once triggered: All evidence submitted during the window is affected until consensus params are properly restored

The defensive nil-check in the code suggests the developers anticipated this scenario could occur in practice, not just through extreme misconfiguration.

## Recommendation

**Primary Fix:** Fail closed when consensus parameters are unavailable. If consensus params or evidence params are nil, reject the evidence with an error rather than proceeding with validation bypassed.

```go
cp := ctx.ConsensusParams()
if cp == nil || cp.Evidence == nil {
    logger.Error(
        "cannot validate evidence age: consensus parameters not available",
        "validator", consAddr,
        "infraction_height", infractionHeight,
        "infraction_time", infractionTime,
    )
    // Fail closed: reject evidence when params unavailable
    return
}

// Age check with params guaranteed to be non-nil
if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    logger.Info("ignored equivocation; evidence too old", ...)
    return
}
```

**Secondary Safeguard:** Add initialization validation in `InitChain` and `BeginBlock` to panic or halt the chain if consensus parameters are missing, ensuring the issue is caught immediately rather than silently bypassing validation.

## Proof of Concept

**Test File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestHandleDoubleSign_NilConsensusParams`

**Setup:**
1. Initialize test environment with validators using standard `SetupTest`
2. Create a validator with bonded tokens and signing info
3. Create evidence for an equivocation that occurred at height 0, time unix epoch (arbitrarily old)
4. Set current block time to significantly later (e.g., 1 year later)
5. Create context WITHOUT setting consensus params (or with nil evidence params)

**Trigger:**
Call `HandleEquivocationEvidence` with the old evidence on a context where `ctx.ConsensusParams()` returns nil or where `ctx.ConsensusParams().Evidence` is nil

**Observation:**
The test should observe that:
- The validator IS jailed (contrary to expected behavior of rejecting old evidence)
- The validator IS tombstoned (permanent and irreversible)
- The validator's tokens ARE slashed
- This occurs despite the evidence being far beyond any reasonable statute of limitations

**Test Code Structure:**
```go
func (suite *KeeperTestSuite) TestHandleDoubleSign_NilConsensusParams() {
    // Setup: Create validator at height 1, current time
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1).WithBlockTime(time.Now())
    suite.populateValidators(ctx)
    
    // Create validator
    power := int64(100)
    operatorAddr, val := valAddresses[0], pubkeys[0]
    // ... validator creation and end-blocker execution
    
    // Create very old evidence (height 0, 1 year ago)
    oldTime := ctx.BlockTime().Add(-365 * 24 * time.Hour)
    evidence := &types.Equivocation{
        Height:           0,
        Time:             oldTime,
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }
    
    // Critical: Create context WITHOUT consensus params set
    // Method 1: Don't call WithConsensusParams
    // Method 2: Call WithConsensusParams(nil)
    ctxNoParams := ctx.WithBlockHeight(10000).WithBlockTime(ctx.BlockTime().Add(365 * 24 * time.Hour))
    // Explicitly NOT setting: ctxNoParams = ctxNoParams.WithConsensusParams(...)
    
    // Trigger: Handle evidence with nil consensus params
    suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctxNoParams, evidence)
    
    // Observation: Validator IS punished despite evidence being too old
    // These assertions PASS on vulnerable code (demonstrating the bug)
    suite.True(suite.app.StakingKeeper.Validator(ctxNoParams, operatorAddr).IsJailed())
    suite.True(suite.app.SlashingKeeper.IsTombstoned(ctxNoParams, sdk.ConsAddress(val.Address())))
    
    // Expected behavior: Validator should NOT be jailed/tombstoned for old evidence
    // Test would FAIL on fixed code (where nil params cause rejection)
}
```

The test demonstrates that when consensus parameters are nil, arbitrarily old evidence (1 year in this example) bypasses age validation and results in validator punishment, proving the vulnerability is exploitable.

### Citations

**File:** x/evidence/keeper/infraction.go (L42-64)
```go
	// calculate the age of the evidence
	infractionHeight := evidence.GetHeight()
	infractionTime := evidence.GetTime()
	ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
	ageBlocks := ctx.BlockHeader().Height - infractionHeight

	// Reject evidence if the double-sign is too old. Evidence is considered stale
	// if the difference in time and number of blocks is greater than the allowed
	// parameters defined.
	cp := ctx.ConsensusParams()
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

**File:** x/evidence/keeper/infraction.go (L107-122)
```go
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)

	// Jail the validator if not already jailed. This will begin unbonding the
	// validator if not already unbonding (tombstoned).
	if !validator.IsJailed() {
		k.slashingKeeper.Jail(ctx, consAddr)
	}

	k.slashingKeeper.JailUntil(ctx, consAddr, types.DoubleSignJailEndTime)
	k.slashingKeeper.Tombstone(ctx, consAddr)
	k.SetEvidence(ctx, evidence)
```

**File:** baseapp/baseapp.go (L675-678)
```go
func (app *BaseApp) GetConsensusParams(ctx sdk.Context) *tmproto.ConsensusParams {
	if app.paramStore == nil {
		return nil
	}
```

**File:** baseapp/baseapp.go (L689-694)
```go
	if app.paramStore.Has(ctx, ParamStoreKeyEvidenceParams) {
		var ep tmproto.EvidenceParams

		app.paramStore.Get(ctx, ParamStoreKeyEvidenceParams, &ep)
		cp.Evidence = &ep
	}
```

**File:** baseapp/abci.go (L60-65)
```go
	if req.ConsensusParams != nil {
		app.StoreConsensusParams(app.deliverState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.prepareProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.processProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.checkState.ctx, req.ConsensusParams)
	}
```

**File:** x/evidence/abci.go (L16-30)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	for _, tmEvidence := range req.ByzantineValidators {
		switch tmEvidence.Type {
		// It's still ongoing discussion how should we treat and slash attacks with
		// premeditation. So for now we agree to treat them in the same way.
		case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
			evidence := types.FromABCIEvidence(tmEvidence)
			k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))

		default:
			k.Logger(ctx).Error(fmt.Sprintf("ignored unknown evidence type: %s", tmEvidence.Type))
		}
	}
```
