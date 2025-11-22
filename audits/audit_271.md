# Audit Report

## Title
Evidence Time Validation Bypass Allows Circumvention of Age Restrictions

## Summary
The `ValidateBasic()` function in the evidence module only validates that evidence timestamps are after Unix epoch (> 0) but does not check if timestamps are in the future. This allows attackers to submit evidence with future timestamps, which produces negative age durations that bypass the age validation checks in `HandleEquivocationEvidence()`, enabling the processing of arbitrarily old evidence that should be rejected. [1](#0-0) 

## Impact
**Medium** - This enables unintended protocol behavior by allowing evidence submission outside design parameters, violating the evidence age policy and potentially causing unjust validator slashing.

## Finding Description

**Location:** 
- Primary: `x/evidence/types/evidence.go`, lines 46-49 (`Equivocation.ValidateBasic()`)
- Secondary: `x/evidence/keeper/infraction.go`, lines 42-64 (age calculation and validation in `HandleEquivocationEvidence()`) [1](#0-0) 

**Intended Logic:** 
The evidence module is designed to enforce age limits on submitted evidence through consensus parameters (`MaxAgeDuration` and `MaxAgeNumBlocks`). Evidence older than these limits should be rejected as stale. The `ValidateBasic()` function should validate that evidence timestamps are reasonable and prevent manipulation of age calculations. [2](#0-1) 

**Actual Logic:** 
The `ValidateBasic()` check only validates `e.Time.Unix() <= 0`, which rejects times at or before Unix epoch but accepts any future timestamp. When age is calculated in `HandleEquivocationEvidence()`:

```
ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
```

A future `infractionTime` results in a **negative** `ageDuration`. The age validation check uses AND logic:

```
if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    return  // reject as too old
}
```

Since negative duration is never greater than positive `MaxAgeDuration`, the first condition fails, and evidence is not rejected even if `ageBlocks` exceeds `MaxAgeNumBlocks`. [3](#0-2) 

**Exploit Scenario:**
1. Attacker identifies a validator and obtains their consensus address
2. Attacker creates an `Equivocation` evidence with:
   - `Height`: A past height (e.g., from 1 year ago) that exceeds `MaxAgeNumBlocks`
   - `Time`: A future timestamp (e.g., year 2099)
   - `Power`: The validator's power at that height
   - `ConsensusAddress`: The target validator's address
3. Attacker submits via `MsgSubmitEvidence` (requires app to have registered evidence handler route)
4. `ValidateBasic()` passes because timestamp > 0
5. In `HandleEquivocationEvidence()`:
   - `ageBlocks` is large (current height - old height) and exceeds `MaxAgeNumBlocks`
   - `ageDuration` is negative (current time - future time)
   - Age check condition `(ageDuration > MaxAgeDuration) && (ageBlocks > MaxAgeNumBlocks)` evaluates to `false && true = false`
   - Evidence is NOT rejected
6. Validator is slashed and jailed for old evidence that should have been rejected [4](#0-3) 

**Security Failure:**
The protocol's evidence age policy is violated. The age restriction is a critical safety mechanism to prevent processing of stale evidence. Bypassing this allows attackers to submit evidence from arbitrarily old blocks, potentially after validators have already been slashed, unbonded, or the evidence has otherwise become invalid.

## Impact Explanation

**Affected Assets:**
- Validator staked tokens (subject to slashing)
- Network security (unjust slashing reduces validator set integrity)
- Protocol trust assumptions (age policy enforcement)

**Severity:**
When an application registers evidence handler routes for user-submitted evidence (as documented in the SDK), attackers can bypass age restrictions to submit old evidence. This violates the protocol's design parameters for evidence handling and can lead to:
- Validators being unjustly slashed for old evidence beyond the acceptable age window
- Potential for double-slashing if evidence was already processed
- Circumvention of the unbonding period protections

While the default simapp configuration doesn't register evidence routes, the SDK documentation explicitly supports and describes this pattern, making it a realistic deployment scenario. [5](#0-4) 

## Likelihood Explanation

**Triggering Conditions:**
- Requires application to have registered evidence handler routes (not default but documented/supported)
- Attacker needs basic knowledge of validator addresses and past heights
- Can be triggered by any network participant via `MsgSubmitEvidence` transaction
- No special privileges required once routes are enabled

**Frequency:**
Once evidence routes are enabled, this can be exploited at will by any participant. The attack is straightforward and deterministic. Applications that enable user-submitted evidence (following SDK patterns) are vulnerable. [6](#0-5) 

## Recommendation

Add validation in `ValidateBasic()` to ensure evidence timestamps are not in the future:

```go
func (e *Equivocation) ValidateBasic() error {
    if e.Time.Unix() <= 0 {
        return fmt.Errorf("invalid equivocation time: %s", e.Time)
    }
    
    // Add check to prevent future timestamps
    if e.Time.After(time.Now()) {
        return fmt.Errorf("evidence time cannot be in the future: %s", e.Time)
    }
    
    // ... rest of validation
}
```

Additionally, consider validating against the current block time in the handler to ensure evidence timestamps are reasonable relative to blockchain state.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add `TestHandleDoubleSign_FutureTimestampBypassesAgeCheck`

**Setup:**
1. Initialize test suite with validator at height 1
2. Configure consensus parameters with `MaxAgeDuration = 504 hours` and `MaxAgeNumBlocks = 302400`
3. Create validator and execute through slashing BeginBlocker to set up signing info

**Trigger:**
1. Create evidence with:
   - `Height`: 0 (very old)
   - `Time`: Far future (e.g., `ctx.BlockTime().Add(10 years)`)
   - Valid validator address and power
2. Advance blockchain forward by `MaxAgeNumBlocks + 1` blocks
3. Call `HandleEquivocationEvidence()` with the evidence

**Observation:**
The test should demonstrate that:
- `ageBlocks` exceeds `MaxAgeNumBlocks` (evidence is old in block height)
- `ageDuration` is negative (evidence timestamp is in future)
- Age check at line 53 fails to reject the evidence (condition evaluates to false)
- Validator is incorrectly slashed and jailed despite evidence being beyond age limits

The validator should have been protected by the age restriction but is slashed anyway, confirming the bypass. The test would assert that `validator.IsJailed()` is true and tokens have been slashed, when it should have been rejected as too old. [7](#0-6)

### Citations

**File:** x/evidence/types/evidence.go (L46-49)
```go
func (e *Equivocation) ValidateBasic() error {
	if e.Time.Unix() <= 0 {
		return fmt.Errorf("invalid equivocation time: %s", e.Time)
	}
```

**File:** x/evidence/keeper/infraction.go (L45-46)
```go
	ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
	ageBlocks := ctx.BlockHeader().Height - infractionHeight
```

**File:** x/evidence/keeper/infraction.go (L48-63)
```go
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
```

**File:** x/evidence/doc.go (L1-43)
```go
/*
Package evidence implements a Cosmos SDK module, per ADR 009, that allows for the
submission and handling of arbitrary evidence of misbehavior.

All concrete evidence types must implement the Evidence interface contract. Submitted
evidence is first routed through the evidence module's Router in which it attempts
to find a corresponding Handler for that specific evidence type. Each evidence type
must have a Handler registered with the evidence module's keeper in order for it
to be successfully executed.

Each corresponding handler must also fulfill the Handler interface contract. The
Handler for a given Evidence type can perform any arbitrary state transitions
such as slashing, jailing, and tombstoning. This provides developers with great
flexibility in designing evidence handling.

A full setup of the evidence module may look something as follows:

	ModuleBasics = module.NewBasicManager(
	  // ...,
	  evidence.AppModuleBasic{},
	)

	// First, create the keeper
	evidenceKeeper := evidence.NewKeeper(
	  appCodec, keys[evidence.StoreKey], &app.StakingKeeper, app.SlashingKeeper,
	)

	// Second, create the evidence Handler and register all desired routes.
	evidenceRouter := evidence.NewRouter().
	  AddRoute(evidenceRoute, evidenceHandler).
	  AddRoute(..., ...)

	evidenceKeeper.SetRouter(evidenceRouter)

	app.EvidenceKeeper = *evidenceKeeper

	app.mm = module.NewManager(
	  // ...
	  evidence.NewAppModule(app.EvidenceKeeper),
	)

	// Remaining application bootstrapping...
*/
```

**File:** x/evidence/keeper/msg_server.go (L22-29)
```go
// SubmitEvidence implements the MsgServer.SubmitEvidence method.
func (ms msgServer) SubmitEvidence(goCtx context.Context, msg *types.MsgSubmitEvidence) (*types.MsgSubmitEvidenceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	evidence := msg.GetEvidence()
	if err := ms.Keeper.SubmitEvidence(ctx, evidence); err != nil {
		return nil, err
	}
```

**File:** x/evidence/keeper/infraction_test.go (L101-139)
```go
func (suite *KeeperTestSuite) TestHandleDoubleSign_TooOld() {
	ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1).WithBlockTime(time.Now())
	suite.populateValidators(ctx)
	params := suite.app.StakingKeeper.GetParams(ctx)
	params.MinCommissionRate = sdk.NewDec(0)
	suite.app.StakingKeeper.SetParams(ctx, params)

	power := int64(100)
	stakingParams := suite.app.StakingKeeper.GetParams(ctx)
	operatorAddr, val := valAddresses[0], pubkeys[0]
	tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)

	amt := tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)

	// execute end-blocker and verify validator attributes
	staking.EndBlocker(ctx, suite.app.StakingKeeper)
	suite.Equal(
		suite.app.BankKeeper.GetAllBalances(ctx, sdk.AccAddress(operatorAddr)),
		sdk.NewCoins(sdk.NewCoin(stakingParams.BondDenom, initAmt.Sub(amt))),
	)
	suite.Equal(amt, suite.app.StakingKeeper.Validator(ctx, operatorAddr).GetBondedTokens())

	evidence := &types.Equivocation{
		Height:           0,
		Time:             ctx.BlockTime(),
		Power:            power,
		ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
	}

	cp := suite.app.BaseApp.GetConsensusParams(ctx)

	ctx = ctx.WithConsensusParams(cp)
	ctx = ctx.WithBlockTime(ctx.BlockTime().Add(cp.Evidence.MaxAgeDuration + 1))
	ctx = ctx.WithBlockHeight(ctx.BlockHeight() + cp.Evidence.MaxAgeNumBlocks + 1)
	suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)

	suite.False(suite.app.StakingKeeper.Validator(ctx, operatorAddr).IsJailed())
	suite.False(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(val.Address())))
}
```
