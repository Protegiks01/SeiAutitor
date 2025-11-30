# Audit Report

## Title
Network-Wide Denial of Service via Future-Height Evidence Submission Causing Panic in Slash Function

## Summary
An attacker can submit equivocation evidence with a future block height through `MsgSubmitEvidence`, which bypasses all validation checks and causes all nodes to panic when the staking keeper's `Slash` function detects the future infraction height, resulting in a complete network shutdown.

## Impact
Medium

## Finding Description

**location:** 
- Validation gap: `x/evidence/types/evidence.go` lines 46-61 [1](#0-0) 
- Age check bypass: `x/evidence/keeper/infraction.go` lines 42-64 [2](#0-1) 
- Panic trigger: `x/staking/keeper/slash.go` lines 67-71 [3](#0-2) 

**intended logic:**
Evidence should only represent past infractions. The system should reject any evidence claiming an infraction occurred at a future block height, as this is logically impossible and indicates malicious or corrupted data.

**actual logic:**
The `Equivocation.ValidateBasic()` function only validates that `Height >= 1` but does not check if the height is in the future. [4](#0-3) 

When `HandleEquivocationEvidence` calculates evidence age, the expression `ageBlocks = ctx.BlockHeader().Height - infractionHeight` produces a negative value for future heights. [5](#0-4)  This negative value does not satisfy the "too old" rejection condition `ageBlocks > cp.Evidence.MaxAgeNumBlocks`. [6](#0-5) 

The evidence proceeds to slashing where `distributionHeight = infractionHeight - sdk.ValidatorUpdateDelay` still results in a future height. [7](#0-6)  This value is passed through the slashing keeper [8](#0-7)  which forwards it to the staking keeper. [9](#0-8) 

When the staking keeper's `Slash` function receives a future height as `infractionHeight`, it explicitly checks for this condition and triggers a panic. [3](#0-2) 

**exploitation path:**
1. Attacker crafts a `MsgSubmitEvidence` with an `Equivocation` where `Height = currentBlockHeight + N` (any positive N)
2. The message is submitted through standard transaction submission [10](#0-9) 
3. Message validation passes because `ValidateBasic()` only checks `Height >= 1`
4. Transaction is included in a block and processed by all validators
5. `HandleEquivocationEvidence` is invoked with `infractionHeight = currentBlockHeight + N`
6. Age check calculates: `ageBlocks = currentBlockHeight - (currentBlockHeight + N) = -N`
7. Since `-N` is NOT `> MaxAgeNumBlocks`, evidence is not rejected
8. `distributionHeight = infractionHeight - 1 = currentBlockHeight + N - 1` (still future)
9. This future height is passed to staking keeper's `Slash` function
10. Check `infractionHeight > ctx.BlockHeight()` evaluates to `true`, causing panic
11. All nodes processing this block panic simultaneously
12. Network halts completely

**security guarantee broken:**
This violates the availability guarantee of the blockchain. The network should reject invalid evidence and continue operating, but instead accepts malicious future-height evidence that causes a coordinated network-wide crash.

## Impact Explanation

**Affected Processes:** Network availability and consensus

**Consequences:**
- All validator nodes processing the block containing the malicious evidence panic simultaneously
- The network cannot progress to produce new blocks
- All pending transactions remain unprocessed indefinitely
- Recovery requires coordinated manual intervention across all validators to restart nodes
- Potential need for emergency patching and network coordination to exclude the malicious transaction

This vulnerability enables a complete denial of service attack against the blockchain network. A single unprivileged attacker can halt the entire network with one transaction, preventing all economic activity and transaction processing until manual recovery procedures are executed.

## Likelihood Explanation

**Who Can Trigger:** Any user with the ability to submit transactions to the network (no special privileges required)

**Required Conditions:**
- Attacker needs a valid validator consensus address (publicly available on-chain information)
- No special timing, state conditions, or privileged access required
- Can be executed at any time during normal network operation

**Frequency:** This attack can be executed immediately and repeatedly. An attacker could submit multiple such transactions to ensure network disruption. Once the vulnerability is discovered by malicious actors, it represents an imminent threat to network availability that could be exploited continuously until patched.

The attack is trivial to execute and has deterministic results - every node will panic when processing the malicious evidence.

## Recommendation

Add explicit validation in `HandleEquivocationEvidence` to reject evidence from the future before any processing occurs:

```go
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) {
    logger := k.Logger(ctx)
    consAddr := evidence.GetConsensusAddress()
    
    infractionHeight := evidence.GetHeight()
    
    // Reject evidence from the future
    if infractionHeight > ctx.BlockHeight() {
        logger.Info(
            "ignored equivocation; evidence from future height",
            "validator", consAddr,
            "infraction_height", infractionHeight,
            "current_height", ctx.BlockHeight(),
        )
        return
    }
    
    // ... rest of the existing function
}
```

This check should be placed immediately after retrieving the infraction height (line 43 of infraction.go) and before any age calculations or slashing operations. This ensures future-height evidence is rejected early in the validation flow before it can reach the panic condition in the staking keeper.

## Proof of Concept

**Test Location:** Create new test in `x/evidence/keeper/infraction_test.go`

**Setup:**
```go
// Initialize test context with block height 10
ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(10)
suite.populateValidators(ctx)

// Create validator
power := int64(100)
operatorAddr, val := valAddresses[0], pubkeys[0]
tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
staking.EndBlocker(ctx, suite.app.StakingKeeper)
```

**Action:**
```go
// Create Equivocation evidence with future height
evidence := &types.Equivocation{
    Height:           50,  // Future height (current is 10)
    Time:             time.Unix(0, 0),
    Power:            power,
    ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
}

// This call will panic
suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
```

**Expected Result:**
- The system panics with message: "impossible attempt to slash future infraction at height 49 but we are at height 10"
- This panic confirms the vulnerability - in production, this would crash all nodes processing this transaction
- The panic occurs because `distributionHeight = 50 - 1 = 49`, which is greater than current height of 10

The test demonstrates that evidence with future heights bypasses all validation checks in `ValidateBasic()` and the age check in `HandleEquivocationEvidence`, proceeding all the way to the staking keeper where it triggers a panic that would cause network-wide denial of service in a production environment.

### Citations

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

**File:** x/evidence/keeper/infraction.go (L101-101)
```go
	distributionHeight := infractionHeight - sdk.ValidatorUpdateDelay
```

**File:** x/evidence/keeper/infraction.go (L107-112)
```go
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)
```

**File:** x/staking/keeper/slash.go (L67-71)
```go
	case infractionHeight > ctx.BlockHeight():
		// Can't slash infractions in the future
		panic(fmt.Sprintf(
			"impossible attempt to slash future infraction at height %d but we are at height %d",
			infractionHeight, ctx.BlockHeight()))
```

**File:** x/slashing/keeper/keeper.go (L78-78)
```go
	k.sk.Slash(ctx, consAddr, distributionHeight, power, fraction)
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
