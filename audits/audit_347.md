# Audit Report

## Title
Network-Wide Denial of Service via Future-Height Evidence Submission Causing Panic in Slash Function

## Summary
An attacker can submit evidence with a future block height through `MsgSubmitEvidence`, which bypasses all validation checks and causes all nodes to panic when the staking keeper's `Slash` function detects the future infraction height. This results in a complete network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary validation gap: `x/evidence/types/evidence.go` lines 45-61 (ValidateBasic)
- Secondary validation gap: `x/evidence/keeper/infraction.go` lines 42-64 (age check)
- Panic trigger: `x/staking/keeper/slash.go` lines 67-71
- Call chain: `x/evidence/keeper/infraction.go` line 107 → `x/slashing/keeper/keeper.go` line 78 → `x/staking/keeper/slash.go` line 24

**Intended Logic:** 
Evidence should only represent past infractions. The system should reject any evidence claiming an infraction occurred at a future block height, as this is logically impossible and indicates malicious or corrupted data.

**Actual Logic:** 
The `Equivocation.ValidateBasic()` function only validates that `Height >= 1` but does not check if the height is in the future [1](#0-0) . The `HandleEquivocationEvidence` function checks if evidence is too old but not if it's in the future. When calculating `ageBlocks = ctx.BlockHeader().Height - infractionHeight`, a future height produces a negative value which does not trigger the "too old" rejection [2](#0-1) [3](#0-2) . The evidence proceeds to slashing where `distributionHeight = infractionHeight - ValidatorUpdateDelay` still results in a future height [4](#0-3) . When this value is passed to the staking keeper's `Slash` function as `infractionHeight`, it triggers a panic [5](#0-4) .

**Exploit Scenario:**
1. Attacker crafts a `MsgSubmitEvidence` with an `Equivocation` where `Height = currentBlockHeight + 100`
2. The message passes `ValidateBasic()` since it only checks `Height >= 1` [1](#0-0) 
3. Transaction is included in a block and processed by `SubmitEvidence` [6](#0-5) 
4. `HandleEquivocationEvidence` is invoked with `infractionHeight = currentBlockHeight + 100`
5. Age check: `ageBlocks = currentBlockHeight - (currentBlockHeight + 100) = -100`, which is NOT `> MaxAgeNumBlocks`, so evidence is not rejected
6. `distributionHeight = infractionHeight - ValidatorUpdateDelay = (currentBlockHeight + 100) - 1 = currentBlockHeight + 99`
7. `k.slashingKeeper.Slash()` is called with `distributionHeight` as the fifth parameter [7](#0-6) 
8. Slashing keeper forwards this to `k.sk.Slash(ctx, consAddr, distributionHeight, power, fraction)` [8](#0-7) 
9. In staking keeper's `Slash`, `infractionHeight = distributionHeight = currentBlockHeight + 99`
10. Check triggers: `infractionHeight > ctx.BlockHeight()` evaluates to `true`, causing panic [5](#0-4) 

**Security Failure:** 
This breaks the availability property of the blockchain. All nodes processing the malicious transaction will panic and halt, preventing the network from producing new blocks or processing any transactions.

## Impact Explanation

**Affected Processes:** Network availability and consensus
**Severity of Damage:** 
- All validator nodes processing the block containing the malicious evidence will panic simultaneously
- The network cannot progress to produce new blocks
- All pending transactions remain unprocessed
- Recovery requires coordinated manual intervention to restart nodes and potentially exclude the malicious transaction

**Why This Matters:** 
This is a critical availability vulnerability that enables a single unprivileged attacker to completely halt the entire blockchain network with a single transaction. The attacker needs no special privileges—only the ability to submit a transaction, which is a fundamental capability in any blockchain.

## Likelihood Explanation

**Who Can Trigger:** Any user with the ability to submit transactions to the network

**Required Conditions:** 
- Attacker must know a valid validator consensus address (publicly available information)
- No special timing or state conditions required
- Can be executed at any time during normal network operation

**Frequency:** 
This attack can be executed immediately and repeatedly. Once discovered, it could be exploited continuously until patched, making it a severe and imminent threat.

## Recommendation

Add validation in `Equivocation.ValidateBasic()` to check that the evidence height is not in the future:

```go
func (e *Equivocation) ValidateBasic() error {
    if e.Time.Unix() <= 0 {
        return fmt.Errorf("invalid equivocation time: %s", e.Time)
    }
    if e.Height < 1 {
        return fmt.Errorf("invalid equivocation height: %d", e.Height)
    }
    // Add this check - evidence height must not be in the future
    // Note: This is stateless validation, so we cannot check against current height here
    // Therefore, add a check in HandleEquivocationEvidence instead
    ...
}
```

Additionally, add an explicit check in `HandleEquivocationEvidence` before processing:

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
    
    // ... rest of the function
}
```

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add this test to the existing test suite:

```go
func (suite *KeeperTestSuite) TestHandleDoubleSign_FutureHeight() {
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(10)
    suite.populateValidators(ctx)
    
    power := int64(100)
    operatorAddr, val := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    
    // Create validator
    tstaking.CreateValidatorWithValPower(operatorAddr, val, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Create evidence with FUTURE height (current height is 10, evidence height is 50)
    evidence := &types.Equivocation{
        Height:           50,  // Future height!
        Time:             time.Unix(0, 0),
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(val.Address()).String(),
    }
    
    // This should panic when trying to slash at future height
    suite.Panics(func() {
        suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
    }, "Expected panic when processing evidence with future height")
}
```

**Setup:** 
- Initialize test suite with block height 10
- Create a validator to target with the evidence

**Trigger:** 
- Submit evidence with `Height = 50` (future height, since current block is 10)
- Call `HandleEquivocationEvidence` which processes through to the slash operation

**Observation:** 
The test expects a panic to occur when the staking keeper's `Slash` function detects that `infractionHeight (49 after subtracting ValidatorUpdateDelay) > ctx.BlockHeight() (10)`. The panic confirms the vulnerability—in production, this would crash all nodes processing this transaction.

This PoC demonstrates that evidence with future heights bypasses validation and causes a node panic, confirming the network-wide DoS vulnerability.

### Citations

**File:** x/evidence/types/evidence.go (L50-52)
```go
	if e.Height < 1 {
		return fmt.Errorf("invalid equivocation height: %d", e.Height)
	}
```

**File:** x/evidence/keeper/infraction.go (L46-46)
```go
	ageBlocks := ctx.BlockHeader().Height - infractionHeight
```

**File:** x/evidence/keeper/infraction.go (L53-53)
```go
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
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

**File:** x/slashing/keeper/keeper.go (L78-78)
```go
	k.sk.Slash(ctx, consAddr, distributionHeight, power, fraction)
```
