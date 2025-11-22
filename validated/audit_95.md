# Audit Report

## Title
Network-Wide Denial of Service via Future-Height Evidence Submission Causing Panic in Slash Function

## Summary
An attacker can submit evidence with a future block height through `MsgSubmitEvidence`, which bypasses all validation checks and causes all nodes to panic when the staking keeper's `Slash` function detects the future infraction height, resulting in a complete network shutdown.

## Impact
**Medium** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:**
- Primary validation gap: `x/evidence/types/evidence.go` lines 46-61 (ValidateBasic function)
- Secondary validation gap: `x/evidence/keeper/infraction.go` lines 42-64 (age check logic)
- Panic trigger: `x/staking/keeper/slash.go` lines 67-71 (future height check)
- Call chain: `x/evidence/keeper/infraction.go` line 107 → `x/slashing/keeper/keeper.go` line 78 → `x/staking/keeper/slash.go` line 24

**Intended Logic:**
Evidence should only represent past infractions. The system is designed to reject any evidence claiming an infraction occurred at a future block height, as this is logically impossible and indicates malicious or corrupted data.

**Actual Logic:**
The validation flow has two critical gaps. First, the `Equivocation.ValidateBasic()` function only validates that `Height >= 1` but does not check if the height is in the future. [1](#0-0)  Second, in `HandleEquivocationEvidence`, when calculating the age of evidence, the expression `ageBlocks = ctx.BlockHeader().Height - infractionHeight` produces a negative value for future heights. [2](#0-1)  This negative value does not satisfy the "too old" rejection condition `ageBlocks > cp.Evidence.MaxAgeNumBlocks`. [3](#0-2) 

The evidence then proceeds to slashing where `distributionHeight = infractionHeight - sdk.ValidatorUpdateDelay` still results in a future height. [4](#0-3)  This value is passed through the slashing keeper [5](#0-4)  which forwards it to the staking keeper. [6](#0-5)  When the staking keeper's `Slash` function receives this future height as `infractionHeight`, it triggers a panic. [7](#0-6) 

**Exploitation Path:**
1. Attacker crafts a `MsgSubmitEvidence` with an `Equivocation` where `Height = currentBlockHeight + 100`
2. The message is submitted through the standard transaction submission process [8](#0-7) 
3. Message validation passes because `ValidateBasic()` only checks `Height >= 1`
4. Transaction is included in a block and processed
5. `HandleEquivocationEvidence` is invoked with `infractionHeight = currentBlockHeight + 100`
6. Age check calculates: `ageBlocks = currentBlockHeight - (currentBlockHeight + 100) = -100`
7. Since `-100` is NOT `> MaxAgeNumBlocks`, evidence is not rejected
8. `distributionHeight = infractionHeight - 1 = currentBlockHeight + 99` 
9. This future height is passed through slashing keeper to staking keeper
10. Check `infractionHeight > ctx.BlockHeight()` evaluates to `true`, causing panic

**Security Guarantee Broken:**
This violates the availability guarantee of the blockchain. All nodes processing the malicious transaction will panic and halt, preventing the network from producing new blocks or processing any transactions.

## Impact Explanation

**Affected Processes:** Network availability and consensus

**Consequences:**
- All validator nodes processing the block containing the malicious evidence will panic simultaneously
- The network cannot progress to produce new blocks
- All pending transactions remain unprocessed
- Recovery requires coordinated manual intervention to restart nodes and potentially exclude the malicious transaction from the block

This is a critical availability vulnerability that enables a single unprivileged attacker to completely halt the entire blockchain network with a single transaction. The attacker needs no special privileges—only the ability to submit a transaction, which is a fundamental capability in any blockchain.

## Likelihood Explanation

**Who Can Trigger:** Any user with the ability to submit transactions to the network

**Required Conditions:**
- Attacker must know a valid validator consensus address (publicly available information)
- No special timing or state conditions required
- Can be executed at any time during normal network operation

**Frequency:** This attack can be executed immediately and repeatedly. Once discovered, it could be exploited continuously until patched, making it a severe and imminent threat.

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

This check should be placed immediately after retrieving the infraction height and before any age calculations or slashing operations.

## Proof of Concept

**Test Location:** `x/evidence/keeper/infraction_test.go`

**Setup:**
- Initialize test context with block height 10
- Create and register a validator with sufficient power

**Action:**
- Create `Equivocation` evidence with `Height = 50` (future height)
- Call `HandleEquivocationEvidence` with this evidence

**Expected Result:**
- The system should panic when the staking keeper's `Slash` function detects that `infractionHeight (49 after subtracting ValidatorUpdateDelay of 1) > ctx.BlockHeight() (10)`
- This panic confirms the vulnerability—in production, this would crash all nodes processing this transaction

The test demonstrates that evidence with future heights bypasses all validation checks and triggers a panic that would cause network-wide denial of service.

## Notes

The severity is classified as **Medium** according to the impact criterion "Network not being able to confirm new transactions (total network shutdown)". While this represents a complete network halt, the classification follows the provided severity guidelines. The vulnerability is fully exploitable by any unprivileged user and requires immediate patching to prevent potential network-wide denial of service attacks.

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

**File:** x/slashing/keeper/keeper.go (L78-78)
```go
	k.sk.Slash(ctx, consAddr, distributionHeight, power, fraction)
```

**File:** x/staking/keeper/slash.go (L67-71)
```go
	case infractionHeight > ctx.BlockHeight():
		// Can't slash infractions in the future
		panic(fmt.Sprintf(
			"impossible attempt to slash future infraction at height %d but we are at height %d",
			infractionHeight, ctx.BlockHeight()))
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
