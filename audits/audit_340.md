# Audit Report

## Title
Retroactive Validator Slashing via MinSignedPerWindow Parameter Change

## Summary
The slashing module evaluates validators' historical missed block counters against the current `MinSignedPerWindow` parameter without resetting counters when the parameter changes. This allows a governance proposal to retroactively slash validators who were compliant under previous parameter values, violating the principle that validators should only be penalized for rule violations under current requirements.

## Impact
**Medium** - A bug in the layer-1 network code that results in unintended behavior with potential validator fund loss and network disruption.

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Parameter retrieval: [2](#0-1) 
- Governance parameter update: [3](#0-2) 

**Intended Logic:** 
Validators should only be slashed for downtime if they fail to meet the signing requirements defined by the current slashing parameters. The security invariant is that validators following the rules at any given time should not be punished retroactively if rules become stricter.

**Actual Logic:** 
At each block, the slashing logic retrieves the current `MinSignedPerWindow` parameter and calculates the maximum allowed missed blocks. [4](#0-3) 

This current threshold is then compared against the validator's historical `MissedBlocksCounter`, which accumulated over the entire sliding window based on past behavior. [5](#0-4) 

When a governance proposal changes `MinSignedPerWindow` to a more strict value, the new threshold is immediately applied to evaluate old counters without any reset or grace period.

**Exploit Scenario:**
1. Initial state: `MinSignedPerWindow = 0.05` (5%), `SignedBlocksWindow = 108,000` blocks
   - Maximum allowed missed blocks = 102,600 (validators can miss up to 95%)
2. A validator misses 100,000 blocks out of the last 108,000 blocks (92.6% missed, compliant under current rules)
3. A governance proposal passes changing `MinSignedPerWindow = 0.95` (95%)
   - New maximum allowed missed blocks = 5,400 (validators can only miss 5%)
4. At the very next block after the parameter change takes effect, the validator is evaluated:
   - Historical counter: 100,000 missed blocks
   - Current threshold: 5,400 maximum allowed
   - Since 100,000 > 5,400, the validator is immediately slashed and jailed [6](#0-5) 

**Security Failure:** 
The system violates the fundamental security property that participants should only be penalized for violations of current rules, not retroactive rule changes. This breaks the trust assumption that validators operating within specified parameters are safe from punishment. The codebase shows awareness of this issue for window size changes (which explicitly reset counters) but fails to apply the same protection for `MinSignedPerWindow` changes. [7](#0-6) 

## Impact Explanation

**Assets Affected:**
- Validator stakes: If `SlashFractionDowntime` is non-zero, validators lose a percentage of their bonded tokens
- Validator rewards: Jailed validators cannot earn block rewards during the jail period
- Network security: Multiple validators could be unexpectedly jailed, reducing the active validator set

**Severity:**
- **Direct financial impact:** With the default `SlashFractionDowntime = 0`, there is no direct token loss, but validators lose potential rewards during jail time [8](#0-7) 
- **Network disruption:** A malicious or poorly-designed governance proposal could jail a significant portion of validators simultaneously, potentially causing network instability
- **Validator operations:** Unexpected jailing disrupts validator operations and damages reputation
- **Governance risk:** This creates a governance attack vector where a proposal could be used to punish specific validators retroactively

**System Impact:**
The vulnerability undermines trust in the governance system and creates uncertainty for validators about whether they are operating safely. This is particularly severe because validators cannot predict or prevent retroactive punishment, as their historical behavior is already recorded.

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit and pass a governance proposal to change the `MinSignedPerWindow` parameter. While governance requires broad consensus, the vulnerability still exists in the code logic.

**Conditions Required:**
1. A governance proposal to increase `MinSignedPerWindow` must be submitted and pass
2. At least one validator must have a historical `MissedBlocksCounter` that exceeds the new, stricter threshold
3. The parameter change takes effect (immediately upon proposal execution) [9](#0-8) 

**Likelihood:**
- **Moderate to High** in practice: 
  - Parameter changes through governance are expected and normal operational procedures
  - Network operators may legitimately want to increase liveness requirements over time as the network matures
  - The vulnerability would be triggered unintentionally by well-meaning governance participants who don't realize the retroactive effect
  - During network stress or issues, some validators may have accumulated significant missed blocks while still being compliant, making them vulnerable to retroactive slashing

**Frequency:**
This could occur every time a governance proposal changes `MinSignedPerWindow` to a stricter value, which could be multiple times per year depending on governance activity.

## Recommendation

Implement the same protective logic that exists for `SignedBlocksWindow` changes. When `MinSignedPerWindow` is modified, reset affected validators' counters to prevent retroactive application:

1. **Immediate fix:** Add a parameter change hook that detects `MinSignedPerWindow` changes and resets `MissedBlocksCounter` to 0 for all validators, similar to the existing `ResizeMissedBlockArray` logic for window size reductions [7](#0-6) 

2. **Alternative approach:** Store the `MinSignedPerWindow` value that was in effect when each missed block was recorded, and only count missed blocks against the threshold that was active at the time. This is more complex but more precise.

3. **Minimum viable fix:** Add a parameter change event listener that resets all validators' `MissedBlocksCounter` and `IndexOffset` to 0 whenever `MinSignedPerWindow` increases, giving validators a fresh start under the new rules.

4. **Documentation:** Clearly document in governance proposal guidelines that changing `MinSignedPerWindow` will reset all validators' missed block counters to prevent retroactive slashing.

## Proof of Concept

**Test File:** `x/slashing/abci_test.go`

**Test Function:** `TestRetroactiveSlashingOnMinSignedPerWindowChange`

**Setup:**
1. Initialize a test blockchain with one validator
2. Set initial parameters: `SignedBlocksWindow = 1000`, `MinSignedPerWindow = 0.05` (5%)
   - This allows validators to miss up to 950 blocks (95%)
3. Create and bond a validator with sufficient power

**Trigger:**
1. Simulate the validator signing for the first 500 blocks (establishing start height + window)
2. Simulate the validator missing the next 900 blocks (90% missed, compliant under 5% requirement)
3. Verify the validator is NOT jailed (expected behavior - 900 < 950 allowed misses)
4. Change `MinSignedPerWindow` to 0.95 (95% must be signed) via `SetParams`
   - This changes max allowed misses from 950 to 50
5. Process one more block where the validator signs

**Observation:**
The test demonstrates that the validator gets slashed and jailed on the very next block after the parameter change, even though:
- The validator was fully compliant under the old 5% requirement (900 < 950)
- The validator signed the block immediately after the parameter change
- The historical counter of 900 missed blocks is now evaluated against the new threshold of 50 allowed misses
- The condition `900 > 50` triggers slashing, demonstrating retroactive punishment

The test would verify:
```
- Before parameter change: validator status = Bonded, not jailed
- After parameter change + 1 block: validator status = Unbonding, jailed
- Validator was slashed despite being compliant under previous rules
```

This proves that changing `MinSignedPerWindow` retroactively slashes validators who were following the rules at the time of their behavior.

### Citations

**File:** x/slashing/keeper/infractions.go (L72-122)
```go
	minSignedPerWindow := k.MinSignedPerWindow(ctx)
	if missed {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeLiveness,
				sdk.NewAttribute(types.AttributeKeyAddress, consAddr.String()),
				sdk.NewAttribute(types.AttributeKeyMissedBlocks, fmt.Sprintf("%d", signInfo.MissedBlocksCounter)),
				sdk.NewAttribute(types.AttributeKeyHeight, fmt.Sprintf("%d", height)),
			),
		)

		logger.Debug(
			"absent validator",
			"height", height,
			"validator", consAddr.String(),
			"missed", signInfo.MissedBlocksCounter,
			"threshold", minSignedPerWindow,
		)
	}

	minHeight := signInfo.StartHeight + window
	maxMissed := window - minSignedPerWindow
	shouldSlash = false
	// if we are past the minimum height and the validator has missed too many blocks, punish them
	if height > minHeight && signInfo.MissedBlocksCounter > maxMissed {
		validator := k.sk.ValidatorByConsAddr(ctx, consAddr)
		if validator != nil && !validator.IsJailed() {
			// Downtime confirmed: slash and jail the validator
			// We need to retrieve the stake distribution which signed the block, so we subtract ValidatorUpdateDelay from the evidence height,
			// and subtract an additional 1 since this is the LastCommit.
			// Note that this *can* result in a negative "distributionHeight" up to -ValidatorUpdateDelay-1,
			// i.e. at the end of the pre-genesis block (none) = at the beginning of the genesis block.
			// That's fine since this is just used to filter unbonding delegations & redelegations.
			shouldSlash = true
			distributionHeight := height - sdk.ValidatorUpdateDelay - 1
			slashInfo = SlashInfo{
				height:             height,
				power:              power,
				distributionHeight: distributionHeight,
				minHeight:          minHeight,
				minSignedPerWindow: minSignedPerWindow,
			}
			// This value is passed back and the validator is slashed and jailed appropriately
		} else {
			// validator was (a) not found or (b) already jailed so we do not slash
			logger.Info(
				"validator would have been slashed for downtime, but was either not found in store or already jailed",
				"validator", consAddr.String(),
			)
		}
	}
```

**File:** x/slashing/keeper/infractions.go (L171-177)
```go
	case missedInfo.WindowSize > window:
		// if window size is reduced, we would like to make a clean state so that no validators are unexpectedly jailed due to more recent missed blocks
		newMissedBlocks := make([]bool, window)
		missedInfo.MissedBlocks = k.ParseBoolArrayToBitGroups(newMissedBlocks)
		signInfo.MissedBlocksCounter = int64(0)
		missedInfo.WindowSize = window
		signInfo.IndexOffset = 0
```

**File:** x/slashing/keeper/params.go (L17-24)
```go
func (k Keeper) MinSignedPerWindow(ctx sdk.Context) int64 {
	var minSignedPerWindow sdk.Dec
	k.paramspace.Get(ctx, types.KeyMinSignedPerWindow, &minSignedPerWindow)
	signedBlocksWindow := k.SignedBlocksWindow(ctx)

	// NOTE: RoundInt64 will never panic as minSignedPerWindow is
	//       less than 1.
	return minSignedPerWindow.MulInt64(signedBlocksWindow).RoundInt64()
```

**File:** x/params/proposal_handler.go (L26-42)
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
```

**File:** x/slashing/types/params.go (L20-21)
```go
	DefaultSlashFractionDoubleSign = sdk.NewDec(0)
	DefaultSlashFractionDowntime   = sdk.NewDec(0)
```
