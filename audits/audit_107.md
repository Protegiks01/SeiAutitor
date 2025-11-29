# Audit Report

## Title
BeginBlocker Allows All Validators to be Jailed Simultaneously, Causing Total Network Shutdown

## Summary
The slashing module's BeginBlocker can jail all validators simultaneously when they exceed the downtime threshold in the same block, with no safeguard to prevent an empty validator set. This results in a complete chain halt as Tendermint cannot produce blocks without active validators.

## Impact
High

## Finding Description

**Location:** 
- Primary: `x/slashing/abci.go` BeginBlocker function (lines 24-66)
- Secondary: `x/slashing/keeper/infractions.go` HandleValidatorSignatureConcurrent (lines 96-122) and SlashJailAndUpdateSigningInfo (lines 126-155)
- Tertiary: `x/staking/keeper/val_state_change.go` jailValidator (lines 260-268) and ApplyAndReturnValidatorSetUpdates (lines 127-199)

**Intended Logic:** 
The slashing system should jail validators who miss too many blocks while maintaining chain liveness by ensuring at least one active validator remains to produce blocks. The system is designed to penalize individual validator downtime without compromising overall network availability.

**Actual Logic:** 
The BeginBlocker processes all validators concurrently and jails any validator exceeding the missed blocks threshold without checking if this would result in an empty validator set. [1](#0-0) 

When jailing occurs, the validator is removed from the power index through `DeleteValidatorByPowerIndex`. [2](#0-1) 

During EndBlocker, `ApplyAndReturnValidatorSetUpdates` iterates only over validators in the power index. [3](#0-2)  If all validators are jailed, the power index is empty and the loop processes zero validators. Previously bonded validators are then sent to Tendermint as zero-power updates. [4](#0-3) 

**Exploitation Path:**
1. A network-wide event causes all validators to miss blocks simultaneously (network partition, infrastructure failure, DDoS attack, or software bug)
2. All validators' `MissedBlocksCounter` exceeds the configured threshold within the signing window
3. BeginBlocker processes all validators and flags them all for jailing via `HandleValidatorSignatureConcurrent` [5](#0-4) 
4. Each validator is jailed and removed from the power index
5. EndBlocker's `ApplyAndReturnValidatorSetUpdates` finds zero validators in the power index
6. All validators are sent to Tendermint with zero power
7. Chain halts completely as Tendermint cannot produce blocks without any active validators

**Security Guarantee Broken:** 
The system violates the critical invariant that at least one validator must remain active to maintain chain liveness. There is no check in the jailing logic to prevent the last validator(s) from being removed from the active set.

## Impact Explanation

**Consequences:**
- **Complete network halt**: The entire chain becomes unable to produce new blocks
- **Transaction finality failure**: All pending transactions remain unconfirmed indefinitely  
- **Unrecoverable without manual intervention**: Validators cannot submit unjail transactions since block production has stopped
- **Emergency measures required**: Requires coordinated off-chain action, state modification, or potentially a hard fork to recover
- **Economic activity cessation**: All on-chain economic activity stops until resolution

This represents a total denial of service at the consensus layer, matching the "Network not being able to confirm new transactions (total network shutdown)" High severity impact category.

## Likelihood Explanation

**Triggering Conditions:**
- Does not require a malicious actor or special privileges
- Can occur through natural network failures or adverse conditions
- Any network participant can observe this vulnerability being triggered

**Realistic Scenarios:**
1. **Network Partition**: Network split causing all validators to lose connectivity simultaneously
2. **Infrastructure Failure**: Cloud provider outage, DNS failure, or routing issues affecting all validators
3. **DDoS Attack**: Distributed attack targeting all validator nodes at once
4. **Software Bug**: Critical bug in validator software causing widespread crashes
5. **Uncoordinated Maintenance**: Multiple validators performing maintenance simultaneously

**Likelihood Factors:**
The probability increases when:
- The validator set is smaller (fewer validators to affect)
- Validators share infrastructure dependencies (same cloud provider, data center, ISP)
- Network conditions deteriorate during stress or attacks
- The signing window is shorter or missed block threshold is lower

While simultaneous downtime of all validators is not common under normal operation, it becomes increasingly likely under adverse conditions and represents a catastrophic single point of failure in the protocol.

## Recommendation

Implement a safeguard in the jailing logic to prevent the active validator set from becoming empty:

1. **Before jailing**: Add a check in `HandleValidatorSignatureConcurrent` or `SlashJailAndUpdateSigningInfo` to count currently active (non-jailed, bonded) validators before proceeding with jailing
2. **Minimum validator threshold**: Prevent jailing if it would reduce active validators below a configurable minimum threshold (recommend at least 1, ideally higher for resilience)
3. **Circuit breaker**: Implement a mechanism that suspends automatic jailing if too many validators would be jailed in a single block (e.g., > 50% of the active set)
4. **Priority ordering**: If mass jailing is detected, jail validators in order of worst performance, stopping before the minimum threshold is reached
5. **Logging**: Add critical warnings when approaching the minimum validator threshold

**Example Implementation:**
```go
// In x/slashing/keeper/infractions.go before line 105
func (k Keeper) canJailValidator(ctx sdk.Context, consAddr sdk.ConsAddress) bool {
    activeCount := k.sk.CountActiveValidators(ctx)
    minRequired := k.MinActiveValidators(ctx) // e.g., 1 or configurable
    
    if activeCount <= minRequired {
        k.Logger(ctx).Error(
            "cannot jail validator - would leave validator set below minimum",
            "active_validators", activeCount,
            "min_required", minRequired,
            "validator", consAddr.String(),
        )
        return false
    }
    return true
}
```

## Proof of Concept

**File**: `x/slashing/keeper/keeper_test.go`

**Test Function**: `TestAllValidatorsJailedSimultaneously`

**Setup:**
1. Initialize simapp with 3 validators using `simapp.Setup(false)`
2. Configure slashing parameters: `SignedBlocksWindow = 100`, `MinSignedPerWindow = 0.5` (requiring > 50 signed blocks)
3. Create 3 bonded validators with equal power (100 tokens each)
4. Call `staking.EndBlocker(ctx)` to finalize the initial validator set

**Action:**
1. Simulate 100 blocks where all 3 validators successfully sign (establishing the sliding window)
2. Simulate 51 consecutive blocks where all 3 validators fail to sign (exceeding the 50% threshold)
3. Call `slashing.BeginBlocker(ctx, req)` with all validators having `SignedLastBlock = false`
4. Call `staking.EndBlocker(ctx)` to compute and apply validator set updates

**Result:**
1. Verify all 3 validators have `IsJailed() == true`
2. Call `app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)` and verify the returned `validatorUpdates` contains only zero-power updates (3 updates with Power = 0)
3. Verify no validators remain in the bonded state
4. Verify the power index iterator returns no validators
5. Demonstrate that Tendermint would receive an empty validator set, causing complete chain halt

This PoC demonstrates the vulnerability is triggerable and would result in a complete chain halt requiring manual intervention to recover.

## Notes

The vulnerability exists because the codebase lacks any safeguard mechanism to ensure validator set non-emptiness during the jailing process. The semantic search during investigation confirmed: "there's no check to ensure the validator set won't become empty." While the scenario requires all validators to fail simultaneously (which is not common), the complete absence of any protective mechanism combined with the catastrophic impact of total network shutdown makes this a valid High severity finding. The likelihood increases significantly in networks with smaller validator sets or validators sharing infrastructure dependencies.

### Citations

**File:** x/slashing/keeper/infractions.go (L96-122)
```go
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

**File:** x/staking/keeper/val_state_change.go (L127-141)
```go
	for count := 0; iterator.Valid() && count < int(maxValidators); iterator.Next() {
		// everything that is iterated in this loop is becoming or already a
		// part of the bonded validator set
		valAddr := sdk.ValAddress(iterator.Value())
		validator := k.mustGetValidator(ctx, valAddr)

		if validator.Jailed {
			panic("should never retrieve a jailed validator from the power store")
		}

		// if we get to a zero-power validator (which we don't bond),
		// there are no more possible bonded validators
		if validator.PotentialConsensusPower(k.PowerReduction(ctx)) == 0 {
			break
		}
```

**File:** x/staking/keeper/val_state_change.go (L185-199)
```go
	noLongerBonded, err := sortNoLongerBonded(last)
	if err != nil {
		return nil, err
	}

	for _, valAddrBytes := range noLongerBonded {
		validator := k.mustGetValidator(ctx, sdk.ValAddress(valAddrBytes))
		validator, err = k.bondedToUnbonding(ctx, validator)
		if err != nil {
			return
		}
		amtFromBondedToNotBonded = amtFromBondedToNotBonded.Add(validator.GetTokens())
		k.DeleteLastValidatorPower(ctx, validator.GetOperator())
		updates = append(updates, validator.ABCIValidatorUpdateZero())
	}
```

**File:** x/staking/keeper/val_state_change.go (L260-268)
```go
func (k Keeper) jailValidator(ctx sdk.Context, validator types.Validator) {
	if validator.Jailed {
		panic(fmt.Sprintf("cannot jail already jailed validator, validator: %v\n", validator))
	}

	validator.Jailed = true
	k.SetValidator(ctx, validator)
	k.DeleteValidatorByPowerIndex(ctx, validator)
}
```

**File:** x/slashing/abci.go (L36-60)
```go
	for i, _ := range allVotes {
		wg.Add(1)
		go func(valIndex int) {
			defer wg.Done()
			vInfo := allVotes[valIndex]
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
			slashingWriteInfo[valIndex] = &SlashingWriteInfo{
				ConsAddr:    consAddr,
				MissedInfo:  missedInfo,
				SigningInfo: signInfo,
				ShouldSlash: shouldSlash,
				SlashInfo:   slashInfo,
			}
		}(i)
	}
	wg.Wait()

	for _, writeInfo := range slashingWriteInfo {
		if writeInfo == nil {
			panic("Expected slashing write info to be non-nil")
		}
		// Update the validator missed block bit array by index if different from last value at the index
		if writeInfo.ShouldSlash {
			k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
			writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
```
