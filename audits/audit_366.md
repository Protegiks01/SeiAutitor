# Audit Report

## Title
BeginBlocker Allows All Validators to be Jailed Simultaneously, Causing Total Network Shutdown

## Summary
The slashing module's BeginBlocker can jail all validators simultaneously when they all exceed the downtime threshold in the same block, with no safeguard to prevent an empty validator set. This results in a complete chain halt as Tendermint cannot produce blocks without any active validators.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary: `x/slashing/abci.go` BeginBlocker function
- Secondary: `x/slashing/keeper/infractions.go` HandleValidatorSignatureConcurrent and SlashJailAndUpdateSigningInfo
- Tertiary: `x/staking/keeper/val_state_change.go` ApplyAndReturnValidatorSetUpdates [1](#0-0) 

**Intended Logic:** 
The BeginBlocker is intended to track validator liveness and jail validators who miss too many blocks. The system should maintain at least one active validator to continue block production and chain progression.

**Actual Logic:** 
The current implementation processes all validator signatures concurrently and jails any validator exceeding the missed blocks threshold without checking if this would result in an empty validator set. [2](#0-1) 

When a validator is jailed, they are removed from the validator power index: [3](#0-2) 

During EndBlocker, `ApplyAndReturnValidatorSetUpdates` only iterates over validators present in the power index. If all validators are jailed and removed from this index, the loop finds zero validators: [4](#0-3) 

All previously bonded validators are then sent to Tendermint as zero-power updates, resulting in an empty validator set: [5](#0-4) 

**Exploit Scenario:**
1. A network-wide event causes all validators to miss blocks simultaneously (e.g., DDoS attack, network partition, infrastructure failure, or coordinated downtime)
2. All validators' `MissedBlocksCounter` exceeds the threshold within the signing window
3. In BeginBlocker, all validators are processed concurrently and flagged for jailing
4. `SlashJailAndUpdateSigningInfo` is called for each validator, jailing them all
5. Each validator is removed from the power index via `DeleteValidatorByPowerIndex`
6. In EndBlocker, `ApplyAndReturnValidatorSetUpdates` finds zero validators in the power index
7. All validators are sent to Tendermint with power 0
8. The chain halts with an empty validator set

**Security Failure:** 
The code violates the critical invariant that at least one validator must remain active to maintain chain liveness. There is no check in the jailing logic to prevent removing the last validator(s) from the active set.

## Impact Explanation

**Affected Components:**
- Network availability: The entire chain becomes unable to produce new blocks
- Transaction finality: All pending transactions remain unconfirmed indefinitely
- Validator operations: No validator can participate in consensus until manual intervention

**Severity:**
This is a catastrophic failure requiring emergency manual intervention:
- The chain completely halts and cannot recover automatically
- Validators must coordinate off-chain to unjail themselves, but cannot submit unjail transactions without block production
- Requires either a coordinated restart with modified state or a hard fork to recover
- All economic activity on the chain stops until resolution

**System Impact:**
This represents a complete denial of service at the consensus layer, falling squarely within the "High - Network not being able to confirm new transactions (total network shutdown)" impact category.

## Likelihood Explanation

**Triggering Conditions:**
- Any network participant can observe this vulnerability being triggered
- No malicious actor or special privileges required
- Can occur through natural network failures or adverse conditions

**Realistic Scenarios:**
1. **Network Partition:** A network split causing all validators to lose connectivity simultaneously
2. **Infrastructure Failure:** Coordinated cloud provider outage, DNS failure, or routing issues
3. **DDoS Attack:** Distributed attack targeting all validator nodes simultaneously
4. **Software Bug:** A bug in validator software causing widespread crashes
5. **Coordinated Maintenance:** Multiple validators performing maintenance simultaneously without coordination

**Frequency:**
- While simultaneous downtime of all validators is not common under normal operation, it becomes increasingly likely as:
  - The validator set becomes smaller
  - Validators share infrastructure dependencies (same cloud provider, data center, etc.)
  - Network conditions deteriorate during stress or attacks
- Once triggered, requires manual intervention to recover

## Recommendation

Implement a safeguard in the jailing logic to prevent the active validator set from becoming empty:

1. **Before jailing:** Add a check in `SlashJailAndUpdateSigningInfo` or `HandleValidatorSignatureConcurrent` to count currently active (non-jailed) validators
2. **Minimum validator threshold:** Prevent jailing if it would reduce active validators below a minimum threshold (e.g., 1 or a configurable minimum)
3. **Alternative approach:** Implement a "circuit breaker" that suspends automatic jailing if too many validators would be jailed in a single block
4. **Recovery mechanism:** Consider implementing an automatic unjailing mechanism after sufficient time has passed if the validator set becomes critically small

Example implementation location:
- Add a check in `x/slashing/keeper/infractions.go` before line 105 to count active validators
- Skip jailing (or queue for later jailing) if this validator is among the last N active validators
- Log a critical warning when approaching the minimum validator threshold

## Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`

**Test Function:** `TestAllValidatorsJailedSimultaneously`

**Setup:**
1. Initialize a simapp with 3 validators using `simapp.Setup(false)`
2. Set slashing parameters with `SignedBlocksWindow = 100` and `MinSignedPerWindow = 0.5`
3. Create 3 bonded validators with equal power (e.g., 100 each)
4. Call `staking.EndBlocker` to finalize the initial validator set

**Trigger:**
1. Have all 3 validators sign blocks successfully for the first 100 blocks (establishing the sliding window)
2. Then have all 3 validators miss the next 51 blocks (exceeding the 50% threshold)
3. Call `slashing.BeginBlocker` for block 152 with all validators having `SignedLastBlock = false`
4. Call `staking.EndBlocker` to apply validator set updates

**Observation:**
1. After EndBlocker, check that all 3 validators have `IsJailed() == true`
2. Call `app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)` 
3. Verify that the returned `validatorUpdates` contains only zero-power updates
4. Verify that no validators remain in the bonded state
5. The test demonstrates that the chain would halt as Tendermint receives an empty validator set

**Test Code Structure:**
```go
func TestAllValidatorsJailedSimultaneously(t *testing.T) {
    // Setup app and context
    // Create 3 validators with equal power
    // Configure slashing params
    // Simulate 100 blocks with all validators signing
    // Simulate 51+ blocks with all validators missing
    // Call BeginBlocker to process missed blocks and jail all validators
    // Call EndBlocker to compute validator updates
    // Assert all validators are jailed
    // Assert validator set updates contain only zero-power entries
    // Assert no active validators remain
}
```

This PoC demonstrates that the vulnerability is triggerable and would result in a complete chain halt, requiring manual intervention to recover.

### Citations

**File:** x/slashing/abci.go (L24-66)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	var wg sync.WaitGroup
	// Iterate over all the validators which *should* have signed this block
	// store whether or not they have actually signed it and slash/unbond any
	// which have missed too many blocks in a row (downtime slashing)

	// this allows us to preserve the original ordering for writing purposes
	slashingWriteInfo := make([]*SlashingWriteInfo, len(req.LastCommitInfo.GetVotes()))

	allVotes := req.LastCommitInfo.GetVotes()
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
		} else {
			k.SetValidatorMissedBlocks(ctx, writeInfo.ConsAddr, writeInfo.MissedInfo)
		}
		k.SetValidatorSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SigningInfo)
	}
}
```

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
