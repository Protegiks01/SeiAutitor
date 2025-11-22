# Audit Report

## Title
BeginBlocker Allows Simultaneous Jailing of All Validators Leading to Complete Network Shutdown

## Summary
The slashing module's BeginBlocker can jail all validators simultaneously when they collectively exceed the downtime threshold, with no safeguard to prevent an empty validator set. This results in a complete and irrecoverable chain halt as Tendermint requires at least one active validator to produce blocks.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location**: 
- Primary: `x/slashing/abci.go` BeginBlocker function [1](#0-0) 
- Secondary: `x/slashing/keeper/infractions.go` HandleValidatorSignatureConcurrent [2](#0-1) 
- Tertiary: `x/staking/keeper/val_state_change.go` ApplyAndReturnValidatorSetUpdates [3](#0-2) 

**Intended Logic**: 
The BeginBlocker should track validator liveness and jail validators who miss too many blocks while maintaining at least one active validator to ensure continuous block production and chain liveness.

**Actual Logic**: 
The implementation processes all validator signatures concurrently and independently jails each validator exceeding the missed blocks threshold. The only check performed is whether each individual validator is already jailed (`!validator.IsJailed()`), not whether jailing would result in an empty validator set [4](#0-3) . 

When validators are jailed, they are removed from the validator power index [5](#0-4) , and the power index iterator in EndBlocker will find zero validators if all are jailed [6](#0-5) . All previously bonded validators are then sent to Tendermint as zero-power updates [7](#0-6) , resulting in an empty validator set.

**Exploitation Path**:
1. Network event causes all validators to miss blocks simultaneously (DDoS, network partition, infrastructure failure, or coordinated downtime)
2. All validators' MissedBlocksCounter exceeds the threshold within the signing window
3. BeginBlocker processes all validators concurrently, marking each for jailing independently
4. SlashJailAndUpdateSigningInfo is called for each validator, jailing all of them
5. Each validator is removed from the power index via DeleteValidatorByPowerIndex
6. EndBlocker's ApplyAndReturnValidatorSetUpdates iterates the now-empty power index
7. All validators are sent to Tendermint with power=0
8. Chain halts permanently with no validators to produce blocks

**Security Guarantee Broken**: 
The code violates the critical invariant that at least one validator must remain active to maintain chain liveness. No safeguard exists to prevent the active validator set from becoming empty.

## Impact Explanation

This vulnerability causes catastrophic network failure:

- **Complete chain halt**: No new blocks can be produced as Tendermint has no active validators
- **Transaction finality loss**: All pending transactions remain unconfirmed indefinitely  
- **Irrecoverable catch-22**: Validators cannot submit unjail transactions without block production, but block production requires active validators
- **Manual intervention required**: Recovery requires coordinated off-chain action, state modification, or hard fork
- **Economic activity cessation**: All on-chain operations stop until manual resolution

The impact directly matches the HIGH severity category: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering Conditions**:
- Any network participant can observe this being triggered
- No malicious actor or special privileges required
- Occurs through natural network failures or adverse conditions

**Realistic Scenarios**:
1. **Network Partition**: Connectivity loss affecting all validators simultaneously
2. **Infrastructure Failure**: Cloud provider outage, DNS failure, or routing issues affecting validator infrastructure
3. **DDoS Attack**: Coordinated attack targeting all validator nodes
4. **Software Bug**: Validator software bug causing widespread crashes
5. **Uncoordinated Maintenance**: Multiple validators performing maintenance simultaneously

**Probability Factors**:
- Likelihood increases with smaller validator sets
- Higher risk when validators share infrastructure (same cloud provider, data center, region)
- More probable during network stress, attacks, or infrastructure failures
- While not common in normal operation, these scenarios have occurred in production blockchain networks

## Recommendation

Implement safeguards to prevent the active validator set from becoming empty:

1. **Active Validator Count Check**: Before jailing in `SlashJailAndUpdateSigningInfo` or `HandleValidatorSignatureConcurrent`, count currently active (non-jailed) validators. Skip jailing if it would reduce active validators below a minimum threshold (e.g., 1 or configurable minimum).

2. **Circuit Breaker**: Implement a mechanism that suspends automatic jailing if too many validators would be jailed in a single block (e.g., if >50% of validators would be jailed).

3. **Minimum Validator Threshold**: Add a protocol parameter for minimum active validators and enforce it in the jailing logic.

4. **Emergency Recovery**: Consider implementing an automatic unjailing mechanism that activates when the validator set becomes critically small.

**Implementation Location**: Add validation in `x/slashing/keeper/infractions.go` before line 105 to count active validators and skip jailing if this validator is among the last N active validators. Log critical warnings when approaching the minimum threshold.

## Proof of Concept

**Test Structure** (Conceptual - not executable without implementation):

**Setup**:
1. Initialize simapp with 3 validators using `simapp.Setup(false)`
2. Configure slashing parameters: `SignedBlocksWindow = 100`, `MinSignedPerWindow = 0.5`
3. Create 3 bonded validators with equal power (100 each)
4. Call `staking.EndBlocker` to finalize initial validator set

**Trigger**:
1. Simulate 100 blocks with all validators signing successfully (establish sliding window)
2. Simulate 51 blocks with all validators missing blocks (exceed 50% threshold)
3. Call `slashing.BeginBlocker` with all validators having `SignedLastBlock = false`
4. Call `staking.EndBlocker` to apply validator set updates

**Observation**:
1. Verify all 3 validators have `IsJailed() == true`
2. Call `app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)`
3. Verify returned `validatorUpdates` contains only zero-power updates
4. Verify no validators remain in bonded state
5. Demonstrates chain would halt with empty Tendermint validator set

**Note**: While a complete executable test is not provided, the vulnerability flow is clearly demonstrable from the code structure and logic analyzed above.

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

**File:** x/staking/keeper/val_state_change.go (L190-198)
```go
	for _, valAddrBytes := range noLongerBonded {
		validator := k.mustGetValidator(ctx, sdk.ValAddress(valAddrBytes))
		validator, err = k.bondedToUnbonding(ctx, validator)
		if err != nil {
			return
		}
		amtFromBondedToNotBonded = amtFromBondedToNotBonded.Add(validator.GetTokens())
		k.DeleteLastValidatorPower(ctx, validator.GetOperator())
		updates = append(updates, validator.ABCIValidatorUpdateZero())
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

**File:** x/staking/keeper/validator.go (L241-243)
```go
func (k Keeper) ValidatorsPowerStoreIterator(ctx sdk.Context) sdk.Iterator {
	store := ctx.KVStore(k.storeKey)
	return sdk.KVStoreReversePrefixIterator(store, types.ValidatorsByPowerIndexKey)
```
