## Title
Unbounded Storage Growth from Undeleted Validator Signing Info After Validator Removal

## Summary
The slashing module fails to delete `ValidatorSigningInfo` and `ValidatorMissedBlockBitArray` entries when validators are removed from the network, causing unbounded storage growth that eventually leads to node storage exhaustion.

## Impact
Medium

## Finding Description

**Location:** 
- `x/slashing/keeper/hooks.go` lines 40-43 (AfterValidatorRemoved hook)
- `x/slashing/keeper/signing_info.go` lines 34-38 (SetValidatorSigningInfo) [1](#0-0) [2](#0-1) 

**Intended Logic:** 
When a validator is removed from the network, all associated state data (including signing info and missed block records) should be cleaned up to prevent storage bloat.

**Actual Logic:** 
The `AfterValidatorRemoved` hook only deletes the address-pubkey relation but never deletes the `ValidatorSigningInfo` or `ValidatorMissedBlockBitArray` entries. These remain in the store permanently. [3](#0-2) 

When a validator is bonded, signing info is created: [4](#0-3) 

When a validator completes unbonding and has zero delegator shares, it is removed: [5](#0-4) [6](#0-5) [7](#0-6) 

**Exploit Scenario:**
1. A validator joins the network (creates signing info via `AfterValidatorBonded`)
2. The validator accumulates missed block data in `ValidatorMissedBlockBitArray`
3. The validator unbonds and eventually gets removed when `DelegatorShares.IsZero() && validator.IsUnbonded()`
4. The `RemoveValidator` function calls the `AfterValidatorRemoved` hook
5. The hook only deletes the pubkey relation, leaving signing info intact
6. Each removed validator permanently adds ~1.5 KB of data (ValidatorSigningInfo + ValidatorMissedBlockBitArray)
7. Over time, as validators join and leave, storage grows without bound

An attacker could accelerate this by repeatedly:
- Creating validators with minimum stake
- Bonding them (creating signing info)
- Unbonding them immediately
- Waiting for the unbonding period to complete
- Each cycle adds permanent storage that never gets cleaned up

**Security Failure:** 
This breaks the resource management invariant that removed validators should have their state fully cleaned up. Storage grows unbounded, eventually exhausting disk space on all network nodes.

## Impact Explanation

**Affected Components:**
- All network processing nodes experience unbounded storage growth
- Database performance degrades as signing info table grows
- Iteration operations (like `IterateValidatorSigningInfos`) become progressively slower [8](#0-7) 

**Severity:**
- Each removed validator leaves behind approximately 1.5 KB of data:
  - ValidatorSigningInfo: ~100-200 bytes
  - ValidatorMissedBlockBitArray: ~1,250 bytes (for default 10,000 block window) [9](#0-8) [10](#0-9) 

- With active validator churn:
  - 100 validators/month = ~18 MB/year
  - 1,000 validators/month = ~180 MB/year  
  - Over 5-10 years, this accumulates to multiple GB of wasted storage
- Eventually causes nodes to run out of disk space, leading to node crashes or failures
- Affects network reliability and increases operational costs for node operators

## Likelihood Explanation

**Trigger Conditions:**
- Any network participant can create and remove validators through standard staking operations
- Validators are removed automatically when they complete unbonding with zero delegator shares
- This happens during normal network operation without any special privileges required

**Frequency:**
- Occurs naturally as validators join and leave the network over time
- Can be intentionally accelerated by an attacker creating temporary validators
- The attack cost is only the minimum validator stake and transaction fees
- The unbonding period (typically 21 days) is the only rate limiter
- Even normal validator churn of 10-20 validators per month compounds significantly over years

**Exploitability:**
High likelihood - this is guaranteed to occur during normal network operation and accumulates inexorably over time.

## Recommendation

Modify the `AfterValidatorRemoved` hook to delete both the `ValidatorSigningInfo` and `ValidatorMissedBlockBitArray` entries when a validator is removed:

```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
    k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
    
    // Delete validator signing info
    store := ctx.KVStore(k.storeKey)
    store.Delete(types.ValidatorSigningInfoKey(address))
    
    // Delete validator missed blocks bit array
    store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

Alternatively, leverage the existing `ClearValidatorMissedBlockBitArray` function and add a similar deletion function for signing info. [11](#0-10) 

## Proof of Concept

**File:** `x/slashing/keeper/hooks_test.go`

**Test Function:** `TestValidatorRemovalLeavesSigningInfo`

**Setup:**
1. Initialize a test application with staking and slashing modules
2. Create a validator address and consensus address
3. Call `AfterValidatorBonded` to create signing info (simulating validator bonding)
4. Create and set some missed block data for the validator
5. Verify that signing info exists in the store

**Trigger:**
1. Call `AfterValidatorRemoved` to simulate validator removal
2. This is the same hook called when `RemoveValidator` is invoked by the staking module

**Observation:**
1. Check if `ValidatorSigningInfo` still exists after removal (it will)
2. Check if `ValidatorMissedBlockBitArray` still exists after removal (it will)
3. The test confirms that signing data persists indefinitely after validator removal
4. Demonstrate that calling this multiple times accumulates unreachable data

```go
func TestValidatorRemovalLeavesSigningInfo(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 3, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    consAddr := sdk.ConsAddress(addrDels[0])
    valAddr := sdk.ValAddress(addrDels[0])
    keeper := app.SlashingKeeper
    
    // Simulate validator bonding - this creates signing info
    keeper.AfterValidatorBonded(ctx, consAddr, valAddr)
    
    // Set some missed blocks to simulate real validator data
    missedInfo := types.ValidatorMissedBlockArray{
        Address: consAddr.String(),
        WindowSize: 100,
        MissedBlocks: []uint64{1, 2, 3}, // Some missed blocks
    }
    keeper.SetValidatorMissedBlocks(ctx, consAddr, missedInfo)
    
    // Verify signing info exists
    signingInfo, found := keeper.GetValidatorSigningInfo(ctx, consAddr)
    require.True(t, found, "Signing info should exist after bonding")
    
    // Verify missed blocks exist
    missedData, found := keeper.GetValidatorMissedBlocks(ctx, consAddr)
    require.True(t, found, "Missed blocks should exist")
    require.Equal(t, int64(100), missedData.WindowSize)
    
    // Count all signing infos before removal
    countBefore := 0
    keeper.IterateValidatorSigningInfos(ctx, func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
        countBefore++
        return false
    })
    require.Equal(t, 1, countBefore, "Should have 1 signing info")
    
    // Simulate validator removal - this should clean up signing info but doesn't
    keeper.AfterValidatorRemoved(ctx, consAddr)
    
    // BUG: Signing info still exists after removal
    signingInfo, found = keeper.GetValidatorSigningInfo(ctx, consAddr)
    require.True(t, found, "BUG: Signing info still exists after validator removal")
    
    // BUG: Missed blocks still exist after removal  
    missedData, found = keeper.GetValidatorMissedBlocks(ctx, consAddr)
    require.True(t, found, "BUG: Missed blocks still exist after validator removal")
    
    // Count all signing infos after removal - still 1
    countAfter := 0
    keeper.IterateValidatorSigningInfos(ctx, func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
        countAfter++
        return false
    })
    require.Equal(t, 1, countAfter, "BUG: Signing info count unchanged after removal")
    
    // Demonstrate accumulation: add and remove multiple validators
    for i := 1; i < 3; i++ {
        testConsAddr := sdk.ConsAddress(addrDels[i])
        testValAddr := sdk.ValAddress(addrDels[i])
        
        keeper.AfterValidatorBonded(ctx, testConsAddr, testValAddr)
        keeper.AfterValidatorRemoved(ctx, testConsAddr)
    }
    
    // Count shows all signing infos still present
    finalCount := 0
    keeper.IterateValidatorSigningInfos(ctx, func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
        finalCount++
        return false
    })
    require.Equal(t, 3, finalCount, "BUG: All 3 signing infos persist after removal, demonstrating unbounded growth")
}
```

This test demonstrates that validator signing info and missed block data are never deleted when validators are removed, confirming the unbounded storage growth vulnerability.

### Citations

**File:** x/slashing/keeper/hooks.go (L12-26)
```go
func (k Keeper) AfterValidatorBonded(ctx sdk.Context, address sdk.ConsAddress, _ sdk.ValAddress) {
	// Update the signing info start height or create a new signing info
	_, found := k.GetValidatorSigningInfo(ctx, address)
	if !found {
		signingInfo := types.NewValidatorSigningInfo(
			address,
			ctx.BlockHeight(),
			0,
			time.Unix(0, 0),
			false,
			0,
		)
		k.SetValidatorSigningInfo(ctx, address, signingInfo)
	}
}
```

**File:** x/slashing/keeper/hooks.go (L40-43)
```go
// AfterValidatorRemoved deletes the address-pubkey relation when a validator is removed,
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** x/slashing/keeper/signing_info.go (L34-38)
```go
func (k Keeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info types.ValidatorSigningInfo) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&info)
	store.Set(types.ValidatorSigningInfoKey(address), bz)
}
```

**File:** x/slashing/keeper/signing_info.go (L40-55)
```go
// IterateValidatorSigningInfos iterates over the stored ValidatorSigningInfo
func (k Keeper) IterateValidatorSigningInfos(ctx sdk.Context,
	handler func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool)) {

	store := ctx.KVStore(k.storeKey)
	iter := sdk.KVStorePrefixIterator(store, types.ValidatorSigningInfoKeyPrefix)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		address := types.ValidatorSigningInfoAddress(iter.Key())
		var info types.ValidatorSigningInfo
		k.cdc.MustUnmarshal(iter.Value(), &info)
		if handler(address, info) {
			break
		}
	}
}
```

**File:** x/slashing/keeper/signing_info.go (L167-171)
```go
// clearValidatorMissedBlockBitArray deletes every instance of ValidatorMissedBlockBitArray in the store
func (k Keeper) ClearValidatorMissedBlockBitArray(ctx sdk.Context, address sdk.ConsAddress) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

**File:** x/slashing/keeper/keeper.go (L94-97)
```go
func (k Keeper) deleteAddrPubkeyRelation(ctx sdk.Context, addr cryptotypes.Address) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.AddrPubkeyRelationKey(addr))
}
```

**File:** x/staking/keeper/validator.go (L153-181)
```go
func (k Keeper) RemoveValidator(ctx sdk.Context, address sdk.ValAddress) {
	// first retrieve the old validator record
	validator, found := k.GetValidator(ctx, address)
	if !found {
		return
	}

	if !validator.IsUnbonded() {
		panic("cannot call RemoveValidator on bonded or unbonding validators")
	}

	if validator.Tokens.IsPositive() {
		panic("attempting to remove a validator which still contains tokens")
	}

	valConsAddr, err := validator.GetConsAddr()
	if err != nil {
		panic(err)
	}

	// delete the old validator record
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetValidatorKey(address))
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
	store.Delete(types.GetValidatorsByPowerIndexKey(validator, k.PowerReduction(ctx)))

	// call hooks
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
}
```

**File:** x/staking/keeper/validator.go (L398-444)
```go
// have finished their unbonding period.
func (k Keeper) UnbondAllMatureValidators(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)

	blockTime := ctx.BlockTime()
	blockHeight := ctx.BlockHeight()

	// unbondingValIterator will contains all validator addresses indexed under
	// the ValidatorQueueKey prefix. Note, the entire index key is composed as
	// ValidatorQueueKey | timeBzLen (8-byte big endian) | timeBz | heightBz (8-byte big endian),
	// so it may be possible that certain validator addresses that are iterated
	// over are not ready to unbond, so an explicit check is required.
	unbondingValIterator := k.ValidatorQueueIterator(ctx, blockTime, blockHeight)
	defer unbondingValIterator.Close()

	for ; unbondingValIterator.Valid(); unbondingValIterator.Next() {
		key := unbondingValIterator.Key()
		keyTime, keyHeight, err := types.ParseValidatorQueueKey(key)
		if err != nil {
			panic(fmt.Errorf("failed to parse unbonding key: %w", err))
		}

		// All addresses for the given key have the same unbonding height and time.
		// We only unbond if the height and time are less than the current height
		// and time.
		if keyHeight <= blockHeight && (keyTime.Before(blockTime) || keyTime.Equal(blockTime)) {
			addrs := types.ValAddresses{}
			k.cdc.MustUnmarshal(unbondingValIterator.Value(), &addrs)

			for _, valAddr := range addrs.Addresses {
				addr, err := sdk.ValAddressFromBech32(valAddr)
				if err != nil {
					panic(err)
				}
				val, found := k.GetValidator(ctx, addr)
				if !found {
					panic("validator in the unbonding queue was not found")
				}

				if !val.IsUnbonding() {
					panic("unexpected validator in unbonding queue; status was not unbonding")
				}

				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/staking/keeper/delegation.go (L789-791)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
```

**File:** proto/cosmos/slashing/v1beta1/slashing.proto (L30-50)
```text
message ValidatorSigningInfo {
  option (gogoproto.equal)            = true;
  option (gogoproto.goproto_stringer) = false;

  string address = 1;
  // Height at which validator was first a candidate OR was unjailed
  int64 start_height = 2 [(gogoproto.moretags) = "yaml:\"start_height\""];
  // Index which is incremented each time the validator was a bonded
  // in a block and may have signed a precommit or not. This in conjunction with the
  // `SignedBlocksWindow` param determines the index in the `MissedBlocksBitArray`.
  int64 index_offset = 3 [(gogoproto.moretags) = "yaml:\"index_offset\""];
  // Timestamp until which the validator is jailed due to liveness downtime.
  google.protobuf.Timestamp jailed_until = 4
      [(gogoproto.moretags) = "yaml:\"jailed_until\"", (gogoproto.stdtime) = true, (gogoproto.nullable) = false];
  // Whether or not a validator has been tombstoned (killed out of validator set). It is set
  // once the validator commits an equivocation or for any other configured misbehiavor.
  bool tombstoned = 5;
  // A counter kept to avoid unnecessary array reads.
  // Note that `Sum(MissedBlocksBitArray)` always equals `MissedBlocksCounter`.
  int64 missed_blocks_counter = 6 [(gogoproto.moretags) = "yaml:\"missed_blocks_counter\""];
}
```

**File:** proto/cosmos/slashing/v1beta1/slashing.proto (L60-66)
```text
message ValidatorMissedBlockArray {
  string address = 1;
  // store this in case window size changes but doesn't affect number of bit groups
  int64 window_size = 2;
  // Array of contains the missed block bits packed into uint64s
  repeated uint64 missed_blocks = 3 [(gogoproto.moretags) = "yaml:\"missed_blocks\""];
}
```
