## Title
Unbounded Storage Growth from Unpruned Validator Signing Info After Validator Removal

## Summary
The slashing module does not prune validator signing info (ValidatorSigningInfo and ValidatorMissedBlockArray) when validators are removed from the staking module. This causes unbounded storage growth as stale data accumulates over time, leading to increased storage costs, degraded genesis export performance, and potential memory exhaustion during chain upgrades.

## Impact
**Medium**

## Finding Description

**Location:** 
- [1](#0-0) 

**Intended Logic:** 
When a validator is permanently removed from the system (after unbonding and having zero delegations), all associated data including signing info should be cleaned up to prevent storage bloat. The slashing module maintains two data structures per validator:
- ValidatorSigningInfo: Contains liveness tracking metadata (~100 bytes)
- ValidatorMissedBlockArray: A bit array tracking missed blocks with default window of 108,000 blocks (~13.5 KB) [2](#0-1) 

**Actual Logic:** 
The `AfterValidatorRemoved` hook only deletes the address-pubkey relation, but does NOT delete the validator's signing info or missed block array: [1](#0-0) 

These data structures remain in storage indefinitely even after the validator has been completely removed via `RemoveValidator`: [3](#0-2) 

The signing info and missed block data are set when validators are created/bonded: [4](#0-3) 

But no corresponding deletion occurs in the removal hook.

**Exploit Scenario:**
1. In a blockchain with permissionless validators (or natural validator churn), an attacker or normal participants create validators by staking the minimum required tokens
2. Each validator's signing info and missed block array (~13.6 KB total) are created and stored
3. Validators unbond and are eventually removed via `RemoveValidator` when they reach Unbonded status with zero tokens [5](#0-4) 
4. The signing data remains in storage permanently, never pruned
5. Over time with many validator additions/removals, storage accumulates:
   - 10,000 removed validators = ~136 MB
   - 100,000 removed validators = ~1.36 GB
   - This data persists forever in the state database

**Security Failure:**
- **Unbounded Storage Growth**: Node storage requirements grow indefinitely with no pruning mechanism
- **Genesis Export DoS**: The `ExportGenesis` function iterates over ALL signing infos, loading them into memory, which becomes extremely slow or causes OOM with large amounts of stale data [6](#0-5) 
- **Migration Performance Degradation**: Chain upgrades that migrate signing info process all stale entries [7](#0-6) 

## Impact Explanation

**Storage Impact:**
Every validator that is created and later removed leaves behind approximately 13.6 KB of permanent storage that cannot be pruned. With default parameters of a 108,000 block signing window, this accumulates to:
- ValidatorSigningInfo: ~100 bytes per validator
- ValidatorMissedBlockArray: 108,000 bits ÷ 8 ÷ 1024 ≈ 13.2 KB per validator [8](#0-7) [9](#0-8) 

**Genesis Export Impact:**
During chain upgrades or state exports, the system must iterate through and load all validator signing info into memory. With tens of thousands of stale entries, this:
- Increases memory consumption by gigabytes
- Slows down export operations proportionally to stale entry count
- Can cause out-of-memory failures on nodes with limited resources
- Makes genesis files bloated and slow to re-import

**Query Impact:**
The legacy `querySigningInfos` endpoint loads ALL signing info into memory before pagination, which can be exploited to cause high memory usage: [10](#0-9) 

This affects all full nodes and validators in the network, increasing infrastructure costs and potentially causing node failures during upgrade operations.

## Likelihood Explanation

**Triggering Conditions:**
- **Who:** Any participant who can create a validator (in permissionless networks) or through natural validator churn in any PoS network
- **When:** Occurs automatically during normal operations as validators join and leave the validator set
- **Frequency:** Accumulates continuously over the blockchain's lifetime. In active networks with validator rotation:
  - Testnet resets or validator experiments: hundreds of validators
  - Mainnet over years: potentially thousands to tens of thousands of validators

**Exploitability:**
- No special privileges required - any participant can create validators by staking tokens
- The cost to an attacker is the minimum validator stake times the number of validators created
- Naturally occurs even without malicious intent due to normal validator churn
- Cannot be mitigated once data has accumulated without a hard fork to prune state

**Realistic Scenarios:**
1. **Testnet Environment**: Developers frequently create/destroy validators during testing, rapidly accumulating stale data
2. **Validator Rotation**: In competitive validator markets, operators may frequently enter/exit, leaving data behind
3. **Malicious Accumulation**: An attacker with moderate capital could deliberately create thousands of validators, stake minimum amounts, then unbond to leave maximum storage footprint

The vulnerability is highly likely to manifest on any long-running chain, with severity increasing over time.

## Recommendation

Add cleanup logic in the `AfterValidatorRemoved` hook to delete validator signing info and missed block arrays when validators are permanently removed:

```go
// In x/slashing/keeper/hooks.go, modify AfterValidatorRemoved:
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
    // Delete address-pubkey relation
    k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
    
    // Delete signing info
    store := ctx.KVStore(k.storeKey)
    store.Delete(types.ValidatorSigningInfoKey(address))
    
    // Delete missed block array
    k.ClearValidatorMissedBlockBitArray(ctx, address)
}
```

The `ClearValidatorMissedBlockBitArray` function already exists and can be reused: [11](#0-10) 

This ensures that when a validator is fully removed from the system (unbonded with zero tokens), all associated slashing data is also cleaned up, preventing unbounded storage growth.

## Proof of Concept

**Test File:** `x/slashing/keeper/hooks_test.go` (new file)

**Test Function:** `TestValidatorSigningInfoNotPrunedAfterRemoval`

**Setup:**
1. Initialize a test application with staking and slashing keepers
2. Create a validator and verify it gets bonded
3. Verify signing info and missed block array are created for the validator
4. Unbond the validator completely (set to Unbonded status with zero tokens)
5. Call RemoveValidator to trigger the AfterValidatorRemoved hook

**Trigger:**
Execute validator removal which should theoretically clean up signing info but doesn't

**Observation:**
After validator removal, the signing info and missed block array still exist in storage, confirming they are not pruned. The test demonstrates that:
- ValidatorSigningInfo remains accessible via GetValidatorSigningInfo
- ValidatorMissedBlockArray remains accessible via GetValidatorMissedBlocks
- Storage continues to hold this data despite validator being completely removed

**Expected Behavior:** Both data structures should be deleted when validator is removed
**Actual Behavior:** Both data structures persist indefinitely in storage

```go
package keeper_test

import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

    "github.com/cosmos/cosmos-sdk/simapp"
    sdk "github.com/cosmos/cosmos-sdk/types"
    "github.com/cosmos/cosmos-sdk/x/slashing/types"
    stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func TestValidatorSigningInfoNotPrunedAfterRemoval(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})

    // Create a validator
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
    pks := simapp.CreateTestPubKeys(1)
    
    // Create validator
    val := stakingtypes.NewValidator(valAddrs[0], pks[0], stakingtypes.Description{})
    val.Status = stakingtypes.Bonded
    val.Tokens = app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
    val.DelegatorShares = sdk.NewDec(100)
    app.StakingKeeper.SetValidator(ctx, val)
    
    // Get consensus address
    consAddr, err := val.GetConsAddr()
    require.NoError(t, err)
    
    // Trigger hook to create signing info
    app.SlashingKeeper.AfterValidatorBonded(ctx, consAddr, valAddrs[0])
    
    // Verify signing info was created
    signingInfo, found := app.SlashingKeeper.GetValidatorSigningInfo(ctx, consAddr)
    require.True(t, found, "Signing info should exist after validator is bonded")
    require.Equal(t, consAddr.String(), signingInfo.Address)
    
    // Create and verify missed blocks array
    missedBlocks := types.ValidatorMissedBlockArray{
        Address:      consAddr.String(),
        WindowSize:   app.SlashingKeeper.SignedBlocksWindow(ctx),
        MissedBlocks: make([]uint64, 2),
    }
    app.SlashingKeeper.SetValidatorMissedBlocks(ctx, consAddr, missedBlocks)
    
    retrievedMissedBlocks, found := app.SlashingKeeper.GetValidatorMissedBlocks(ctx, consAddr)
    require.True(t, found, "Missed blocks array should exist")
    require.Equal(t, consAddr.String(), retrievedMissedBlocks.Address)
    
    // Now simulate validator removal
    // First set validator to unbonded status with zero tokens
    val.Status = stakingtypes.Unbonded
    val.Tokens = sdk.ZeroInt()
    val.DelegatorShares = sdk.ZeroDec()
    app.StakingKeeper.SetValidator(ctx, val)
    
    // Remove the validator (this should trigger AfterValidatorRemoved hook)
    app.StakingKeeper.RemoveValidator(ctx, valAddrs[0])
    
    // Verify validator is actually removed from staking module
    _, found = app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    require.False(t, found, "Validator should be removed from staking module")
    
    // BUG: Signing info should be deleted but still exists
    signingInfo, found = app.SlashingKeeper.GetValidatorSigningInfo(ctx, consAddr)
    require.True(t, found, "BUG: Signing info still exists after validator removal - should have been pruned")
    
    // BUG: Missed blocks array should be deleted but still exists
    retrievedMissedBlocks, found = app.SlashingKeeper.GetValidatorMissedBlocks(ctx, consAddr)
    require.True(t, found, "BUG: Missed blocks array still exists after validator removal - should have been pruned")
    
    // Calculate approximate storage waste
    // ValidatorSigningInfo: ~100 bytes
    // ValidatorMissedBlockArray: ~13.5 KB (for 108,000 block window)
    // Total per validator: ~13.6 KB that persists forever
    
    t.Logf("Storage waste per removed validator: ~13.6 KB")
    t.Logf("With 10,000 removed validators: ~136 MB of unprunable state")
    t.Logf("With 100,000 removed validators: ~1.36 GB of unprunable state")
}
```

This test demonstrates that validator signing info and missed block arrays are not deleted when validators are removed, confirming the unbounded storage growth vulnerability.

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

**File:** x/slashing/types/params.go (L13-13)
```go
	DefaultSignedBlocksWindow   = int64(108000) // ~12 hours based on 0.4s block times
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

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** x/slashing/genesis.go (L47-66)
```go
	params := keeper.GetParams(ctx)
	signingInfos := make([]types.SigningInfo, 0)
	missedBlocks := make([]types.ValidatorMissedBlockArray, 0)
	keeper.IterateValidatorSigningInfos(ctx, func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
		bechAddr := address.String()
		signingInfos = append(signingInfos, types.SigningInfo{
			Address:              bechAddr,
			ValidatorSigningInfo: info,
		})

		localMissedBlocks, found := keeper.GetValidatorMissedBlocks(ctx, address)
		if !found {
			return false
		}
		missedBlocks = append(missedBlocks, localMissedBlocks)
		return false
	})

	return types.NewGenesisState(params, signingInfos, missedBlocks)
}
```

**File:** x/slashing/keeper/migrations.go (L32-68)
```go
func (m Migrator) Migrate2to3(ctx sdk.Context) error {
	store := ctx.KVStore(m.keeper.storeKey)
	valMissedMap := make(map[string]types.ValidatorMissedBlockArrayLegacyMissedHeights)

	ctx.Logger().Info("Migrating Signing Info")
	signInfoIter := sdk.KVStorePrefixIterator(store, types.ValidatorSigningInfoKeyPrefix)
	newSignInfoKeys := [][]byte{}
	newSignInfoVals := []types.ValidatorSigningInfoLegacyMissedHeights{}
	// Note that we close the iterator twice. 2 iterators cannot be open at the same time due to mutex on the storage
	// This close within defer is a safety net, while the close() after iteration is to close the iterator before opening
	// a new one.
	defer signInfoIter.Close()
	for ; signInfoIter.Valid(); signInfoIter.Next() {
		ctx.Logger().Info(fmt.Sprintf("Migrating Signing Info for key: %v\n", signInfoIter.Key()))
		var oldInfo types.ValidatorSigningInfo
		m.keeper.cdc.MustUnmarshal(signInfoIter.Value(), &oldInfo)

		newInfo := types.ValidatorSigningInfoLegacyMissedHeights{
			Address:             oldInfo.Address,
			StartHeight:         oldInfo.StartHeight,
			JailedUntil:         oldInfo.JailedUntil,
			Tombstoned:          oldInfo.Tombstoned,
			MissedBlocksCounter: oldInfo.MissedBlocksCounter,
		}
		newSignInfoKeys = append(newSignInfoKeys, signInfoIter.Key())
		newSignInfoVals = append(newSignInfoVals, newInfo)
	}
	signInfoIter.Close()

	if len(newSignInfoKeys) != len(newSignInfoVals) {
		return fmt.Errorf("new sign info data length doesn't match up")
	}
	ctx.Logger().Info("Writing New Signing Info")
	for i := range newSignInfoKeys {
		bz := m.keeper.cdc.MustMarshal(&newSignInfoVals[i])
		store.Set(newSignInfoKeys[i], bz)
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

**File:** x/slashing/keeper/signing_info.go (L71-75)
```go
func (k Keeper) SetValidatorMissedBlocks(ctx sdk.Context, address sdk.ConsAddress, missedInfo types.ValidatorMissedBlockArray) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&missedInfo)
	store.Set(types.ValidatorMissedBlockBitArrayKey(address), bz)
}
```

**File:** x/slashing/keeper/signing_info.go (L168-171)
```go
func (k Keeper) ClearValidatorMissedBlockBitArray(ctx sdk.Context, address sdk.ConsAddress) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

**File:** x/slashing/keeper/querier.go (L64-92)
```go
func querySigningInfos(ctx sdk.Context, req abci.RequestQuery, k Keeper, legacyQuerierCdc *codec.LegacyAmino) ([]byte, error) {
	var params types.QuerySigningInfosParams

	err := legacyQuerierCdc.UnmarshalJSON(req.Data, &params)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrJSONUnmarshal, err.Error())
	}

	var signingInfos []types.ValidatorSigningInfo

	k.IterateValidatorSigningInfos(ctx, func(consAddr sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
		signingInfos = append(signingInfos, info)
		return false
	})

	start, end := client.Paginate(len(signingInfos), params.Page, params.Limit, int(k.sk.MaxValidators(ctx)))
	if start < 0 || end < 0 {
		signingInfos = []types.ValidatorSigningInfo{}
	} else {
		signingInfos = signingInfos[start:end]
	}

	res, err := codec.MarshalJSONIndent(legacyQuerierCdc, signingInfos)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrJSONMarshal, err.Error())
	}

	return res, nil
}
```
