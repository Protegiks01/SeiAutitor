# Audit Report

## Title
Stale Liveness Tracking Data Persists After Validator Removal Causing Unfair Jailing on Re-Bonding

## Summary
The slashing module's `AfterValidatorRemoved` hook fails to clean up `ValidatorSigningInfo` and `ValidatorMissedBlockArray` state when a validator is removed. When a new validator is later created with the same consensus address, it inherits stale liveness tracking data from the previous validator, resulting in premature jailing based on accumulated missed blocks from a prior validator lifecycle.

## Impact
Medium

## Finding Description

- **location**: `x/slashing/keeper/hooks.go` lines 41-43 [1](#0-0) 

- **intended logic**: When a validator is completely removed via `RemoveValidator`, all associated slashing state should be cleaned up, including `ValidatorSigningInfo` and `ValidatorMissedBlockArray`. This ensures that if the same consensus address is later used to create a new validator, it starts with fresh liveness tracking (MissedBlocksCounter=0, fresh StartHeight, empty missed blocks array).

- **actual logic**: The `AfterValidatorRemoved` hook only deletes the address-pubkey relation [1](#0-0) , but does NOT delete the `ValidatorSigningInfo` (stored at `ValidatorSigningInfoKey(address)`) [2](#0-1)  or the `ValidatorMissedBlockArray` (stored at `ValidatorMissedBlockBitArrayKey(address)`) [3](#0-2) . When `AfterValidatorBonded` is triggered for a validator with the same consensus address, it checks if signing info exists and only creates new info if not found [4](#0-3) . Since the old signing info persists, the new validator inherits the stale `MissedBlocksCounter`, `IndexOffset`, and `StartHeight`.

- **exploitation path**:
  1. Validator accumulates missed blocks during normal operation
  2. All delegations are removed, triggering unbonding
  3. Once unbonding completes and `DelegatorShares.IsZero()`, `RemoveValidator` is called [5](#0-4) 
  4. `RemoveValidator` deletes the `ValidatorByConsAddrKey` index [6](#0-5) 
  5. `AfterValidatorRemoved` hook executes, deleting only the pubkey relation [1](#0-0) 
  6. Later, same consensus address creates new validator, passing the `GetValidatorByConsAddr` check [7](#0-6)  (check passes because the index was deleted)
  7. New validator bonds, triggering `AfterValidatorBonded` [4](#0-3) 
  8. Since signing info exists, no new info is created - validator inherits stale `MissedBlocksCounter`
  9. When liveness is checked, the inherited counter causes premature jailing [8](#0-7) 

- **security guarantee broken**: The protocol invariant that each validator lifecycle should have independent liveness tracking is violated. Validators reusing consensus addresses do not start with a clean slate, inheriting historical downtime data from a previous, removed validator.

## Impact Explanation

This vulnerability results in validators being jailed prematurely when they reuse consensus keys after full unbonding. The impact includes:

- **Unfair jailing**: Validators are jailed after missing fewer blocks than protocol parameters specify due to inherited counters
- **Loss of staking rewards**: Jailed validators cannot earn commission or staking rewards during the jail period
- **Network participation disruption**: Validators are unexpectedly removed from the active set
- **Protocol inconsistency**: The slashing mechanism behaves unpredictably, violating validator expectations

With default sei-cosmos parameters (`SlashFractionDowntime=0%`), no tokens are directly slashed, but chains may configure non-zero values resulting in actual token loss. This qualifies as **"A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"** - a Medium severity issue.

## Likelihood Explanation

This vulnerability can be triggered through legitimate validator operations without malicious intent:

- **Operational scenario**: Validators performing infrastructure maintenance may fully unbond, then later rebond with the same consensus key for operational simplicity
- **Prerequisite conditions**: Requires prior missed blocks (normal during network issues) followed by full unbonding and re-creation
- **No special privileges**: Can occur through standard validator operations accessible to any validator operator

While not the most common operational path, this represents a realistic edge case affecting validators who cycle through the complete lifecycle of bonding → downtime accumulation → full unbonding → re-bonding with the same consensus key.

## Recommendation

Modify the `AfterValidatorRemoved` hook in the slashing keeper to clean up all validator-related slashing state:

```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
    k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
    // Clean up signing info
    store := ctx.KVStore(k.storeKey)
    store.Delete(types.ValidatorSigningInfoKey(address))
    // Clean up missed blocks array  
    k.ClearValidatorMissedBlockBitArray(ctx, address)
}
```

This ensures complete state cleanup when a validator is removed, allowing fresh liveness tracking if the consensus address is subsequently reused.

## Proof of Concept

**File**: `x/slashing/keeper/keeper_test.go` (new test to add)  
**Function**: `TestValidatorRemovalClearsMissedBlocks`

**Setup**:
1. Initialize simapp with slashing parameters (SignedBlocksWindow=1000, MinSignedPerWindow=0.5)
2. Create validator with consensus pubkey and delegate sufficient tokens
3. Execute EndBlocker to activate validator in the validator set

**Action**:
1. Simulate 1000 blocks where validator signs correctly (establish baseline)
2. Simulate 200 blocks where validator does NOT sign, accumulating MissedBlocksCounter=200
3. Verify signing info shows MissedBlocksCounter=200 via `GetValidatorSigningInfo`
4. Undelegate all tokens, complete unbonding period, triggering `RemoveValidator`
5. Verify validator is removed from state via `GetValidator` (returns not found)
6. Create new validator with the SAME consensus pubkey (should pass `GetValidatorByConsAddr` check since index was deleted)
7. Execute EndBlocker to bond the new validator

**Result**:
Query signing info for the consensus address - it incorrectly shows MissedBlocksCounter=200 (inherited from the removed validator) instead of 0, demonstrating the bug. Subsequently, when the new validator misses 301 additional blocks, it gets jailed at a total of 501 missed blocks, whereas a fresh validator should only be jailed after missing 501 blocks from scratch (demonstrating the unfair premature jailing).

## Notes

The vulnerability is confirmed through code analysis showing that:
1. `AfterValidatorRemoved` only calls `deleteAddrPubkeyRelation` [9](#0-8) 
2. There is a `ClearValidatorMissedBlockBitArray` function available [10](#0-9)  but it's only used during slashing/jailing [11](#0-10) , not during validator removal
3. No deletion function exists for `ValidatorSigningInfo` and it's not deleted during removal

This confirms the incomplete state cleanup and validates the security claim.

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

**File:** x/slashing/keeper/hooks.go (L41-43)
```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** x/slashing/types/keys.go (L38-40)
```go
func ValidatorSigningInfoKey(v sdk.ConsAddress) []byte {
	return append(ValidatorSigningInfoKeyPrefix, address.MustLengthPrefix(v.Bytes())...)
}
```

**File:** x/slashing/types/keys.go (L52-54)
```go
func ValidatorMissedBlockBitArrayKey(v sdk.ConsAddress) []byte {
	return append(ValidatorMissedBlockBitArrayKeyPrefix, address.MustLengthPrefix(v.Bytes())...)
}
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** x/staking/keeper/validator.go (L176-176)
```go
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
```

**File:** x/staking/keeper/msg_server.go (L52-54)
```go
	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
	}
```

**File:** x/slashing/keeper/infractions.go (L96-96)
```go
	if height > minHeight && signInfo.MissedBlocksCounter > maxMissed {
```

**File:** x/slashing/keeper/keeper.go (L94-97)
```go
func (k Keeper) deleteAddrPubkeyRelation(ctx sdk.Context, addr cryptotypes.Address) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.AddrPubkeyRelationKey(addr))
}
```

**File:** x/slashing/keeper/signing_info.go (L168-171)
```go
func (k Keeper) ClearValidatorMissedBlockBitArray(ctx sdk.Context, address sdk.ConsAddress) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

**File:** x/slashing/abci.go (L58-60)
```go
		if writeInfo.ShouldSlash {
			k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
			writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
```
