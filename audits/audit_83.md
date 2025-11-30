# Audit Report

## Title
Stale Liveness Tracking State Persists After Validator Removal Causing Unfair Slashing on Consensus Key Reuse

## Summary
When a validator is removed from the validator set after all delegations are unbonded, the slashing module's `AfterValidatorRemoved` hook fails to delete `ValidatorSigningInfo` and `ValidatorMissedBlockArray`. If the same consensus address later creates a new validator, the stale liveness tracking data persists, causing the new validator to inherit the previous validator's `MissedBlocksCounter` and face premature downtime slashing.

## Impact
Medium

## Finding Description
- **location**: `x/slashing/keeper/hooks.go:40-43` (AfterValidatorRemoved function)

- **intended logic**: When a validator is completely removed from the validator set (all delegations unbonded), all associated slashing state should be cleaned up. If the same consensus address later creates a new validator, it should start with fresh liveness tracking: `MissedBlocksCounter=0`, fresh `StartHeight`, and an empty missed blocks array.

- **actual logic**: The `AfterValidatorRemoved` hook only deletes the address-pubkey relation but does NOT delete the `ValidatorSigningInfo` or `ValidatorMissedBlockArray`. [1](#0-0)  These persist in storage keyed by consensus address. When a new validator with the same consensus address bonds, `AfterValidatorBonded` checks if signing info exists and only creates new info if not found. [2](#0-1)  Since the old signing info persists, the new validator inherits the stale `MissedBlocksCounter`, `IndexOffset`, and `StartHeight`.

- **exploitation path**: 
  1. Validator accumulates missed blocks during operation (e.g., 200 out of 1000-block window, below slashing threshold of 501)
  2. Validator's operator unbonds all delegations, causing `DelegatorShares` to reach zero [3](#0-2) 
  3. `RemoveValidator` is called, deleting the `ValidatorByConsAddrKey` index [4](#0-3)  but leaving signing info intact
  4. Later, the same consensus key creates a new validator (passes the `GetValidatorByConsAddr` check [5](#0-4)  since the index was deleted [6](#0-5) )
  5. New validator bonds, triggering `AfterValidatorBonded` which finds existing signing info and reuses it
  6. New validator inherits `MissedBlocksCounter=200` from previous lifecycle
  7. If new validator misses 301 additional blocks, it reaches 501 total and gets slashed/jailed [7](#0-6) , whereas a fresh validator would need to miss 501 blocks from the start

- **security guarantee broken**: The protocol invariant that each validator lifecycle has independent liveness tracking is violated. Validators cannot rely on getting a clean slate when creating a new validator with an existing consensus key after full unbonding and removal.

## Impact Explanation
Validators who reuse consensus keys after complete unbonding and removal inherit stale missed block counters from their previous lifecycle. This causes them to be slashed and jailed after missing significantly fewer blocks than the configured `SignedBlocksWindow - MinSignedPerWindow` threshold. With default parameters (window=1000, min=500), a validator with inherited `MissedBlocksCounter=200` would be slashed after missing only 301 new blocks instead of 501, a 40% reduction in the downtime tolerance. 

This results in:
- Unfair economic penalties through slashing (loss of validator stake based on `SlashFractionDowntime` parameter)
- Validators being incorrectly jailed and removed from the active set, losing block rewards and commission
- Undermined fairness of the slashing mechanism, as validators with reused keys are treated differently than fresh validators
- Potential operational disruption and discouragement of validator participation

This qualifies as **Medium severity** under the impact category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Likelihood Explanation
This vulnerability can be triggered through normal validator operations without any malicious intent:
- Validators performing infrastructure maintenance or upgrades who fully unbond temporarily
- Validators who reuse existing consensus keys for operational simplicity (common practice to avoid key management complexity)
- Any validator operator who accumulates some missed blocks (normal during network issues or node problems) before complete unbonding

While complete unbonding followed by recreation with the same consensus key is not a frequent operation, it is a legitimate use case. The conditions required are all standard validator lifecycle operations accessible to any validator operator, making this a realistic edge case that affects the protocol's fairness guarantees.

## Recommendation
Modify the `AfterValidatorRemoved` hook in `x/slashing/keeper/hooks.go` to properly clean up all validator-related slashing state:

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

This ensures that when a validator is removed, all liveness tracking data is cleared, allowing a fresh start if the consensus address is later reused. This pattern follows the proper cleanup demonstrated by the distribution module's `AfterValidatorRemoved` hook. [8](#0-7) 

## Proof of Concept

**Test Location**: `x/slashing/keeper/keeper_test.go` (new test to add)  
**Function**: `TestValidatorRemovalClearsMissedBlocks`

**Setup**:
1. Initialize test chain with slashing parameters (`SignedBlocksWindow=1000`, `MinSignedPerWindow=500`)
2. Create and bond validator A with a specific consensus pubkey
3. Simulate 200 blocks where validator does NOT sign (accumulate `MissedBlocksCounter=200`)
4. Verify signing info exists with `MissedBlocksCounter=200` using `GetValidatorSigningInfo` [9](#0-8) 

**Action**:
1. Unbond all delegations from validator A
2. Complete unbonding period and verify validator is removed from state
3. Verify `GetValidatorByConsAddr` returns not found (index deleted)
4. Create new validator B with the SAME consensus pubkey as validator A
5. Bond the new validator

**Result**:
Query signing info for the consensus address - it incorrectly shows `MissedBlocksCounter=200` (inherited from removed validator A) instead of `MissedBlocksCounter=0` for a fresh validator. This proves the bug exists and demonstrates that the new validator starts with stale liveness tracking state, leading to premature slashing if it misses additional blocks.

## Notes

The slashing module specification [10](#0-9)  only mentions that `AfterValidatorRemoved` "removes a validator's consensus key" but does NOT mention cleaning up signing info or missed block data, indicating incomplete design. The only cleanup function `ClearValidatorMissedBlockBitArray` [11](#0-10)  exists but is only called during slashing operations [12](#0-11) , NOT during validator removal. No function exists to delete `ValidatorSigningInfo` when a validator is removed.

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

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** x/staking/keeper/validator.go (L36-45)
```go
func (k Keeper) GetValidatorByConsAddr(ctx sdk.Context, consAddr sdk.ConsAddress) (validator types.Validator, found bool) {
	store := ctx.KVStore(k.storeKey)

	opAddr := store.Get(types.GetValidatorByConsAddrKey(consAddr))
	if opAddr == nil {
		return validator, false
	}

	return k.GetValidator(ctx, opAddr)
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

**File:** x/distribution/keeper/hooks.go (L25-76)
```go
// AfterValidatorRemoved performs clean up after a validator is removed
func (h Hooks) AfterValidatorRemoved(ctx sdk.Context, _ sdk.ConsAddress, valAddr sdk.ValAddress) {
	// fetch outstanding
	outstanding := h.k.GetValidatorOutstandingRewardsCoins(ctx, valAddr)

	// force-withdraw commission
	commission := h.k.GetValidatorAccumulatedCommission(ctx, valAddr).Commission
	if !commission.IsZero() {
		// subtract from outstanding
		outstanding = outstanding.Sub(commission)

		// split into integral & remainder
		coins, remainder := commission.TruncateDecimal()

		// remainder to community pool
		feePool := h.k.GetFeePool(ctx)
		feePool.CommunityPool = feePool.CommunityPool.Add(remainder...)
		h.k.SetFeePool(ctx, feePool)

		// add to validator account
		if !coins.IsZero() {
			accAddr := sdk.AccAddress(valAddr)
			withdrawAddr := h.k.GetDelegatorWithdrawAddr(ctx, accAddr)

			if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, coins); err != nil {
				panic(err)
			}
		}
	}

	// Add outstanding to community pool
	// The validator is removed only after it has no more delegations.
	// This operation sends only the remaining dust to the community pool.
	feePool := h.k.GetFeePool(ctx)
	feePool.CommunityPool = feePool.CommunityPool.Add(outstanding...)
	h.k.SetFeePool(ctx, feePool)

	// delete outstanding
	h.k.DeleteValidatorOutstandingRewards(ctx, valAddr)

	// remove commission record
	h.k.DeleteValidatorAccumulatedCommission(ctx, valAddr)

	// clear slashes
	h.k.DeleteValidatorSlashEvents(ctx, valAddr)

	// clear historical rewards
	h.k.DeleteValidatorHistoricalRewards(ctx, valAddr)

	// clear current rewards
	h.k.DeleteValidatorCurrentRewards(ctx, valAddr)
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

**File:** x/slashing/keeper/signing_info.go (L168-171)
```go
func (k Keeper) ClearValidatorMissedBlockBitArray(ctx sdk.Context, address sdk.ConsAddress) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

**File:** x/slashing/spec/05_hooks.md (L15-17)
```markdown
+ `AfterValidatorBonded` creates a `ValidatorSigningInfo` instance as described in the following section.
+ `AfterValidatorCreated` stores a validator's consensus key.
+ `AfterValidatorRemoved` removes a validator's consensus key.
```

**File:** x/slashing/abci.go (L58-60)
```go
		if writeInfo.ShouldSlash {
			k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
			writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
```
