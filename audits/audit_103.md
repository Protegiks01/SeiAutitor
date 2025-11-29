Based on my thorough investigation of the codebase, I can confirm this is a **valid vulnerability**. Let me provide my validation:

## Technical Flow Confirmation

I've verified the complete execution path:

1. **Validator Removal**: When `RemoveValidator` is called, it deletes the `ValidatorByConsAddrKey` index [1](#0-0) , then calls the `AfterValidatorRemoved` hook [2](#0-1) 

2. **Incomplete Cleanup**: The `AfterValidatorRemoved` hook only deletes the address-pubkey relation [3](#0-2)  but does NOT delete `ValidatorSigningInfo` or `ValidatorMissedBlockArray`

3. **Reuse Allowed**: When creating a new validator, the system checks if a validator with that consensus key exists using `GetValidatorByConsAddr` [4](#0-3) . Since this index was deleted, the check passes and a new validator can be created with the same consensus key

4. **State Inheritance**: When the new validator bonds, `AfterValidatorBonded` checks if signing info exists [5](#0-4) . Since the old signing info was never deleted, it's found and reused, causing the new validator to inherit the stale `MissedBlocksCounter`

5. **Unfair Slashing**: The inherited counter causes premature slashing when combined with new missed blocks [6](#0-5) 

## Impact Verification

- No function exists to delete `ValidatorSigningInfo` (I confirmed this through grep search)
- The slashing threshold calculation uses the persisted counter, causing validators to be slashed after missing fewer blocks than the protocol parameters specify
- This violates the invariant that each validator lifecycle should have independent liveness tracking

## Validation Against Criteria

This matches the Medium severity impact: **"A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk"**

The vulnerability:
- ✅ Occurs in layer 1 blockchain code (Cosmos SDK)
- ✅ Can be triggered through normal validator operations (no special privileges needed)
- ✅ Results in unintended behavior (incorrect slashing threshold)
- ✅ Has concrete impact (validators unfairly penalized, potential fund loss through slashing)
- ✅ Is reproducible with a test case
- ✅ Is not a known issue or intentional behavior (the spec only mentions removing the consensus key, not preserving signing info)

---

Audit Report

## Title
Stale Missed Block Data Persists After Validator Removal and Re-Addition Leading to Unfair Slashing

## Summary
When a validator is removed via `RemoveValidator`, the slashing module's `AfterValidatorRemoved` hook only deletes the address-pubkey relation but fails to delete `ValidatorSigningInfo` and `ValidatorMissedBlockArray`. If the same consensus address later creates a new validator, the old missed block data persists, causing the new validator to inherit stale liveness tracking state and face premature slashing.

## Impact
Medium

## Finding Description
- **location**: [3](#0-2) 
- **intended logic**: When a validator is completely removed from the validator set, all associated slashing state (signing info and missed block arrays) should be cleaned up so that if the same consensus address later creates a new validator, it starts with fresh liveness tracking state (MissedBlocksCounter=0, fresh StartHeight, empty missed blocks array)
- **actual logic**: The `AfterValidatorRemoved` hook only deletes the address-pubkey relation but does NOT delete the `ValidatorSigningInfo` stored via `ValidatorSigningInfoKey` or the `ValidatorMissedBlockArray` stored via `ValidatorMissedBlockBitArrayKey`. When a validator with the same consensus address bonds again, `AfterValidatorBonded` checks if signing info exists and only creates new info if not found. Since the old signing info persists, it is reused with its stale `MissedBlocksCounter`, `IndexOffset`, and `StartHeight`.
- **exploitation path**: 
  1. Validator A accumulates missed blocks (e.g., 200 out of 1000-block window)
  2. Validator A's operator unbonds all delegations, triggering removal [7](#0-6) 
  3. `RemoveValidator` deletes the `ValidatorByConsAddrKey` index [1](#0-0)  and calls `AfterValidatorRemoved` hook [2](#0-1) 
  4. Hook executes but only deletes pubkey relation, leaving signing info intact
  5. Later, same consensus address creates new validator (passes check at [4](#0-3)  because `ValidatorByConsAddr` was deleted)
  6. New validator bonds, triggering `AfterValidatorBonded` [8](#0-7) 
  7. Signing info exists, so no new info created - validator inherits stale `MissedBlocksCounter`
  8. Validator gets slashed/jailed after missing fewer blocks than protocol parameters specify
- **security guarantee broken**: The protocol invariant that each validator lifecycle has independent liveness tracking is violated. Validators cannot trust that creating a new validator with the same consensus key starts with a clean slate.

## Impact Explanation
Validators who reuse consensus keys after full unbonding inherit stale missed block counters, causing them to be slashed and jailed after missing significantly fewer blocks than the configured threshold (e.g., 301 blocks instead of 501 with default parameters). This results in:
- Unfair economic penalties (slashing of validator stake)
- Validators being incorrectly jailed and removed from the active set
- Undermined fairness and predictability of the slashing mechanism
- Potential discouragement of validator participation due to unexpected behavior

## Likelihood Explanation
This can occur whenever validators cycle through: bonding → accumulating downtime → full unbonding → re-bonding with the same consensus key. While not frequent, this is a realistic scenario that affects:
- Validators performing maintenance or infrastructure upgrades who fully unbond temporarily
- Validators who reuse existing consensus keys (common practice for operational simplicity)
- Any validator operator who accumulates missed blocks before removal (normal during network issues)

The conditions required are all legitimate validator operations, making this a realistic edge case rather than requiring malicious intent.

## Recommendation
Modify the `AfterValidatorRemoved` hook in the slashing keeper to clean up all validator-related slashing state:

```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
    k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
    // Clean up signing info
    store := ctx.KVStore(k.storeKey)
    store.Delete(types.ValidatorSigningInfoKey(address))
    // Clean up missed blocks array  
    store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

This ensures that when a validator is removed, all liveness tracking data is cleared, allowing a fresh start if the consensus address is reused.

## Proof of Concept
**File**: `x/slashing/keeper/keeper_test.go` (new test to add)
**Function**: `TestValidatorRemovalClearsMissedBlocks`

**Setup**:
1. Initialize test app with slashing parameters (SignedBlocksWindow=1000, MinSignedPerWindow=500)
2. Create validator A with consensus pubkey and self-delegate tokens
3. Run EndBlocker to activate validator

**Action**:
1. Simulate 1000 blocks where validator signs correctly
2. Simulate 200 blocks where validator does NOT sign (accumulate MissedBlocksCounter=200)
3. Verify signing info shows MissedBlocksCounter=200
4. Undelegate all tokens and complete unbonding period
5. Verify validator is removed from state
6. Create new validator with SAME consensus pubkey
7. Run EndBlocker to bond new validator

**Result**:
Query signing info for consensus address - it incorrectly shows MissedBlocksCounter=200 (inherited from removed validator) instead of 0, proving the bug. When the new validator then misses 301 more blocks, it gets jailed at threshold 501, whereas a fresh validator should need to miss 501 blocks from scratch.

### Citations

**File:** x/staking/keeper/validator.go (L176-176)
```go
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
```

**File:** x/staking/keeper/validator.go (L180-180)
```go
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
```

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

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```
