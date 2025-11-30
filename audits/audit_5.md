Based on my thorough investigation of the sei-cosmos codebase, I have validated this security claim and confirm it is a **valid vulnerability**.

# Audit Report

## Title
Stale Liveness Tracking Data Persists After Validator Removal Causing Unfair Jailing on Re-Bonding

## Summary
When a validator is completely removed from the system via `RemoveValidator`, the slashing module's `AfterValidatorRemoved` hook only deletes the address-pubkey relation but fails to clean up `ValidatorSigningInfo` and `ValidatorMissedBlockArray` state. When a validator with the same consensus address is later created and bonded, it inherits the stale liveness tracking data, causing premature jailing based on accumulated missed blocks from the previous validator lifecycle.

## Impact
Medium

## Finding Description

- **location**: [1](#0-0) 

- **intended logic**: When a validator is removed from the validator set, all associated slashing state (signing info, missed block counters, and bit arrays) should be deleted so that if the same consensus address later creates a new validator, it starts with fresh liveness tracking state (MissedBlocksCounter=0, fresh StartHeight, empty missed blocks array).

- **actual logic**: The `AfterValidatorRemoved` hook implementation only deletes the address-pubkey relation via `deleteAddrPubkeyRelation`. It does NOT delete the `ValidatorSigningInfo` (stored at `ValidatorSigningInfoKey(address)`) or the `ValidatorMissedBlockArray` (stored at `ValidatorMissedBlockBitArrayKey(address)`). When `AfterValidatorBonded` is called for a validator with the same consensus address, it checks if signing info exists and only creates new info if not found. Since the old signing info persists, it gets reused with its stale `MissedBlocksCounter`, `IndexOffset`, and `StartHeight`.

- **exploitation path**:
  1. Validator accumulates missed blocks during normal operation (e.g., 200 out of 108000-block window)
  2. All delegations are removed from validator, triggering unbonding
  3. Once unbonding completes and `DelegatorShares.IsZero()`, `RemoveValidator` is called [2](#0-1) 
  4. `RemoveValidator` deletes `ValidatorByConsAddrKey` index [3](#0-2) 
  5. `AfterValidatorRemoved` hook executes, deleting only the pubkey relation, leaving signing info intact [1](#0-0) 
  6. Later, same consensus address creates new validator, which passes the `GetValidatorByConsAddr` check [4](#0-3) 
  7. New validator bonds, triggering `AfterValidatorBonded` [5](#0-4) 
  8. Since signing info exists, no new info is created - validator inherits stale `MissedBlocksCounter`
  9. When liveness is checked, the inherited counter causes premature jailing [6](#0-5) 

- **security guarantee broken**: The protocol invariant that each validator lifecycle should have independent liveness tracking is violated. Validators reusing consensus keys do not start with a clean slate, inheriting historical downtime data from a previous, removed validator.

## Impact Explanation

Validators who reuse consensus keys after full unbonding inherit stale missed block counters from the previous validator lifecycle. This causes them to be jailed after missing fewer total blocks than the protocol parameters specify. With default sei-cosmos parameters (`SignedBlocksWindow=108000`, `MinSignedPerWindow=0.05`, `SlashFractionDowntime=0`), this results in:

- **Unfair jailing**: Validators get jailed prematurely based on inherited missed block counts
- **Loss of rewards**: While jailed, validators cannot earn commission or staking rewards
- **Network participation disruption**: Validators are removed from the active set unexpectedly
- **Undermined predictability**: The slashing mechanism behaves inconsistently, violating validator expectations

Note: With default parameters, no tokens are directly slashed (slash fraction is 0%), but chains may configure non-zero `SlashFractionDowntime` which would result in actual token loss. This qualifies as "unintended behavior with no concrete funds at direct risk" under default configuration.

## Likelihood Explanation

This vulnerability can be triggered through legitimate validator operations without any malicious intent:

- **Common scenario**: Validators performing infrastructure maintenance may fully unbond temporarily, then rebond with the same consensus key
- **Operational practice**: Reusing consensus keys is common for operational simplicity rather than generating new keys
- **Prerequisite conditions**: Only requires prior missed blocks (normal during network congestion or node issues) followed by full unbonding

While not the most frequent path, this represents a realistic edge case affecting validators who cycle through bonding → accumulating downtime → full unbonding → re-bonding with the same consensus key.

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

This ensures complete cleanup when a validator is removed, allowing fresh liveness tracking if the consensus address is reused.

## Proof of Concept

**File**: `x/slashing/keeper/keeper_test.go` (new test to add)
**Function**: `TestValidatorRemovalClearsMissedBlocks`

**Setup**:
1. Initialize simapp with slashing parameters (SignedBlocksWindow=1000, MinSignedPerWindow=0.5)
2. Create validator with consensus pubkey and delegate tokens
3. Run EndBlocker to activate validator

**Action**:
1. Simulate 1000 blocks where validator signs correctly
2. Simulate 200 blocks where validator does NOT sign (accumulate MissedBlocksCounter=200)
3. Verify signing info shows MissedBlocksCounter=200 using `GetValidatorSigningInfo`
4. Undelegate all tokens triggering `RemoveValidator` when unbonding completes
5. Verify validator is removed from state using `GetValidator`
6. Create new validator with SAME consensus pubkey
7. Run EndBlocker to bond new validator

**Result**:
Query signing info for the consensus address - it incorrectly shows MissedBlocksCounter=200 (inherited from removed validator) instead of 0, proving the bug. When the new validator then misses 301 additional blocks, it gets jailed at the threshold of 501 total, whereas a fresh validator should require missing 501 blocks from scratch.

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
