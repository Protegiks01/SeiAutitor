## Audit Report

## Title
Stale Missed Block Data Persists After Validator Removal and Re-Addition Leading to Unfair Slashing

## Summary
When a validator is completely removed from the validator set (via `RemoveValidator` after full unbonding), the slashing module's `AfterValidatorRemoved` hook only deletes the address-pubkey relation but fails to delete the `ValidatorSigningInfo` and `ValidatorMissedBlockArray`. If the same consensus address later creates a new validator, the old missed block data persists, causing the new validator to inherit stale liveness tracking state and face premature slashing.

## Impact
**Medium** - This bug results in unintended validator behavior where validators are unfairly penalized based on historical data from a previous validator lifecycle, violating protocol design parameters for liveness tracking.

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Validator removal trigger: [2](#0-1) 
- Removal hook call: [3](#0-2) 
- Re-bonding logic: [4](#0-3) 

**Intended Logic:** 
When a validator is removed from the validator set, all associated slashing state (signing info and missed block arrays) should be cleaned up so that if the same consensus address later creates a new validator, it starts with a fresh liveness tracking state. A new validator should have `MissedBlocksCounter=0`, a fresh `StartHeight`, and an empty missed blocks bit array.

**Actual Logic:** 
The `AfterValidatorRemoved` hook only deletes the address-pubkey relation [1](#0-0) , but does NOT delete:
1. The `ValidatorSigningInfo` stored via `ValidatorSigningInfoKey`
2. The `ValidatorMissedBlockArray` stored via `ValidatorMissedBlockBitArrayKey`

When the validator re-bonds, `AfterValidatorBonded` checks if signing info exists and only creates new info if NOT found [5](#0-4) . Since the old signing info persists, it is reused with its stale `MissedBlocksCounter`, `IndexOffset`, and `StartHeight`.

**Exploit Scenario:**
1. Validator A accumulates 200 missed blocks (out of 1000-block window, threshold is 501 for jailing based on `MinSignedPerWindow`)
2. Validator A's operator unbonds all delegations, triggering complete removal
3. After unbonding period completes, `RemoveValidator` is called [2](#0-1) 
4. `AfterValidatorRemoved` hook executes but only deletes pubkey relation, leaving signing info intact
5. Later, same consensus address creates a new validator and bonds
6. New validator inherits `MissedBlocksCounter=200` from old signing info
7. New validator only needs to miss 301 more blocks (instead of 501) to trigger slashing/jailing
8. Validator is unfairly penalized based on previous lifecycle's behavior

**Security Failure:** 
This violates the accounting invariant that each validator lifecycle should have independent liveness tracking. The missed block tracking system incorrectly accumulates data across validator lifecycles, causing premature slashing that deviates from protocol parameters.

## Impact Explanation

**Affected Assets/Processes:**
- Validator stake (subject to unfair slashing penalties)
- Validator liveness tracking accuracy
- Network validator set stability (validators incorrectly jailed)

**Severity of Damage:**
- Validators can be slashed and jailed based on missed blocks from a previous, unrelated validator lifecycle
- The `MissedBlocksCounter` persists across removals, meaning a validator could be jailed after missing significantly fewer blocks than the configured threshold
- The stale `StartHeight` in signing info also persists, potentially causing incorrect window calculations
- This breaks the fundamental expectation that creating a new validator starts with a clean slate

**System Security Impact:**
This undermines the fairness and predictability of the slashing mechanism. Validators cannot trust that their liveness penalties reset when they restart as a new validator, which could discourage validator participation or lead to unexpected economic losses.

## Likelihood Explanation

**Who Can Trigger:**
Any validator operator can trigger this by:
1. Operating a validator that accumulates some missed blocks (normal operation)
2. Fully unbonding their validator (legitimate operational decision)
3. Later re-creating a validator with the same consensus key

**Conditions Required:**
- Validator must accumulate missed blocks before removal (common during network issues or maintenance)
- Validator must fully unbond (all delegations removed) and complete unbonding period
- Same consensus address must be reused for a new validator (likely if operator reuses keys)

**Frequency:**
This can occur whenever validators cycle through the lifecycle of bonding → accumulating some downtime → full unbonding → re-bonding. While not constant, this is a realistic scenario that could happen multiple times across a network's lifetime, especially for validators performing maintenance or upgrading infrastructure.

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

Alternatively, add a function to delete validator signing info and call it from the hook:
```go
func (k Keeper) DeleteValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress) {
    store := ctx.KVStore(k.storeKey)
    store.Delete(types.ValidatorSigningInfoKey(address))
    store.Delete(types.ValidatorMissedBlockBitArrayKey(address))
}
```

This ensures that when a validator is removed, all liveness tracking data is cleared, allowing a fresh start if the consensus address is reused.

## Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`

**Test Function:** `TestValidatorRemovalClearsMissedBlocks` (new test to add)

**Setup:**
1. Initialize test app with slashing parameters: `SignedBlocksWindow=1000`, `MinSignedPerWindow=500` (allowing up to 500 missed blocks)
2. Create validator A with consensus pubkey `pk` and self-delegate 100 tokens
3. Run `EndBlocker` to activate validator

**Trigger:**
1. Simulate 1000 blocks where validator signs correctly to establish the window
2. Simulate 200 blocks where validator does NOT sign (accumulate 200 missed blocks)
3. Verify `MissedBlocksCounter=200` in signing info
4. Undelegate all 100 tokens from validator A
5. Advance time past unbonding period and call `EndBlocker` to complete unbonding
6. Verify validator A is removed from state
7. Create a new validator B with the SAME consensus pubkey `pk` and delegate 100 tokens
8. Run `EndBlocker` to bond validator B
9. Query signing info for consensus address

**Observation:**
The test should observe that the signing info for the new validator B shows:
- `MissedBlocksCounter=200` (inherited from old validator A) instead of `0`
- Stale `StartHeight` from validator A instead of current block height
- Existing missed blocks bit array instead of empty array

When validator B then misses 301 more blocks (total inherited + new = 501), it gets jailed, whereas a fresh validator should need to miss 501 blocks from scratch.

**Test Code Structure:**
```go
func TestValidatorRemovalClearsMissedBlocks(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    app.SlashingKeeper.SetParams(ctx, testslashing.TestParams())
    
    pks := simapp.CreateTestPubKeys(1)
    pk := pks[0]
    addr := sdk.ConsAddress(pk.Address())
    valAddr := sdk.ValAddress(addr)
    
    // Create validator and accumulate 200 missed blocks
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    tstaking.CreateValidatorWithValPower(valAddr, pk, 100, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Sign 1000 blocks correctly
    for i := 0; i < 1000; i++ {
        ctx = ctx.WithBlockHeight(int64(i))
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(pk.Address(), 100, true), app.SlashingKeeper)
    }
    
    // Miss 200 blocks
    for i := 1000; i < 1200; i++ {
        ctx = ctx.WithBlockHeight(int64(i))
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(pk.Address(), 100, false), app.SlashingKeeper)
    }
    
    // Verify 200 missed blocks recorded
    signInfo, found := app.SlashingKeeper.GetValidatorSigningInfo(ctx, addr)
    require.True(t, found)
    require.Equal(t, int64(200), signInfo.MissedBlocksCounter)
    
    // Unbond all delegations
    tstaking.Undelegate(sdk.AccAddress(valAddr), valAddr, app.StakingKeeper.TokensFromConsensusPower(ctx, 100), true)
    
    // Complete unbonding
    ctx = ctx.WithBlockHeight(5000).WithBlockTime(ctx.BlockTime().Add(app.StakingKeeper.UnbondingTime(ctx)))
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Verify validator removed
    _, found = app.StakingKeeper.GetValidator(ctx, valAddr)
    require.False(t, found)
    
    // Create new validator with same consensus key
    tstaking.CreateValidatorWithValPower(valAddr, pk, 100, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // BUG: Old signing info persists
    signInfo2, found := app.SlashingKeeper.GetValidatorSigningInfo(ctx, addr)
    require.True(t, found)
    // This should be 0 for a new validator, but is 200 from the old validator
    require.Equal(t, int64(200), signInfo2.MissedBlocksCounter) // FAILS - proves the bug
}
```

The test demonstrates that `MissedBlocksCounter` from a removed validator incorrectly persists when the same consensus address creates a new validator, confirming the vulnerability.

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

**File:** x/staking/keeper/validator.go (L179-180)
```go
	// call hooks
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
```
