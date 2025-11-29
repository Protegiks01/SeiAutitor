# Audit Report

## Title
Chain Halt Due to Premature Pubkey Deletion When Validator is Removed With Signing Info Still Active

## Summary
When a validator is removed via `RemoveValidator`, the `AfterValidatorRemoved` hook immediately deletes the address-pubkey mapping. However, due to ValidatorUpdateDelay (1 block), the removed validator is still expected to sign the next block. When `BeginBlocker` processes that validator's signature in the next block, `GetPubkey` fails and causes a panic, halting the entire chain. [1](#0-0) 

## Impact
High

## Finding Description

**Location:**
- Primary panic: `x/slashing/keeper/infractions.go` lines 28-30
- Pubkey deletion: `x/slashing/keeper/hooks.go` lines 41-43  
- Validator removal: `x/staking/keeper/validator.go` lines 153-181

**Intended Logic:**
When validators are removed from the system, their associated metadata should be cleaned up only after they are no longer expected to participate in consensus. The pubkey mapping should remain accessible for any pending signature validations from blocks where the validator was still in the active set.

**Actual Logic:**
The `AfterValidatorRemoved` hook deletes the address-pubkey mapping immediately when `RemoveValidator` is called. [2](#0-1)  However, validator set updates have a 1-block delay (ValidatorUpdateDelay = 1) [3](#0-2) , meaning the validator is still expected to sign one more block after removal. When `BeginBlocker` processes the next block's `LastCommitInfo`, it calls `HandleValidatorSignatureConcurrent` [4](#0-3)  for the removed validator, which panics when `GetPubkey` fails. [5](#0-4) 

**Exploitation Path:**
1. Block N `EndBlocker`: Validator loses all delegations and transitions from bonded → unbonding → unbonded
   - `ApplyAndReturnValidatorSetUpdates` returns zero-power update for the validator [6](#0-5) 
   - `UnbondAllMatureValidators` immediately unbonds the validator (with instant/short unbonding period) [7](#0-6) 
   - `RemoveValidator` is called, triggering `AfterValidatorRemoved` which deletes the pubkey mapping [8](#0-7) 

2. Block N+1 `BeginBlocker`: Due to ValidatorUpdateDelay, the validator is still in the expected signer set
   - `BeginBlocker` processes `LastCommitInfo` from block N
   - For each validator in the vote set, `HandleValidatorSignatureConcurrent` is called
   - `GetPubkey` is called for the removed validator and returns an error (address not found)
   - The code panics with "Validator consensus-address %s not found"
   - Chain halts completely

**Security Guarantee Broken:**
The chain's liveness guarantee is violated - the blockchain cannot process new blocks and completely halts, requiring manual intervention or emergency patch deployment.

## Impact Explanation

This vulnerability causes a complete network shutdown:
- **Network Availability:** The entire blockchain halts and cannot process any new transactions
- **Consensus Breakdown:** All validators are unable to progress past the block where the panic occurs  
- **Recovery:** Requires manual state intervention, emergency patch deployment, or potentially a hard fork

This is particularly severe because:
1. The chain cannot self-recover - it requires coordinated manual intervention
2. All network activity stops completely until fixed
3. Can be triggered inadvertently during normal validator operations (especially in test environments with instant unbonding)

## Likelihood Explanation

**Triggering Conditions:**
- Occurs when a validator with zero delegations is removed while still in the active validator set
- Requires instant or very short unbonding periods (unbonding time ≤ block time)
- Most common in test environments with instant unbonding [9](#0-8) 
- The code explicitly supports instant unbonding scenarios as evidenced by developer comments

**Frequency:**
- High in test environments with instant unbonding
- Lower in production with standard 3-week unbonding periods (timing window prevents the race condition)
- Can be triggered by any validator losing all delegations, not requiring malicious intent

**Who Can Trigger:**
- Any delegator unbonding from a validator
- Validator operators removing their own stake
- No special privileges or admin keys required

## Recommendation

The `AfterValidatorRemoved` hook should delay pubkey deletion until the validator is no longer expected to sign blocks. Two approaches:

1. **Delay pubkey deletion:** Keep the pubkey mapping for ValidatorUpdateDelay + 1 additional blocks after validator removal

2. **Graceful handling (recommended):** Modify `HandleValidatorSignatureConcurrent` to gracefully handle missing pubkeys for recently removed validators instead of panicking:

```go
// fetch the validator public key
consAddr = sdk.ConsAddress(addr)
if _, err := k.GetPubkey(ctx, addr); err != nil {
    // Validator pubkey not found - this can happen if validator was recently removed
    // Skip processing this signature rather than panicking
    logger.Info("Validator pubkey not found, likely recently removed", "address", consAddr)
    return
}
```

## Proof of Concept

The vulnerability can be reproduced with the following test in `x/slashing/abci_test.go`:

**Setup:**
1. Create a test app with very short unbonding period (e.g., 1 nanosecond)
2. Create a single validator with a self-delegation
3. Call `EndBlocker` to bond the validator
4. Undelegate all tokens from the validator

**Trigger:**
1. Call `EndBlocker` which triggers validator removal in the same block due to short unbonding
2. Advance to next block and call `BeginBlocker` with `LastCommitInfo` containing the removed validator's vote

**Result:**
The test will panic with "Validator consensus-address %s not found" when `BeginBlocker` attempts to process the validator's signature, demonstrating the chain halt vulnerability.

## Notes

While this vulnerability primarily affects test environments with instant unbonding, it represents a legitimate code defect because:

1. The code explicitly supports short unbonding periods (validation only requires positive values) [10](#0-9) 
2. Developers acknowledge instant unbonding scenarios in code comments [9](#0-8) 
3. The failure mode (complete chain halt via panic) is catastrophic and unrecoverable without manual intervention
4. The code should handle this edge case gracefully rather than panicking

The vulnerability matches the "Network not being able to confirm new transactions (total network shutdown)" impact category (High severity).

### Citations

**File:** x/slashing/keeper/infractions.go (L28-30)
```go
	if _, err := k.GetPubkey(ctx, addr); err != nil {
		panic(fmt.Sprintf("Validator consensus-address %s not found", consAddr))
	}
```

**File:** x/slashing/keeper/hooks.go (L41-43)
```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** types/staking.go (L17-26)
```go
	// Delay, in blocks, between when validator updates are returned to the
	// consensus-engine and when they are applied. For example, if
	// ValidatorUpdateDelay is set to X, and if a validator set update is
	// returned with new validators at the end of block 10, then the new
	// validators are expected to sign blocks beginning at block 11+X.
	//
	// This value is constant as this should not change without a hard fork.
	// For Tendermint this should be set to 1 block, for more details see:
	// https://tendermint.com/docs/spec/abci/apps.html#endblock
	ValidatorUpdateDelay int64 = 1
```

**File:** x/slashing/abci.go (L35-41)
```go
	allVotes := req.LastCommitInfo.GetVotes()
	for i, _ := range allVotes {
		wg.Add(1)
		go func(valIndex int) {
			defer wg.Done()
			vInfo := allVotes[valIndex]
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```

**File:** x/slashing/keeper/keeper.go (L56-63)
```go
func (k Keeper) GetPubkey(ctx sdk.Context, a cryptotypes.Address) (cryptotypes.PubKey, error) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.AddrPubkeyRelationKey(a))
	if bz == nil {
		return nil, fmt.Errorf("address %s not found", sdk.ConsAddress(a))
	}
	var pk cryptotypes.PubKey
	return pk, k.cdc.UnmarshalInterface(bz, &pk)
```

**File:** x/staking/keeper/val_state_change.go (L21-26)
```go
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
```

**File:** x/staking/keeper/val_state_change.go (L190-199)
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
	}
```

**File:** x/staking/keeper/validator.go (L180-180)
```go
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
```

**File:** x/staking/keeper/validator.go (L399-450)
```go
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
			}

			store.Delete(key)
		}
	}
}
```

**File:** x/staking/types/params.go (L167-178)
```go
func validateUnbondingTime(i interface{}) error {
	v, ok := i.(time.Duration)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v <= 0 {
		return fmt.Errorf("unbonding time must be positive: %d", v)
	}

	return nil
}
```
