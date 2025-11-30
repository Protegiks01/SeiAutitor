Based on my investigation, I will now validate this security claim.

## Investigation Summary

I have traced through the complete execution flow and verified each component of the claim:

**1. Code Path Verification:**

The panic occurs in `HandleValidatorSignatureConcurrent` when it cannot find a validator's pubkey: [1](#0-0) 

The pubkey is deleted immediately when a validator is removed: [2](#0-1) 

This hook is called during validator removal: [3](#0-2) 

**2. Timing Analysis:**

ValidatorUpdateDelay is set to 1 block: [4](#0-3) 

This means when a validator set update is returned at the end of block N, the validator stops signing at block N+2, but still signs block N+1.

The critical sequence in `BlockValidatorUpdates`: [5](#0-4) 

When unbonding completes and delegator shares are zero, the validator is immediately removed: [6](#0-5) 

**3. Trigger Conditions:**

The code explicitly supports instant unbonding scenarios: [7](#0-6) 

The validation only requires positive unbonding time: [8](#0-7) 

**4. Evidence of Correct Pattern:**

The evidence keeper demonstrates the correct architectural approach - graceful handling instead of panicking: [9](#0-8) 

## Validation Decision

This is a **VALID** vulnerability with **Medium** severity.

# Audit Report

## Title
Chain Halt Due to Race Condition Between Validator Removal and Signature Processing

## Summary
When a validator completes unbonding with zero delegator shares, the `AfterValidatorRemoved` hook immediately deletes its pubkey mapping. However, due to ValidatorUpdateDelay (1 block), the next block's BeginBlocker must still process this validator's signature from the previous block. When `GetPubkey` fails, the system panics, causing a complete chain halt.

## Impact
Medium

## Finding Description
- **location:** `x/slashing/keeper/infractions.go` line 28-30 (panic point), `x/slashing/keeper/hooks.go` line 42 (premature deletion), `x/staking/keeper/validator.go` line 180 (removal trigger)

- **intended logic:** Validator metadata should remain accessible for processing signatures from blocks where the validator was still in the active set. Cleanup should occur only after all signature processing is complete.

- **actual logic:** The `AfterValidatorRemoved` hook deletes the pubkey mapping immediately during `RemoveValidator`. However, ValidatorUpdateDelay causes a 1-block lag where the removed validator's signature from the previous block must still be processed in the next block's BeginBlocker. When `HandleValidatorSignatureConcurrent` calls `GetPubkey`, it receives an error and panics.

- **exploitation path:**
  1. Block N EndBlocker: A validator with zero delegations completes its unbonding period (requires unbonding time ≤ block time)
  2. `ApplyAndReturnValidatorSetUpdates` returns a zero-power update for the validator
  3. `UnbondAllMatureValidators` calls `RemoveValidator` since delegator shares are zero
  4. `AfterValidatorRemoved` hook deletes the pubkey mapping
  5. Block N+1 BeginBlocker: Processes `LastCommitInfo.Votes` from block N
  6. Block N was signed by the old validator set (including the removed validator)
  7. `HandleValidatorSignatureConcurrent` is called for the removed validator
  8. `GetPubkey` returns error "address not found"
  9. System panics with "Validator consensus-address %s not found"
  10. Chain halts completely, requiring manual intervention

- **security guarantee broken:** The blockchain's liveness guarantee is violated. The system cannot recover automatically and requires coordinated manual intervention or an emergency patch.

## Impact Explanation
This vulnerability causes complete network shutdown matching the "Network not being able to confirm new transactions (total network shutdown)" impact category. All validators are unable to progress past the block where the panic occurs. The chain cannot self-recover and requires external coordination, emergency patch deployment, or potentially a hard fork to resume operations.

## Likelihood Explanation
**Production environments:** Very low likelihood due to standard 3-week unbonding periods creating a sufficient timing buffer.

**Test environments:** High likelihood as instant unbonding is commonly used.

**Triggering conditions:**
- Requires unbonding time ≤ block time for the race condition to occur
- The code explicitly supports this configuration through validation accepting any positive duration
- Can be triggered through normal validator operations (delegator unbonding)
- No special privileges or malicious intent required

**Configuration validity:** The code explicitly acknowledges and supports instant unbonding scenarios, making this a legitimate code defect rather than a misconfiguration issue.

## Recommendation
Implement graceful handling of missing pubkeys in `HandleValidatorSignatureConcurrent`, consistent with the evidence keeper's approach:

```go
consAddr = sdk.ConsAddress(addr)
if _, err := k.GetPubkey(ctx, addr); err != nil {
    logger.Info("Validator pubkey not found, likely recently removed", "address", consAddr)
    return
}
```

Alternatively, delay pubkey deletion in the `AfterValidatorRemoved` hook for ValidatorUpdateDelay + 1 blocks to ensure signature processing completes before cleanup.

## Proof of Concept
**Setup:**
1. Create test app with unbonding period of 1 nanosecond
2. Create validator with self-delegation
3. Call EndBlocker to bond the validator
4. Undelegate all tokens

**Action:**
1. Call EndBlocker - triggers `UnbondAllMatureValidators` which removes validator and deletes pubkey
2. Advance to next block
3. Call BeginBlocker with `LastCommitInfo` containing the removed validator's vote

**Result:**
Panic occurs with message "Validator consensus-address %s not found" when BeginBlocker attempts to call `GetPubkey` for the removed validator, demonstrating the chain halt vulnerability.

## Notes
While this primarily affects test environments, it represents a legitimate code defect because:
1. The code explicitly supports short unbonding periods through permissive validation
2. The evidence keeper demonstrates graceful handling as the correct architectural pattern
3. The failure mode (panic causing chain halt) is catastrophic and requires manual intervention
4. Chains might theoretically choose shorter unbonding periods for operational reasons
5. This creates an architectural inconsistency that should be resolved for defensive programming and system robustness

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

**File:** x/staking/keeper/validator.go (L180-180)
```go
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
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

**File:** x/staking/keeper/val_state_change.go (L17-33)
```go
func (k Keeper) BlockValidatorUpdates(ctx sdk.Context) []abci.ValidatorUpdate {
	// Calculate validator set changes.
	//
	// NOTE: ApplyAndReturnValidatorSetUpdates has to come before
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)
```

**File:** x/staking/types/params.go (L167-177)
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
```

**File:** x/evidence/keeper/infraction.go (L29-40)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
	}
```
