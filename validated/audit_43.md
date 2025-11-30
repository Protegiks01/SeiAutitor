# Audit Report

## Title
Chain Halt Due to Race Condition Between Validator Removal and Signature Processing

## Summary
When a validator completes unbonding with zero delegator shares, the pubkey mapping is immediately deleted via the `AfterValidatorRemoved` hook. Due to ValidatorUpdateDelay (1 block), the next block's BeginBlocker must still process this validator's signature from the previous block. When `GetPubkey` fails, the system panics, causing complete chain halt.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended logic:** Validator metadata (including pubkey mappings) should remain accessible for processing signatures from blocks where the validator was part of the active set. Cleanup should only occur after all signature processing completes for blocks signed by that validator.

**Actual logic:** The `AfterValidatorRemoved` hook immediately deletes the pubkey mapping during `RemoveValidator`. [2](#0-1)  However, ValidatorUpdateDelay creates a 1-block lag [3](#0-2)  where the removed validator's signature from the previous block must still be processed in the next block's BeginBlocker.

When BeginBlocker processes `LastCommitInfo` votes [4](#0-3) , it calls `HandleValidatorSignatureConcurrent` for the removed validator. The `GetPubkey` call returns an error, triggering a panic that halts the entire chain.

**Exploitation path:**
1. Block N EndBlocker: Validator completes unbonding period with zero delegator shares [5](#0-4) 
2. `BlockValidatorUpdates` executes [6](#0-5) 
3. `ApplyAndReturnValidatorSetUpdates` returns validator update (zero power)
4. `UnbondAllMatureValidators` calls `RemoveValidator` since shares are zero
5. `AfterValidatorRemoved` hook is invoked [7](#0-6)  and deletes pubkey mapping immediately
6. Block N+1 BeginBlocker: Processes `LastCommitInfo` from Block N
7. Block N was signed by old validator set (including removed validator due to ValidatorUpdateDelay)
8. `HandleValidatorSignatureConcurrent` called for removed validator
9. `GetPubkey` returns "address not found" error
10. System panics: "Validator consensus-address %s not found"
11. Complete chain halt requiring manual intervention

**Security guarantee broken:** Blockchain liveness guarantee. The panic in BeginBlocker prevents all nodes from processing subsequent blocks. The chain cannot automatically recover and requires coordinated emergency response.

## Impact Explanation
This vulnerability causes complete network shutdown matching the "Network not being able to confirm new transactions (total network shutdown)" impact category. The panic occurs in BeginBlocker, which is called at the start of every block. When this panic triggers, all validator nodes hit the same error when attempting to process the same block height, causing the entire network to halt. The chain cannot self-recover and requires external coordination, emergency patch deployment, or potentially a hard fork to resume operations.

## Likelihood Explanation

**Production environments:** Very low likelihood. Standard unbonding periods are 3 weeks [8](#0-7) , providing sufficient timing buffer to prevent the race condition from manifesting.

**Test environments:** High likelihood. Tests commonly use instant or very short unbonding periods, as explicitly acknowledged in code comments [9](#0-8) .

**Triggering conditions:**
- Requires unbonding time short enough for race condition to manifest
- Code explicitly validates and accepts any positive unbonding duration [10](#0-9) 
- Triggered through normal validator operations (delegator unbonding)
- No special privileges or malicious intent required

**Configuration validity:** This is NOT a misconfiguration issue. The code explicitly supports short unbonding periods through permissive validation that only requires positive duration. Any chain choosing shorter unbonding periods for faster capital efficiency would be vulnerable.

## Recommendation

Implement graceful handling of missing pubkeys in `HandleValidatorSignatureConcurrent`, consistent with the evidence keeper's established pattern [11](#0-10) .

The evidence keeper demonstrates the correct architectural approach - it explicitly notes they changed from panic to graceful handling for this exact scenario. The comment states: "We used to panic with: `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`, but this couples the expectations of the app to both Tendermint and the simulator... it is easier to relax the constraints and ignore evidence that cannot be handled."

Apply the same pattern in `HandleValidatorSignatureConcurrent`:

```go
consAddr = sdk.ConsAddress(addr)
if _, err := k.GetPubkey(ctx, addr); err != nil {
    logger.Info("Validator pubkey not found, likely recently removed", "address", consAddr)
    return
}
```

The staking keeper's slash function also demonstrates graceful handling [12](#0-11) , logging an error and returning when a validator is not found rather than panicking.

Alternatively, delay pubkey deletion in `AfterValidatorRemoved` for ValidatorUpdateDelay + 1 blocks to ensure signature processing completes before cleanup.

## Proof of Concept

**Setup:**
1. Create test app with unbonding period of 1 nanosecond (explicitly supported by validation)
2. Create validator with self-delegation
3. Call EndBlocker to bond the validator
4. Undelegate all tokens to trigger unbonding

**Action:**
1. Call EndBlocker - triggers `UnbondAllMatureValidators` which removes validator and deletes pubkey
2. Advance to next block
3. Call BeginBlocker with `LastCommitInfo` containing the removed validator's vote from previous block

**Result:**
Panic occurs with message "Validator consensus-address %s not found" when BeginBlocker attempts to call `GetPubkey` for the removed validator, demonstrating the chain halt vulnerability.

## Notes

While this primarily affects test environments due to production chains using 3-week unbonding periods, it represents a legitimate code defect because:

1. **Code explicitly supports triggering configuration:** Validation accepts any positive unbonding duration with no minimum requirement
2. **Established correct pattern exists:** The evidence keeper explicitly demonstrates graceful handling instead of panicking, with comments noting they changed from panic to graceful handling for this exact scenario
3. **Catastrophic failure mode:** Panic causes complete chain halt requiring manual intervention
4. **Architectural inconsistency:** Slashing keeper uses panic while evidence keeper uses graceful handling for the same missing validator scenario
5. **Defensive programming failure:** Edge cases should be handled gracefully rather than causing system-wide failures

The evidence keeper's comment is particularly revealing: it demonstrates that panic is the wrong approach and graceful handling is the correct solution for this exact type of validator-not-found scenario.

### Citations

**File:** x/slashing/keeper/infractions.go (L28-30)
```go
	if _, err := k.GetPubkey(ctx, addr); err != nil {
		panic(fmt.Sprintf("Validator consensus-address %s not found", consAddr))
	}
```

**File:** x/slashing/keeper/hooks.go (L41-42)
```go
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
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

**File:** x/slashing/abci.go (L36-41)
```go
	for i, _ := range allVotes {
		wg.Add(1)
		go func(valIndex int) {
			defer wg.Done()
			vInfo := allVotes[valIndex]
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
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

**File:** x/staking/types/params.go (L18-21)
```go
	// DefaultUnbondingTime reflects three weeks in seconds as the default
	// unbonding time.
	// TODO: Justify our choice of default here.
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
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

**File:** x/staking/keeper/slash.go (L38-49)
```go
	validator, found := k.GetValidatorByConsAddr(ctx, consAddr)
	if !found {
		// If not found, the validator must have been overslashed and removed - so we don't need to do anything
		// NOTE:  Correctness dependent on invariant that unbonding delegations / redelegations must also have been completely
		//        slashed in this case - which we don't explicitly check, but should be true.
		// Log the slash attempt for future reference (maybe we should tag it too)
		logger.Error(
			"WARNING: ignored attempt to slash a nonexistent validator; we recommend you investigate immediately",
			"validator", consAddr.String(),
		)
		return
	}
```
