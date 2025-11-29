# Audit Report

## Title
Consensus Key Reuse Allows Slashing Wrong Validator After Validator Removal

## Summary
When a validator is removed from the validator set, their consensus key becomes available for reuse. If evidence of the original validator's misbehavior is submitted after removal, the evidence handling system incorrectly slashes the new validator using that consensus key, rather than the original offender. This occurs because validator lookups use current mappings instead of historical records.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended logic:** When evidence of validator misbehavior is submitted, the system should identify and slash the specific validator who committed the infraction at the height specified in the evidence. Each validator should only be accountable for their own consensus violations.

**Actual logic:** The evidence handling system uses the consensus address to look up validators via `ValidatorByConsAddr`, which returns the CURRENT validator with that consensus address, not the validator who committed the infraction. When a validator is removed: [4](#0-3) [5](#0-4) 

The `ValidatorByConsAddr` mapping and address-pubkey relation are deleted. However, the `ValidatorSigningInfo` persists (intentionally, for historical slashing). The CreateValidator check only verifies if a validator currently exists with that key, not if the key has historical usage.

**Exploitation path:**
1. ValidatorA creates validator with consensus key K1
2. ValidatorA commits double-sign infraction at height H
3. ValidatorA fully unbonds and is removed from validator set [6](#0-5) 
4. ValidatorB creates new validator with same consensus key K1 (check passes because ValidatorByConsAddr mapping was deleted)
5. Within evidence validity window, evidence of ValidatorA's infraction is submitted [7](#0-6) 
6. Evidence handler retrieves validator using `ValidatorByConsAddr(K1)` which now returns ValidatorB
7. ValidatorB is slashed, jailed, and permanently tombstoned [8](#0-7) 

**Security guarantee broken:** The accountability invariant is violated - validators must only be responsible for their own consensus violations. ValidatorB is punished for ValidatorA's misbehavior.

## Impact Explanation

**Assets Affected:** Validator stake (bonded tokens) of the innocent validator reusing the consensus key, plus all delegated stake to that validator.

**Consequences:**
- **Direct Loss of Funds:** The innocent validator's stake is slashed by 5% (default double-sign slash fraction)
- **Permanent Freezing:** The validator is tombstoned, preventing them from ever unjailing or participating in consensus again. This requires a hard fork to reverse.
- **Delegator Impact:** All delegators to the innocent validator lose their proportional stake

This fundamentally undermines the slashing mechanism's integrity and creates perverse incentives where malicious validators can escape punishment by allowing others to unknowingly absorb it.

## Likelihood Explanation

**Who can trigger:**
- Any validator can commit infractions
- Any user can create a new validator with any unused consensus key
- Any user can submit evidence within the validity window

**Required conditions:**
- Original validator must complete unbonding period (3 weeks default) [9](#0-8) 
- Evidence must be submitted within validity window (3 weeks default)
- A new validator must reuse the consensus key before evidence submission

**Likelihood:** HIGH
- The evidence validity window (3 weeks) matches the unbonding period, creating a substantial attack window
- Evidence submission timing can be deliberately controlled by the attacker or their associates
- Consensus key reuse can be orchestrated by the same operator using different identities
- The attack requires only standard blockchain operations (creating validators, submitting evidence)

## Recommendation

Implement historical consensus key tracking to prevent key reuse:

1. **Prevent Consensus Key Reuse:** Modify the `CreateValidator` check to verify consensus keys against historical usage, not just current validators. Check if `ValidatorSigningInfo` exists for the consensus address and reject creation if found.

2. **Tombstone Consensus Address:** When tombstoning a validator, mark the consensus address itself as permanently unusable, preventing any future validator from using that key.

3. **Historical Validator Lookup:** Implement validator lookup by consensus address at specific heights, storing historical mappings for at least the evidence validity period. This aligns with ADR-016 principles. [10](#0-9) 

4. **Extended Signing Info Lifecycle:** Maintain signing info for at least the evidence validity period after validator removal to preserve accountability.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestSlashingWrongValidatorWithReusedConsensusKey`

**Setup:**
- Initialize chain with staking and slashing parameters
- Set slash fraction to 5% for double-sign
- Create initial validator accounts with funding

**Action:**
1. Create ValidatorA with consensus key K1, self-delegate, and bond
2. Generate double-sign evidence for ValidatorA at height 10
3. ValidatorA unbonds all delegations completely
4. Advance time past unbonding period (3 weeks) to trigger validator removal
5. Verify ValidatorA is removed from validator set
6. Create ValidatorB with different operator address but SAME consensus key K1
7. ValidatorB bonds successfully
8. Submit the double-sign evidence from step 2

**Result:**
- ValidatorB's token balance decreases (slashed by 5%)
- ValidatorB is jailed
- ValidatorB is permanently tombstoned
- All for ValidatorA's infraction, not ValidatorB's

This confirms the wrong validator is punished due to consensus key reuse, violating the accountability invariant and causing direct fund loss plus permanent freezing for an innocent validator.

### Citations

**File:** x/evidence/keeper/infraction.go (L66-66)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
```

**File:** x/evidence/keeper/infraction.go (L107-121)
```go
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)

	// Jail the validator if not already jailed. This will begin unbonding the
	// validator if not already unbonding (tombstoned).
	if !validator.IsJailed() {
		k.slashingKeeper.Jail(ctx, consAddr)
	}

	k.slashingKeeper.JailUntil(ctx, consAddr, types.DoubleSignJailEndTime)
	k.slashingKeeper.Tombstone(ctx, consAddr)
```

**File:** x/staking/keeper/slash.go (L38-38)
```go
	validator, found := k.GetValidatorByConsAddr(ctx, consAddr)
```

**File:** x/staking/keeper/msg_server.go (L52-54)
```go
	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
	}
```

**File:** x/staking/keeper/validator.go (L176-176)
```go
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
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

**File:** simapp/test_helpers.go (L44-46)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
```

**File:** x/staking/types/params.go (L21-21)
```go
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** docs/architecture/adr-016-validator-consensus-key-rotation.md (L29-31)
```markdown
    - store history of each key mapping changes in the kvstore.
    - the state machine can search corresponding consensus key paired with given validator operator for any arbitrary height in a recent unbonding period.
    - the state machine does not need any historical mapping information which is past more than unbonding period.
```
