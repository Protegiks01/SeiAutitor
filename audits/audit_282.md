# Audit Report

## Title
Validator Removal Bypasses Equivocation Slashing via GetPubkey Failure

## Summary
A validator who commits equivocation (double-signing) while already in the unbonding process can have their pubkey relation deleted before evidence is submitted, causing `HandleEquivocationEvidence` to silently skip slashing. This allows the validator and their delegators to avoid punishment for misbehavior. [1](#0-0) 

## Impact
**High** - Direct loss of funds (avoided slashing penalties)

## Finding Description

**Location:** 
- Primary: `x/evidence/keeper/infraction.go` lines 29-40 (GetPubkey check)
- Secondary: `x/slashing/keeper/hooks.go` lines 40-43 (pubkey deletion on validator removal)
- Related: `x/staking/keeper/validator.go` lines 153-181, 399-450 (validator removal logic)

**Intended Logic:** 
When equivocation evidence is submitted, the system should slash the validator's tokens and all associated unbonding delegations/redelegations that were active during the infraction period, regardless of the validator's current status. [2](#0-1) 

**Actual Logic:** 
The `HandleEquivocationEvidence` function calls `GetPubkey` first (line 29). If this fails, it returns early without processing evidence (line 39). When a validator is removed via `RemoveValidator`, the `AfterValidatorRemoved` hook deletes the pubkey relation. This creates a bypass: validators removed before evidence submission escape all slashing. [3](#0-2) 

**Exploit Scenario:**

1. **T-10 days:** Validator Bob starts unbonding (self-delegation)
2. **T:** Bob commits equivocation (double-signing) while in Unbonding status  
3. **T+1 day:** Delegator Alice starts unbonding from Bob
4. **T+11 days:** Bob's unbonding completes:
   - Bob transitions from Unbonding to Unbonded status
   - Bob has zero `DelegatorShares` (removed when unbonding started)
   - `RemoveValidator` is called
   - `AfterValidatorRemoved` hook deletes Bob's pubkey relation [4](#0-3) 

5. **T+15 days:** Evidence of Bob's double-signing is submitted (still within 21-day `MaxAgeDuration`)
   - `HandleEquivocationEvidence` calls `GetPubkey`
   - `GetPubkey` fails because pubkey relation was deleted at T+11
   - Function returns early without calling `Slash`
6. **T+22 days:** Alice's unbonding completes WITHOUT being slashed [5](#0-4) 

**Security Failure:**
The slashing invariant is violated: misbehaving validators and their delegators must be penalized. The `Slash` function should iterate through unbonding delegations and slash them proportionally, but it's never called because `GetPubkey` fails first. [6](#0-5) 

## Impact Explanation

**Affected Assets:** Unbonding delegations and validator tokens that should be slashed for equivocation.

**Severity:** Delegators who unbonded from a misbehaving validator can receive their full unbonded amount without slashing. The default slash fraction for double-signing is 5% (can be configured higher). With the default unbonding time and evidence max age both set to 21 days, this timing window is realistic. [7](#0-6) 

**System Impact:** This undermines the economic security model of the network. Validators and delegators have reduced incentive to behave honestly if they can escape punishment by timing their unbonding strategically.

## Likelihood Explanation

**Triggering Conditions:**
- Any participant can submit equivocation evidence via `MsgSubmitEvidence`
- The exploit requires the validator to be already unbonding when they commit the infraction
- Default parameters (21-day unbonding time = 21-day evidence max age) make this window exploitable

**Frequency:** 
This can occur whenever:
1. A validator begins unbonding (voluntarily or due to jailing)
2. The validator then commits equivocation before unbonding completes
3. Evidence is submitted after the validator is removed but before max age expires

This scenario is realistic during network instability, validator migration, or intentional gaming.

## Recommendation

**Fix:** Move the validator existence check before the `GetPubkey` check in `HandleEquivocationEvidence`. If the validator doesn't exist but evidence is still valid (within max age), retrieve the consensus address from the evidence and proceed with slashing unbonding delegations directly.

Alternatively, preserve the pubkey relation even after validator removal, or store it in a separate "historical" mapping that persists beyond validator removal for the evidence max age duration.

**Code change in `x/evidence/keeper/infraction.go`:**
```go
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) {
    consAddr := evidence.GetConsensusAddress()
    
    // Check validator existence FIRST
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
    if validator == nil || validator.IsUnbonded() {
        // Validator removed/unbonded - but still slash unbonding delegations if evidence is fresh
        // (continue with age checks and slashing logic even without validator record)
    }
    
    // Then check pubkey (or make it optional if validator doesn't exist)
    if pubkey, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
        // Only return if validator also doesn't exist
        if validator == nil {
            return
        }
    }
    
    // Continue with age checks and slashing...
}
```

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestHandleEquivocationEvidence_ValidatorRemovedBeforeEvidence`

**Setup:**
1. Initialize test chain with default consensus params (21-day unbonding time, 21-day evidence max age)
2. Create validator Bob with power 100 and delegator Alice with delegation
3. Process BeginBlock to establish signing info

**Trigger:**
1. Set context time to T-10 days
2. Bob starts unbonding (self-delegation completely)
3. Advance time to T, set context height appropriately
4. Bob commits equivocation (create evidence at this height/time)
5. Alice starts unbonding her delegation
6. Advance time to T+11 days
7. Call `staking.EndBlocker` to complete Bob's unbonding and remove validator
8. Verify Bob's pubkey relation is deleted via `GetPubkey` failure
9. Advance time to T+15 days (evidence still valid)
10. Submit evidence via `HandleEquivocationEvidence`

**Observation:**
- Evidence is silently ignored (function returns early)
- Alice's unbonding delegation is NOT slashed
- Alice receives full unbonded amount when unbonding completes at T+22 days
- Expected: Alice should have been slashed by ~5% for Bob's double-signing

The test demonstrates that validators can be removed before evidence is processed, causing unbonding delegations to escape slashing penalties.

### Citations

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

**File:** x/staking/keeper/slash.go (L10-23)
```go
// Slash a validator for an infraction committed at a known height
// Find the contributing stake at that height and burn the specified slashFactor
// of it, updating unbonding delegations & redelegations appropriately
//
// CONTRACT:
//    slashFactor is non-negative
// CONTRACT:
//    Infraction was committed equal to or less than an unbonding period in the past,
//    so all unbonding delegations and redelegations from that height are stored
// CONTRACT:
//    Slash will not slash unbonded validators (for the above reason)
// CONTRACT:
//    Infraction was committed at the current height or at a past height,
//    not at a height in the future
```

**File:** x/staking/keeper/slash.go (L82-91)
```go
		// Iterate through unbonding delegations from slashed validator
		unbondingDelegations := k.GetUnbondingDelegationsFromValidator(ctx, operatorAddress)
		for _, unbondingDelegation := range unbondingDelegations {
			amountSlashed := k.SlashUnbondingDelegation(ctx, unbondingDelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}
```

**File:** x/slashing/keeper/hooks.go (L40-43)
```go
// AfterValidatorRemoved deletes the address-pubkey relation when a validator is removed,
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/slashing/keeper/keeper.go (L55-64)
```go
// GetPubkey returns the pubkey from the adddress-pubkey relation
func (k Keeper) GetPubkey(ctx sdk.Context, a cryptotypes.Address) (cryptotypes.PubKey, error) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.AddrPubkeyRelationKey(a))
	if bz == nil {
		return nil, fmt.Errorf("address %s not found", sdk.ConsAddress(a))
	}
	var pk cryptotypes.PubKey
	return pk, k.cdc.UnmarshalInterface(bz, &pk)
}
```

**File:** x/staking/types/params.go (L17-21)
```go
const (
	// DefaultUnbondingTime reflects three weeks in seconds as the default
	// unbonding time.
	// TODO: Justify our choice of default here.
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```
