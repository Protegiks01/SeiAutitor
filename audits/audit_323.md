## Audit Report

## Title
Validator Can Escape Slashing Through Timing Attack Exploiting AND-Based Evidence Age Validation

## Summary
A malicious validator can avoid slashing by exploiting the logical AND condition in evidence age validation combined with variable block production times. When a validator commits an infraction, immediately unbonds, and network block production slows down, the validator can be removed from state after the unbonding period completes (time-based) but before evidence expires (block-based). Evidence submitted in this window passes the age check but fails to slash because the validator is no longer found in state. [1](#0-0) [2](#0-1) 

## Impact
**High** - Direct loss of funds through complete evasion of slashing mechanism.

## Finding Description

**Location:** 
- Evidence age validation: [3](#0-2) 
- Validator removal during unbonding: [4](#0-3) 
- Early return in Slash when validator not found: [2](#0-1) 

**Intended Logic:** 
Evidence should be rejected if it's too old, where "too old" means it occurred before the unbonding period. This prevents Nothing-At-Stake attacks where validators unbond their stake and then can no longer be slashed. The unbonding period and evidence max age are both set to 21 days by default to ensure validators can be slashed for infractions committed while they had stake. [5](#0-4) [6](#0-5) 

**Actual Logic:** 
The evidence age check uses logical AND, requiring BOTH time duration AND block count to exceed their respective limits before rejecting evidence. During network slowdowns with reduced block production, time-based unbonding can complete (allowing validator removal) while block-based evidence validation still accepts the evidence. When the `Slash` function is called, it finds the validator has been removed and returns early without performing any slashing. [1](#0-0) [7](#0-6) 

**Exploit Scenario:**
1. Malicious validator commits double-sign at height H, time T
2. Validator immediately initiates unbonding (all delegators unbond)
3. Network experiences slowdown (validator outages, network issues, attacks) causing block time to increase from 6s to 10-12s
4. After 21 days (UnbondingTime), validator completes unbonding at height H'
5. Since validator has zero delegator shares, `RemoveValidator` is called, deleting the validator from state including the ValidatorByConsAddr mapping
6. Evidence is submitted at day 22, height H'' where (H'' - H) < MaxAgeNumBlocks (302,400)
7. Evidence passes age check because: `(22 days > 21 days) AND (blocks < 302,400)` = `TRUE AND FALSE` = `FALSE` (not rejected)
8. `HandleEquivocationEvidence` calls `ValidatorByConsAddr` which returns nil
9. Control passes to `Slash`, which immediately returns at line 48 without slashing
10. Unbonding delegations completed during step 4, tokens already distributed to delegators [8](#0-7) [9](#0-8) 

**Security Failure:** 
The slashing mechanism fails to punish misbehaving validators. The protocol's economic security model assumes validators face consequences for infractions, but this exploit allows complete evasion of those consequences. The comment at line 40-42 assumes validators not found "must have been overslashed and removed" but doesn't account for validators removed due to completing unbonding without being slashed. [10](#0-9) 

## Impact Explanation

**Assets Affected:** Validator stake that should be slashed, unbonding delegations that should be slashed, network security deposits.

**Severity:** Complete loss of slashing capability for affected infractions. Validators who double-sign can:
- Keep 100% of their staked tokens instead of losing 5% (default slash fraction)
- Allow all delegators to keep their full stake instead of being partially slashed
- Avoid being tombstoned and permanently banned

**System Impact:** This undermines the entire economic security model of the blockchain. If validators know they can escape slashing through timing, they have reduced incentive to behave honestly. This could lead to increased attacks, reduced network security, and loss of user confidence.

## Likelihood Explanation

**Trigger Conditions:**
- Any validator can attempt this exploit after committing an infraction
- Requires network to experience slower-than-normal block production for the unbonding period
- Slower block times occur naturally during network congestion, validator outages, or coordinated attacks

**Frequency:**
- Realistic during network stress or after major validator outages
- Attackers can intentionally cause slowdowns by coordinating validator downtime
- With default parameters (6s blocks assumed but 10-12s common in practice), the window exists frequently

**Exploitability:**
Block times vary significantly in real networks. Cosmos chains commonly experience 8-15 second block times during normal operation or network stress. With a 21-day unbonding period:
- At 6s blocks: 302,400 blocks 
- At 10s blocks: 181,440 blocks (~40% fewer)
- At 12s blocks: 151,200 blocks (~50% fewer)

This makes the exploit highly practical and likely to occur even without deliberate manipulation.

## Recommendation

Replace the AND logic with OR logic in evidence age validation, or enforce that evidence parameters must be configured to prevent the timing window:

**Option 1 (Recommended):** Change the evidence age check to use OR instead of AND:
```go
if ageDuration > cp.Evidence.MaxAgeDuration || ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    // reject evidence
}
```

**Option 2:** Add validation during parameter updates to ensure `MaxAgeNumBlocks` accounts for realistic block times. Calculate minimum required blocks as: `MaxAgeDuration / (average_block_time * 0.5)` to provide buffer for slowdowns.

**Option 3:** Prevent validator removal if they have pending slash-able unbonding delegations or redelegations that haven't reached maturity plus evidence max age.

**Option 4:** Store historical validator records for the evidence max age period, even after removal, to allow slashing to proceed against removed validators' unbonding delegations.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`

**Test Function:** `TestSlashEvasionThroughTimingAttack`

**Setup:**
1. Initialize chain with default consensus params (MaxAgeDuration=21 days, MaxAgeNumBlocks=302,400)
2. Create validator with delegations
3. Validator commits double-sign infraction at height 1000, time T0

**Trigger:**
1. Immediately initiate unbonding of all delegations (height 1000)
2. Simulate slow block production: advance time by 21 days but only advance blocks by 180,000 (simulating ~10s block time)
3. Process EndBlock to complete unbonding - validator should be removed
4. Submit double-sign evidence from height 1000

**Observation:**
1. Evidence age check: `ageDuration (21d) > MaxAgeDuration (21d)` = FALSE, `ageBlocks (179,000) > MaxAgeNumBlocks (302,400)` = FALSE → Evidence NOT rejected
2. `HandleEquivocationEvidence` calls `ValidatorByConsAddr` → returns nil
3. Evidence is accepted but no slashing occurs
4. Validator's unbonded tokens remain with delegators (not slashed)
5. Assert that validator's tokens were NOT burned
6. Assert that unbonding delegation balances were NOT reduced

**Expected Result:** Test demonstrates that validator and delegators escaped slashing despite valid evidence being submitted within the supposed "max age" window. The test fails on vulnerable code by showing tokens that should have been slashed remain intact.

The test would require mocking time advancement with slow block production to create the timing window, then verifying that the validator removal occurs before slashing can be processed despite evidence being "valid" according to the AND-based age check.

### Citations

**File:** x/evidence/keeper/infraction.go (L48-63)
```go
	// Reject evidence if the double-sign is too old. Evidence is considered stale
	// if the difference in time and number of blocks is greater than the allowed
	// parameters defined.
	cp := ctx.ConsensusParams()
	if cp != nil && cp.Evidence != nil {
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
			logger.Info(
				"ignored equivocation; evidence too old",
				"validator", consAddr,
				"infraction_height", infractionHeight,
				"max_age_num_blocks", cp.Evidence.MaxAgeNumBlocks,
				"infraction_time", infractionTime,
				"max_age_duration", cp.Evidence.MaxAgeDuration,
			)
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

**File:** x/staking/keeper/validator.go (L176-176)
```go
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/staking/types/params.go (L21-21)
```go
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** simapp/test_helpers.go (L46-46)
```go
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** x/staking/spec/05_end_block.md (L62-68)
```markdown
Complete the unbonding of all mature `UnbondingDelegations.Entries` within the
`UnbondingDelegations` queue with the following procedure:

- transfer the balance coins to the delegator's wallet address
- remove the mature entry from `UnbondingDelegation.Entries`
- remove the `UnbondingDelegation` object from the store if there are no
  remaining entries.
```
