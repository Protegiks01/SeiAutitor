# Audit Report

## Title
Validator Escapes Slashing via AND-Based Evidence Age Validation During Network Slowdowns

## Summary
The evidence age validation mechanism uses AND logic that creates a vulnerability window during network slowdowns. When block production is slower than the assumed 6-second baseline, the time-based 21-day unbonding period completes before the block-based evidence window (302,400 blocks) closes, allowing validators to unbond and escape slashing. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** [2](#0-1) 

**Intended Logic:**
The system is designed to ensure validators can be slashed for infractions committed while they had bonded stake. The evidence age parameters are configured to align with the unbonding period. [3](#0-2) [4](#0-3) 

The specification explicitly documents the "follow the stake" principle: [5](#0-4) 

The slash function contract states: [6](#0-5) 

**Actual Logic:**
The evidence age check uses AND logic requiring BOTH conditions to be true before rejecting evidence. During network slowdowns (e.g., 10-second blocks), after 21 days only ~181,440 blocks are produced. Unbonding completes based solely on time: [7](#0-6) 

When evidence is submitted at day 22 (~190,000 blocks): ageDuration > 21 days (TRUE) but ageBlocks < 302,400 (FALSE), so AND evaluates to FALSE and evidence is NOT rejected. However, the validator is already unbonded: [8](#0-7) 

The slash function refuses to process unbonded validators: [9](#0-8) 

And mature unbonding entries cannot be slashed: [10](#0-9) 

**Exploitation Path:**
1. Validator commits double-sign infraction at height H
2. Validator immediately initiates unbonding (self-delegated validators can do this unilaterally)
3. Network experiences sustained slower block production (10-12 second blocks) during the 21-day unbonding period
4. After 21 days (time-based), unbonding completes at ~181,440 blocks instead of expected 302,400 blocks
5. Validator transitions to Unbonded status and is removed if shares are zero: [11](#0-10) 
6. Unbonding delegations mature and tokens are returned to delegators: [12](#0-11) 
7. Evidence submitted between day 21 and block 302,400 passes AND-based age validation
8. Evidence handler finds validator is unbonded and returns early without slashing
9. No economic penalties applied; tokens remain with validator

**Security Guarantee Broken:**
The documented "follow the stake" principle is violated. The system explicitly states stake contributing to infractions should be slashed even if unbonding has started, but this vulnerability allows complete evasion.

## Impact Explanation

This vulnerability results in **direct loss of funds** representing economic penalties that should be enforced. The slashed funds should be burned from circulation as an economic penalty (typically 5% for double-signing), but instead remain with the malicious validator and delegators. This represents direct loss of economic value that should have been destroyed to maintain protocol security.

The vulnerability fundamentally undermines the proof-of-stake security model. The slashing mechanism serves as the primary economic deterrent against validator misbehavior. When validators can escape slashing, the incentive structure collapses, potentially leading to increased misbehavior and systemic security reduction.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability requires three realistic conditions:
1. **Validator commits slashable infraction** - Double-signing events occur in production chains
2. **Network experiences sustained slow blocks** - Cosmos SDK chains commonly show variable block times between 5-15 seconds due to congestion, validator outages, or consensus delays
3. **Evidence submitted within vulnerability window** - The specification explicitly acknowledges evidence delays: [13](#0-12) 

Self-delegated validators can initiate unbonding unilaterally. The vulnerability window extends for tens of thousands of blocks, providing ample opportunity for delayed evidence to encounter the unbonded validator state.

## Recommendation

**Primary Recommendation:**
Change the evidence age validation logic from AND to OR:

```go
if ageDuration > cp.Evidence.MaxAgeDuration || ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    // reject evidence as too old
    return
}
```

This ensures evidence is rejected if EITHER the time duration OR block count exceeds the limit, closing the timing window regardless of block production rate and keeping the two age limits synchronized.

**Alternative Approaches:**
1. Add parameter validation requiring MaxAgeNumBlocks to account for worst-case block times
2. Maintain historical validator state records for the evidence max age period
3. Prevent validator removal if pending unbonding delegations haven't matured beyond the evidence window

## Proof of Concept

**Test Setup:**
1. Initialize test chain with default consensus params (MaxAgeDuration: 21 days, MaxAgeNumBlocks: 302,400)
2. Create validator with self-delegation of 10,000 tokens
3. Record infraction at block 1000, time T0

**Execution:**
1. Validator immediately unbonds all delegations
2. Simulate slow block production: advance 181,440 blocks (21 days at 10-second blocks)
3. Advance time by exactly 21 days
4. Call `BlockValidatorUpdates(ctx)` to process mature unbonding queue
5. Verify validator is Unbonded or `ValidatorByConsAddr` returns nil
6. Verify delegator balance equals 10,000 tokens (unbonding completed, no slashing)
7. Advance to day 22 (~190,080 blocks total)
8. Submit evidence via `HandleEquivocationEvidence(ctx, evidence)`

**Expected Result:**
- Evidence age validation: ageDuration > 21 days (TRUE), ageBlocks < 302,400 (FALSE)
- AND evaluates to FALSE → Evidence NOT rejected
- Validator lookup returns nil or IsUnbonded() = true
- Evidence handler returns early
- No slashing occurs, balance remains 10,000 tokens
- Security guarantee violated: validator escaped slashing despite evidence within configured window

## Notes

The vulnerability is confirmed by the defensive comment acknowledging unbonded validators might be encountered, and by explicit specification that evidence can experience delays. The AND logic creates a design flaw where two parameters intended to represent the same period become misaligned under realistic network conditions, violating the documented "follow the stake" security principle.

### Citations

**File:** x/evidence/keeper/infraction.go (L53-64)
```go
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
	}
```

**File:** x/evidence/keeper/infraction.go (L66-71)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
	if validator == nil || validator.IsUnbonded() {
		// Defensive: Simulation doesn't take unbonding periods into account, and
		// Tendermint might break this assumption at some point.
		return
	}
```

**File:** simapp/test_helpers.go (L44-48)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
		MaxBytes:        10000,
	},
```

**File:** x/staking/types/params.go (L21-21)
```go
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** x/evidence/spec/06_begin_block.md (L43-44)
```markdown
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
```

**File:** x/staking/keeper/slash.go (L17-20)
```go
//    Infraction was committed equal to or less than an unbonding period in the past,
//    so all unbonding delegations and redelegations from that height are stored
// CONTRACT:
//    Slash will not slash unbonded validators (for the above reason)
```

**File:** x/staking/keeper/slash.go (L51-54)
```go
	// should not be slashing an unbonded validator
	if validator.IsUnbonded() {
		panic(fmt.Sprintf("should not be slashing unbonded validator: %s", validator.GetOperator()))
	}
```

**File:** x/staking/keeper/slash.go (L179-182)
```go
		if entry.IsMature(now) {
			// Unbonding delegation no longer eligible for slashing, skip it
			continue
		}
```

**File:** x/staking/types/delegation.go (L108-111)
```go
// IsMature - is the current entry mature
func (e UnbondingDelegationEntry) IsMature(currentTime time.Time) bool {
	return !e.CompletionTime.After(currentTime)
}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/staking/keeper/delegation.go (L887-893)
```go
				if err := k.bankKeeper.UndelegateCoinsFromModuleToAccount(
					ctx, types.NotBondedPoolName, delegatorAddress, sdk.NewCoins(amt),
				); err != nil {
					return nil, err
				}

				balances = balances.Add(amt)
```

**File:** x/slashing/spec/07_tombstone.md (L13-21)
```markdown
consensus faults and ABCI, there can be a delay between an infraction occurring,
and evidence of the infraction reaching the state machine (this is one of the
primary reasons for the existence of the unbonding period).

> Note: The tombstone concept, only applies to faults that have a delay between
> the infraction occurring and evidence reaching the state machine. For example,
> evidence of a validator double signing may take a while to reach the state machine
> due to unpredictable evidence gossip layer delays and the ability of validators to
> selectively reveal double-signatures (e.g. to infrequently-online light clients).
```
