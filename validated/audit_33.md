# Audit Report

## Title
Validator Escapes Slashing via AND-Based Evidence Age Validation During Network Slowdowns

## Summary
The evidence age validation mechanism uses AND logic requiring both time duration AND block count to exceed limits before rejecting evidence. During network slowdowns with reduced block production, time-based unbonding completes while block-based evidence validation continues accepting evidence, allowing validators to escape slashing after transitioning to unbonded status.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The system is designed to ensure validators can be slashed for infractions committed while they had stake. Evidence age parameters (MaxAgeDuration and MaxAgeNumBlocks) are configured to align with the 21-day unbonding period [2](#0-1) [3](#0-2) . The slash function contract explicitly states [4](#0-3)  that infractions within the unbonding period should result in slashing. The specification documents the "follow the stake" principle [5](#0-4)  requiring that stake contributing to infractions be slashed even if unbonding has started.

**Actual Logic:**
The evidence age check uses AND logic, requiring BOTH `ageDuration > MaxAgeDuration` AND `ageBlocks > MaxAgeNumBlocks` before rejecting evidence. With default parameters assuming 6-second blocks (21 days = 302,400 blocks), network slowdowns create a vulnerability window. When blocks average 10 seconds, after 21 days only ~181,440 blocks are produced. Time-based unbonding completes at 21 days, transitioning the validator to Unbonded status [6](#0-5) . If the validator has zero delegator shares, it's removed from state [7](#0-6) . Unbonding delegations mature and tokens are returned [8](#0-7) .

Evidence submitted on day 22 (~190,000 blocks) encounters: ageDuration = 22 days > 21 days (TRUE), but ageBlocks = 190,000 < 302,400 (FALSE). The AND condition evaluates to FALSE, so evidence is NOT rejected. However, the validator status check [9](#0-8)  finds the validator is unbonded and returns early without slashing. The slash function explicitly refuses to process unbonded validators [10](#0-9) , and mature unbonding entries cannot be slashed [11](#0-10) .

**Exploitation Path:**
1. Validator commits double-sign infraction at height H
2. Validator immediately initiates unbonding (self-delegated validators can do this unilaterally)
3. Network experiences sustained slower block production (10-12 second blocks) during the 21-day unbonding period - this occurs naturally during network congestion, validator outages, or reduced participation
4. After 21 days (time-based), unbonding completes at ~181,440 blocks instead of expected 302,400
5. Validator status changes to Unbonded and is potentially removed from state if shares are zero
6. Unbonding delegations mature and tokens are returned to delegators
7. Evidence submitted on day 22 at ~190,000 blocks passes the AND-based age validation
8. Evidence handler finds validator is unbonded/nil and returns early without slashing
9. No economic penalties are applied; tokens that should be burned remain with the validator

**Security Guarantee Broken:**
The documented "follow the stake" principle is violated. The specification explicitly states that stake contributing to infractions should be slashed even if it has since been redelegated or started unbonding. This vulnerability allows validators to completely evade slashing consequences, undermining the fundamental economic security model of the proof-of-stake system.

## Impact Explanation

This vulnerability results in **direct loss of funds** representing the economic penalties that should be enforced. In a typical double-sign scenario with 5% slash fraction, the validator and all delegators retain 100% of their stake instead of losing 5%. These slashed funds should be burned from circulation as an economic penalty, but instead remain with the malicious actors. This represents a direct loss of the economic value that should have been destroyed to maintain protocol security guarantees.

Beyond the immediate fund loss, this fundamentally undermines the proof-of-stake security model. The slashing mechanism serves as the primary economic deterrent against validator misbehavior. When validators can escape slashing consequences, the incentive structure collapses, potentially leading to increased misbehavior and systemic reduction in network security.

## Likelihood Explanation

**Likelihood: Medium**

**Trigger Conditions:**
- Validator commits slashable infraction (double-signing)
- Network experiences slower-than-expected block production during 21-day unbonding period
- Evidence submitted after unbonding completes but within block-based window
- Self-delegated validators can trigger unbonding unilaterally

**Realistic Assessment:**
Cosmos SDK chains commonly experience variable block times. Production chains show block times frequently vary between 5-15 seconds due to network congestion, validator outages, reduced validator participation, and consensus delays during validator set changes. With default parameters assuming 6-second blocks, any sustained period of 10+ second blocks creates this vulnerability window.

Self-delegated validators (common in practice) can initiate unbonding without requiring coordinated action from other delegators. Evidence propagation delays are realistic - not all nodes detect infractions immediately, and evidence may take time to propagate through the network, especially during the same network conditions causing slow blocks.

A malicious validator could commit an infraction, immediately initiate unbonding, and wait for natural network slowdown (or contribute to it by going offline). Evidence submitted late would pass validation but find the validator already unbonded, achieving complete evasion of slashing consequences.

## Recommendation

**Primary Recommendation (Strongly Recommended):**
Change the evidence age validation logic from AND to OR:

```go
if ageDuration > cp.Evidence.MaxAgeDuration || ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    // reject evidence as too old
    return
}
```

This ensures evidence is rejected if EITHER the time duration OR block count exceeds the limit, closing the timing window regardless of block production rate.

**Alternative Approaches:**

1. Add genesis-time parameter validation requiring `MaxAgeNumBlocks >= MaxAgeDuration / minimum_expected_block_time` where minimum accounts for realistic worst-case scenarios (15-20 seconds), providing a safety buffer for network slowdowns.

2. Maintain historical validator state records via HistoricalInfo for the evidence max age period even after validator removal, allowing the slash function to process slashing against historical state.

3. Prevent validator removal if they have pending unbonding delegations or redelegations that haven't matured beyond the evidence max age period, ensuring validators remain slashable throughout the evidence window.

## Proof of Concept

**Test Name:** `TestValidatorEscapesSlashingDuringSlowBlocks`

**Setup:**
1. Initialize test chain with default consensus params (MaxAgeDuration: 21 days, MaxAgeNumBlocks: 302,400)
2. Create validator with self-delegation of 10,000 tokens
3. Validator commits double-sign at block 1000, time T0
4. Record evidence data (consensus address, height, time, power)

**Execution:**
1. Validator immediately unbonds all delegations at block 1000
2. Advance blockchain state simulating slow block production:
   - Add 181,440 blocks (21 days at 10-second blocks instead of 6-second)
   - Advance time by 21 days
3. Call `app.StakingKeeper.BlockValidatorUpdates(ctx)` to process mature unbonding queue
4. Verify validator status is Unbonded or removed from ValidatorByConsAddr mapping
5. Verify delegator account balance equals original 10,000 tokens (unbonding completed)
6. Advance time by 1 more day and blocks by ~8,640 (continuing 10-second block rate)
7. Submit double-sign evidence from block 1000 via `app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)`

**Expected Result:**
- Evidence age check: ageDuration = 22 days > 21 days (TRUE), ageBlocks = 190,080 < 302,400 (FALSE)
- AND logic: TRUE && FALSE = FALSE → Evidence NOT rejected
- ValidatorByConsAddr lookup returns nil or validator status is Unbonded
- Evidence handler returns early without entering slashing logic
- Delegator balance remains 10,000 tokens (not reduced by 5% slash fraction)
- No tokens burned from slash operation
- Validator not tombstoned

This test demonstrates that valid evidence submitted within the configured "evidence window" fails to trigger slashing when block production is slower than default parameter assumptions, allowing complete evasion of slashing consequences and violating the documented "follow the stake" security guarantee.

### Citations

**File:** x/evidence/keeper/infraction.go (L53-53)
```go
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
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

**File:** x/staking/types/params.go (L21-21)
```go
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** simapp/test_helpers.go (L44-48)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
		MaxBytes:        10000,
	},
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

**File:** x/evidence/spec/06_begin_block.md (L43-44)
```markdown
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
```

**File:** x/staking/keeper/val_state_change.go (L250-256)
```go
// UnbondingToUnbonded switches a validator from unbonding state to unbonded state
func (k Keeper) UnbondingToUnbonded(ctx sdk.Context, validator types.Validator) types.Validator {
	if !validator.IsUnbonding() {
		panic(fmt.Sprintf("bad state transition unbondingToBonded, validator: %v\n", validator))
	}

	return k.completeUnbondingValidator(ctx, validator)
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
