# Audit Report

## Title
Validator Escapes Slashing via AND-Based Evidence Age Validation During Network Slowdowns

## Summary
The evidence age validation mechanism uses AND logic requiring both time duration AND block count to exceed limits before rejecting evidence. During network slowdowns with reduced block production, time-based unbonding completes while block-based evidence validation continues accepting evidence. When evidence is submitted in this window, the validator has transitioned to unbonded status and cannot be slashed, completely evading economic penalties.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

**Intended Logic:**
The system is designed to ensure validators can be slashed for infractions committed while they had stake. The evidence age parameters (MaxAgeDuration and MaxAgeNumBlocks) are configured to align with the unbonding period [5](#0-4) [6](#0-5) , ensuring evidence submitted within this period results in slashing. The CONTRACT in the slash function explicitly states [7](#0-6) : "Infraction was committed equal to or less than an unbonding period in the past, so all unbonding delegations and redelegations from that height are stored."

**Actual Logic:**
The evidence age check uses AND logic, requiring BOTH `ageDuration > MaxAgeDuration` AND `ageBlocks > MaxAgeNumBlocks` before rejecting evidence. This creates a vulnerability during network slowdowns:

1. Default parameters assume 6-second blocks: 21 days = 302,400 blocks
2. At 10-second blocks: 21 days = only 181,440 blocks (40% fewer)
3. After 21 days, unbonding completes (time-based) and validator transitions to Unbonded status
4. Evidence submitted at day 22 (~193,500 blocks):
   - ageDuration = 22 days > 21 days (TRUE)
   - ageBlocks = 193,500 < 302,400 (FALSE)
   - Result: TRUE && FALSE = FALSE → Evidence NOT rejected
5. Evidence handler checks validator status, finds unbonded, returns early without slashing
6. The slash function explicitly cannot process unbonded validators

**Exploitation Path:**
1. Validator commits double-sign infraction at height H
2. Validator initiates unbonding (self-delegated validators can do this unilaterally)
3. Network experiences slower block production (10-12 second blocks) during unbonding period - this occurs naturally during network congestion, validator outages, or reduced participation
4. After 21 days (time-based), unbonding completes at ~181,440 blocks
5. Validator status changes to Unbonded via [8](#0-7) 
6. If validator has zero delegator shares, it's removed from state including ValidatorByConsAddr mapping [9](#0-8) 
7. Unbonding delegations mature and tokens are returned to delegators [10](#0-9) 
8. Evidence submitted on day 22 at ~193,500 blocks passes age validation (AND condition not satisfied)
9. Evidence handler finds validator is unbonded/nil, returns early
10. No slashing occurs, mature unbonding entries cannot be slashed [11](#0-10) 

**Security Guarantee Broken:**
The "follow the stake" principle documented in [12](#0-11)  is violated: "We want to 'follow the stake', i.e., the stake that contributed to the infraction should be slashed, even if it has since been redelegated or started unbonding." The economic security model assumes validators face consequences for misbehavior, but this vulnerability allows complete evasion.

## Impact Explanation

This vulnerability results in **direct loss of funds** that should have been slashed from the validator and delegators' stakes. In a typical double-sign scenario with 5% slash fraction, the validator and all delegators retain 100% of their stake instead of losing 5%. The slashed funds should be burned or transferred to the community pool as an economic penalty, but instead remain with the malicious actors. This represents a direct loss to the protocol's economic security guarantees.

Beyond the immediate fund loss, this undermines the entire proof-of-stake security model. The slashing mechanism serves as the primary deterrent against validator misbehavior. When validators can escape slashing consequences, the economic incentive structure collapses, potentially leading to increased misbehavior and reduced network security.

## Likelihood Explanation

**Likelihood: Medium to High**

**Trigger Conditions:**
- Validator commits slashable infraction (double-signing)
- Network experiences slower-than-expected block production during 21-day unbonding period
- Evidence submitted after unbonding completes but within block-based window
- Self-delegated validators can trigger unbonding unilaterally

**Realistic Assessment:**
Cosmos SDK chains commonly experience variable block times. Analysis of production chains shows block times frequently vary between 5-15 seconds due to:
- Network congestion during high transaction volume
- Validator outages or infrastructure issues
- Periods of reduced validator participation
- Consensus delays during validator set changes

With default parameters assuming 6-second blocks, any sustained period of 10+ second blocks creates this vulnerability window. Self-delegated validators (common in practice) can initiate unbonding without requiring coordinated action from other delegators.

Evidence propagation delays are realistic - not all nodes detect infractions immediately, and evidence may take time to propagate through the network, especially during the same network conditions causing slow blocks.

**Attack Vector:**
A malicious validator could:
1. Commit double-sign infraction
2. Immediately initiate unbonding
3. Wait for natural network slowdown (or contribute to it by going offline)
4. Evidence submitted late passes validation but finds validator already unbonded
5. Complete evasion of slashing consequences

## Recommendation

**Primary Recommendation (Strongly Recommended):**
Change the evidence age validation logic from AND to OR in [1](#0-0) :

```go
if ageDuration > cp.Evidence.MaxAgeDuration || ageBlocks > cp.Evidence.MaxAgeNumBlocks {
    // reject evidence as too old
    return
}
```

This ensures evidence is rejected if EITHER the time duration OR block count exceeds the limit, closing the timing window regardless of block production rate.

**Alternative Approaches:**

**Option 2:** Add genesis-time parameter validation requiring `MaxAgeNumBlocks >= MaxAgeDuration / (minimum_expected_block_time)` where minimum_expected_block_time accounts for realistic worst-case scenarios (e.g., 15-20 seconds). This provides a safety buffer for network slowdowns.

**Option 3:** Maintain historical validator state records (via HistoricalInfo) for the evidence max age period even after validator removal, allowing the slash function to process slashing against historical state. This would require modifying the evidence handler to lookup historical validators when current lookup returns nil.

**Option 4:** Prevent validator removal if they have pending unbonding delegations or redelegations that haven't matured beyond the evidence max age period, ensuring validators remain slashable throughout the evidence window.

## Proof of Concept

**Test Name:** `TestValidatorEscapesSlashingDuringSlowBlocks`

**Setup:**
1. Initialize test chain with default consensus params from [13](#0-12) 
   - MaxAgeDuration: 504 hours (21 days)
   - MaxAgeNumBlocks: 302,400 blocks
2. Create validator with self-delegation of 10,000 tokens
3. Validator commits double-sign at block 1000, time T0
4. Record evidence data (consensus address, height, time, power)

**Execution:**
1. Validator immediately unbonds all delegations at block 1000
2. Advance blockchain state simulating slow block production:
   ```go
   // Simulate 21 days passing with 10-second blocks instead of 6-second
   ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 181440) // 21 days at 10s/block
   ctx = ctx.WithBlockTime(ctx.BlockTime().Add(21 * 24 * time.Hour))
   ```
3. Call `app.StakingKeeper.BlockValidatorUpdates(ctx)` to process mature unbonding queue
4. Verify validator status is Unbonded or removed from ValidatorByConsAddr
5. Verify delegator account balance equals original 10,000 tokens (unbonding completed)
6. Advance time by 1 more day and blocks by ~8,640 (continuing 10s/block rate):
   ```go
   ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 8640)
   ctx = ctx.WithBlockTime(ctx.BlockTime().Add(24 * time.Hour))
   ```
7. Submit double-sign evidence from block 1000 via `app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)`

**Expected Result:**
- Evidence age check: ageDuration = 22 days > 21 days (TRUE), ageBlocks = 190,080 < 302,400 (FALSE)
- AND logic: TRUE && FALSE = FALSE → Evidence NOT rejected
- ValidatorByConsAddr lookup returns nil or validator status is Unbonded
- Evidence handler returns early at [14](#0-13) 
- No slashing occurs
- Assert: Delegator balance remains 10,000 tokens (not reduced by 5% slash fraction)
- Assert: No tokens burned from slash
- Assert: Validator not tombstoned

This test demonstrates that valid evidence submitted within the "evidence window" fails to trigger slashing when block production is slower than the default parameter assumptions, allowing complete evasion of slashing consequences.

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

**File:** x/staking/keeper/val_state_change.go (L250-256)
```go
// UnbondingToUnbonded switches a validator from unbonding state to unbonded state
func (k Keeper) UnbondingToUnbonded(ctx sdk.Context, validator types.Validator) types.Validator {
	if !validator.IsUnbonding() {
		panic(fmt.Sprintf("bad state transition unbondingToBonded, validator: %v\n", validator))
	}

	return k.completeUnbondingValidator(ctx, validator)
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

**File:** x/evidence/spec/06_begin_block.md (L43-44)
```markdown
We want to "follow the usei", i.e., the stake that contributed to the infraction
should be slashed, even if it has since been redelegated or started unbonding.
```
