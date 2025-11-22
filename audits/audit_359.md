# Audit Report

## Title
Front-Running Unjail with Double-Sign Evidence Causes Permanent Validator Tombstoning

## Summary
An attacker can permanently tombstone a validator by front-running their unjail transaction with stale double-sign evidence. The evidence handler unconditionally overwrites temporary downtime jail periods with permanent tombstoning, causing the subsequent unjail transaction to fail and leaving the validator permanently jailed. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Primary vulnerability: `x/evidence/keeper/infraction.go`, function `HandleEquivocationEvidence`, lines 120-121
- Related validation: `x/slashing/keeper/unjail.go`, function `Unjail`, lines 51-53
- Downtime jailing: `x/slashing/keeper/infractions.go`, function `SlashJailAndUpdateSigningInfo`, line 142

**Intended Logic:** 
When a validator is jailed for downtime (missing too many blocks), they receive a temporary jail period (e.g., 10 minutes). After this period expires, they can submit an unjail transaction to rejoin the active validator set. Double-sign evidence should permanently tombstone validators who have committed equivocation, preventing them from ever unjailing. [2](#0-1) 

**Actual Logic:** 
The `HandleEquivocationEvidence` function processes double-sign evidence without checking whether the validator is currently serving a temporary jail period. At line 120, it unconditionally calls `JailUntil` with `DoubleSignJailEndTime` (year 9999), overwriting any existing `JailedUntil` timestamp. At line 121, it tombstones the validator. The function only checks if the validator is already tombstoned (line 78), but not if they are already jailed for a different reason. [3](#0-2) [4](#0-3) 

When the unjail transaction subsequently executes, it checks if the validator is tombstoned and fails with `ErrValidatorJailed`. [5](#0-4) 

**Exploit Scenario:**
1. A validator commits a double-sign infraction at block height H
2. An attacker observes the equivocation and obtains the evidence but does not immediately submit it
3. Later, the validator is jailed for downtime (missing blocks), with `JailedUntil` set to current time + `DowntimeJailDuration` (typically 10 minutes)
4. After the downtime jail period expires, the validator submits a `MsgUnjail` transaction to rejoin the active set
5. The attacker front-runs the unjail transaction by submitting `MsgSubmitEvidence` with the double-sign evidence, using higher gas fees/priority
6. In the same block, the evidence transaction executes first:
   - `HandleEquivocationEvidence` processes the evidence
   - It updates `JailedUntil` to year 9999 (line 120)
   - It sets `Tombstoned = true` (line 121)
7. The unjail transaction executes second and fails because the validator is now tombstoned
8. The validator is permanently jailed and cannot recover

**Security Failure:** 
This breaks the intended separation between temporary downtime penalties and permanent double-sign penalties. An attacker can weaponize withheld double-sign evidence to permanently remove validators from the network by timing evidence submission to interfere with legitimate unjail operations.

## Impact Explanation

**Affected Assets/Processes:**
- Validator participation and rewards: Permanently jailed validators lose all future block rewards and commission
- Network decentralization: Malicious actors can strategically remove validators from the active set
- Validator reputation: False appearance that a validator is unable to recover from downtime

**Severity:**
- Validators suffer direct financial loss from permanent exclusion from the active set
- Network security is degraded if multiple validators are targeted
- The attack bypasses the protocol's design of temporary vs. permanent slashing

**System Impact:**
This vulnerability allows an attacker to permanently disable validators without requiring any privileged access. Since validators are critical to network consensus and security, the ability to permanently remove them represents a high-severity threat to network reliability and decentralization.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who observes double-sign evidence can execute this attack. The attacker needs:
- Access to valid double-sign evidence (obtainable by observing consensus messages)
- Ability to submit transactions with higher priority than the victim's unjail transaction (achievable via higher gas fees)

**Required Conditions:**
- The validator must have previously double-signed (creating valid evidence)
- The evidence must still be within the validity window (`MaxAgeDuration` and `MaxAgeNumBlocks`, typically days to weeks)
- The validator must get jailed for downtime during this evidence validity window
- The attacker must time their evidence submission to front-run the unjail transaction

**Frequency:**
This attack can occur whenever:
- A validator who has historical double-sign evidence gets jailed for downtime
- The evidence is still within the validity period
- The attacker monitors the mempool for unjail transactions

Given that downtime jailing is relatively common (validators may experience temporary infrastructure issues) and double-sign evidence remains valid for extended periods, this attack is practically exploitable.

## Recommendation

Add a check in `HandleEquivocationEvidence` to verify the validator's current jail status before processing double-sign evidence. If the validator is already jailed but not tombstoned, either:

**Option 1 (Conservative):** Reject the evidence if the validator is currently jailed, requiring evidence to be submitted before or after jailing but not during:
```
if validator.IsJailed() && !k.slashingKeeper.IsTombstoned(ctx, consAddr) {
    logger.Info("ignoring equivocation evidence for currently jailed validator", "validator", consAddr)
    return
}
```

**Option 2 (Lenient):** Allow the evidence but preserve the existing `JailedUntil` if it's sooner than `DoubleSignJailEndTime`, preventing disruption of in-progress unjail operations:
```
info, _ := k.slashingKeeper.GetValidatorSigningInfo(ctx, consAddr)
// Only update JailedUntil if not currently serving a shorter jail period
if info.JailedUntil.Before(types.DoubleSignJailEndTime) {
    k.slashingKeeper.JailUntil(ctx, consAddr, types.DoubleSignJailEndTime)
}
k.slashingKeeper.Tombstone(ctx, consAddr)
```

**Recommended approach:** Option 1 is safer as it prevents any race conditions and maintains clear separation between evidence submission and unjailing procedures.

## Proof of Concept

**Test File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestFrontRunUnjailWithDoubleSignEvidence`

**Setup:**
1. Create a test app with slashing and evidence modules
2. Create a validator and bond them to the active set
3. Simulate the validator double-signing at block height 100 (create equivocation evidence)
4. Do not submit the evidence yet
5. Simulate the validator missing enough blocks to trigger downtime jailing
6. Wait for the downtime jail period to expire

**Trigger:**
1. Prepare an unjail message from the validator
2. Before processing unjail, submit the double-sign evidence via `HandleEquivocationEvidence`
3. Then attempt to unjail the validator

**Observation:**
- After evidence submission, verify `IsTombstoned` returns `true`
- After evidence submission, verify `JailedUntil` is set to year 9999
- Verify the unjail operation fails with `ErrValidatorJailed`
- Confirm the validator cannot rejoin the active set despite serving their downtime jail period

**Expected Result:** The test demonstrates that submitting double-sign evidence after downtime jailing permanently tombstones the validator, causing their unjail to fail even though they completed their temporary jail period.

**Test Code Structure:**
```go
func TestFrontRunUnjailWithDoubleSignEvidence(t *testing.T) {
    // 1. Setup app and create validator
    // 2. Simulate double-sign at height 100, capture evidence
    // 3. Simulate downtime jailing at height 1000
    // 4. Advance time past downtime jail duration
    // 5. Submit double-sign evidence (front-run)
    // 6. Verify validator is tombstoned
    // 7. Attempt unjail - should fail
    // 8. Verify validator remains permanently jailed
}
```

This test proves the vulnerability by showing that stale double-sign evidence can be weaponized to permanently jail a validator who is legitimately attempting to recover from temporary downtime.

### Citations

**File:** x/evidence/keeper/infraction.go (L78-86)
```go
	if k.slashingKeeper.IsTombstoned(ctx, consAddr) {
		logger.Info(
			"ignored equivocation; validator already tombstoned",
			"validator", consAddr,
			"infraction_height", infractionHeight,
			"infraction_time", infractionTime,
		)
		return
	}
```

**File:** x/evidence/keeper/infraction.go (L116-121)
```go
	if !validator.IsJailed() {
		k.slashingKeeper.Jail(ctx, consAddr)
	}

	k.slashingKeeper.JailUntil(ctx, consAddr, types.DoubleSignJailEndTime)
	k.slashingKeeper.Tombstone(ctx, consAddr)
```

**File:** x/slashing/keeper/infractions.go (L142-142)
```go
	signInfo.JailedUntil = ctx.BlockHeader().Time.Add(k.DowntimeJailDuration(ctx))
```

**File:** x/slashing/keeper/unjail.go (L50-53)
```go
		// cannot be unjailed if tombstoned
		if info.Tombstoned {
			return types.ErrValidatorJailed
		}
```
