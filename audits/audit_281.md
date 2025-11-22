## Audit Report

## Title
Delegators Can Escape Downtime Slashing Through Early Unbonding Due to Incorrect Infraction Height Calculation

## Summary
The downtime slashing mechanism in `BeginBlocker` uses an infraction height of `currentHeight - 2` to determine which unbonding delegations to slash. This allows delegators to unbond during the validator's downtime period and escape slashing if they unbond more than 2 blocks before the threshold is reached, even though the validator was already missing blocks when they unbonded.

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/slashing/keeper/infractions.go` lines 106 and 140 [1](#0-0) 
- Secondary: `x/staking/keeper/slash.go` lines 175-177 [2](#0-1) 

**Intended Logic:** 
When a validator is slashed for downtime, all unbonding delegations that were initiated after the validator started misbehaving should be slashed to ensure delegators cannot escape penalties by unbonding once they observe their validator going offline.

**Actual Logic:** 
The code calculates `distributionHeight = currentHeight - ValidatorUpdateDelay - 1`, where `ValidatorUpdateDelay = 1`. This results in `infractionHeight = currentHeight - 2`. Only unbonding delegations with `CreationHeight >= infractionHeight` are slashed. Unbonding delegations created earlier escape slashing, regardless of whether they were initiated during the validator's downtime period. [3](#0-2) 

**Exploit Scenario:**
1. At block 100, a validator stops signing blocks
2. From blocks 101-197, the validator continues to miss blocks while accumulating toward the downtime threshold (e.g., 50 out of 100 blocks in the signed blocks window)
3. At block 150, a delegator observes the validator is offline and initiates unbonding with `CreationHeight = 150`
4. At block 200, `BeginBlocker` detects the validator has exceeded the threshold and triggers slashing with `infractionHeight = 200 - 2 = 198`
5. The unbonding created at height 150 is evaluated: `150 < 198`, so it is NOT slashed (skipped at line 176) [4](#0-3) 

6. The delegator successfully escapes slashing despite unbonding after the validator's infractions began

**Security Failure:** 
This breaks the economic security invariant that delegators must share the risk of their validator's misbehavior. It allows informed delegators to front-run slashing events by monitoring validator liveness in real-time and unbonding before the threshold is reached, while less-informed delegators bear the full slashing penalty.

## Impact Explanation

**Assets Affected:** Staking rewards and validator security bonds. While no funds are directly stolen, the slashing mechanism's effectiveness is undermined.

**Severity:** The vulnerability creates systemic unfairness in the delegation security model:
1. **Reduced Deterrent Effect:** If delegators can escape slashing by monitoring and unbonding early, the economic incentive to choose reliable validators is weakened
2. **Unfair Penalty Distribution:** Sophisticated delegators with monitoring infrastructure escape penalties while retail delegators bear the full burden
3. **Gaming Opportunity:** Creates a profitable strategy for delegators to monitor validators and front-run slashing events
4. **Validator Economics Impact:** Validators may experience mass unbonding cascades as soon as downtime is detected, potentially destabilizing the validator set

**Why This Matters:** The security of a Proof-of-Stake network relies on proper alignment of economic incentives. When delegators can systematically escape slashing, it undermines the fundamental security assumption that delegators are economically bound to validator performance.

## Likelihood Explanation

**Triggering Conditions:**
- Any network participant can trigger this by monitoring validator liveness and submitting unbonding transactions
- Requires no special privileges or coordination
- Can be automated with simple monitoring scripts observing missed blocks

**Frequency:**
- Occurs whenever validators experience extended downtime (common due to infrastructure issues, upgrades, or attacks)
- With typical parameters (`SignedBlocksWindow = 100 blocks`, `MinSignedPerWindow = 0.5`), delegators have a 40-50 block window to react after observing the validator going offline
- In a network with 5-10 second block times, this provides 3-8 minutes for sophisticated delegators to unbond

**Likelihood Assessment:** HIGH - This is easily exploitable by any delegator with basic monitoring capabilities during every validator downtime incident.

## Recommendation

Modify the infraction height calculation to use the actual beginning of the downtime period rather than a recent height. Options include:

1. **Track First Missed Block:** Add a field to `ValidatorSigningInfo` that records the block height when the validator first started missing blocks in the current sequence. Use this as the infraction height.

2. **Use Conservative Window Start:** Calculate `infractionHeight = currentHeight - SignedBlocksWindow` to capture the entire period during which infractions occurred.

3. **Immediate Partial Jail:** Implement a "warning state" that prevents new unbonding once a validator crosses a certain missed blocks threshold (e.g., 25% of window), before full slashing occurs.

The recommended fix is option 1, as it precisely captures when the validator's misbehavior began:

```go
// In HandleValidatorSignatureConcurrent, track when missing starts
if missed && signInfo.MissedBlocksCounter == 0 {
    signInfo.FirstMissedHeight = height
}

// In SlashJailAndUpdateSigningInfo, use FirstMissedHeight
distributionHeight := signInfo.FirstMissedHeight - sdk.ValidatorUpdateDelay - 1
```

## Proof of Concept

**File:** `x/slashing/keeper/downtime_slash_escape_test.go` (new test file)

**Test Function:** `TestDelegatorEscapesSlashingByUnbondingDuringDowntime`

**Setup:**
1. Initialize a test chain with one validator having 100 consensus power
2. Configure slashing parameters: `SignedBlocksWindow = 100`, `MinSignedPerWindow = 0.5`, `SlashFractionDowntime = 0.01`
3. Create a delegation from a test account to the validator
4. Run validator through 100 blocks with all signatures to establish signing history

**Trigger:**
1. At block 101, have the validator stop signing (set `SignedLastBlock = false`)
2. At block 125 (mid-downtime), delegator initiates unbonding of 50% of their delegation
3. Continue validator missing blocks through block 150 (total 50 consecutive misses)
4. At block 151, BeginBlocker triggers slashing with `infractionHeight = 149`

**Observation:**
1. Query the unbonding delegation created at height 125
2. Verify that `ubd.Entries[0].Balance` equals `ubd.Entries[0].InitialBalance` (no slashing occurred)
3. Confirm validator was slashed and jailed
4. Assert that `125 < 149`, demonstrating unbonding escaped slashing despite being created during downtime

**Expected Result:** The test demonstrates that unbonding delegations created during the validator's downtime period (but more than 2 blocks before detection) are not slashed, confirming the vulnerability.

**Test Code Structure:**
```go
func TestDelegatorEscapesSlashingByUnbondingDuringDowntime(t *testing.T) {
    // Setup app, context, validator, and delegator
    // Set slashing params: window=100, minSigned=0.5
    // Validator signs for first 100 blocks
    // At block 125: delegator unbonds (during downtime)
    // Blocks 101-150: validator misses (50 misses total)
    // At block 151: BeginBlocker detects and slashes (infractionHeight=149)
    // Verify: unbonding.Balance == unbonding.InitialBalance (NOT slashed)
    // Verify: 125 < 149 (proves escape condition)
}
```

This test would fail to find slashing on the unbonding delegation, proving that delegators can escape penalties by unbonding during the downtime period.

### Citations

**File:** x/slashing/keeper/infractions.go (L106-106)
```go
			distributionHeight := height - sdk.ValidatorUpdateDelay - 1
```

**File:** x/staking/keeper/slash.go (L166-211)
```go
func (k Keeper) SlashUnbondingDelegation(ctx sdk.Context, unbondingDelegation types.UnbondingDelegation,
	infractionHeight int64, slashFactor sdk.Dec) (totalSlashAmount sdk.Int) {
	now := ctx.BlockHeader().Time
	totalSlashAmount = sdk.ZeroInt()
	burnedAmount := sdk.ZeroInt()

	// perform slashing on all entries within the unbonding delegation
	for i, entry := range unbondingDelegation.Entries {
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}

		if entry.IsMature(now) {
			// Unbonding delegation no longer eligible for slashing, skip it
			continue
		}

		// Calculate slash amount proportional to stake contributing to infraction
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)

		// Don't slash more tokens than held
		// Possible since the unbonding delegation may already
		// have been slashed, and slash amounts are calculated
		// according to stake held at time of infraction
		unbondingSlashAmount := sdk.MinInt(slashAmount, entry.Balance)

		// Update unbonding delegation if necessary
		if unbondingSlashAmount.IsZero() {
			continue
		}

		burnedAmount = burnedAmount.Add(unbondingSlashAmount)
		entry.Balance = entry.Balance.Sub(unbondingSlashAmount)
		unbondingDelegation.Entries[i] = entry
		k.SetUnbondingDelegation(ctx, unbondingDelegation)
	}

	if err := k.burnNotBondedTokens(ctx, burnedAmount); err != nil {
		panic(err)
	}

	return totalSlashAmount
}
```

**File:** types/staking.go (L26-26)
```go
	ValidatorUpdateDelay int64 = 1
```
