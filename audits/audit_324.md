## Audit Report

## Title
Incorrect Slash Accounting for Redelegations When Destination Validator Has Been Slashed

## Summary
The `SlashRedelegation` function calculates slash amounts based on `InitialBalance` but actually burns tokens based on current share values. When the destination validator has been slashed between the redelegation and the source validator's slash, this creates an accounting mismatch that causes the source validator to be under-slashed. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in `x/staking/keeper/slash.go` in the `SlashRedelegation` function (lines 219-296) and its interaction with the main `Slash` function (lines 24-143). [2](#0-1) 

**Intended Logic:** According to the protocol specification, when a validator is slashed, all redelegations from that validator that began after the infraction should be slashed proportionally. The total amount slashed (from both redelegations and the validator's bonded tokens) should equal `slashFactor * power` at the infraction height. [3](#0-2) 

**Actual Logic:** The `SlashRedelegation` function calculates the theoretical slash amount from `entry.InitialBalance` and returns this value as `totalSlashAmount`. However, the actual tokens burned come from unbonding shares at their current value via the `Unbond` function. When the destination validator has been slashed between the redelegation and the source validator's slash, the share value decreases, causing the actual burn to be less than the theoretical amount. The main `Slash` function subtracts the theoretical amount (not the actual burn) from `remainingSlashAmount`, leading to under-slashing of the source validator's bonded tokens. [4](#0-3) 

**Exploit Scenario:**
1. Validator A commits a double-sign infraction at height H1
2. At height H2 (after H1), a delegator redelegates 1000 tokens from A to B, creating a redelegation entry with `InitialBalance=1000` and `SharesDst=1000` shares
3. At height H3, validator B is slashed 50% for its own infraction, reducing share values to 0.5 tokens per share (the 1000 shares are now worth 500 tokens)
4. At height H4, evidence for validator A's infraction is submitted with a 50% slash factor:
   - The redelegation slash calculates: theoretical slash = 0.5 × 1000 = 500 tokens
   - But actual burn = 0.5 × 1000 shares × 0.5 tokens/share = 250 tokens
   - The function returns 500 (theoretical), which is subtracted from `remainingSlashAmount`
   - The validator's bonded tokens are slashed by the remaining amount
   - Total actual burn: 250 + (remaining) tokens, which is 250 tokens less than intended
   - Validator A escapes 250 tokens worth of punishment (50% of the redelegated amount)

**Security Failure:** This violates the protocol's slashing invariant that validators should be slashed by exactly `slashFactor * power` at the infraction height. The accounting mismatch allows validators to escape proportional punishment through redelegations to validators that are subsequently slashed.

## Impact Explanation

**Affected Assets/Processes:**
- Validator slashing mechanism and protocol security model
- Token supply accounting (fewer tokens burned than intended)
- Validator accountability and deterrence mechanism

**Severity:**
The vulnerability causes systematic under-slashing when cascading slashing events occur or when redelegations exist to risky validators. For example, if a validator with 10,000 tokens has 2,000 tokens redelegated to a validator that gets slashed 50%, and then the source validator is slashed 50%, the shortfall would be 500 tokens (2.5% of total intended slash). This can accumulate across multiple redelegations and slashing events.

**Why It Matters:**
The slashing mechanism is fundamental to blockchain security—it ensures validators face financial consequences for misbehavior. Under-slashing reduces the economic security guarantees of the network and may not adequately deter malicious behavior. This violates the protocol's design invariants and could be exploited by sophisticated attackers who strategically redelegate to risky validators after committing infractions.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can trigger this through normal operations. No special privileges are required.

**Conditions Required:**
1. A validator commits a slashable infraction
2. After the infraction, delegators redelegate from that validator to another validator (normal user operation)
3. The destination validator gets slashed for its own independent infraction
4. The source validator's infraction is eventually detected and slashed

**Frequency:**
This can occur naturally during periods of network instability when multiple validators are being slashed. It can also be strategically exploited by attackers who:
- Commit an infraction and then redelegate to risky/compromised validators they control
- Cause those destination validators to be slashed before their original infraction is discovered
- Thereby reduce their total slashing penalty

The issue is systemic and will occur whenever the conditions align, making it a repeatable vulnerability rather than a one-time edge case.

## Recommendation

Modify `SlashRedelegation` to return the actual burned amount rather than the theoretical slash amount. This requires tracking the actual `tokensToBurn` from all redelegation entries and returning that sum instead of `totalSlashAmount`:

```
// In SlashRedelegation function:
1. Replace the accumulation logic to track actual burns:
   - Instead of: totalSlashAmount = totalSlashAmount.Add(slashAmount)
   - Use: totalSlashAmount = totalSlashAmount.Add(tokensToBurn)

2. Return the sum of actual tokensToBurn values instead of theoretical slashAmount

3. Ensure proper accounting in the main Slash function to use actual burn amounts
```

Alternatively, implement a two-phase approach where redelegation slashing records both theoretical and actual amounts, and adjust the validator slash to compensate for any shortfall in the actual burn.

## Proof of Concept

**File:** `x/staking/keeper/slash_test.go`
**Function:** Add a new test function `TestSlashRedelegationWithSlashedDestination`

**Setup:**
1. Bootstrap test environment with 3 validators (A, B, C) each with 1000 tokens (power=10 at reduction factor of 100)
2. Create a delegator with sufficient funds
3. Create a redelegation from validator A to validator B of 400 tokens at height 11
4. Set validator A's infraction at height 10 (before redelegation)

**Trigger:**
1. Slash validator B by 50% at height 12 (this reduces the share value to 0.5 tokens per share)
2. Record the bonded pool balance before slashing A
3. Slash validator A by 50% at height 13 for the infraction at height 10
4. Record the bonded pool balance after slashing A

**Observation:**
The test should demonstrate that:
- Theoretical slash for the redelegation: 50% × 400 = 200 tokens
- Actual burn from redelegation: 50% × 400 shares × 0.5 tokens/share = 100 tokens
- Total intended slash: 50% × 1000 = 500 tokens
- Actual total burn: 100 (redelegation) + 400 (validator) = 500 tokens... wait, let me recalculate

Actually, the validator had 1000 tokens initially. After the redelegation, 400 tokens moved to B, so A has 600 tokens bonded.
- slashAmount = 50% × 1000 = 500 tokens (based on power at infraction)
- Redelegation theoretical: 200 tokens
- remainingSlashAmount = 500 - 200 = 300 tokens
- Validator A slash: min(300, 600) = 300 tokens
- Total burn: 100 (actual from redelegation) + 300 (from A) = 400 tokens
- Expected: 500 tokens
- **Shortfall: 100 tokens (20% under-slash)**

The test asserts that the total burned amount (bonded pool balance decrease) is less than the expected 500 tokens, confirming the under-slashing vulnerability.

### Citations

**File:** x/staking/keeper/slash.go (L93-102)
```go
		// Iterate through redelegations from slashed source validator
		redelegations := k.GetRedelegationsFromSrcValidator(ctx, operatorAddress)
		for _, redelegation := range redelegations {
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}
```

**File:** x/staking/keeper/slash.go (L219-296)
```go
func (k Keeper) SlashRedelegation(ctx sdk.Context, srcValidator types.Validator, redelegation types.Redelegation,
	infractionHeight int64, slashFactor sdk.Dec) (totalSlashAmount sdk.Int) {
	now := ctx.BlockHeader().Time
	totalSlashAmount = sdk.ZeroInt()
	bondedBurnedAmount, notBondedBurnedAmount := sdk.ZeroInt(), sdk.ZeroInt()

	// perform slashing on all entries within the redelegation
	for _, entry := range redelegation.Entries {
		// If redelegation started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}

		if entry.IsMature(now) {
			// Redelegation no longer eligible for slashing, skip it
			continue
		}

		// Calculate slash amount proportional to stake contributing to infraction
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)

		// Unbond from target validator
		sharesToUnbond := slashFactor.Mul(entry.SharesDst)
		if sharesToUnbond.IsZero() {
			continue
		}

		valDstAddr, err := sdk.ValAddressFromBech32(redelegation.ValidatorDstAddress)
		if err != nil {
			panic(err)
		}

		delegatorAddress := sdk.MustAccAddressFromBech32(redelegation.DelegatorAddress)

		delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
		if !found {
			// If deleted, delegation has zero shares, and we can't unbond any more
			continue
		}

		if sharesToUnbond.GT(delegation.Shares) {
			sharesToUnbond = delegation.Shares
		}

		tokensToBurn, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
		if err != nil {
			panic(fmt.Errorf("error unbonding delegator: %v", err))
		}

		dstValidator, found := k.GetValidator(ctx, valDstAddr)
		if !found {
			panic("destination validator not found")
		}

		// tokens of a redelegation currently live in the destination validator
		// therefor we must burn tokens from the destination-validator's bonding status
		switch {
		case dstValidator.IsBonded():
			bondedBurnedAmount = bondedBurnedAmount.Add(tokensToBurn)
		case dstValidator.IsUnbonded() || dstValidator.IsUnbonding():
			notBondedBurnedAmount = notBondedBurnedAmount.Add(tokensToBurn)
		default:
			panic("unknown validator status")
		}
	}

	if err := k.burnBondedTokens(ctx, bondedBurnedAmount); err != nil {
		panic(err)
	}

	if err := k.burnNotBondedTokens(ctx, notBondedBurnedAmount); err != nil {
		panic(err)
	}

	return totalSlashAmount
}
```

**File:** x/staking/spec/02_state_transitions.md (L131-138)
```markdown
- The total `slashAmount` is calculated as the `slashFactor` (a chain parameter) \* `TokensFromConsensusPower`,
  the total number of tokens bonded to the validator at the time of the infraction.
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```
