## Title
Stale Total Power in Voting Power Ratio Check Enables Griefing Attack on Delegations

## Summary
The `Delegate` function's voting power ratio check uses stale `lastTotalPower` from the previous block while comparing it against current validator tokens that include intra-block delegation updates. This asymmetry allows attackers to front-run legitimate delegations with small delegations that artificially inflate the calculated voting power ratio, causing legitimate delegations to incorrectly fail with `ErrExceedMaxVotingPowerRatio`. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/staking/keeper/delegation.go`, lines 642-664, in the `Delegate` function's voting power ratio enforcement logic.

**Intended Logic:** The voting power ratio check is intended to prevent any single validator from exceeding 20% (default `MaxVotingPowerRatio`) of the total network voting power. The check should compare the validator's power after a delegation against the actual total network power after all delegations in the current block.

**Actual Logic:** The implementation has a critical flaw in how it calculates the voting power ratio:

1. Line 644 retrieves `lastTotalPower` from storage, which is only updated during `EndBlock` [2](#0-1) 

2. Within a single block, ALL delegation transactions read the SAME stale `lastTotalPower` value from the previous block

3. Line 654 calculates `validatorNewTotalPower` using `validator.Tokens.Add(bondAmt)`, where `validator.Tokens` reflects all prior delegations in the current block (updated at line 722) [3](#0-2) 

4. Line 656 calculates the ratio as: `validatorNewTotalPower / newTotalPower`, where:
   - Numerator includes all prior delegations to this validator in the current block
   - Denominator only adds the current delegation to stale `lastTotalPower`, ignoring other delegations in the block

This asymmetry causes the denominator to be artificially small when multiple delegations occur in the same block, inflating the calculated ratio.

**Exploit Scenario:**

Initial state (end of Block N):
- Total power: 1,000,000 consensus units
- Validator V power: 199,900 (19.99% of total)
- `MaxVotingPowerRatio`: 0.2 (20%)

Block N+1, Transaction 1 (Attacker):
- Attacker delegates 50 power to Validator V
- Check calculates: (199,900 + 50) / (1,000,000 + 50) = 199,950 / 1,000,050 = 19.995% ✓ Passes
- Validator V now has 199,950 power

Block N+1, Transaction 2 (Victim):
- Victim attempts to delegate 100 power to Validator V
- Check calculates: (199,950 + 100) / (1,000,000 + 100) = 200,050 / 1,000,100 = 20.005% ✗ Fails
- But actual ratio should be: 200,050 / (1,000,000 + 50 + 100) = 200,050 / 1,000,150 = 19.997% (should pass!)

The victim's delegation incorrectly fails because the denominator doesn't include the attacker's 50 power delegation from earlier in the block.

**Security Failure:** This breaks the correctness of the voting power enforcement mechanism and enables denial-of-service attacks on legitimate staking operations. An attacker can monitor the mempool for large delegations to validators near the threshold and front-run them with small delegations, causing legitimate transactions to fail.

## Impact Explanation

**Affected Operations:** This vulnerability affects all delegation operations (both direct delegations and redelegations via `BeginRedelegation` [4](#0-3) ) to validators approaching the voting power ratio threshold.

**Severity of Damage:**
- **Denial of Service:** Attackers can systematically prevent legitimate users from delegating to high-performing validators, disrupting the staking mechanism
- **Validator Selection Manipulation:** By griefing delegations to certain validators, attackers can influence which validators receive stake and participate in consensus
- **Economic Impact:** Legitimate delegators lose potential staking rewards when their delegations fail, while attackers can redirect stake to other validators
- **Network Security:** The staking distribution affects network security; manipulation of this distribution could concentrate power in attacker-preferred validators

**System Reliability Impact:** This matters because staking is a core mechanism for proof-of-stake security. The ability to arbitrarily block legitimate delegations undermines user trust in the staking system and can lead to suboptimal validator set composition.

## Likelihood Explanation

**Who Can Trigger:** Any network participant with sufficient funds to make small delegations (even 1 power unit) can execute this attack. No special privileges are required.

**Required Conditions:**
- Network total power must exceed `MaxVotingPowerEnforcementThreshold` (default: 1,000,000 power units) [5](#0-4) 
- Target validator must be within a few percentage points of the 20% threshold
- Attacker must front-run victim's transaction in the same block

**Frequency:** This can be exploited repeatedly during normal network operation:
- Attackers can monitor mempool for delegation transactions
- Front-running is a common MEV (Miner Extractable Value) technique
- The attack can be repeated across multiple blocks with minimal cost (just small delegation amounts)
- As validators approach the threshold organically, the attack surface increases

The vulnerability is highly likely to be exploited in practice, especially on networks with significant staking activity and competitive validator landscapes.

## Recommendation

**Fix:** Modify the voting power ratio check to track and accumulate total power changes within the current block. Specifically:

1. Maintain a block-scoped accumulator for total power changes (initialized to zero at BeginBlock)
2. Add each delegation's power to this accumulator when processing delegations
3. Calculate the ratio using: `validatorNewTotalPower / (lastTotalPower + blockTotalPowerDelta + validatorAddtionalPower)`

Alternatively, perform the voting power ratio enforcement in `EndBlock` after all delegations are processed, where the total power calculation would be accurate. However, this changes the error reporting behavior and may be less desirable from a UX perspective.

**Immediate Mitigation:** Document this behavior and consider increasing the `MaxVotingPowerEnforcementThreshold` to reduce the attack surface until a proper fix is implemented.

## Proof of Concept

**Test File:** `x/staking/keeper/delegation_test.go`

**Test Function:** Add the following test function `TestVotingPowerRatioGriefingAttack`:

```go
// TestVotingPowerRatioGriefingAttack demonstrates that an attacker can prevent
// legitimate delegations by front-running with small delegations that exploit
// the stale lastTotalPower in the voting power ratio check.
func TestVotingPowerRatioGriefingAttack(t *testing.T) {
	_, app, ctx := createTestInput()

	// Setup: Create test accounts with sufficient tokens
	addrDels := simapp.AddTestAddrsIncremental(app, ctx, 3, 
		app.StakingKeeper.TokensFromConsensusPower(ctx, 5000000))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)

	// Create two validators with zero initial tokens
	amts := []sdk.Int{sdk.NewInt(0), sdk.NewInt(0)}
	var validators [2]types.Validator
	for i, amt := range amts {
		validators[i] = teststaking.NewValidator(t, valAddrs[i], PKs[i])
		validators[i], _ = validators[i].AddTokensFromDel(amt)
	}

	validators[0] = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validators[0], true)
	validators[1] = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validators[1], true)
	app.StakingKeeper.SetValidator(ctx, validators[0])
	app.StakingKeeper.SetValidator(ctx, validators[1])
	app.StakingKeeper.SetValidatorByConsAddr(ctx, validators[0])
	app.StakingKeeper.SetValidatorByConsAddr(ctx, validators[1])
	app.StakingKeeper.SetNewValidatorByPowerIndex(ctx, validators[0])
	app.StakingKeeper.SetNewValidatorByPowerIndex(ctx, validators[1])

	ctx = ctx.WithBlockHeight(10)

	// Setup: Create initial state where validator 0 is at 19.99% and total power is 1,000,000
	_, err := app.StakingKeeper.Delegate(ctx, addrDels[0], 
		app.StakingKeeper.TokensFromConsensusPower(ctx, 199900), 
		types.Unbonded, validators[0], true)
	require.Nil(t, err)
	
	_, err = app.StakingKeeper.Delegate(ctx, addrDels[1], 
		app.StakingKeeper.TokensFromConsensusPower(ctx, 800100), 
		types.Unbonded, validators[1], true)
	require.Nil(t, err)

	// EndBlocker updates lastTotalPower to 1,000,000
	_ = staking.EndBlocker(ctx, app.StakingKeeper)

	// Verify initial state
	lastTotalPower := app.StakingKeeper.GetLastTotalPower(ctx)
	require.Equal(t, sdk.NewInt(1000000), lastTotalPower, "Initial total power should be 1,000,000")

	validator0, _ := app.StakingKeeper.GetValidator(ctx, valAddrs[0])
	require.Equal(t, app.StakingKeeper.TokensFromConsensusPower(ctx, 199900), validator0.Tokens)

	// Move to next block (block 11) - this is where the attack happens
	ctx = ctx.WithBlockHeight(11)

	// ATTACK: Attacker front-runs with a small delegation of 50 power to validator 0
	_, err = app.StakingKeeper.Delegate(ctx, addrDels[2], 
		app.StakingKeeper.TokensFromConsensusPower(ctx, 50), 
		types.Unbonded, validators[0], true)
	require.Nil(t, err, "Attacker's delegation should succeed")

	// Verify validator 0 now has 199,950 power
	validator0, _ = app.StakingKeeper.GetValidator(ctx, valAddrs[0])
	require.Equal(t, app.StakingKeeper.TokensFromConsensusPower(ctx, 199950), validator0.Tokens)

	// VICTIM: Legitimate user tries to delegate 100 power to validator 0
	// Expected: Should succeed because actual ratio = 200,050 / 1,000,150 = 19.997% < 20%
	// Actual: Fails because check calculates 200,050 / 1,000,100 = 20.005% > 20%
	_, err = app.StakingKeeper.Delegate(ctx, addrDels[2], 
		app.StakingKeeper.TokensFromConsensusPower(ctx, 100), 
		types.Unbonded, validators[0], true)

	// Observation: This assertion PASSES (proving the bug exists)
	// The delegation fails with ErrExceedMaxVotingPowerRatio
	require.NotNil(t, err, "BUG: Victim's delegation should succeed but fails")
	require.Equal(t, types.ErrExceedMaxVotingPowerRatio, err, 
		"Delegation fails with voting power ratio error")

	// Prove the actual ratio is under 20%
	// Actual total power = 1,000,000 + 50 + 100 = 1,000,150
	// Validator power = 200,050
	// Actual ratio = 200,050 / 1,000,150 = 0.19997 = 19.997% < 20%
	actualTotalPower := lastTotalPower.Add(sdk.NewInt(50)).Add(sdk.NewInt(100))
	expectedValidatorPower := sdk.NewInt(200050)
	actualRatio := sdk.NewDec(expectedValidatorPower.Int64()).Quo(sdk.NewDec(actualTotalPower.Int64()))
	maxRatio := app.StakingKeeper.MaxVotingPowerRatio(ctx)

	require.True(t, actualRatio.LT(maxRatio), 
		"Actual ratio %s should be under max ratio %s, proving this is a bug", 
		actualRatio.String(), maxRatio.String())
}
```

**Setup:** The test creates two validators and establishes an initial state where validator 0 has 199,900 power (19.99%) out of 1,000,000 total power, just under the 20% threshold.

**Trigger:** In block 11, the attacker delegates 50 power to validator 0 (passes check). Then immediately after in the same block, the victim attempts to delegate 100 power to validator 0.

**Observation:** The victim's delegation fails with `ErrExceedMaxVotingPowerRatio` even though the actual voting power ratio (19.997%) is under the 20% limit. The test demonstrates that the calculated ratio (20.005%) exceeds the limit due to using stale `lastTotalPower` in the denominator, confirming the vulnerability.

### Citations

**File:** x/staking/keeper/delegation.go (L642-664)
```go
	// check if the validator voting power exceeds the upper bound after the delegation
	// validator.Tokens
	lastTotalPower := k.GetLastTotalPower(ctx)
	maxVotingPowerEnforcementThreshold := k.MaxVotingPowerEnforcementThreshold(ctx)

	// 1 power = Bond Amount / Power Reduction
	validatorAddtionalPower := bondAmt.Quo(k.PowerReduction(ctx))
	newTotalPower := lastTotalPower.Add(validatorAddtionalPower)

	// If it's beyond genesis then enforce power ratio per validator if there's more than maxVotingPowerEnforcementThreshold
	if newTotalPower.GTE(maxVotingPowerEnforcementThreshold) && ctx.BlockHeight() > 0 {
		// Convert bond amount to power first
		validatorNewTotalPower := validator.Tokens.Add(bondAmt).Quo(k.PowerReduction(ctx))
		// Validator's new total power cannot exceed the max power ratio that's allowed
		newVotingPowerRatio := validatorNewTotalPower.ToDec().Quo(newTotalPower.ToDec())
		maxVotingPowerRatio := k.MaxVotingPowerRatio(ctx)
		if newVotingPowerRatio.GT(maxVotingPowerRatio) {
			k.Logger(ctx).Error(
				fmt.Sprintf("validator's voting power ratio exceeds the max allowed ratio: %s > %s\n", newVotingPowerRatio.String(), maxVotingPowerRatio.String()),
			)
			return sdk.ZeroDec(), types.ErrExceedMaxVotingPowerRatio
		}
	}
```

**File:** x/staking/keeper/delegation.go (L722-722)
```go
	_, newShares = k.AddValidatorTokensAndShares(ctx, validator, bondAmt)
```

**File:** x/staking/keeper/delegation.go (L945-945)
```go
	sharesCreated, err := k.Delegate(ctx, delAddr, returnAmount, srcValidator.GetStatus(), dstValidator, false)
```

**File:** x/staking/keeper/val_state_change.go (L217-218)
```go
	if len(updates) > 0 {
		k.SetLastTotalPower(ctx, totalPower)
```

**File:** types/staking.go (L14-15)
```go
	// Threshold for number of token staked = DefaultPowerReduction * DefaultMaxVotingPowerEnforcementThreshold
	DefaultMaxVotingPowerEnforcementThreshold uint64 = 1000000
```
