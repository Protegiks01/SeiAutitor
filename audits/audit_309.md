# Audit Report

## Title
Pre-Threshold Voting Power Accumulation Bypass Allows Validator Centralization

## Summary
The voting power enforcement logic in the staking module only enforces the maximum voting power ratio (default 20%) after the total network power reaches the enforcement threshold (default 1,000,000 power units). Before this threshold is reached, validators can accumulate unlimited voting power percentage, bypassing the intended security control. Additionally, within a single block, multiple delegations use the same stale `lastTotalPower` value, allowing an attacker to bypass the threshold check by splitting delegations across multiple transactions in the same block. [1](#0-0) 

## Impact
**High** - Unintended smart contract behavior with consensus security implications. This vulnerability allows a single validator to accumulate excessive voting power (>33% can halt the chain, >66% can control consensus), violating the protocol's security invariant designed to prevent validator centralization.

## Finding Description

**Location:** `x/staking/keeper/delegation.go`, function `Delegate`, lines 642-664

**Intended Logic:** The voting power enforcement mechanism is designed to prevent any single validator from controlling more than the `maxVotingPowerRatio` (default 20%) of the total network voting power. This prevents validator centralization and maintains decentralization guarantees.

**Actual Logic:** The enforcement check only executes when two conditions are met (line 652):
1. `newTotalPower >= maxVotingPowerEnforcementThreshold` 
2. `ctx.BlockHeight() > 0`

The critical flaw is that `newTotalPower` is calculated as `lastTotalPower.Add(validatorAdditionalPower)` where `lastTotalPower` comes from the previous block. This creates two distinct vulnerabilities:

**Vulnerability 1 - Pre-Threshold Accumulation:** [2](#0-1) 

Before the network reaches the enforcement threshold, the ratio check is completely bypassed. A validator can accumulate 90% or more of the network's voting power during this window. Once the threshold is crossed, only future delegations are blocked, but the validator retains their excessive power permanently.

**Vulnerability 2 - Intra-Block Bypass:** [3](#0-2) 

The `GetLastTotalPower` function retrieves the total power from the END of the previous block. Within a single block, this value remains constant for all transactions. An attacker can split a large delegation into multiple transactions within the same block, where each transaction independently calculates `newTotalPower` using the same stale `lastTotalPower` value, allowing all transactions to stay below the threshold even though their cumulative effect exceeds it. [4](#0-3) 

The `SetLastTotalPower` is only called at EndBlock, confirming that the value doesn't update during block execution.

**Exploit Scenario:**

*Scenario 1 (Pre-threshold):*
1. Network launches with total power = 100,000 (below 1M threshold)
2. Attacker delegates 900,000 power to their validator over multiple blocks
3. Each delegation calculates `newTotalPower < 1,000,000`, bypassing the check
4. Validator now has 90% of network power (far exceeding 20% limit)
5. When threshold is crossed, validator retains 90% power indefinitely

*Scenario 2 (Intra-block):*
1. Network has 999,000 total power (just below threshold)
2. Attacker creates 10 transactions in the same block, each delegating 100 power
3. All transactions see `lastTotalPower = 999,000` (from previous block)
4. Each calculates `newTotalPower = 999,100 < 1,000,000`, all pass
5. After block, actual total is 1,000,000, but validator gained power without triggering check

**Security Failure:** This breaks the consensus security invariant that no single validator should control more than 20% of voting power. With >33% power, a malicious validator can halt the chain by refusing to sign blocks. With >66% power, they can control consensus entirely.

## Impact Explanation

**Assets/Processes Affected:**
- Network consensus security and liveness guarantees
- Decentralization properties of the PoS system
- Chain finality and block production

**Severity:** 
A validator with >33% voting power can halt the blockchain by refusing to participate in consensus. A validator with >66% can completely control consensus, potentially enabling double-spending or censorship attacks. This fundamentally compromises the security model of the Proof-of-Stake blockchain.

**Significance:**
The entire security model of PoS blockchains relies on voting power being distributed among multiple validators. This vulnerability allows circumventing that fundamental assumption, making the chain vulnerable to single-entity control during the critical early growth phase or through strategic transaction timing.

## Likelihood Explanation

**Who can trigger:** Any network participant with sufficient tokens to delegate. No special privileges required.

**Conditions required:**
- For Scenario 1: Network must be below the enforcement threshold (common during network launch or growth phases)
- For Scenario 2: Ability to submit multiple transactions in the same block (standard capability)

**Frequency:** 
- Pre-threshold accumulation can occur throughout the entire period before reaching 1M power units (could be days, weeks, or months depending on network growth)
- Intra-block bypass can be attempted at any time when approaching the threshold
- Given that the existing test explicitly demonstrates this behavior with the comment "delegate more than ratio but under threshold will also succeed", this is a known and reproducible condition [5](#0-4) 

## Recommendation

**Fix 1 - Remove threshold-based enforcement:**
Always enforce the maximum voting power ratio regardless of total network power. Remove the `newTotalPower.GTE(maxVotingPowerEnforcementThreshold)` condition and enforce the ratio from genesis.

**Fix 2 - Use current block's accumulated power:**
Instead of using `lastTotalPower` from the previous block, track accumulated delegations within the current block and use the cumulative total when checking the threshold. This prevents intra-block bypass.

**Fix 3 - Retroactive enforcement:**
At EndBlock, check if any validator exceeds the max ratio. If so, force unbonding of excess delegations or prevent the validator from entering the active set until their ratio is compliant.

**Recommended implementation:**
```go
// Remove the threshold check entirely
// Always calculate and enforce the ratio
validatorNewTotalPower := validator.Tokens.Add(bondAmt).Quo(k.PowerReduction(ctx))
currentTotalPower := k.calculateCurrentBlockTotalPower(ctx) // New function to track intra-block total
newVotingPowerRatio := validatorNewTotalPower.ToDec().Quo(currentTotalPower.ToDec())
maxVotingPowerRatio := k.MaxVotingPowerRatio(ctx)
if newVotingPowerRatio.GT(maxVotingPowerRatio) && ctx.BlockHeight() > 0 {
    return sdk.ZeroDec(), types.ErrExceedMaxVotingPowerRatio
}
```

## Proof of Concept

**File:** `x/staking/keeper/delegation_test.go`

**Test Function:** `TestVotingPowerThresholdBypass` (new test to add)

**Setup:**
```go
func TestVotingPowerThresholdBypass(t *testing.T) {
    _, app, ctx := createTestInput()
    
    // Create accounts with sufficient tokens
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 2, 
        app.StakingKeeper.TokensFromConsensusPower(ctx, 10000000))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
    
    // Create two validators with minimal initial power
    amts := []sdk.Int{sdk.NewInt(1), sdk.NewInt(1)}
    var validators [2]types.Validator
    for i, amt := range amts {
        validators[i] = teststaking.NewValidator(t, valAddrs[i], PKs[i])
        validators[i], _ = validators[i].AddTokensFromDel(amt)
    }
    
    validators[0] = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validators[0], true)
    validators[1] = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validators[1], true)
    
    ctx = ctx.WithBlockHeight(1)
    _ = staking.EndBlocker(ctx, app.StakingKeeper)
```

**Trigger:**
```go
    // Demonstrate pre-threshold accumulation vulnerability
    // Total power is currently 2, far below threshold of 1,000,000
    // Max ratio is 20%, so validator should not exceed 20% of total
    
    // Delegate 900,000 power to validator 0 (will be 90% of total after)
    _, err := app.StakingKeeper.Delegate(ctx, addrDels[0], 
        app.StakingKeeper.TokensFromConsensusPower(ctx, 900000), 
        types.Unbonded, validators[0], true)
    require.Nil(t, err, "Delegation should succeed below threshold")
    
    // Delegate 100,000 to validator 1 to bring total to 1,000,002
    _, err = app.StakingKeeper.Delegate(ctx, addrDels[1], 
        app.StakingKeeper.TokensFromConsensusPower(ctx, 100000), 
        types.Unbonded, validators[1], true)
    require.Nil(t, err)
    
    _ = staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Now total power is above threshold
    totalPower := app.StakingKeeper.GetLastTotalPower(ctx)
    require.True(t, totalPower.GTE(sdk.NewInt(1000000)), 
        "Total power should be above threshold")
```

**Observation:**
```go
    // Verify validator 0 has ~90% of voting power, far exceeding 20% max
    val0 := app.StakingKeeper.Validator(ctx, valAddrs[0])
    val0Power := val0.GetConsensusPower(app.StakingKeeper.PowerReduction(ctx))
    
    ratio := sdk.NewDec(val0Power).Quo(totalPower.ToDec())
    
    // This assertion SHOULD fail but actually passes, demonstrating the vulnerability
    require.True(t, ratio.GT(sdk.NewDecWithPrec(2, 1)), // 0.2 = 20%
        "Validator 0 has %s of voting power, exceeding 20%% max - VULNERABILITY CONFIRMED", 
        ratio.String())
    
    // Attempting to delegate more to validator 0 now fails (threshold crossed)
    _, err = app.StakingKeeper.Delegate(ctx, addrDels[0], 
        app.StakingKeeper.TokensFromConsensusPower(ctx, 1), 
        types.Unbonded, validators[0], true)
    require.Equal(t, types.ErrExceedMaxVotingPowerRatio, err,
        "New delegations correctly blocked, but damage already done")
}
```

This test demonstrates that a validator can accumulate 90% voting power before the threshold is reached, and once the threshold is crossed, the excessive power is retained permanently. The test confirms the vulnerability by showing the validator holds far more than the 20% maximum ratio, violating the security invariant.

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

**File:** x/staking/keeper/keeper.go (L80-92)
```go
func (k Keeper) GetLastTotalPower(ctx sdk.Context) sdk.Int {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.LastTotalPowerKey)

	if bz == nil {
		return sdk.ZeroInt()
	}

	ip := sdk.IntProto{}
	k.cdc.MustUnmarshal(bz, &ip)

	return ip.Int
}
```

**File:** x/staking/keeper/val_state_change.go (L216-219)
```go
	// set total power on lookup index if there are any updates
	if len(updates) > 0 {
		k.SetLastTotalPower(ctx, totalPower)
	}
```

**File:** x/staking/keeper/delegation_test.go (L214-217)
```go
	// delegate more than ratio but under threshold will also succeed
	_, err = app.StakingKeeper.Delegate(ctx, addrDels[1], app.StakingKeeper.TokensFromConsensusPower(ctx, 950000), types.Unbonded, validators[0], true)
	_ = staking.EndBlocker(ctx, app.StakingKeeper)
	require.Nil(t, err)
```
