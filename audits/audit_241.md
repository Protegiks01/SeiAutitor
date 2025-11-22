## Title
Chain Halt Due to Missing Nil Check for Unbonded Validators in Distribution BeginBlocker

## Summary
The `AllocateTokens` function in the distribution module's BeginBlocker lacks a nil check for validators in the voting loop, causing a panic and complete chain halt when any validator has unbonded between blocks. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** `x/distribution/keeper/allocation.go`, lines 91-102, specifically line 100 where `AllocateTokensToValidator` is called without a nil check.

**Intended Logic:** The code should safely distribute rewards to all validators who voted in the previous block, handling cases where validators may have been removed from the validator set.

**Actual Logic:** The code performs a validator lookup by consensus address but does NOT check if the returned validator is nil before passing it to `AllocateTokensToValidator`. When `AllocateTokensToValidator` receives a nil validator, it immediately panics when attempting to call `val.GetCommission()` on line 113. [2](#0-1) 

**Exploit Scenario:** 
1. A validator unbonds all their tokens completely within a very short unbonding period (e.g., 1 block)
2. The validator is removed from the validator set during EndBlock processing
3. In the next block's BeginBlock, the distribution module's `AllocateTokens` is called with vote information that still includes the now-deleted validator's consensus address
4. `ValidatorByConsAddr` returns nil for the deleted validator
5. `AllocateTokensToValidator` is called with the nil validator
6. A nil pointer dereference panic occurs at line 113
7. The BeginBlocker panics, halting the entire chain [3](#0-2) 

**Security Failure:** This breaks the liveness property of the blockchain. A panic in BeginBlocker causes all nodes to crash when processing the block, preventing consensus from progressing. The chain cannot produce new blocks until the code is patched and nodes are restarted with the fix.

Notably, the code DOES include protection for this exact scenario for the proposer validator (lines 57-79), with an explicit comment explaining that validators can be removed if the unbonding period is very short: [4](#0-3) 

However, this same protection is missing for validators in the voting loop.

## Impact Explanation

**Affected:** All network participants, as the entire blockchain halts.

**Severity:** When this vulnerability is triggered:
- All nodes panic and stop processing blocks
- No new transactions can be confirmed
- The network is completely unavailable until emergency patching
- Requires coordinated network upgrade to resume operations

This is a critical availability failure that renders the entire blockchain inoperable. Unlike other bugs that may affect individual transactions or accounts, this halts the entire network consensus mechanism, preventing any blockchain activity whatsoever.

## Likelihood Explanation

**Trigger:** This can be triggered by normal validator operations under specific timing conditions.

**Conditions Required:**
1. Unbonding period must be very short (e.g., 1 block) OR a validator must completely unbond all delegations rapidly
2. Validator must be removed from the validator set between blocks
3. The removed validator's consensus address must still appear in the vote information for the next block

**Likelihood:** While the comment in the code suggests this "generally should not happen except in exceptional circumstances (or fuzz testing)", the fact that explicit protection was added for the proposer case indicates this scenario is considered realistic enough to handle. The vulnerability exists any time a validator can be removed faster than the vote information is updated.

In testnets with short unbonding periods or during network stress, this could occur with moderate frequency. In production networks with standard unbonding periods (21 days), this is less likely but still possible during coordinated validator exits or emergency situations.

## Recommendation

Add a nil check for the validator in the voting loop, mirroring the protection already in place for the proposer validator:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    // Add nil check here
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s. "+
            "This validator may have unbonded completely within a single block.",
            vote.Validator.Address.String()))
        continue
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)
    
    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

This matches the defensive pattern already established for the proposer case and prevents the chain halt while gracefully handling the edge case.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensWithRemovedValidator` (new test to be added)

**Setup:**
1. Initialize a test chain with two validators using the standard test setup
2. Fund the fee collector with tokens for distribution
3. Create vote information including both validators
4. Manually remove one validator from the staking keeper's validator set to simulate rapid unbonding

**Trigger:**
1. Call `AllocateTokens` with the vote information that includes the now-deleted validator
2. The function will lookup the validator by consensus address, receive nil
3. Pass the nil validator to `AllocateTokensToValidator`

**Observation:**
The test will panic with a nil pointer dereference when `AllocateTokensToValidator` attempts to call `val.GetCommission()` on the nil validator. This demonstrates that the vulnerability causes a chain-halting panic.

```go
func TestAllocateTokensWithRemovedValidator(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    addrs := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1234))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    // Create two validators
    tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDec(0), sdk.NewDec(0), sdk.NewDec(0))
    tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
    tstaking.CreateValidator(valAddrs[1], valConsPk2, sdk.NewInt(100), true)
    
    // Fund fee collector
    fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100)))
    feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
    require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
    
    // Simulate validator 1 being removed (unbonded completely)
    val1, _ := app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    app.StakingKeeper.RemoveValidator(ctx, valAddrs[0])
    
    // Prepare votes including the now-deleted validator
    abciValA := abci.Validator{
        Address: valConsPk1.Address(), // This validator was just removed
        Power:   100,
    }
    abciValB := abci.Validator{
        Address: valConsPk2.Address(),
        Power:   100,
    }
    
    votes := []abci.VoteInfo{
        {Validator: abciValA, SignedLastBlock: true},
        {Validator: abciValB, SignedLastBlock: true},
    }
    
    // This should panic with nil pointer dereference
    // In production, this panics BeginBlocker and halts the chain
    require.Panics(t, func() {
        app.DistrKeeper.AllocateTokens(ctx, 200, 200, sdk.ConsAddress(valConsPk2.Address()), votes)
    }, "Expected panic due to nil validator")
}
```

The test demonstrates that when a validator is removed but still appears in the vote list, `AllocateTokens` panics, which in a live network would halt the entire chain.

### Citations

**File:** x/distribution/keeper/allocation.go (L68-79)
```go
	} else {
		// previous proposer can be unknown if say, the unbonding period is 1 block, so
		// e.g. a validator undelegates at block X, it's removed entirely by
		// block X+1's endblock, then X+2 we need to refer to the previous
		// proposer for X+1, but we've forgotten about them.
		logger.Error(fmt.Sprintf(
			"WARNING: Attempt to allocate proposer rewards to unknown proposer %s. "+
				"This should happen only if the proposer unbonded completely within a single block, "+
				"which generally should not happen except in exceptional circumstances (or fuzz testing). "+
				"We recommend you investigate immediately.",
			previousProposer.String()))
	}
```

**File:** x/distribution/keeper/allocation.go (L91-102)
```go
	for _, vote := range bondedVotes {
		validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)

		// TODO: Consider micro-slashing for missing votes.
		//
		// Ref: https://github.com/cosmos/cosmos-sdk/issues/2525#issuecomment-430838701
		powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
		reward := feeMultiplier.MulDecTruncate(powerFraction)

		k.AllocateTokensToValidator(ctx, validator, reward)
		remaining = remaining.Sub(reward)
	}
```

**File:** x/distribution/keeper/allocation.go (L111-114)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** x/staking/keeper/alias_functions.go (L88-96)
```go
// ValidatorByConsAddr gets the validator interface for a particular pubkey
func (k Keeper) ValidatorByConsAddr(ctx sdk.Context, addr sdk.ConsAddress) types.ValidatorI {
	val, found := k.GetValidatorByConsAddr(ctx, addr)
	if !found {
		return nil
	}

	return val
}
```
