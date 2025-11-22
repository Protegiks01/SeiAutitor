## Audit Report

## Title
Chain Halt Due to Missing Nil Check When Allocating Rewards to Removed Validators

## Summary
The distribution module's `AllocateTokens` function fails to check if a validator exists before allocating rewards, causing a panic and chain halt when a validator that participated in consensus is completely removed from state before rewards are distributed.

## Impact
High - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `AllocateTokens` function should distribute block rewards to all validators that participated in creating the previous block. When a validator is looked up by consensus address, the function should handle cases where the validator may have been removed from state.

**Actual Logic:** 
The function calls `ValidatorByConsAddr` at line 92 to look up each validator in the `bondedVotes` list, but does not check if the returned validator is nil before passing it to `AllocateTokensToValidator` at line 100. When `AllocateTokensToValidator` is called with a nil validator, it immediately panics at line 113 when attempting to call `val.GetCommission()` on the nil interface. [2](#0-1) 

The code does handle this case for the proposer validator (lines 55-79), gracefully logging an error when the proposer is not found, but fails to apply the same nil check for regular voters. [3](#0-2) 

**Exploit Scenario:**
1. Configure the chain with a short unbonding period (e.g., 1-2 blocks) or wait for a validator to complete unbonding
2. A validator V is in the active bonded set at block N and participates in consensus
3. At block N EndBlock, validator V is kicked out of the active set and transitions to Unbonding state [4](#0-3) 
4. At block N+1 EndBlock, V completes unbonding with zero delegations and is removed via `RemoveValidator` [5](#0-4) 
5. At block N+2 BeginBlock, `AllocateTokens` is called with `bondedVotes` from block N+1 (which includes validator V)
6. The code calls `ValidatorByConsAddr` for V, which returns nil since V was removed [6](#0-5) 
7. `AllocateTokensToValidator(ctx, nil, reward)` is called
8. The function panics at `val.GetCommission()` causing all nodes to crash

**Security Failure:** 
This is a denial-of-service vulnerability. The validator set update (removing a validator from state) does not properly synchronize with the distribution module, which still attempts to allocate rewards to the removed validator. The panic propagates to all nodes processing BeginBlock, causing a complete network halt.

## Impact Explanation

**Assets Affected:** Network availability - all nodes halt and cannot produce blocks

**Severity:** The entire blockchain network becomes unable to confirm new transactions. All validator nodes panic during BeginBlock execution and cannot advance to the next block. This requires either:
- A coordinated hard fork to skip the problematic block, or  
- Manual intervention to modify the unbonding parameters and restart from a previous state

**Why This Matters:** This vulnerability can be triggered naturally during normal chain operation when validators unbond with short unbonding periods. The comment in the code itself acknowledges this scenario can occur ("if the unbonding period is 1 block"). A malicious actor could also deliberately trigger this by creating a validator, bonding it, then immediately unbonding all delegations to cause removal within the critical time window.

## Likelihood Explanation

**Who Can Trigger:** Any participant who can create and operate a validator, or any existing validator that unbonds when the unbonding period is configured to be very short (1-2 blocks).

**Conditions Required:** 
- The chain must have a short unbonding period (naturally set in some test environments, or if chain governance reduces the parameter)
- A validator must be removed from state (reaches Unbonded status with zero delegations) between participating in block N and the allocation of rewards for block N in block N+2 BeginBlock

**Frequency:** While requiring specific timing, this can occur during normal operation when:
- Test networks or development chains use short unbonding periods
- Validators quickly unbond all delegations
- The chain experiences the documented edge case mentioned in the code comments

## Recommendation

Add a nil check for validators in the `bondedVotes` loop, similar to the existing check for the proposer validator. If a validator is not found, log a warning and skip reward allocation for that validator, allowing the community pool to retain those rewards:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    // Skip reward allocation if validator was removed (similar to proposer handling)
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s. "+
            "This can happen if the validator unbonded completely within a short period.",
            vote.Validator.Address))
        continue
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)
    
    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensToRemovedValidator`

**Setup:**
1. Create a test application with a very short unbonding time (1 second)
2. Create a validator with a self-delegation
3. Fund the fee collector with tokens for distribution

**Trigger:**
1. Undelegate all tokens from the validator
2. Apply validator set updates (EndBlock) to remove the validator from active set
3. Advance time past the unbonding period
4. Call `UnbondAllMatureValidators` to complete unbonding and remove the validator
5. Create a VoteInfo list that includes the now-removed validator
6. Call `AllocateTokens` with these votes

**Observation:**
The test will panic at line 113 of `allocation.go` with a nil pointer dereference when calling `val.GetCommission()`, demonstrating the vulnerability.

```go
func TestAllocateTokensToRemovedValidator(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Set very short unbonding time
    params := app.StakingKeeper.GetParams(ctx)
    params.UnbondingTime = time.Second * 1
    app.StakingKeeper.SetParams(ctx, params)
    
    addrs := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1234))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    // Create validator
    tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDec(0), sdk.NewDec(0), sdk.NewDec(0))
    tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
    val := app.StakingKeeper.Validator(ctx, valAddrs[0])
    require.NotNil(t, val)
    
    // Undelegate all tokens
    delAddr := sdk.AccAddress(valAddrs[0])
    _, err := app.StakingKeeper.Undelegate(ctx, delAddr, valAddrs[0], sdk.NewDec(100))
    require.NoError(t, err)
    
    // Apply validator set updates (simulates EndBlock)
    app.StakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
    
    // Advance time past unbonding period
    ctx = ctx.WithBlockTime(ctx.BlockTime().Add(time.Second * 2))
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    
    // Complete unbonding - this removes the validator
    app.StakingKeeper.UnbondAllMatureValidators(ctx)
    
    // Verify validator is removed
    val, found := app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    require.False(t, found)
    
    // Fund fee collector
    fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100)))
    feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
    require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
    app.AccountKeeper.SetAccount(ctx, feeCollector)
    
    // Create vote info with the removed validator
    votes := []abci.VoteInfo{
        {
            Validator: abci.Validator{
                Address: valConsPk1.Address(),
                Power:   100,
            },
            SignedLastBlock: true,
        },
    }
    
    // This should panic when trying to allocate to removed validator
    require.Panics(t, func() {
        app.DistrKeeper.AllocateTokens(ctx, 100, 100, sdk.ConsAddress(valConsPk1.Address()), votes)
    })
}
```

The test demonstrates that calling `AllocateTokens` with a vote from a removed validator causes a panic, confirming the vulnerability.

### Citations

**File:** x/distribution/keeper/allocation.go (L55-79)
```go
	proposerValidator := k.stakingKeeper.ValidatorByConsAddr(ctx, previousProposer)

	if proposerValidator != nil {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeProposerReward,
				sdk.NewAttribute(sdk.AttributeKeyAmount, proposerReward.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, proposerValidator.GetOperator().String()),
			),
		)

		k.AllocateTokensToValidator(ctx, proposerValidator, proposerReward)
		remaining = remaining.Sub(proposerReward)
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

**File:** x/distribution/keeper/allocation.go (L109-114)
```go
// AllocateTokensToValidator allocate tokens to a particular validator,
// splitting according to commission.
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** x/staking/keeper/val_state_change.go (L190-199)
```go
	for _, valAddrBytes := range noLongerBonded {
		validator := k.mustGetValidator(ctx, sdk.ValAddress(valAddrBytes))
		validator, err = k.bondedToUnbonding(ctx, validator)
		if err != nil {
			return
		}
		amtFromBondedToNotBonded = amtFromBondedToNotBonded.Add(validator.GetTokens())
		k.DeleteLastValidatorPower(ctx, validator.GetOperator())
		updates = append(updates, validator.ABCIValidatorUpdateZero())
	}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
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
