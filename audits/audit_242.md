## Title
Chain Halt via Nil Pointer Dereference When Allocating Rewards to Removed Validators

## Summary
The `AllocateTokens` function in `x/distribution/keeper/allocation.go` fails to check if validators from `bondedVotes` still exist before allocating rewards to them. When a validator votes on a block but is then removed from state before the next block's BeginBlock (possible with very short unbonding periods), the code attempts to allocate rewards to a nil validator, causing a panic that halts the entire chain. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Module: `x/distribution/keeper`
- File: `allocation.go`
- Lines: 91-102 (bondedVotes loop), specifically line 92 (validator lookup) and line 100 (allocation call without nil check) [2](#0-1) 

**Intended Logic:**
The `AllocateTokens` function should safely distribute block rewards to all validators who participated in voting on the previous block. The function is designed to handle the edge case where the previous proposer might be unknown (lines 57-79 have a nil check), but it should similarly handle validators in the bondedVotes list who might no longer exist. [3](#0-2) 

**Actual Logic:**
The code performs a validator lookup at line 92 using `ValidatorByConsAddr`, which can return nil if the validator no longer exists in state. However, unlike the previous proposer check (line 57), there is NO nil check before calling `AllocateTokensToValidator` at line 100. When `AllocateTokensToValidator` is called with a nil validator, it immediately panics at line 113 when attempting to call `val.GetCommission()` on the nil interface. [4](#0-3) 

**Exploit Scenario:**
1. Configuration: The unbonding period is set to a very short duration (1 block or instant), which can occur in test environments or via governance proposal
2. Block X: Validator A is bonded with voting power and votes on block X
3. Block X: A transaction causes all delegations to be removed from Validator A (e.g., validator self-unbonds all stake)
4. Block X EndBlock: The validator state changes are processed:
   - `ApplyAndReturnValidatorSetUpdates` transitions Validator A from Bonded to Unbonding
   - `UnbondAllMatureValidators` immediately transitions Validator A from Unbonding to Unbonded and removes the validator from state (since unbonding period is instant/1-block and validator has zero shares) [5](#0-4) [6](#0-5) 

5. Block X+1 BeginBlock: `AllocateTokens` is called with `LastCommitInfo.GetVotes()` containing Validator A (who voted on block X)
6. The bondedVotes loop iterates and calls `ValidatorByConsAddr` for Validator A, which returns nil
7. `AllocateTokensToValidator(ctx, nil, reward)` is called
8. Panic occurs at `val.GetCommission()` attempting to dereference nil
9. **Chain halts** - no further blocks can be processed [7](#0-6) 

**Security Failure:**
This is a denial-of-service vulnerability that breaks the liveness property of the blockchain. The panic in BeginBlock prevents the chain from processing any further blocks, resulting in total network shutdown until a coordinated restart with a patched version.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability: The entire blockchain network halts and cannot confirm any new transactions
- All user funds become temporarily inaccessible (cannot move or use funds)
- All dependent applications and services stop functioning
- Block production completely stops

**Severity of Damage:**
This is a critical network shutdown. Once triggered, the chain cannot recover without intervention:
- All validator nodes will crash when attempting to process BeginBlock
- The network cannot produce or finalize any new blocks
- Requires coordinated emergency response: validators must upgrade to a patched version and restart
- Depending on network governance structure, may require an emergency hard fork or coordinated restart

**System Impact:**
This directly maps to the "High: Network not being able to confirm new transactions (total network shutdown)" impact category. The vulnerability completely breaks the chain's ability to function, affecting all network participants simultaneously.

## Likelihood Explanation

**Who can trigger it:**
- A malicious validator who intentionally unbonds all their stake immediately after voting (if they can set short unbonding period via governance)
- Accidentally triggered in test/development environments that use short unbonding periods
- Could occur through a combination of governance action (setting short unbonding period) and unfortunate timing of validator exits

**Conditions required:**
1. Unbonding period must be set to 1 block or near-instant duration (requires governance approval in production, but explicitly mentioned in the security question as the attack scenario)
2. A validator must completely unbond (lose all delegations) in the same block where they vote
3. The validator must have zero remaining delegator shares when unbonding completes

The code comment explicitly acknowledges this scenario can occur: [8](#0-7) 

The comment at line 22-26 of val_state_change.go confirms instant unbonding is used in tests and is a known edge case: [9](#0-8) 

**Frequency:**
- Low frequency in production networks with standard 3-week unbonding periods
- High frequency in test environments or if governance sets short unbonding periods
- Once triggered, requires immediate emergency response
- The vulnerability is deterministic - if conditions are met, the chain WILL halt

## Recommendation

Add a nil check in the bondedVotes loop before allocating rewards, consistent with the existing nil check for the previous proposer. When a validator in bondedVotes cannot be found, skip them and log an error rather than panicking.

**Suggested fix:**

In `x/distribution/keeper/allocation.go`, modify the bondedVotes loop to add a nil check:

```go
for _, vote := range bondedVotes {
    validator := k.stakingKeeper.ValidatorByConsAddr(ctx, vote.Validator.Address)
    
    // Add nil check here (similar to proposerValidator check at line 57)
    if validator == nil {
        logger.Error(fmt.Sprintf(
            "WARNING: Attempt to allocate rewards to unknown validator %s from bondedVotes. "+
            "This should happen only if the validator unbonded completely within a single block. "+
            "Skipping reward allocation for this validator.",
            vote.Validator.Address))
        continue
    }
    
    powerFraction := sdk.NewDec(vote.Validator.Power).QuoTruncate(sdk.NewDec(totalPreviousPower))
    reward := feeMultiplier.MulDecTruncate(powerFraction)
    
    k.AllocateTokensToValidator(ctx, validator, reward)
    remaining = remaining.Sub(reward)
}
```

This ensures the unallocated rewards remain in the `remaining` balance and eventually go to the community pool, preventing the panic while maintaining accounting consistency.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** Add `TestAllocateTokensWithRemovedValidator`

**Setup:**
1. Initialize a test application with two validators
2. Set the staking unbonding time to 1 nanosecond (instant unbonding)
3. Fund the fee collector with test fees
4. Create one validator (Validator A) with initial stake
5. Create vote info showing Validator A voted on the previous block

**Trigger:**
1. Have Validator A unbond all their delegations
2. Call `BlockValidatorUpdates` (EndBlock) which will:
   - Move Validator A to Unbonding state
   - Immediately complete unbonding (due to instant unbonding period)
   - Remove Validator A from state (if zero shares)
3. Call `AllocateTokens` (BeginBlock) with bondedVotes containing Validator A
4. Expect panic from nil pointer dereference

**Observation:**
The test will panic with a nil pointer dereference when `AllocateTokensToValidator` tries to call `val.GetCommission()` on a nil validator. The panic message will indicate dereferencing nil interface.

**Test Code Location:**
Add the following test to `x/distribution/keeper/allocation_test.go`:

```go
func TestAllocateTokensWithRemovedValidator(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Set instant unbonding period
    stakingParams := app.StakingKeeper.GetParams(ctx)
    stakingParams.UnbondingTime = time.Nanosecond
    app.StakingKeeper.SetParams(ctx, stakingParams)
    
    addrs := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(1000000))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    // Create validator with self-delegation
    tstaking.CreateValidator(valAddrs[0], valConsPk1, sdk.NewInt(100), true)
    validator := app.StakingKeeper.Validator(ctx, valAddrs[0])
    require.NotNil(t, validator)
    
    // Fund fee collector
    fees := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(100)))
    feeCollector := app.AccountKeeper.GetModuleAccount(ctx, types.FeeCollectorName)
    require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, feeCollector.GetName(), fees))
    app.AccountKeeper.SetAccount(ctx, feeCollector)
    
    // Validator votes on block
    votes := []abci.VoteInfo{{
        Validator: abci.Validator{
            Address: valConsPk1.Address(),
            Power: 100,
        },
        SignedLastBlock: true,
    }}
    
    // Unbond all delegations
    ctx = ctx.WithBlockHeight(2).WithBlockTime(time.Unix(1000, 0))
    _, err := app.StakingKeeper.Undelegate(ctx, sdk.AccAddress(valAddrs[0]), valAddrs[0], sdk.NewDec(100))
    require.NoError(t, err)
    
    // Process EndBlock - validator should be removed
    _ = staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Verify validator was removed
    _, found := app.StakingKeeper.GetValidator(ctx, valAddrs[0])
    require.False(t, found, "validator should be removed after instant unbonding")
    
    // This should panic when trying to allocate to nil validator
    require.Panics(t, func() {
        app.DistrKeeper.AllocateTokens(ctx, 100, 100, sdk.ConsAddress(valConsPk1.Address()), votes)
    }, "AllocateTokens should panic when validator in bondedVotes is nil")
}
```

This test demonstrates that when a validator is removed from state but still appears in bondedVotes, the `AllocateTokens` function panics, causing a chain halt.

### Citations

**File:** x/distribution/keeper/allocation.go (L57-79)
```go
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

**File:** x/distribution/keeper/allocation.go (L111-113)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
```

**File:** x/staking/keeper/val_state_change.go (L20-33)
```go
	// NOTE: ApplyAndReturnValidatorSetUpdates has to come before
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/distribution/abci.go (L20-31)
```go
	for _, voteInfo := range req.LastCommitInfo.GetVotes() {
		previousTotalPower += voteInfo.Validator.Power
		if voteInfo.SignedLastBlock {
			sumPreviousPrecommitPower += voteInfo.Validator.Power
		}
	}

	// TODO this is Tendermint-dependent
	// ref https://github.com/cosmos/cosmos-sdk/issues/3095
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```
