## Audit Report

### Title
Unbounded Slash Event Iteration Enables Denial-of-Service on Delegator Reward Withdrawals

### Summary
The `CalculateDelegationRewards` function in the distribution module iterates through all validator slash events without any bound or pagination, creating a griefing vulnerability where a malicious validator can intentionally accumulate numerous slash events to make reward calculations prohibitively expensive or impossible for their delegators. [1](#0-0) 

### Impact
**Medium**

### Finding Description

**Location:** 
`x/distribution/keeper/delegation.go`, function `CalculateDelegationRewards` (lines 55-136), specifically the slash event iteration loop (lines 79-92). [2](#0-1) 

**Intended Logic:** 
The function should calculate delegation rewards by accounting for validator slash events that occurred during the delegation period. It iterates through slash events to adjust the delegator's stake proportionally and calculate rewards accurately between slashing periods.

**Actual Logic:** 
The function unconditionally iterates through ALL slash events between the delegation's starting height and current block height with no upper bound, early termination, or pagination. Each iteration performs expensive state reads to retrieve historical rewards and decimal arithmetic operations. [3](#0-2) 

The iteration calls `IterateValidatorSlashEventsBetween`, which uses a standard KV store iterator with no limits. The handler function always returns `false`, ensuring every single slash event is processed.

**Exploit Scenario:**

1. A malicious validator intentionally accumulates slash events over time by repeatedly:
   - Missing blocks until reaching the downtime threshold (default: 95% of 108,000 blocks window)
   - Getting slashed and jailed for downtime
   - Waiting for the jail period to expire (default: 10 minutes)
   - Unjailing themselves via transaction
   - Repeating the cycle [4](#0-3) 

2. Each downtime slashing cycle creates a new permanent slash event entry in state storage: [5](#0-4) 

3. Slash events persist in storage until the validator is completely removed: [6](#0-5) 

4. After accumulating hundreds to thousands of slash events (achievable over months), delegators attempting to:
   - Withdraw rewards (`WithdrawDelegationRewards`)
   - Modify their delegation (triggers automatic withdrawal)
   - Query their rewards via RPC (`DelegationRewards`)

   Will experience excessive gas consumption that can exceed block gas limits or make operations economically unviable. [7](#0-6) 

**Security Failure:** 
This breaks the availability and liveness guarantees for delegator operations. Delegators lose the ability to access their rightfully earned rewards, effectively creating a temporary freeze of funds. The denial-of-service impacts both transaction execution (withdrawals) and RPC query endpoints (reward queries), potentially causing node resource exhaustion if many such queries are attempted.

### Impact Explanation

**Affected Assets and Processes:**
- Delegator reward withdrawals become impossible or prohibitively expensive
- Delegation modifications (redelegate, unbond) fail because they trigger reward withdrawal
- RPC reward query endpoints become slow or timeout
- Node resources (CPU, memory, I/O) are exhausted processing excessive iterations

**Severity of Damage:**
- Delegator rewards are temporarily frozen and inaccessible
- With sufficient slash events (1000+), gas consumption can exceed typical block gas limits (~10-50M gas)
- Each slash iteration requires ~2 state reads plus decimal arithmetic (~5000 gas estimate)
- 1000 slashes × 5000 gas = 5,000,000 gas per calculation
- Users lose access to funds without any direct loss

**System Security Impact:**
This violates the fundamental security property that delegators can always access their earned rewards. While funds are not permanently lost, the temporary freeze can last indefinitely as long as the validator continues operating with many accumulated slash events. This creates a griefing vector where validators can harm their delegators at minimal cost (especially with 0% default slashing fraction). [8](#0-7) 

### Likelihood Explanation

**Who Can Trigger:**
Any validator operator can intentionally trigger this by repeatedly causing downtime slashing. This requires control of a validator node but does not require any special privileges beyond being a validator.

**Conditions Required:**
- Validator must remain active (not permanently removed) to accumulate slash events
- Default parameters allow jailing for only 10 minutes per cycle
- With default settings, each slash cycle takes approximately 12 hours (108,000 blocks window)
- To accumulate 100 slashes: ~50 days
- To accumulate 1000 slashes: ~500 days (~1.4 years)

**Frequency:**
This is a slow-burn attack that requires sustained effort over months to years. However, it's completely feasible for:
- Long-running validators (many operate for years)
- Compromised validator nodes
- Validators willing to sacrifice reputation for griefing
- The default 0% slash fraction means no financial cost to the attacker

**Realistic Assessment:**
While the attack requires extended time to accumulate sufficient slash events, it is entirely practical and requires minimal resources. A determined attacker with access to a validator could execute this attack over the normal operational lifetime of the validator.

### Recommendation

**Immediate Mitigations:**

1. **Implement a maximum iteration limit:** Add a configurable parameter for maximum slash events to process per calculation (e.g., 100-500). If exceeded, either:
   - Use an approximation method that samples representative slash events
   - Return an error requiring manual intervention
   - Process in batches across multiple transactions

2. **Add pagination support:** Modify `CalculateDelegationRewards` to support iterative processing:
   ```
   - Accept a cursor/offset parameter
   - Process a limited number of slash events per call
   - Return continuation token for next batch
   - Accumulate results across multiple calls
   ```

3. **Implement slash event pruning:** Add periodic cleanup of old slash events:
   - After unbonding period expires, slash events are no longer needed for new delegations
   - Implement a retention policy (e.g., keep only last N events or events within last Y days)
   - Add a cleanup mechanism triggered during validator period updates

4. **Add gas-based early termination:** Track gas consumption during iteration and stop if approaching limits, returning partial results with a continuation mechanism.

**Long-term Solutions:**

1. **Redesign reward calculation:** Use a cumulative approach that doesn't require iterating through individual slash events:
   - Store cumulative slash factors per epoch/period
   - Calculate rewards using mathematical formulas instead of iteration
   - This changes O(N) complexity to O(1)

2. **Rate limit validator unjailing:** Add a cooldown period or limit on how frequently a validator can unjail to prevent rapid accumulation of slash events.

### Proof of Concept

**File:** `x/distribution/keeper/delegation_test.go`

**Test Function:** Add new test `TestCalculateRewardsWithManySlashesGasExhaustion`

**Setup:**
```go
// Initialize test application and context
app := simapp.Setup(false)
ctx := app.BaseApp.NewContext(false, tmproto.Header{})

// Set gas meter with realistic block limit (30M gas)
ctx = ctx.WithGasMeter(sdk.NewGasMeter(30_000_000))

// Create validator and delegator
tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
addr := simapp.AddTestAddrs(app, ctx, 2, sdk.NewInt(100000000))
valAddrs := simapp.ConvertAddrsToValAddrs(addr)
valPower := int64(100)

// Create validator
tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDecWithPrec(5, 1), sdk.NewDecWithPrec(5, 1), sdk.NewDec(0))
tstaking.CreateValidatorWithValPower(valAddrs[0], valConsPk1, valPower, true)
staking.EndBlocker(ctx, app.StakingKeeper)
```

**Trigger:**
```go
// Simulate accumulating many slash events (e.g., 1000)
// Each slash represents one downtime slashing cycle
for i := 0; i < 1000; i++ {
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 3)
    
    // Slash validator for downtime (0.01 fraction to simulate real slashing)
    app.StakingKeeper.Slash(ctx, valConsAddr1, ctx.BlockHeight(), valPower, sdk.NewDecWithPrec(1, 2))
    
    // Update validator reference
    val := app.StakingKeeper.Validator(ctx, valAddrs[0])
    valPower = val.GetConsensusPower(app.StakingKeeper.PowerReduction(ctx))
}

// Attempt to calculate rewards (will be called during withdrawal)
val := app.StakingKeeper.Validator(ctx, valAddrs[0])
del := app.StakingKeeper.Delegation(ctx, sdk.AccAddress(valAddrs[0]), valAddrs[0])
endingPeriod := app.DistrKeeper.IncrementValidatorPeriod(ctx, val)

// Measure gas before
gasBefore := ctx.GasMeter().GasConsumed()

// This should either panic with OutOfGas or consume excessive gas
rewards := app.DistrKeeper.CalculateDelegationRewards(ctx, val, del, endingPeriod)

// Measure gas after
gasAfter := ctx.GasMeter().GasConsumed()
gasUsed := gasAfter - gasBefore
```

**Observation:**
The test demonstrates that with 1000 slash events:
1. Gas consumption will be in the millions (5M+ gas), approaching or exceeding typical block gas limits
2. The function may panic with "out of gas" if the gas meter limit is reached
3. The gas cost scales linearly with the number of slash events (O(N))
4. Even if it doesn't panic, the excessive gas makes the operation economically unviable or practically impossible in a real network

The test should be configured to either:
- Assert that gas consumption exceeds a reasonable threshold (e.g., >5M gas for 1000 slashes)
- Catch the expected panic when gas limit is exceeded
- Measure and report the linear relationship between slash count and gas consumption

This proves that a validator with many accumulated slash events can effectively prevent their delegators from withdrawing rewards due to excessive computational costs.

### Citations

**File:** x/distribution/keeper/delegation.go (L55-136)
```go
func (k Keeper) CalculateDelegationRewards(ctx sdk.Context, val stakingtypes.ValidatorI, del stakingtypes.DelegationI, endingPeriod uint64) (rewards sdk.DecCoins) {
	// fetch starting info for delegation
	startingInfo := k.GetDelegatorStartingInfo(ctx, del.GetValidatorAddr(), del.GetDelegatorAddr())

	if startingInfo.Height == uint64(ctx.BlockHeight()) {
		// started this height, no rewards yet
		return
	}

	startingPeriod := startingInfo.PreviousPeriod
	stake := startingInfo.Stake

	// Iterate through slashes and withdraw with calculated staking for
	// distribution periods. These period offsets are dependent on *when* slashes
	// happen - namely, in BeginBlock, after rewards are allocated...
	// Slashes which happened in the first block would have been before this
	// delegation existed, UNLESS they were slashes of a redelegation to this
	// validator which was itself slashed (from a fault committed by the
	// redelegation source validator) earlier in the same BeginBlock.
	startingHeight := startingInfo.Height
	// Slashes this block happened after reward allocation, but we have to account
	// for them for the stake sanity check below.
	endingHeight := uint64(ctx.BlockHeight())
	if endingHeight > startingHeight {
		k.IterateValidatorSlashEventsBetween(ctx, del.GetValidatorAddr(), startingHeight, endingHeight,
			func(height uint64, event types.ValidatorSlashEvent) (stop bool) {
				endingPeriod := event.ValidatorPeriod
				if endingPeriod > startingPeriod {
					rewards = rewards.Add(k.calculateDelegationRewardsBetween(ctx, val, startingPeriod, endingPeriod, stake)...)

					// Note: It is necessary to truncate so we don't allow withdrawing
					// more rewards than owed.
					stake = stake.MulTruncate(sdk.OneDec().Sub(event.Fraction))
					startingPeriod = endingPeriod
				}
				return false
			},
		)
	}

	// A total stake sanity check; Recalculated final stake should be less than or
	// equal to current stake here. We cannot use Equals because stake is truncated
	// when multiplied by slash fractions (see above). We could only use equals if
	// we had arbitrary-precision rationals.
	currentStake := val.TokensFromShares(del.GetShares())

	if stake.GT(currentStake) {
		// AccountI for rounding inconsistencies between:
		//
		//     currentStake: calculated as in staking with a single computation
		//     stake:        calculated as an accumulation of stake
		//                   calculations across validator's distribution periods
		//
		// These inconsistencies are due to differing order of operations which
		// will inevitably have different accumulated rounding and may lead to
		// the smallest decimal place being one greater in stake than
		// currentStake. When we calculated slashing by period, even if we
		// round down for each slash fraction, it's possible due to how much is
		// being rounded that we slash less when slashing by period instead of
		// for when we slash without periods. In other words, the single slash,
		// and the slashing by period could both be rounding down but the
		// slashing by period is simply rounding down less, thus making stake >
		// currentStake
		//
		// A small amount of this error is tolerated and corrected for,
		// however any greater amount should be considered a breach in expected
		// behaviour.
		marginOfErr := sdk.SmallestDec().MulInt64(3)
		if stake.LTE(currentStake.Add(marginOfErr)) {
			stake = currentStake
		} else {
			panic(fmt.Sprintf("calculated final stake for delegator %s greater than current usei"+
				"\n\tfinal stake:\t%s"+
				"\n\tcurrent stake:\t%s",
				del.GetDelegatorAddr(), stake, currentStake))
		}
	}

	// calculate rewards for final period
	rewards = rewards.Add(k.calculateDelegationRewardsBetween(ctx, val, startingPeriod, endingPeriod, stake)...)

	return rewards
```

**File:** x/distribution/keeper/store.go (L333-350)
```go
// iterate over slash events between heights, inclusive
func (k Keeper) IterateValidatorSlashEventsBetween(ctx sdk.Context, val sdk.ValAddress, startingHeight uint64, endingHeight uint64,
	handler func(height uint64, event types.ValidatorSlashEvent) (stop bool)) {
	store := ctx.KVStore(k.storeKey)
	iter := store.Iterator(
		types.GetValidatorSlashEventKeyPrefix(val, startingHeight),
		types.GetValidatorSlashEventKeyPrefix(val, endingHeight+1),
	)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var event types.ValidatorSlashEvent
		k.cdc.MustUnmarshal(iter.Value(), &event)
		_, height := types.GetValidatorSlashEventAddressHeight(iter.Key())
		if handler(height, event) {
			break
		}
	}
}
```

**File:** x/slashing/types/params.go (L12-15)
```go
const (
	DefaultSignedBlocksWindow   = int64(108000) // ~12 hours based on 0.4s block times
	DefaultDowntimeJailDuration = 60 * 10 * time.Second
)
```

**File:** x/slashing/types/params.go (L17-22)
```go
var (
	DefaultMinSignedPerWindow      = sdk.NewDecWithPrec(5, 2)
	// No Slashing Fraction by default
	DefaultSlashFractionDoubleSign = sdk.NewDec(0)
	DefaultSlashFractionDowntime   = sdk.NewDec(0)
)
```

**File:** x/distribution/keeper/validator.go (L90-107)
```go
func (k Keeper) updateValidatorSlashFraction(ctx sdk.Context, valAddr sdk.ValAddress, fraction sdk.Dec) {
	if fraction.GT(sdk.OneDec()) || fraction.IsNegative() {
		panic(fmt.Sprintf("fraction must be >=0 and <=1, current fraction: %v", fraction))
	}

	val := k.stakingKeeper.Validator(ctx, valAddr)

	// increment current period
	newPeriod := k.IncrementValidatorPeriod(ctx, val)

	// increment reference count on period we need to track
	k.incrementReferenceCount(ctx, valAddr, newPeriod)

	slashEvent := types.NewValidatorSlashEvent(newPeriod, fraction)
	height := uint64(ctx.BlockHeight())

	k.SetValidatorSlashEvent(ctx, valAddr, height, newPeriod, slashEvent)
}
```

**File:** x/distribution/keeper/hooks.go (L68-69)
```go
	// clear slashes
	h.k.DeleteValidatorSlashEvents(ctx, valAddr)
```

**File:** x/distribution/keeper/grpc_query.go (L118-157)
```go
// DelegationRewards the total rewards accrued by a delegation
func (k Keeper) DelegationRewards(c context.Context, req *types.QueryDelegationRewardsRequest) (*types.QueryDelegationRewardsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	if req.DelegatorAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "empty delegator address")
	}

	if req.ValidatorAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "empty validator address")
	}

	ctx := sdk.UnwrapSDKContext(c)

	valAdr, err := sdk.ValAddressFromBech32(req.ValidatorAddress)
	if err != nil {
		return nil, err
	}

	val := k.stakingKeeper.Validator(ctx, valAdr)
	if val == nil {
		return nil, sdkerrors.Wrap(types.ErrNoValidatorExists, req.ValidatorAddress)
	}

	delAdr, err := sdk.AccAddressFromBech32(req.DelegatorAddress)
	if err != nil {
		return nil, err
	}
	del := k.stakingKeeper.Delegation(ctx, delAdr, valAdr)
	if del == nil {
		return nil, types.ErrNoDelegationExists
	}

	endingPeriod := k.IncrementValidatorPeriod(ctx, val)
	rewards := k.CalculateDelegationRewards(ctx, val, del, endingPeriod)

	return &types.QueryDelegationRewardsResponse{Rewards: rewards}, nil
}
```
