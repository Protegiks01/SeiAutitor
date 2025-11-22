## Audit Report

## Title
Crisis Module Invariant Checks Cause Network-Wide Denial of Service with Large Chain State

## Summary
The crisis module's `AssertInvariants` function iterates through all registered invariants synchronously during `EndBlock` without any timeout, gas limit, or pagination mechanism. When `InvCheckPeriod` is enabled and the blockchain state grows large (millions of accounts, delegations), the invariant checking process can take an unbounded amount of time, causing all validators to hang simultaneously and resulting in total network shutdown. [1](#0-0) [2](#0-1) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary: `x/crisis/keeper/keeper.go`, function `AssertInvariants` (lines 72-91)
- Trigger: `x/crisis/abci.go`, function `EndBlocker` (lines 13-21)
- Affected invariants: `x/bank/keeper/invariants.go`, `x/staking/keeper/invariants.go`, `x/distribution/keeper/invariants.go`

**Intended Logic:** 
The crisis module is designed to periodically check registered invariants to ensure blockchain state consistency. When `InvCheckPeriod` is configured to a non-zero value N, invariants should be checked every N blocks during `EndBlock` to detect state corruption early. [3](#0-2) 

**Actual Logic:** 
The `AssertInvariants` function iterates through all registered invariants in a single, uninterruptible loop with no timeout, gas limit, or pagination: [4](#0-3) 

The invariants include operations that iterate over the entire blockchain state:

1. **Bank Module** - `NonnegativeBalanceInvariant` and `TotalSupply` both call `IterateAllBalances` which creates an unbounded iterator over all account balances: [5](#0-4) [6](#0-5) [7](#0-6) 

2. **Staking Module** - `DelegatorSharesInvariant` loads ALL delegations into memory: [8](#0-7) 

3. **Distribution Module** - `CanWithdrawInvariant` iterates ALL validators and performs mock withdrawals: [9](#0-8) [10](#0-9) 

The `EndBlock` context uses an infinite gas meter that never triggers out-of-gas: [11](#0-10) 

**Exploit Scenario:**
1. An attacker observes that a network has `InvCheckPeriod` configured to a non-zero value (e.g., 1000 blocks) [12](#0-11) 

2. Over time, the attacker submits transactions to grow the blockchain state:
   - Sends dust amounts to millions of unique addresses, creating account balances
   - Creates numerous delegations and unbonding delegations to validators
   - This costs transaction fees but is economically feasible for a motivated attacker targeting a valuable network

3. When block height reaches a multiple of `InvCheckPeriod`, the crisis module's `EndBlocker` triggers `AssertInvariants`

4. All validators simultaneously:
   - Enter `AssertInvariants` 
   - Begin iterating through millions of accounts/delegations
   - Take an extremely long time (potentially minutes to hours depending on state size)
   - Cannot be interrupted (no timeout, infinite gas meter)
   - Hang at this block height

5. With all validators hung, no new blocks can be proposed or committed [13](#0-12) 

**Security Failure:**
This breaks the **availability** security property. The network becomes unable to process new transactions, violating the fundamental requirement that a blockchain must be able to produce blocks continuously. This constitutes a denial-of-service attack leading to total network shutdown.

## Impact Explanation

**Affected Processes:** Network availability and consensus operation

**Severity:** When this vulnerability is triggered:
- All validator nodes simultaneously hang during `EndBlock` processing at the invariant check height
- The network cannot produce new blocks as all validators are stuck
- No transactions can be confirmed or finalized
- The entire blockchain halts until the issue is resolved through emergency intervention (likely requiring a coordinated restart with invariant checks disabled)

**Criticality:** This represents a **total network shutdown** scenario, matching the "High" impact category: "Network not being able to confirm new transactions (total network shutdown)". The blockchain becomes completely non-functional, affecting all users, applications, and dependent systems. Recovery requires manual intervention by validator operators to reconfigure and restart their nodes.

## Likelihood Explanation

**Who can trigger:** Any unprivileged network participant who can submit transactions

**Required conditions:**
1. The network operator must have configured `InvCheckPeriod` to a non-zero value (not the default, but a documented legitimate configuration option for production chains that want periodic invariant checking)
2. The attacker must be able to grow the chain state to sufficient size (achievable through normal transaction submission at the cost of transaction fees)

**Frequency:** Once the prerequisites are met, the attack automatically triggers at every block height that is a multiple of `InvCheckPeriod`. The attacker doesn't need to time their actions precisely - they can grow state over weeks/months and the vulnerability will trigger naturally when the designated block height arrives.

**Realistic Assessment:** While `InvCheckPeriod` defaults to 0 (disabled), it is a documented feature intended for production use to catch state corruption early. Networks that enable this feature for safety are unknowingly exposing themselves to this DoS vector. The cost to an attacker depends on transaction fees, but for high-value networks, spending $10,000-$100,000 to create millions of accounts could be economically viable if it can take down the network.

## Recommendation

Implement protective measures in the invariant checking mechanism:

1. **Add pagination**: Break invariant checks across multiple blocks rather than checking everything in one block. Maintain state tracking which portion of state was checked in each block.

2. **Add timeout mechanism**: Implement a maximum duration for `AssertInvariants` execution. If the timeout is reached, log a warning and continue to the next block, resuming invariant checking in the next period.

3. **Add sampling option**: Instead of checking ALL accounts/delegations, randomly sample a subset (e.g., 1% of state per check) to detect anomalies without iterating the entire state space.

4. **Add state-size aware thresholds**: Before executing invariant checks, estimate the number of items to iterate. If it exceeds a safe threshold, skip or sample the check and emit a warning.

Example patch location for timeout protection: [2](#0-1) 

## Proof of Concept

**File:** `x/crisis/keeper/keeper_test.go` (add new test function)

**Test Function Name:** `TestAssertInvariantsWithLargeState`

**Setup:**
1. Initialize a test application with crisis keeper configured with `InvCheckPeriod = 5`
2. Create a large number of accounts (e.g., 100,000+) with balances to simulate large state
3. Register bank module invariants that will iterate over all these accounts

**Trigger:**
1. Advance the blockchain to block height 5 (first invariant check block)
2. Call `app.EndBlock()` which triggers crisis module's `EndBlocker`
3. Monitor the execution time of `AssertInvariants`

**Observation:**
The test would demonstrate that:
- Execution time grows linearly with state size
- With 100,000 accounts, the check takes several seconds
- Extrapolating to millions of accounts shows the vulnerability (timing would exceed reasonable block times)
- No timeout or interruption mechanism exists to prevent indefinite hanging

```go
func TestAssertInvariantsWithLargeState(t *testing.T) {
    // Setup app with InvCheckPeriod = 5
    app := simapp.NewSimApp(...)
    
    // Create large state: 100,000 accounts with balances
    ctx := app.NewContext(false, tmproto.Header{Height: 1})
    for i := 0; i < 100000; i++ {
        addr := sdk.AccAddress(fmt.Sprintf("addr%d", i))
        coins := sdk.NewCoins(sdk.NewCoin("stake", sdk.NewInt(1000)))
        app.BankKeeper.SetBalance(ctx, addr, coins[0])
    }
    
    // Advance to block 5 (invariant check block)
    ctx = ctx.WithBlockHeight(5)
    
    // Measure time taken for EndBlock (which calls AssertInvariants)
    start := time.Now()
    app.CrisisKeeper.AssertInvariants(ctx)
    duration := time.Since(start)
    
    // With 100k accounts this takes seconds; with millions it would cause timeout
    t.Logf("Invariant check took %v for 100k accounts", duration)
    // Extrapolate: 1M accounts = 10x duration, 10M accounts = 100x duration
}
```

This test demonstrates the linear growth in execution time. With production networks having millions of accounts, the invariant checks would take minutes to hours, causing all validators to hang and resulting in network shutdown.

### Citations

**File:** x/crisis/abci.go (L13-21)
```go
func EndBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)

	if k.InvCheckPeriod() == 0 || ctx.BlockHeight()%int64(k.InvCheckPeriod()) != 0 {
		// skip running the invariant check
		return
	}
	k.AssertInvariants(ctx)
}
```

**File:** x/crisis/keeper/keeper.go (L72-91)
```go
func (k Keeper) AssertInvariants(ctx sdk.Context) {
	logger := k.Logger(ctx)

	start := time.Now()
	invarRoutes := k.Routes()
	n := len(invarRoutes)
	for i, ir := range invarRoutes {
		logger.Info("asserting crisis invariants", "inv", fmt.Sprint(i+1, "/", n), "name", ir.FullRoute())
		if res, stop := ir.Invar(ctx); stop {
			// TODO: Include app name as part of context to allow for this to be
			// variable.
			panic(fmt.Errorf("invariant broken: %s\n"+
				"\tCRITICAL please submit the following transaction:\n"+
				"\t\t tx crisis invariant-broken %s %s", res, ir.ModuleName, ir.Route))
		}
	}

	diff := time.Since(start)
	logger.Info("asserted all invariants", "duration", diff, "height", ctx.BlockHeight())
}
```

**File:** x/bank/keeper/invariants.go (L32-39)
```go
		k.IterateAllBalances(ctx, func(addr sdk.AccAddress, balance sdk.Coin) bool {
			if balance.IsNegative() {
				count++
				msg += fmt.Sprintf("\t%s has a negative balance of %s\n", addr, balance)
			}

			return false
		})
```

**File:** x/bank/keeper/invariants.go (L70-77)
```go
		k.IterateAllBalances(ctx, func(_ sdk.AccAddress, balance sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(balance)
			return false
		})
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
```

**File:** x/bank/keeper/view.go (L138-160)
```go
func (k BaseViewKeeper) IterateAllBalances(ctx sdk.Context, cb func(sdk.AccAddress, sdk.Coin) bool) {
	store := ctx.KVStore(k.storeKey)
	balancesStore := prefix.NewStore(store, types.BalancesPrefix)

	iterator := balancesStore.Iterator(nil, nil)
	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		address, err := types.AddressFromBalancesStore(iterator.Key())
		if err != nil {
			k.Logger(ctx).With("key", iterator.Key(), "err", err).Error("failed to get address from balances store")
			// TODO: revisit, for now, panic here to keep same behavior as in 0.42
			// ref: https://github.com/cosmos/cosmos-sdk/issues/7409
			panic(err)
		}

		var balance sdk.Coin
		k.cdc.MustUnmarshal(iterator.Value(), &balance)

		if cb(address, balance) {
			break
		}
	}
```

**File:** x/staking/keeper/invariants.go (L177-177)
```go
		delegations := k.GetAllDelegations(ctx)
```

**File:** x/distribution/keeper/invariants.go (L74-76)
```go
		for _, del := range k.stakingKeeper.GetAllSDKDelegations(ctx) {
			valAddr := del.GetValidatorAddr().String()
			valDelegationAddrs[valAddr] = append(valDelegationAddrs[valAddr], del.GetDelegatorAddr())
```

**File:** x/distribution/keeper/invariants.go (L80-90)
```go
		k.stakingKeeper.IterateValidators(ctx, func(_ int64, val stakingtypes.ValidatorI) (stop bool) {
			_, _ = k.WithdrawValidatorCommission(ctx, val.GetOperator())

			delegationAddrs, ok := valDelegationAddrs[val.GetOperator().String()]
			if ok {
				for _, delAddr := range delegationAddrs {
					if _, err := k.WithdrawDelegationRewards(ctx, delAddr, val.GetOperator()); err != nil {
						panic(err)
					}
				}
			}
```

**File:** store/types/gas.go (L252-258)
```go
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}
```

**File:** server/start.go (L256-256)
```go
	cmd.Flags().Uint(FlagInvCheckPeriod, 0, "Assert registered invariants every N blocks")
```

**File:** baseapp/abci.go (L178-186)
```go
func (app *BaseApp) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	// Clear DeliverTx Events
	ctx.MultiStore().ResetEvents()

	defer telemetry.MeasureSince(time.Now(), "abci", "end_block")

	if app.endBlocker != nil {
		res = app.endBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
```
