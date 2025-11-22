## Audit Report

## Title
Array Index Out-of-Bounds Panic in Slashing Module Migration Causes Network Halt During Upgrade

## Summary
The `Migrate3to4` function in the slashing module contains an array index out-of-bounds vulnerability that can cause a panic during state migration, halting the entire network when an upgrade is executed. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** The vulnerability exists in `x/slashing/keeper/migrations.go` in the `Migrate3to4` function, specifically at lines 206-212 where missed block heights are converted to a boolean array. [2](#0-1) 

**Intended Logic:** The migration is supposed to convert legacy missed block height data into a boolean array representation for the current sliding window. It should only include heights within the window range `[startWindowHeight, ctx.BlockHeight())` by filtering out old heights. [3](#0-2) 

**Actual Logic:** The code calculates `startWindowHeight = ctx.BlockHeight() - window` and creates `newBoolArray` with length `window`. When iterating through missed heights, it skips heights less than `startWindowHeight` but does NOT validate that heights are less than `ctx.BlockHeight()`. For any height `>= ctx.BlockHeight()`, the calculated index `height - startWindowHeight >= window`, causing an out-of-bounds array access that panics. [2](#0-1) 

**Exploit Scenario:** 
1. A blockchain operates normally, accumulating missed block data for validators at various heights
2. Due to a consensus failure or deliberate rollback, the chain reverts to an earlier height
3. An upgrade is scheduled at the rolled-back height
4. When the upgrade executes in BeginBlocker, the `Migrate3to4` function runs
5. The migration encounters stored missed block heights that are greater than the current block height (from before the rollback)
6. The code attempts to access `newBoolArray[index]` where `index >= window`, causing a panic
7. The panic occurs during the upgrade's BeginBlocker execution, causing all nodes to crash when processing that block
8. The entire network halts as no node can successfully process the upgrade block

**Security Failure:** This breaks the availability and liveness properties of the blockchain. The upgrade mechanism, which runs in BeginBlocker before other module operations, panics and prevents block processing, causing a total network shutdown. [4](#0-3) 

## Impact Explanation

**Affected Components:** The entire blockchain network is affected. All validator nodes attempting to process the upgrade block will experience the same panic and halt.

**Severity of Damage:** 
- Complete network shutdown - no blocks can be processed
- All transaction finality ceases
- The chain cannot recover without manual intervention (state surgery to remove invalid missed heights or a coordinated rollback)
- Requires emergency coordination among validators to resolve
- May require a hard fork if state cannot be easily repaired

**System Significance:** This vulnerability directly undermines the blockchain's core property of continuous operation. An upgrade, which is intended to improve the system, instead becomes a kill switch that can be triggered by specific state conditions resulting from chain rollbacks or state corruption.

## Likelihood Explanation

**Who Can Trigger:** While no single malicious actor can directly trigger this (it's not an external attack vector), the vulnerability activates automatically when:
- A chain rollback occurs (from consensus failures, intentional state rollback, or replay)
- Followed by an upgrade at a height lower than previously stored missed block heights

**Conditions Required:**
- The blockchain must experience a rollback to a height lower than some stored missed block heights
- An upgrade must be scheduled and executed after the rollback
- The slashing module's consensus version must be upgrading from version 3 to 4

**Frequency:** While chain rollbacks are rare in production, they do occur during:
- Major consensus bugs requiring rollback
- Network splits requiring state reconciliation
- Testnet/devnet operations where rollbacks are more common
- State replay during node recovery

Once these conditions exist, the vulnerability triggers deterministically during the upgrade, making it 100% reproducible.

## Recommendation

Add bounds checking before array access to ensure the calculated index is within valid range:

```go
for _, height := range heights {
    if height < startWindowHeight {
        continue
    }
    // Add upper bound check
    if height >= startWindowHeight + window {
        continue  // Skip heights beyond the current window
    }
    index := height - startWindowHeight
    newBoolArray[index] = true
}
```

Alternatively, add validation at the beginning:
```go
endWindowHeight := ctx.BlockHeight()
for _, height := range heights {
    if height < startWindowHeight || height >= endWindowHeight {
        continue
    }
    index := height - startWindowHeight
    newBoolArray[index] = true
}
```

This ensures only heights within the valid window `[startWindowHeight, ctx.BlockHeight())` are processed, preventing out-of-bounds access.

## Proof of Concept

**File:** `x/slashing/keeper/migrations_test.go`

**Test Function:** Add the following test function:

```go
func TestMigrate3to4WithFutureHeights(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
	pks := simapp.CreateTestPubKeys(1)
	addr, val := valAddrs[0], pks[0]
	tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)

	params := app.SlashingKeeper.GetParams(ctx)
	params.SignedBlocksWindow = 100
	app.SlashingKeeper.SetParams(ctx, params)

	// Set context at height 9000 (simulating chain rollback scenario)
	ctx = ctx.WithBlockHeight(9000)

	amt := tstaking.CreateValidatorWithValPower(addr, val, 100, true)
	staking.EndBlocker(ctx, app.StakingKeeper)
	require.Equal(t, amt, app.StakingKeeper.Validator(ctx, addr).GetBondedTokens())

	consAddr := sdk.GetConsAddress(val)
	store := ctx.KVStore(app.SlashingKeeper.GetStoreKey())

	// Create signing info
	oldSignInfo := types.ValidatorSigningInfoLegacyMissedHeights{
		Address:             consAddr.String(),
		StartHeight:         8900,
		MissedBlocksCounter: 3,
	}
	bz := app.AppCodec().MustMarshal(&oldSignInfo)
	store.Set(types.ValidatorSigningInfoKey(consAddr), bz)

	// Create missed array with heights BEYOND current block height
	// This simulates data from before a chain rollback
	// Heights 9950, 9960, 9970 are all > ctx.BlockHeight() (9000)
	missedArray := types.ValidatorMissedBlockArrayLegacyMissedHeights{
		Address:       consAddr.String(),
		MissedHeights: []int64{9950, 9960, 9970}, // Future heights!
	}
	bz = app.AppCodec().MustMarshal(&missedArray)
	store.Set(types.ValidatorMissedBlockBitArrayKey(consAddr), bz)

	// This should panic with index out of range
	m := keeper.NewMigrator(app.SlashingKeeper)
	
	// The migration will panic when trying to access newBoolArray[index]
	// where index = 9950 - (9000 - 100) = 9950 - 8900 = 1050
	// but newBoolArray has length 100
	require.Panics(t, func() {
		_ = m.Migrate3to4(ctx)
	}, "Expected panic due to out-of-bounds array access")
}
```

**Setup:** 
- Initialize test app and blockchain context
- Set block height to 9000 (simulating rollback scenario)
- Create a validator with signing info
- Set SignedBlocksWindow parameter to 100

**Trigger:** 
- Store legacy missed block data with heights (9950, 9960, 9970) that are greater than current height 9000
- Call `Migrate3to4` migration function

**Observation:**
- The test expects a panic with `require.Panics()`
- The panic occurs when the migration calculates `index = 9950 - 8900 = 1050` and attempts to access `newBoolArray[1050]`
- The array only has length 100, so indices 0-99 are valid
- Accessing index 1050 causes a runtime panic: "index out of range [1050] with length 100"

This demonstrates that the vulnerability causes BeginBlocker to fail (panic) during an upgrade when the migration encounters future heights, which would halt the entire network.

### Citations

**File:** x/slashing/keeper/migrations.go (L147-238)
```go
// Migrate3to4 migrates from version 3 to 4.
func (m Migrator) Migrate3to4(ctx sdk.Context) error {
	ctx.Logger().Info("Migrating 3 -> 4")
	store := ctx.KVStore(m.keeper.storeKey)
	valMissedMap := make(map[string]types.ValidatorMissedBlockArray)
	ctx.Logger().Info("Migrating Signing Info")
	signInfoIter := sdk.KVStorePrefixIterator(store, types.ValidatorSigningInfoKeyPrefix)
	newSignInfoKeys := [][]byte{}
	newSignInfoVals := []types.ValidatorSigningInfo{}
	// use previous height to calculate index offset
	window := m.keeper.SignedBlocksWindow(ctx)
	index := window - 1
	// Note that we close the iterator twice. 2 iterators cannot be open at the same time due to mutex on the storage
	// This close within defer is a safety net, while the close() after iteration is to close the iterator before opening
	// a new one.
	defer signInfoIter.Close()
	for ; signInfoIter.Valid(); signInfoIter.Next() {
		ctx.Logger().Info(fmt.Sprintf("Migrating Signing Info for key: %v\n", signInfoIter.Key()))
		var oldInfo types.ValidatorSigningInfoLegacyMissedHeights
		m.keeper.cdc.MustUnmarshal(signInfoIter.Value(), &oldInfo)

		newInfo := types.ValidatorSigningInfo{
			Address:             oldInfo.Address,
			StartHeight:         oldInfo.StartHeight,
			IndexOffset:         index,
			JailedUntil:         oldInfo.JailedUntil,
			Tombstoned:          oldInfo.Tombstoned,
			MissedBlocksCounter: oldInfo.MissedBlocksCounter,
		}
		newSignInfoKeys = append(newSignInfoKeys, signInfoIter.Key())
		newSignInfoVals = append(newSignInfoVals, newInfo)
	}
	signInfoIter.Close()

	if len(newSignInfoKeys) != len(newSignInfoVals) {
		return fmt.Errorf("new sign info data length doesn't match up")
	}
	ctx.Logger().Info("Writing New Signing Info")
	for i := range newSignInfoKeys {
		bz := m.keeper.cdc.MustMarshal(&newSignInfoVals[i])
		store.Set(newSignInfoKeys[i], bz)
	}

	// need to turn this into a bool array
	ctx.Logger().Info("Migrating Missed Block Bit Array")
	startWindowHeight := ctx.BlockHeight() - window
	iter := sdk.KVStorePrefixIterator(store, types.ValidatorMissedBlockBitArrayKeyPrefix)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var missedInfo types.ValidatorMissedBlockArrayLegacyMissedHeights
		key := iter.Key()
		consAddrBytes := key[2:]

		consAddr := sdk.ConsAddress(consAddrBytes)
		ctx.Logger().Info(fmt.Sprintf("Migrating for next validator with consAddr: %s\n", consAddr.String()))

		newBoolArray := make([]bool, window)
		m.keeper.cdc.MustUnmarshal(iter.Value(), &missedInfo)
		heights := missedInfo.MissedHeights
		for _, height := range heights {
			if height < startWindowHeight {
				continue
			}
			index := height - startWindowHeight
			newBoolArray[index] = true
		}

		valMissedMap[consAddr.String()] = types.ValidatorMissedBlockArray{
			Address:      missedInfo.Address,
			MissedBlocks: m.keeper.ParseBoolArrayToBitGroups(newBoolArray),
			WindowSize:   window,
		}
	}

	ctx.Logger().Info("Writing new validator missed blocks infos")
	valKeys := []string{}
	for key := range valMissedMap {
		valKeys = append(valKeys, key)
	}
	sort.Strings(valKeys)
	for _, key := range valKeys {
		missedBlockArray := valMissedMap[key]
		consAddr, err := sdk.ConsAddressFromBech32(key)
		ctx.Logger().Info(fmt.Sprintf("Writing missed heights for validator: %s\n", consAddr.String()))
		if err != nil {
			return err
		}
		m.keeper.SetValidatorMissedBlocks(ctx, consAddr, missedBlockArray)
	}
	ctx.Logger().Info("Done migrating")
	return nil
}
```

**File:** x/upgrade/abci.go (L23-98)
```go
func BeginBlocker(k keeper.Keeper, ctx sdk.Context, _ abci.RequestBeginBlock) {
	if ctx.IsTracing() {
		return
	}
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	plan, planFound := k.GetUpgradePlan(ctx)

	if !k.DowngradeVerified() {
		k.SetDowngradeVerified(true)
		lastAppliedPlan, _ := k.GetLastCompletedUpgrade(ctx)
		// This check will make sure that we are using a valid binary.
		// It'll panic in these cases if there is no upgrade handler registered for the last applied upgrade.
		// 1. If there is no scheduled upgrade.
		// 2. If the plan is not ready.
		// 3. If the plan is ready and skip upgrade height is set for current height.
		if !planFound || !plan.ShouldExecute(ctx) || (plan.ShouldExecute(ctx) && k.IsSkipHeight(ctx.BlockHeight())) {
			if lastAppliedPlan != "" && !k.HasHandler(lastAppliedPlan) {
				panic(fmt.Sprintf("Wrong app version %d, upgrade handler is missing for %s upgrade plan", ctx.ConsensusParams().Version.AppVersion, lastAppliedPlan))
			}
		}
	}

	if !planFound {
		return
	}

	telemetry.SetGaugeWithLabels(
		[]string{"cosmos", "upgrade", "plan", "height"},
		float32(plan.Height),
		[]metrics.Label{
			{Name: "name", Value: plan.Name},
			{Name: "info", Value: plan.Info},
		},
	)

	// If the plan's block height has passed, then it must be the executed version
	// All major and minor releases are REQUIRED to execute on the scheduled block height
	if plan.ShouldExecute(ctx) {
		// If skip upgrade has been set for current height, we clear the upgrade plan
		if k.IsSkipHeight(ctx.BlockHeight()) {
			skipUpgrade(k, ctx, plan)
			return
		}
		// If we don't have an upgrade handler for this upgrade name, then we need to shutdown
		if !k.HasHandler(plan.Name) {
			panicUpgradeNeeded(k, ctx, plan)
		}
		applyUpgrade(k, ctx, plan)
		return
	}

	details, err := plan.UpgradeDetails()
	if err != nil {
		ctx.Logger().Error("failed to parse upgrade details", "err", err)
	}

	// If running a pending minor release, apply the upgrade if handler is present
	// Minor releases are allowed to run before the scheduled upgrade height, but not required to.
	if details.IsMinorRelease() {
		// if not yet present, then emit a scheduled log (every 100 blocks, to reduce logs)
		if !k.HasHandler(plan.Name) && !k.IsSkipHeight(plan.Height) {
			if ctx.BlockHeight()%100 == 0 {
				ctx.Logger().Info(BuildUpgradeScheduledMsg(plan))
			}
		}
		return
	}

	// if we have a handler for a non-minor upgrade, that means it updated too early and must stop
	if k.HasHandler(plan.Name) {
		downgradeMsg := fmt.Sprintf("BINARY UPDATED BEFORE TRIGGER! UPGRADE \"%s\" - in binary but not executed on chain", plan.Name)
		ctx.Logger().Error(downgradeMsg)
		panic(downgradeMsg)
	}
}
```
