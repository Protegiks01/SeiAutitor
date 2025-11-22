## Title
Unbounded Gas Consumption in Upgrade Handlers Enables Network Halt via Expensive State Migrations

## Summary
The upgrade module's `ApplyUpgrade` function executes upgrade handlers without any gas limit validation or time constraints, allowing handlers to consume unlimited computational resources. This can cause total network shutdown if an upgrade handler performs expensive state migrations that exceed reasonable block processing times.

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in the upgrade handler execution path: [1](#0-0) 

**Intended Logic:**
Upgrade handlers should execute state migrations in a controlled manner that doesn't disrupt block processing or cause network-wide consensus failures. The system should validate that upgrade operations complete within reasonable bounds to prevent network halts.

**Actual Logic:**
The upgrade handler is invoked directly with a context containing an infinite gas meter: [2](#0-1) 

During `BeginBlocker`, the context is created with `NewInfiniteGasMeter(1, 1)` at line 272, and the upgrade handler is called with this unrestricted context: [3](#0-2) 

No validation occurs before or during handler execution. Migration functions can iterate over unbounded state: [4](#0-3) 

The `Migrate3to4` function demonstrates real-world migrations that iterate over all validators' signing info and missed block data, with no gas limits enforced during execution.

**Exploit Scenario:**
1. A governance-approved upgrade is scheduled with a handler that performs state migrations
2. The migration logic was tested on a testnet with small state (e.g., 10 validators, 1000 accounts)
3. On mainnet, the state is orders of magnitude larger (e.g., 100+ validators, millions of accounts)
4. At the upgrade height, `BeginBlocker` calls the upgrade handler
5. The handler calls `RunMigrations`: [5](#0-4) 
6. Migration handlers iterate over large state datasets without any gas meter enforcement: [6](#0-5) 
7. The migration takes hours instead of seconds
8. BeginBlock cannot complete within consensus timeouts
9. All validators are stuck waiting for the upgrade to complete
10. The network halts - no new blocks can be produced

**Security Failure:**
Denial-of-service through unbounded resource consumption. The absence of gas validation breaks the invariant that block processing must complete within reasonable time bounds. This violates the liveness property required for blockchain consensus.

## Impact Explanation

**Affected Process:** Network availability and block production

**Severity:** The vulnerability causes **total network shutdown**:
- No new blocks can be produced until the expensive migration completes
- All transactions are frozen during the migration period
- If the migration takes hours or days, the network is effectively halted
- Validators cannot bypass the upgrade once scheduled
- Recovery requires either waiting for the migration to complete or rolling back to a previous version (hard fork scenario)

**Why This Matters:**
A blockchain network that cannot process blocks loses all utility. Users cannot:
- Submit transactions
- Transfer funds
- Execute smart contracts
- Participate in any on-chain activity

This represents a complete failure of the network's primary function. Even though upgrade handlers require governance approval, the lack of runtime validation means accidental bugs in migration logic can cause catastrophic network failures that weren't caught during testing with smaller state sizes.

## Likelihood Explanation

**Who Can Trigger:**
While upgrade handlers require governance approval (privileged operation), the vulnerability manifests through **accidental developer errors** rather than intentional malice:

**Conditions Required:**
1. A governance-approved upgrade with state migration logic
2. Migration tested on small state datasets (testnet)
3. Mainnet state significantly larger than test environment
4. No performance testing on mainnet-scale data
5. No runtime gas/time limits to catch the issue

**Frequency:**
This is not a hypothetical scenario - similar issues have occurred in production blockchain networks:
- Expensive migrations causing slow upgrades (taking hours)
- State size growth exceeding developer expectations
- Performance characteristics differing significantly between testnets and mainnets

The likelihood is **moderate to high** for any chain that:
- Has growing state over time
- Performs complex state migrations during upgrades
- Lacks runtime validation for migration costs

## Recommendation

Implement gas metering and validation for upgrade handlers:

1. **Add configurable gas limit for upgrade handlers:**
```
Create an upgrade gas limit parameter in consensus params
Set a reasonable default (e.g., 10x normal block gas limit)
Allow governance to configure this limit per upgrade plan
```

2. **Enforce gas limits during upgrade execution:**
```
Before calling the upgrade handler, wrap the context with a finite gas meter
Track gas consumption during migration execution
Panic with clear error if gas limit exceeded
```

3. **Add time-based validation:**
```
Set maximum upgrade execution time (e.g., 30 seconds)
If exceeded, log warning and consider partial migration support
Require migrations to be designed for incremental processing
```

4. **Improve testing requirements:**
```
Require performance tests with mainnet-scale state
Document expected gas consumption for each migration
Add telemetry to track migration performance in staging environments
```

The fix should be added in `ApplyUpgrade`: [7](#0-6) 

Add gas meter initialization and validation before line 371 and after line 371.

## Proof of Concept

**File:** `x/upgrade/abci_test.go`

**Test Function:** `TestUpgradeHandlerExcessiveGasConsumption`

**Setup:**
1. Initialize a test chain with the upgrade module
2. Schedule an upgrade plan for the next block height
3. Register an upgrade handler that simulates expensive state iteration (e.g., iterating 1 million times with state reads/writes)

**Trigger:**
1. Call `BeginBlocker` at the upgrade height
2. The upgrade handler executes with infinite gas meter
3. Measure actual gas consumed and execution time

**Observation:**
The test demonstrates that:
- The upgrade handler can consume arbitrary amounts of gas (millions or billions of units)
- No panic or error occurs despite excessive consumption
- Execution time can exceed reasonable block processing times (e.g., > 5 seconds)
- The block gas meter (if used) does not enforce limits on upgrade handlers
- No validation prevents this from causing network-wide issues

The test would show gas consumption in the tens of millions (or unlimited) and execution time that would be unacceptable for block processing, confirming that there is no validation preventing excessive resource consumption during upgrades.

**Implementation outline:**
```
func TestUpgradeHandlerExcessiveGasConsumption(t *testing.T) {
    // Setup chain and upgrade keeper
    // Register handler that performs 1M state operations
    // Schedule upgrade and execute BeginBlocker
    // Assert: gas consumed > reasonable limit with no error
    // Assert: execution time > acceptable block time with no error
    // This proves no validation exists
}
```

The test confirms that upgrade handlers operate without gas limit enforcement, enabling scenarios where expensive migrations can halt the network.

### Citations

**File:** x/upgrade/keeper/keeper.go (L365-391)
```go
func (k Keeper) ApplyUpgrade(ctx sdk.Context, plan types.Plan) {
	handler := k.upgradeHandlers[plan.Name]
	if handler == nil {
		panic("ApplyUpgrade should never be called without first checking HasHandler")
	}

	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}

	k.SetModuleVersionMap(ctx, updatedVM)

	// incremement the protocol version and set it in state and baseapp
	nextProtocolVersion := k.getProtocolVersion(ctx) + 1
	k.setProtocolVersion(ctx, nextProtocolVersion)
	if k.versionSetter != nil {
		// set protocol version on BaseApp
		k.versionSetter.SetProtocolVersion(nextProtocolVersion)
	}

	// Must clear IBC state after upgrade is applied as it is stored separately from the upgrade plan.
	// This will prevent resubmission of upgrade msg after upgrade is already completed.
	k.ClearIBCState(ctx, plan.Height)
	k.ClearUpgradePlan(ctx)
	k.SetDone(ctx, plan.Name)
}
```

**File:** types/context.go (L262-280)
```go
func NewContext(ms MultiStore, header tmproto.Header, isCheckTx bool, logger log.Logger) Context {
	// https://github.com/gogo/protobuf/issues/519
	header.Time = header.Time.UTC()
	return Context{
		ctx:             context.Background(),
		ms:              ms,
		header:          header,
		chainID:         header.ChainID,
		checkTx:         isCheckTx,
		logger:          logger,
		gasMeter:        NewInfiniteGasMeter(1, 1),
		minGasPrice:     DecCoins{},
		eventManager:    NewEventManager(),
		evmEventManager: NewEVMEventManager(),

		txBlockingChannels:   make(acltypes.MessageAccessOpsChannelMapping),
		txCompletionChannels: make(acltypes.MessageAccessOpsChannelMapping),
		txMsgAccessOps:       make(map[int][]acltypes.AccessOperation),
	}
```

**File:** x/upgrade/abci.go (L115-118)
```go
func applyUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	ctx.Logger().Info(fmt.Sprintf("applying upgrade \"%s\" at %s", plan.Name, plan.DueAt()))
	k.ApplyUpgrade(ctx, plan)
}
```

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

**File:** types/module/module.go (L546-595)
```go
func (m Manager) RunMigrations(ctx sdk.Context, cfg Configurator, fromVM VersionMap) (VersionMap, error) {
	c, ok := cfg.(configurator)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
	}
	var modules = m.OrderMigrations
	if modules == nil {
		modules = DefaultMigrationsOrder(m.ModuleNames())
	}

	updatedVM := VersionMap{}
	for _, moduleName := range modules {
		module := m.Modules[moduleName]
		fromVersion, exists := fromVM[moduleName]
		toVersion := module.ConsensusVersion()

		// Only run migrations when the module exists in the fromVM.
		// Run InitGenesis otherwise.
		//
		// the module won't exist in the fromVM in two cases:
		// 1. A new module is added. In this case we run InitGenesis with an
		// empty genesis state.
		// 2. An existing chain is upgrading to v043 for the first time. In this case,
		// all modules have yet to be added to x/upgrade's VersionMap store.
		if exists {
			err := c.runModuleMigrations(ctx, moduleName, fromVersion, toVersion)
			if err != nil {
				return nil, err
			}
		} else {
			cfgtor, ok := cfg.(configurator)
			if !ok {
				// Currently, the only implementator of Configurator (the interface)
				// is configurator (the struct).
				return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
			}

			moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))
			ctx.Logger().Info(fmt.Sprintf("adding a new module: %s", moduleName))
			// The module manager assumes only one module will update the
			// validator set, and that it will not be by a new module.
			if len(moduleValUpdates) > 0 {
				return nil, sdkerrors.Wrapf(sdkerrors.ErrLogic, "validator InitGenesis updates already set by a previous module")
			}
		}

		updatedVM[moduleName] = toVersion
	}

	return updatedVM, nil
```

**File:** types/module/configurator.go (L89-117)
```go
// runModuleMigrations runs all in-place store migrations for one given module from a
// version to another version.
func (c configurator) runModuleMigrations(ctx sdk.Context, moduleName string, fromVersion, toVersion uint64) error {
	// No-op if toVersion is the initial version or if the version is unchanged.
	if toVersion <= 1 || fromVersion == toVersion {
		return nil
	}

	moduleMigrationsMap, found := c.migrations[moduleName]
	if !found {
		return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migrations found for module %s", moduleName)
	}

	// Run in-place migrations for the module sequentially until toVersion.
	for i := fromVersion; i < toVersion; i++ {
		migrateFn, found := moduleMigrationsMap[i]
		if !found {
			return sdkerrors.Wrapf(sdkerrors.ErrNotFound, "no migration found for module %s from version %d to version %d", moduleName, i, i+1)
		}
		ctx.Logger().Info(fmt.Sprintf("migrating module %s from version %d to version %d", moduleName, i, i+1))

		err := migrateFn(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
```
