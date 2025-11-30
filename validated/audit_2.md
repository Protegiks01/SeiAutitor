# Audit Report

## Title
Bank Module Missing EndBlock Causes Permanent Loss of All Transaction Fees

## Summary
The bank module lacks an EndBlock implementation, preventing the required `WriteDeferredBalances` call that flushes transaction fees from the deferred cache to persistent storage. Fees are deducted from users and stored in a memory-backed cache (prefix 0x03), but distribution reads from persistent storage (prefix 0x02), finding zero fees. This results in validators receiving no fee compensation and permanent loss of all transaction fees. [1](#0-0) 

## Impact
Critical

## Finding Description

**Location:**
- Missing EndBlock: `x/bank/module.go` (entire module reviewed, no EndBlock method exists)
- Fee deduction: `x/auth/ante/fee.go` line 208 [2](#0-1) 
- Distribution reading: `x/distribution/keeper/allocation.go` line 26 [3](#0-2) 
- Storage prefixes: `x/bank/types/key.go` lines 31-32 [4](#0-3) 

**Intended Logic:**
The deferred cache is designed to batch module transfers for gas optimization. The code explicitly documents: "In the EndBlocker, it will then perform one deposit for each module account" [5](#0-4) 

The intended flow:
1. Fees deducted from users, stored in deferred cache (prefix 0x03)
2. At EndBlock, `WriteDeferredBalances` flushes cache to persistent balances (prefix 0x02)
3. Distribution reads fees from persistent balances and distributes to validators

**Actual Logic:**
1. Ante handler deducts fees using `DeferredSendCoinsFromAccountToModule`, which immediately decreases user balance and stores in deferred cache [6](#0-5) 
2. Bank module has NO EndBlock method - module manager skips it during EndBlock processing (type assertion at line 647 fails) [7](#0-6) 
3. `WriteDeferredBalances` is never called in production (only appears in test files)
4. Distribution's `AllocateTokens` (called in BeginBlock) reads fee collector balance via `GetAllBalances` [8](#0-7) 
5. `GetAllBalances` iterates only over `BalancesPrefix` (0x02) through `CreateAccountBalancesPrefix` [9](#0-8) 
6. Fee collector balance reads as zero, validators receive nothing

**Exploitation Path:**
1. User submits transaction with fees (normal operation)
2. Ante handler deducts fees via `DeductFeeDecorator` [10](#0-9) 
3. Fees stored in deferred cache (memory store with prefix 0x03) [11](#0-10) 
4. Block ends, but bank module's EndBlock never called (doesn't exist)
5. Next block's BeginBlock: distribution reads zero balance for fee collector
6. Fees remain permanently inaccessible in deferred cache

**Security Guarantee Broken:**
Fundamental accounting invariant violated - transaction fees collected from users must be distributed to validators. User balances decrease but no corresponding increase occurs in any accessible account balance.

## Impact Explanation

**Direct Financial Loss:**
- Every transaction fee deducted from users is permanently lost
- Fees accumulate in an inaccessible memory cache (DeferredCachePrefix 0x03) that's never flushed
- Validators receive zero fee rewards, completely breaking the network's economic incentive model
- Affects 100% of transactions with fees across the entire network

**System-Wide Effects:**
- Validator economics fundamentally broken (no fee revenue despite processing transactions)
- Network sustainability threatened as validators receive no compensation
- User funds extracted without corresponding value delivery

## Likelihood Explanation

**Probability:** Certain (100%)
- Triggered automatically by normal transaction processing
- No special conditions, configurations, or attacker actions required
- Occurs on every single transaction that includes fees
- Bank keeper initialized with deferred cache in production [12](#0-11) 

**Evidence:** The test `TestLazySendToModuleAccount` explicitly demonstrates this issue - after fee deduction, fee collector balance has NOT increased (lines 175-180). Only after manually calling `WriteDeferredBalances` (line 183) does the balance increase (lines 185-194), proving that without this call, fees remain inaccessible. [13](#0-12) 

## Recommendation

Add EndBlock implementation to the bank module in `x/bank/module.go`:

```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

This ensures the AppModule implements the `EndBlockAppModule` interface, allowing the module manager to invoke it during block finalization and flush the deferred cache to actual balances. [14](#0-13) 

**Verification Steps:**
1. Confirm `WriteDeferredBalances` is called at end of every block
2. Add invariant checks to detect any remaining balance in deferred cache after EndBlock
3. Verify fee collector balance increases correctly after transactions
4. Confirm distribution module successfully reads and allocates fees to validators

**Deployment:** Requires coordinated network upgrade as it changes the state transition function.

## Proof of Concept

The existing test `TestLazySendToModuleAccount` in `x/auth/ante/fee_test.go` demonstrates this scenario:

**Setup:**
- Bank keeper initialized with deferred cache enabled
- User account funded with sufficient balance
- Fee collector module account exists

**Action:**
- Call ante handler twice to deduct fees (lines 170-171)
- Fees stored in deferred cache via `DeferredSendCoinsFromAccountToModule`

**Result:**
- Lines 175-180: Fee collector balance has NOT increased after fee deduction
- Line 183: Manual call to `WriteDeferredBalances` (should happen in EndBlock but doesn't)
- Lines 185-194: Only after manual flush does fee collector balance increase by expected amount

This proves that without the EndBlock call to `WriteDeferredBalances`, fees remain permanently inaccessible in production.

## Notes

Multiple lines of evidence confirm this vulnerability:
1. Code comment explicitly states "In the EndBlocker" but EndBlock method doesn't exist [5](#0-4) 
2. Module manager skips bank module during EndBlock due to failed type assertion [7](#0-6) 
3. Deferred cache and actual balances use separate storage prefixes with no automatic synchronization [4](#0-3) 
4. All test files manually invoke `WriteDeferredBalances` as a workaround

This represents a critical architectural flaw where an optimization mechanism was partially implemented without the essential flush mechanism, resulting in complete loss of all transaction fees.

### Citations

**File:** x/bank/module.go (L107-210)
```go
// AppModule implements an application module for the bank module.
type AppModule struct {
	AppModuleBasic

	keeper        keeper.Keeper
	accountKeeper types.AccountKeeper
}

// RegisterServices registers module services.
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
	types.RegisterQueryServer(cfg.QueryServer(), am.keeper)

	m := keeper.NewMigrator(am.keeper.(keeper.BaseKeeper))
	cfg.RegisterMigration(types.ModuleName, 1, m.Migrate1to2)
}

// NewAppModule creates a new AppModule object
func NewAppModule(cdc codec.Codec, keeper keeper.Keeper, accountKeeper types.AccountKeeper) AppModule {
	return AppModule{
		AppModuleBasic: AppModuleBasic{cdc: cdc},
		keeper:         keeper,
		accountKeeper:  accountKeeper,
	}
}

// Name returns the bank module's name.
func (AppModule) Name() string { return types.ModuleName }

// RegisterInvariants registers the bank module invariants.
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {
	keeper.RegisterInvariants(ir, am.keeper)
}

// Route returns the message routing key for the bank module.
func (am AppModule) Route() sdk.Route {
	return sdk.NewRoute(types.RouterKey, NewHandler(am.keeper))
}

// QuerierRoute returns the bank module's querier route name.
func (AppModule) QuerierRoute() string { return types.RouterKey }

// LegacyQuerierHandler returns the bank module sdk.Querier.
func (am AppModule) LegacyQuerierHandler(legacyQuerierCdc *codec.LegacyAmino) sdk.Querier {
	return keeper.NewQuerier(am.keeper, legacyQuerierCdc)
}

// InitGenesis performs genesis initialization for the bank module. It returns
// no validator updates.
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
	start := time.Now()
	var genesisState types.GenesisState
	cdc.MustUnmarshalJSON(data, &genesisState)
	telemetry.MeasureSince(start, "InitGenesis", "crisis", "unmarshal")

	am.keeper.InitGenesis(ctx, &genesisState)
	return []abci.ValidatorUpdate{}
}

// ExportGenesis returns the exported genesis state as raw bytes for the bank
// module.
func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	gs := am.keeper.ExportGenesis(ctx)
	return cdc.MustMarshalJSON(gs)
}

func (am AppModule) ExportGenesisStream(ctx sdk.Context, cdc codec.JSONCodec) <-chan json.RawMessage {
	ch := make(chan json.RawMessage)
	go func() {
		ch <- am.ExportGenesis(ctx, cdc)
		close(ch)
	}()
	return ch
}

// ConsensusVersion implements AppModule/ConsensusVersion.
func (AppModule) ConsensusVersion() uint64 { return 2 }

// AppModuleSimulation functions

// GenerateGenesisState creates a randomized GenState of the bank module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	simulation.RandomizedGenState(simState)
}

// ProposalContents doesn't return any content functions for governance proposals.
func (AppModule) ProposalContents(_ module.SimulationState) []simtypes.WeightedProposalContent {
	return nil
}

// RandomizedParams creates randomized bank param changes for the simulator.
func (AppModule) RandomizedParams(r *rand.Rand) []simtypes.ParamChange {
	return simulation.ParamChanges(r)
}

// RegisterStoreDecoder registers a decoder for supply module's types
func (am AppModule) RegisterStoreDecoder(_ sdk.StoreDecoderRegistry) {}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	return simulation.WeightedOperations(
		simState.AppParams, simState.Cdc, am.accountKeeper, am.keeper,
	)
}
```

**File:** x/auth/ante/fee.go (L208-208)
```go
	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
```

**File:** x/distribution/keeper/allocation.go (L26-26)
```go
	feesCollectedInt := k.bankKeeper.GetAllBalances(ctx, feeCollector.GetAddress())
```

**File:** x/bank/types/key.go (L31-32)
```go
	DeferredCachePrefix  = []byte{0x03}
	BalancesPrefix       = []byte{0x02}
```

**File:** x/bank/keeper/keeper.go (L406-406)
```go
// In the EndBlocker, it will then perform one deposit for each module account.
```

**File:** x/bank/keeper/keeper.go (L415-426)
```go
	err := k.SubUnlockedCoins(ctx, senderAddr, amount, true)
	if err != nil {
		return err
	}
	// get recipient module address
	moduleAcc := k.ak.GetModuleAccount(ctx, recipientModule)
	if moduleAcc == nil {
		panic(sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", recipientModule))
	}
	// get txIndex
	txIndex := ctx.TxIndex()
	err = k.deferredCache.UpsertBalances(ctx, moduleAcc.GetAddress(), uint64(txIndex), amount)
```

**File:** x/bank/keeper/keeper.go (L435-483)
```go
func (k BaseKeeper) WriteDeferredBalances(ctx sdk.Context) []abci.Event {
	if k.deferredCache == nil {
		panic("bank keeper created without deferred cache")
	}
	ctx = ctx.WithEventManager(sdk.NewEventManager())

	// maps between bech32 stringified module account address and balance
	moduleAddrBalanceMap := make(map[string]sdk.Coins)
	// slice of modules to be sorted for consistent write order later
	moduleList := []string{}

	// iterate over deferred cache and accumulate totals per module
	k.deferredCache.IterateDeferredBalances(ctx, func(moduleAddr sdk.AccAddress, amount sdk.Coin) bool {
		currCoins, ok := moduleAddrBalanceMap[moduleAddr.String()]
		if !ok {
			// add to list of modules
			moduleList = append(moduleList, moduleAddr.String())
			// set the map value
			moduleAddrBalanceMap[moduleAddr.String()] = sdk.NewCoins(amount)
			return false
		}
		// add to currCoins
		newCoins := currCoins.Add(amount)
		// update map
		moduleAddrBalanceMap[moduleAddr.String()] = newCoins
		return false
	})
	// sort module list
	sort.Strings(moduleList)

	// iterate through module list and add the balance to module bank balances in sorted order
	for _, moduleBech32Addr := range moduleList {
		amount, ok := moduleAddrBalanceMap[moduleBech32Addr]
		if !ok {
			err := fmt.Errorf("Failed to get module balance for writing deferred balances for address=%s", moduleBech32Addr)
			ctx.Logger().Error(err.Error())
			panic(err)
		}
		err := k.AddCoins(ctx, sdk.MustAccAddressFromBech32(moduleBech32Addr), amount, true)
		if err != nil {
			ctx.Logger().Error(fmt.Sprintf("Failed to add coin=%s to module address=%s, error is: %s", amount, moduleBech32Addr, err))
			panic(err)
		}
	}

	// clear deferred cache
	k.deferredCache.Clear(ctx)
	return ctx.EventManager().ABCIEvents()
}
```

**File:** types/module/module.go (L647-650)
```go
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
		}
```

**File:** x/distribution/abci.go (L31-31)
```go
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```

**File:** x/bank/keeper/view.go (L232-235)
```go
func (k BaseViewKeeper) getAccountStore(ctx sdk.Context, addr sdk.AccAddress) prefix.Store {
	store := ctx.KVStore(k.storeKey)

	return prefix.NewStore(store, types.CreateAccountBalancesPrefix(addr))
```

**File:** x/auth/ante/ante.go (L54-54)
```go
		NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ParamsKeeper.(paramskeeper.Keeper), options.TxFeeChecker),
```

**File:** simapp/app.go (L230-230)
```go
	memKeys := sdk.NewMemoryStoreKeys(capabilitytypes.MemStoreKey, "testingkey", banktypes.DeferredCacheStoreKey)
```

**File:** simapp/app.go (L264-266)
```go
	app.BankKeeper = bankkeeper.NewBaseKeeperWithDeferredCache(
		appCodec, keys[banktypes.StoreKey], app.AccountKeeper, app.GetSubspace(banktypes.ModuleName), app.ModuleAccountAddrs(), memKeys[banktypes.DeferredCacheStoreKey],
	)
```

**File:** x/auth/ante/fee_test.go (L175-194)
```go
	// Fee Collector actual account balance should not have increased
	resultFeeCollectorBalance := suite.app.BankKeeper.GetBalance(suite.ctx, feeCollectorAcc.GetAddress(), "usei")
	suite.Assert().Equal(
		expectedFeeCollectorBalance,
		resultFeeCollectorBalance,
	)

	// Fee Collector actual account balance deposit coins into the fee collector account
	suite.app.BankKeeper.WriteDeferredBalances(suite.ctx)

	depositFeeCollectorBalance := suite.app.BankKeeper.GetBalance(suite.ctx, feeCollectorAcc.GetAddress(), "usei")

	expectedAtomFee := feeAmount.AmountOf("usei")

	suite.Assert().Equal(
		// Called antehandler twice, expect fees to be deducted twice
		expectedFeeCollectorBalance.Add(sdk.NewCoin("usei", expectedAtomFee)).Add(sdk.NewCoin("usei", expectedAtomFee)),
		depositFeeCollectorBalance,
	)
}
```
