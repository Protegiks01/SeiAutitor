# Audit Report

## Title
Deferred Fee Cache Never Flushed Leading to Permanent Loss of Transaction Fees

## Summary
The bank module's deferred cache mechanism collects transaction fees but fails to flush them to module accounts because the bank module lacks an EndBlock implementation. Fees are immediately deducted from users and stored in a memory-based deferred cache, but the distribution module queries only actual bank balances (excluding the deferred cache), resulting in zero fees being distributed and permanent loss of all transaction fees.

## Impact
High

## Finding Description

**Location:**
- Primary: `x/bank/module.go` (lines 107-210) - missing EndBlock implementation [1](#0-0) 
  
- Fee deduction: `x/auth/ante/fee.go` (line 208) - uses DeferredSendCoinsFromAccountToModule [2](#0-1) 
  
- Cache write: `x/bank/keeper/keeper.go` (lines 408-432) - defers fees to cache [3](#0-2) 
  
- Never called: `x/bank/keeper/keeper.go` (lines 434-483) - WriteDeferredBalances exists but unreachable [4](#0-3) 

**Intended Logic:**
The code comment at line 406 explicitly states: "In the EndBlocker, it will then perform one deposit for each module account." [5](#0-4) 

The intended flow should be:
1. User pays fees → `DeferredSendCoinsFromAccountToModule` deducts from user and stores in cache
2. EndBlock → bank module calls `WriteDeferredBalances` to flush cache to module accounts
3. BeginBlock → distribution module retrieves and distributes fees

**Actual Logic:**
1. Ante handler calls `DeferredSendCoinsFromAccountToModule` [2](#0-1) 
   
2. User balance is immediately reduced via `SubUnlockedCoins` (line 415), fees stored in deferred cache (line 426) [6](#0-5) [7](#0-6) 
   
3. Bank module has NO EndBlock method, so module manager skips it [8](#0-7) 
   
4. Fees remain in deferred cache (memory store persists across blocks) [9](#0-8) 
   
5. Distribution module calls `GetAllBalances` which only reads actual balances, not deferred cache [10](#0-9) [11](#0-10) 
   
6. Distribution sees zero balance and transfers nothing

**Exploitation Path:**
No attacker action needed - this occurs automatically:
1. Any user submits a transaction with fees (normal operation)
2. Ante handler processes fee deduction
3. User balance decreased, fee stored in deferred cache
4. EndBlock executes but bank module skipped (no EndBlock method)
5. BeginBlock distribution queries fee collector: balance = 0
6. Fees permanently inaccessible in deferred cache

**Security Guarantee Broken:**
Fundamental accounting invariant violated: `total_supply = sum(all_account_balances)`. User balances decrease but no account is credited, causing systemic fund loss equal to all transaction fees.

## Impact Explanation

**Direct Loss of Funds:** Every transaction fee is deducted from user accounts but never credited to the fee collector module account. The fees remain trapped in the deferred cache, which is:
- Not included in balance queries (`GetAllBalances` bypasses it)
- Never flushed to actual balances (no EndBlock to call `WriteDeferredBalances`)
- Inaccessible for distribution to validators

**Cascading Effects:**
- **Broken validator economics**: Validators receive no fee rewards, undermining network security incentives
- **Accounting corruption**: Total supply tracking becomes incorrect as fees vanish from circulation
- **Cumulative damage**: Problem compounds with every transaction across every block

## Likelihood Explanation

**Probability:** 100% - Occurs automatically on every transaction with fees

**Who Can Trigger:** Any network participant submitting transactions (normal usage, not an attack)

**Conditions Required:** None - this is the default behavior during normal network operation

**Evidence from Tests:** Multiple test files explicitly call `WriteDeferredBalances` after using `DeferredSendCoinsFromAccountToModule`, proving this flush operation is required but missing in production code: [12](#0-11) [13](#0-12) [14](#0-13) 

The test at lines 176-193 in `fee_test.go` explicitly demonstrates:
- Fee collector balance remains unchanged after ante handler
- Manual call to `WriteDeferredBalances` is required
- Only after flush does the fee collector balance increase [15](#0-14) 

## Recommendation

**Immediate Fix:**
Implement EndBlock method in the bank module to flush the deferred cache. Add the following to `x/bank/module.go`:

```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

This will:
1. Satisfy the `EndBlockAppModule` interface [16](#0-15) 
   
2. Ensure module manager calls bank's EndBlock (currently skipped at lines 647-650) [8](#0-7) 
   
3. Flush deferred fees to module accounts before distribution BeginBlock

**Additional Measures:**
- Add invariant checks to detect balance discrepancies between deferred cache and actual balances
- The bank module is already in `OrderEndBlockers` but was being skipped - this fix activates that ordering [17](#0-16) 
- Requires coordinated network upgrade to deploy

## Proof of Concept

The existing tests in the codebase demonstrate this vulnerability. A minimal reproduction:

**Setup:**
1. Initialize user account with balance
2. Initialize fee collector module account

**Action:**
1. Call `DeferredSendCoinsFromAccountToModule` to simulate fee deduction (as ante handler does)
2. Do NOT call `WriteDeferredBalances` (mimicking production behavior)

**Result:**
1. User balance decreased by fee amount ✓
2. Fee collector actual balance remains 0 ✓ (fees stuck in deferred cache)
3. `GetAllBalances(feeCollector)` returns 0 ✓ (bypasses deferred cache)
4. Distribution module sees 0 balance to distribute ✓
5. Accounting invariant broken: fees permanently lost ✓

The test evidence clearly shows that `WriteDeferredBalances` must be called manually in tests to avoid this exact problem, but production code has no such call because the bank module lacks an EndBlock implementation.

## Notes

This vulnerability is particularly severe because:
1. The code comment explicitly documents the intended behavior ("In the EndBlocker") that was never implemented
2. The deferred cache infrastructure exists and is used, but the critical flush operation is missing
3. Memory stores persist across blocks, so fees accumulate indefinitely but remain permanently inaccessible
4. This affects the core economic mechanism of the blockchain (fee collection and validator rewards)
5. Every transaction with fees triggers this issue automatically - no attacker action required

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

**File:** x/bank/keeper/keeper.go (L406-406)
```go
// In the EndBlocker, it will then perform one deposit for each module account.
```

**File:** x/bank/keeper/keeper.go (L408-432)
```go
func (k BaseKeeper) DeferredSendCoinsFromAccountToModule(
	ctx sdk.Context, senderAddr sdk.AccAddress, recipientModule string, amount sdk.Coins,
) error {
	if k.deferredCache == nil {
		panic("bank keeper created without deferred cache")
	}
	// Deducts Fees from the Sender Account
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
	if err != nil {
		return err
	}

	return nil
}
```

**File:** x/bank/keeper/keeper.go (L434-483)
```go
// WriteDeferredDepositsToModuleAccounts Iterates on all the deferred deposits and deposit them into the store
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

**File:** types/module/module.go (L226-229)
```go
type EndBlockAppModule interface {
	AppModule
	EndBlock(sdk.Context, abci.RequestEndBlock) []abci.ValidatorUpdate
}
```

**File:** types/module/module.go (L647-650)
```go
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
		}
```

**File:** store/mem/store.go (L20-21)
```go
// Store implements an in-memory only KVStore. Entries are persisted between
// commits and thus between blocks. State in Memory store is not committed as part of app state but maintained privately by each node
```

**File:** x/bank/keeper/view.go (L64-72)
```go
func (k BaseViewKeeper) GetAllBalances(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins {
	balances := sdk.NewCoins()
	k.IterateAccountBalances(ctx, addr, func(balance sdk.Coin) bool {
		balances = append(balances, balance)
		return false
	})

	return balances.Sort()
}
```

**File:** x/distribution/keeper/allocation.go (L26-26)
```go
	feesCollectedInt := k.bankKeeper.GetAllBalances(ctx, feeCollector.GetAddress())
```

**File:** x/bank/keeper/keeper_test.go (L679-679)
```go
	app.BankKeeper.WriteDeferredBalances(ctx)
```

**File:** x/auth/ante/fee_test.go (L176-193)
```go
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
```

**File:** x/bank/keeper/deferred_cache_test.go (L66-66)
```go
	app.BankKeeper.WriteDeferredBalances(ctx)
```

**File:** simapp/app.go (L374-374)
```go
		capabilitytypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName, distrtypes.ModuleName,
```
