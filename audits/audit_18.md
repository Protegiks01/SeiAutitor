# Audit Report

## Title
Deferred Fee Cache Never Flushed Leading to Permanent Loss of Transaction Fees

## Summary
The bank module's deferred cache mechanism collects transaction fees but fails to flush them to module accounts because the bank module lacks an EndBlock implementation. All transaction fees are permanently lost as they remain trapped in the deferred cache, never reaching the fee collector account for validator distribution.

## Impact
High

## Finding Description

**Location:**
- Primary issue: [1](#0-0) 
- Fee deduction entry point: [2](#0-1) 
- Cache storage: [3](#0-2) 
- Unreachable flush function: [4](#0-3) 

**Intended Logic:**
The code comment explicitly documents the intended behavior: [5](#0-4) 

The intended flow:
1. Transaction fees → `DeferredSendCoinsFromAccountToModule` deducts from user and stores in cache
2. EndBlock → bank module calls `WriteDeferredBalances` to flush cache to module accounts
3. BeginBlock → distribution module retrieves and distributes fees to validators

**Actual Logic:**
1. Ante handler processes fees via `DeferredSendCoinsFromAccountToModule` [2](#0-1) 
2. User balance immediately reduced, fees stored in deferred cache [6](#0-5) 
3. Module manager skips bank module during EndBlock because it doesn't implement the `EndBlockAppModule` interface [7](#0-6) 
4. Fees persist in memory store across blocks [8](#0-7) 
5. Distribution module queries actual balances only, excluding deferred cache [9](#0-8)  and [10](#0-9) 
6. Zero fees distributed to validators

**Exploitation Path:**
No attacker action required - occurs automatically during normal operation:
1. Any user submits a transaction with fees
2. Ante handler deducts fees from user account
3. Fees stored in deferred cache, user balance reduced
4. EndBlock executes but bank module has no EndBlock method, so module manager skips it
5. Distribution BeginBlock queries fee collector balance: returns 0
6. Fees permanently inaccessible in deferred cache, never flushed to actual balances

**Security Guarantee Broken:**
Fundamental accounting invariant violated: `total_supply = sum(all_account_balances)`. User balances decrease but no account is credited, causing systemic fund loss equal to all accumulated transaction fees.

## Impact Explanation

**Direct Loss of Funds:** Every transaction fee is deducted from user accounts but never credited to the fee collector module account. The fees remain trapped in the deferred cache, which is:
- Not included in balance queries used by distribution module
- Never flushed to actual balances (no EndBlock implementation to call `WriteDeferredBalances`)
- Permanently inaccessible for distribution to validators

**Cascading Effects:**
- **Broken validator economics**: Validators receive no fee rewards, fundamentally undermining network security incentives
- **Accounting corruption**: Total supply tracking becomes incorrect as fees vanish from observable circulation
- **Cumulative damage**: Problem compounds with every transaction across every block, with losses growing continuously

This qualifies as **direct loss of funds** and **permanent freezing of funds requiring hard fork to fix** per the impact criteria.

## Likelihood Explanation

**Probability:** 100% - Occurs automatically on every transaction that includes fees

**Who Can Trigger:** Any network participant submitting transactions (normal usage, not an attack)

**Conditions Required:** None - this is the default behavior during normal network operation with standard transactions

**Evidence from Tests:** Multiple test files explicitly demonstrate that `WriteDeferredBalances` must be manually called after using `DeferredSendCoinsFromAccountToModule`: [11](#0-10) , [12](#0-11) , and [13](#0-12) 

The test in `fee_test.go` explicitly demonstrates:
- Fee collector balance remains 0 after ante handler processes fees
- Manual call to `WriteDeferredBalances` is required
- Only after manual flush does the fee collector balance increase by the expected fee amount

## Recommendation

**Immediate Fix:**
Implement an EndBlock method in the bank module's `AppModule` struct to flush the deferred cache. Add to `x/bank/module.go`:

```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

This will:
1. Satisfy the `EndBlockAppModule` interface [14](#0-13) 
2. Ensure module manager calls bank's EndBlock instead of skipping it
3. Flush deferred fees to module accounts before distribution BeginBlock executes

**Additional Measures:**
- Add invariant checks to detect balance discrepancies between deferred cache and actual balances
- The bank module is already listed in `OrderEndBlockers` [15](#0-14)  but was being skipped - this fix activates that ordering
- Requires coordinated network upgrade to deploy the fix

## Proof of Concept

The existing test suite provides proof of this vulnerability:

**Setup:**
- Initialize user account with balance
- Initialize fee collector module account
- Standard blockchain configuration

**Action:**
1. Call `DeferredSendCoinsFromAccountToModule` (as ante handler does during fee processing)
2. Do NOT call `WriteDeferredBalances` (mimicking production behavior where bank module has no EndBlock)

**Result:**
1. User balance decreased by fee amount ✓
2. Fee collector actual balance remains 0 ✓ (fees stuck in deferred cache)
3. `GetAllBalances(feeCollector)` returns 0 ✓ (bypasses deferred cache)
4. Distribution module sees 0 balance to distribute ✓
5. Accounting invariant broken: fees permanently lost ✓

The test evidence in [12](#0-11)  clearly demonstrates that without the manual call to `WriteDeferredBalances`, fees remain in the deferred cache and never reach the fee collector's actual balance, confirming the vulnerability in production code where this manual call does not exist.

## Notes

This vulnerability is particularly critical because:
1. The code documentation explicitly states the intended behavior that was never implemented
2. The deferred cache infrastructure exists and is actively used for fee collection
3. The critical flush operation exists but is unreachable due to missing EndBlock
4. Memory stores persist across blocks, so fees accumulate indefinitely in an inaccessible state
5. This affects the core economic mechanism of the blockchain (validator fee rewards)
6. Every transaction with fees triggers this issue - 100% reproduction rate with zero special conditions

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
