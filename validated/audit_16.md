# Audit Report

## Title
Permanent Loss of Transaction Fees Due to Missing EndBlock Implementation in Bank Module

## Summary
The bank module's deferred balance system deducts transaction fees from user accounts immediately (persisted to disk) and caches them in a memory-only store with the documented intent to flush to module accounts during EndBlock. However, the bank module completely lacks an EndBlock method implementation, causing `WriteDeferredBalances` to never be called in production. This results in permanent loss of all accumulated transaction fees when nodes restart, as the memory-only cache is cleared while user deductions remain persisted to disk.

## Impact
High

## Finding Description

**Location:**
- Fee deduction entry point: [1](#0-0) 
- Deferred send implementation: [2](#0-1) 
- Bank module structure (no EndBlock): [3](#0-2) 
- Memory store characteristics: [4](#0-3) 

**Intended logic:**
The code documentation explicitly states the intended behavior: [5](#0-4) 

The system is designed to: (1) immediately deduct fees via `SubUnlockedCoins` which persists to the IAVL store, (2) cache amounts in a deferred memory store indexed by transaction, and (3) flush all deferred balances to module accounts in EndBlock via `WriteDeferredBalances`.

**Actual logic:**
- User fees are deducted immediately and persisted to disk through the SubUnlockedCoins call
- Amounts are stored in a memory-only deferred cache that is "not committed as part of app state but maintained privately by each node"
- The bank module AppModule struct (lines 107-210) contains no EndBlock method, failing to implement the `EndBlockAppModule` interface
- Module manager skips modules lacking EndBlock: [6](#0-5) 
- `WriteDeferredBalances` is never called in production code (verified by comprehensive grep - only appears in test files)
- On node restart, memory stores are recreated fresh: [7](#0-6) 
- User accounts retain reduced balances but module accounts never receive funds

**Exploitation path:**
No attacker required - occurs during normal blockchain operation:
1. User submits transaction with fees
2. Ante handler calls DeductFees which invokes `DeferredSendCoinsFromAccountToModule`
3. User balance reduced via SubUnlockedCoins (persisted to IAVL store)
4. Amount cached in memory-only deferred store
5. Block processing completes, EndBlock is called: [8](#0-7) 
6. Bank module is skipped during EndBlock iteration (no EndBlock implementation)
7. `WriteDeferredBalances` never called
8. State committed with user balance reduced but module account unchanged
9. Fees accumulate in memory cache across multiple blocks
10. Node restarts (maintenance, upgrade, crash, or hardware operations)
11. Memory store cleared, deferred cache emptied
12. All accumulated fees permanently lost

**Security guarantee broken:**
Violates the fundamental accounting invariant that all deducted coins must exist somewhere in the system. The TotalSupply invariant correctly includes deferred balances during normal operation: [9](#0-8) 

However, after restart when the cache is cleared, the invariant would fail as the sum of account balances would be less than total supply (user balances reduced without corresponding module credits).

## Impact Explanation

All transaction fees paid since the last node restart are permanently lost. This includes fees intended for the fee collector module which funds validator rewards and governance operations. The impact is severe because:

- **Direct permanent fund loss**: Fees deducted from users never reach module accounts
- **Continuous accumulation**: Every transaction contributes to the growing loss
- **No recovery mechanism**: Once the memory store is cleared on restart, amounts are irrecoverable
- **Network-wide issue**: Affects every validator and full node independently on each restart
- **Invariant violation**: After restart, total supply accounting breaks (user balances reduced without corresponding module credits)

The deferred cache is confirmed to be used in production: [10](#0-9) 

## Likelihood Explanation

**Very High** - Triggered continuously during normal blockchain operation:

- **Frequency**: Every transaction that pays fees (essentially all transactions) uses the deferred system via the ante handler
- **Restart triggers**: Node restarts occur regularly for software updates, network upgrades, crashes, hardware maintenance, and datacenter operations
- **No special conditions**: Happens automatically without attacker involvement or special circumstances
- **Network-wide**: Every validator and full node experiences this loss independently

The test file demonstrates that developers were aware `WriteDeferredBalances` must be called to credit module accounts: [11](#0-10) 

However, this call was only implemented in tests (line 183), never in production EndBlock code.

## Recommendation

Add an EndBlock method to the bank module that calls `WriteDeferredBalances`. In `x/bank/module.go`, add:

```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

Verification steps:
1. Confirm `WriteDeferredBalances` is called exactly once per block
2. Verify fee collector module accounts receive all accumulated fees
3. Ensure TotalSupply invariant passes consistently after node restarts
4. Confirm deferred cache is empty at the end of each block
5. Add monitoring to alert if deferred cache accumulates unexpectedly

## Proof of Concept

The existing test demonstrates the vulnerability: [11](#0-10) 

**Setup:**
1. Initialize test app with bank keeper configured with deferred cache
2. Create user account and fee collector module account  
3. Fund user account with initial balance (900 usei)

**Action:**
1. Call ante handler twice (lines 170-171), which invokes `DeferredSendCoinsFromAccountToModule` each time
2. Verify fee collector balance unchanged (lines 176-180) - fees are deferred, not immediately credited
3. Manually call `WriteDeferredBalances` (line 183) - **THIS MANUAL CALL IS ONLY DONE IN TESTS**
4. Verify fee collector balance increased by 2x fee amount (lines 185-193)

**Result:**
The test proves that without calling `WriteDeferredBalances`, module accounts never receive deferred fees. In production code, this call never happens because the bank module has no EndBlock method. When a node restarts, the memory store is cleared and all deferred fees are permanently lost while user account deductions remain persisted.

## Notes

This vulnerability represents a critical architectural flaw where the implementation is incomplete relative to the documented design. The deferred balance system was clearly intended to optimize gas costs by batching transfers to module accounts, but the critical EndBlock flush operation was never implemented in the bank module itself, only in test code. The memory-only nature of the deferred cache combined with the missing EndBlock creates an accounting black hole that permanently destroys transaction fees on every node restart.

### Citations

**File:** x/auth/ante/fee.go (L208-208)
```go
	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
```

**File:** x/bank/keeper/keeper.go (L404-407)
```go
// DeferredSendCoinsFromAccountToModule transfers coins from an AccAddress to a ModuleAccount.
// It deducts the balance from an accAddress and stores the balance in a mapping for ModuleAccounts.
// In the EndBlocker, it will then perform one deposit for each module account.
// It will panic if the module account does not exist.
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

**File:** store/mem/store.go (L20-21)
```go
// Store implements an in-memory only KVStore. Entries are persisted between
// commits and thus between blocks. State in Memory store is not committed as part of app state but maintained privately by each node
```

**File:** types/module/module.go (L647-649)
```go
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
```

**File:** store/rootmulti/store.go (L1003-1008)
```go
	case types.StoreTypeMemory:
		if _, ok := key.(*types.MemoryStoreKey); !ok {
			return nil, fmt.Errorf("unexpected key type for a MemoryStoreKey; got: %s", key.String())
		}

		return mem.NewStore(), nil
```

**File:** simapp/app.go (L264-266)
```go
	app.BankKeeper = bankkeeper.NewBaseKeeperWithDeferredCache(
		appCodec, keys[banktypes.StoreKey], app.AccountKeeper, app.GetSubspace(banktypes.ModuleName), app.ModuleAccountAddrs(), memKeys[banktypes.DeferredCacheStoreKey],
	)
```

**File:** simapp/app.go (L538-540)
```go
	endBlockResp := app.EndBlock(ctx, abci.RequestEndBlock{
		Height: req.Height,
	})
```

**File:** x/bank/keeper/invariants.go (L74-78)
```go
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
```

**File:** x/auth/ante/fee_test.go (L138-194)
```go
func (suite *AnteTestSuite) TestLazySendToModuleAccount() {
	suite.SetupTest(false) // setup
	suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()

	// keys and addresses
	priv1, _, addr1 := testdata.KeyTestPubAddr()

	// msg and signatures
	msg := testdata.NewTestMsg(addr1)
	feeAmount := testdata.NewTestFeeAmount()
	gasLimit := testdata.NewTestGasLimit()
	suite.Require().NoError(suite.txBuilder.SetMsgs(msg))
	suite.txBuilder.SetFeeAmount(feeAmount)
	suite.txBuilder.SetGasLimit(gasLimit)

	privs, accNums, accSeqs := []cryptotypes.PrivKey{priv1}, []uint64{0}, []uint64{0}
	tx, err := suite.CreateTestTx(privs, accNums, accSeqs, suite.ctx.ChainID())
	suite.Require().NoError(err)

	// Set account with insufficient funds
	acc := suite.app.AccountKeeper.NewAccountWithAddress(suite.ctx, addr1)
	suite.app.AccountKeeper.SetAccount(suite.ctx, acc)
	err = simapp.FundAccount(suite.app.BankKeeper, suite.ctx, addr1, sdk.NewCoins(sdk.NewCoin("usei", sdk.NewInt(900))))
	suite.Require().NoError(err)

	feeCollectorAcc := suite.app.AccountKeeper.GetModuleAccount(suite.ctx, types.FeeCollectorName)
	expectedFeeCollectorBalance := suite.app.BankKeeper.GetBalance(suite.ctx, feeCollectorAcc.GetAddress(), "usei")

	dfd := ante.NewDeductFeeDecorator(suite.app.AccountKeeper, suite.app.BankKeeper, nil, suite.app.ParamsKeeper, nil)
	antehandler, _ := sdk.ChainAnteDecorators(dfd)

	// Set account with sufficient funds
	antehandler(suite.ctx, tx, false)
	_, err = antehandler(suite.ctx, tx, false)

	suite.Require().Nil(err, "Tx errored after account has been set with sufficient funds")

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
