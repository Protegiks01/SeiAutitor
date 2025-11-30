# Audit Report

## Title
Permanent Loss of Transaction Fees Due to Missing WriteDeferredBalances Call in EndBlocker

## Summary
The banking module's deferred balance system deducts transaction fees from user accounts into persistent storage but caches them in a non-persistent memory-only store. The system is designed to flush these cached amounts to module accounts via `WriteDeferredBalances` during EndBlock, but the bank module does not implement an EndBlock method, and `WriteDeferredBalances` is never called in production code. This results in permanent loss of all accumulated transaction fees when nodes restart.

## Impact
Critical - Direct loss of funds

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended logic:**
The code documentation explicitly states the intended behavior at [4](#0-3) . The system is designed to: (1) immediately deduct fees from user accounts via `SubUnlockedCoins` to persistent storage, (2) cache the deducted amounts in a deferred cache indexed by module and transaction, and (3) flush all deferred balances to module accounts during EndBlock by calling `WriteDeferredBalances`.

**Actual logic:**
The deferred cache uses a memory store that is explicitly not persisted as part of app state [5](#0-4) . When transaction fees are processed:
1. User balance is reduced via `SubUnlockedCoins` which writes to persistent storage [6](#0-5) 
2. The amount is stored in the memory-only deferred cache via `UpsertBalances` [7](#0-6) 
3. The bank module has no EndBlock method (confirmed by code inspection of the entire x/bank/module.go)
4. `WriteDeferredBalances` is never called in production code (only in test files)
5. On node restart, the memory store is cleared, losing all deferred amounts
6. User accounts retain their reduced balances, but module accounts never receive the funds

**Exploitation path:**
No attacker is required - this occurs during normal blockchain operation:
1. User submits transaction with fees, processed via ante handler [8](#0-7) 
2. `DeferredSendCoinsFromAccountToModule` is called [9](#0-8) 
3. User's balance is immediately reduced and persisted to the IAVL store [10](#0-9) 
4. Amount is cached in memory-only deferred store [11](#0-10) 
5. Block processing completes. EndBlock is called [12](#0-11)  but the bank module has no EndBlock implementation
6. The module manager skips modules without EndBlock implementations [13](#0-12) 
7. Node operator performs routine restart, upgrade, or node crashes
8. Memory store is cleared on restart (not persisted to disk)
9. Deferred cache loses all accumulated fees since last restart
10. User accounts show permanently reduced balances, but fee collector module account never received the funds

**Security guarantee broken:**
This violates the fundamental accounting invariant that all coins deducted from accounts must exist somewhere in the system. The `TotalSupply` invariant correctly includes deferred balances during normal operation [14](#0-13) , but after a node restart when the deferred cache is cleared, the sum of all account balances would be less than the recorded total supply, breaking the invariant.

## Impact Explanation

All transaction fees paid by users since the last node restart are permanently and irrecoverably lost. This represents direct loss of funds with severe consequences:

- **Permanent fund loss**: Transaction fees are deducted from user accounts but never reach the fee collector module account intended for validator rewards and governance
- **Accumulates continuously**: Every transaction that pays fees contributes to the loss until node restart
- **No recovery mechanism**: Once the node restarts and clears the memory store, the deferred amounts cannot be recovered from any source
- **Network-wide impact**: Every validator and full node experiences this independently on every restart, affecting the entire network's economic model
- **Economic sustainability**: The blockchain's fee collection mechanism is fundamentally broken, making it economically unsustainable as validators never receive transaction fee rewards

## Likelihood Explanation

**Triggering conditions:**
- Any transaction that pays fees (essentially all transactions on the network)
- Any node restart (routine maintenance, crashes, upgrades, hardware failures)

**Frequency and scope:**
- **Every transaction**: Fees are deferred on every single transaction via the ante handler
- **Every restart**: All accumulated deferred fees are lost on every node restart
- **Network-wide**: Every validator node and full node experiences this independently

Node restarts are routine operational requirements that occur regularly for software updates, security patches, network upgrades, crashes, hardware maintenance, and datacenter operations.

The likelihood is **very high** because this vulnerability is triggered during normal blockchain operation without requiring any special conditions or attacker action. Node restarts are unavoidable operational requirements.

## Recommendation

**Immediate fix:**
Add an EndBlock method to the bank module that calls `WriteDeferredBalances` in `x/bank/module.go`:

```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

The bank module is already registered in the EndBlocker order [15](#0-14) , so once the method is added, it will be called automatically by the module manager [16](#0-15) .

**Alternative fix:**
Add the call directly in the application's FinalizeBlocker before `SetDeliverStateToCommit()` at [17](#0-16) :

```go
deferredEvents := app.BankKeeper.WriteDeferredBalances(ctx)
events = append(events, deferredEvents...)
```

**Verification:**
- Ensure `WriteDeferredBalances` is called exactly once per block
- Verify fee collector module accounts receive all accumulated fees
- Confirm TotalSupply invariant passes after node restarts
- Validate no deferred balances remain in cache at the end of each block

## Proof of Concept

The vulnerability is demonstrated through code analysis and test file examination:

**Setup:**
1. System configured with deferred cache as memory store [11](#0-10) 
2. Bank keeper uses memory store for deferred cache [18](#0-17) 

**Action:**
1. Transaction processed, `DeferredSendCoinsFromAccountToModule` called for fee deduction
2. User balance reduced via persistent storage (`SubUnlockedCoins`)
3. Amount cached in memory store (`UpsertBalances`)
4. Block completes without calling `WriteDeferredBalances`
5. Node restart clears memory store

**Result:**
- User balance remains reduced (persisted to disk)
- Fee collector never receives funds
- Deferred cache is empty (cleared on restart)
- Funds permanently lost

**Evidence from test files:**
Test files explicitly call `WriteDeferredBalances` after ante handler processing with comments stating "deposit coins into the fee collector account" [19](#0-18) , confirming that this call is required for fees to reach the fee collector. The fact that production code never makes this call proves the vulnerability.

## Notes

This vulnerability represents a critical implementation gap where the documented design (calling `WriteDeferredBalances` in EndBlocker) was never implemented in production code, despite the deferred balance system being actively used for fee collection on every transaction. The memory store explicitly states it is "not committed as part of app state" [5](#0-4) , confirming that deferred balances are lost on node restart.

### Citations

**File:** x/bank/keeper/keeper.go (L404-432)
```go
// DeferredSendCoinsFromAccountToModule transfers coins from an AccAddress to a ModuleAccount.
// It deducts the balance from an accAddress and stores the balance in a mapping for ModuleAccounts.
// In the EndBlocker, it will then perform one deposit for each module account.
// It will panic if the module account does not exist.
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

**File:** simapp/app.go (L372-379)
```go
	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName, govtypes.ModuleName, stakingtypes.ModuleName,
		capabilitytypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName, distrtypes.ModuleName,
		slashingtypes.ModuleName, minttypes.ModuleName,
		genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName, upgradetypes.ModuleName, vestingtypes.ModuleName, acltypes.ModuleName,
	)
```

**File:** simapp/app.go (L476-574)
```go
func (app *SimApp) FinalizeBlocker(ctx sdk.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	events := []abci.Event{}
	beginBlockResp := app.BeginBlock(ctx, abci.RequestBeginBlock{
		Hash: req.Hash,
		ByzantineValidators: utils.Map(req.ByzantineValidators, func(mis abci.Misbehavior) abci.Evidence {
			return abci.Evidence{
				Type:             abci.MisbehaviorType(mis.Type),
				Validator:        abci.Validator(mis.Validator),
				Height:           mis.Height,
				Time:             mis.Time,
				TotalVotingPower: mis.TotalVotingPower,
			}
		}),
		LastCommitInfo: abci.LastCommitInfo{
			Round: req.DecidedLastCommit.Round,
			Votes: utils.Map(req.DecidedLastCommit.Votes, func(vote abci.VoteInfo) abci.VoteInfo {
				return abci.VoteInfo{
					Validator:       abci.Validator(vote.Validator),
					SignedLastBlock: vote.SignedLastBlock,
				}
			}),
		},
		Header: tmproto.Header{
			ChainID:         app.ChainID,
			Height:          req.Height,
			Time:            req.Time,
			ProposerAddress: ctx.BlockHeader().ProposerAddress,
		},
	})
	events = append(events, beginBlockResp.Events...)

	typedTxs := []sdk.Tx{}
	for _, tx := range req.Txs {
		typedTx, err := app.txDecoder(tx)
		if err != nil {
			typedTxs = append(typedTxs, nil)
		} else {
			typedTxs = append(typedTxs, typedTx)
		}
	}

	txResults := []*abci.ExecTxResult{}
	for i, tx := range req.Txs {
		ctx = ctx.WithContext(context.WithValue(ctx.Context(), ante.ContextKeyTxIndexKey, i))
		if typedTxs[i] == nil {
			txResults = append(txResults, &abci.ExecTxResult{}) // empty result
			continue
		}
		deliverTxResp := app.DeliverTx(ctx, abci.RequestDeliverTx{
			Tx: tx,
		}, typedTxs[i], sha256.Sum256(tx))
		txResults = append(txResults, &abci.ExecTxResult{
			Code:      deliverTxResp.Code,
			Data:      deliverTxResp.Data,
			Log:       deliverTxResp.Log,
			Info:      deliverTxResp.Info,
			GasWanted: deliverTxResp.GasWanted,
			GasUsed:   deliverTxResp.GasUsed,
			Events:    deliverTxResp.Events,
			Codespace: deliverTxResp.Codespace,
		})
	}
	endBlockResp := app.EndBlock(ctx, abci.RequestEndBlock{
		Height: req.Height,
	})
	events = append(events, endBlockResp.Events...)

	app.SetDeliverStateToCommit()
	app.WriteState()
	appHash := app.GetWorkingHash()
	return &abci.ResponseFinalizeBlock{
		Events:    events,
		TxResults: txResults,
		ValidatorUpdates: utils.Map(endBlockResp.ValidatorUpdates, func(v abci.ValidatorUpdate) abci.ValidatorUpdate {
			return abci.ValidatorUpdate{
				PubKey: v.PubKey,
				Power:  v.Power,
			}
		}),
		ConsensusParamUpdates: &tmproto.ConsensusParams{
			Block: &tmproto.BlockParams{
				MaxBytes: endBlockResp.ConsensusParamUpdates.Block.MaxBytes,
				MaxGas:   endBlockResp.ConsensusParamUpdates.Block.MaxGas,
			},
			Evidence: &tmproto.EvidenceParams{
				MaxAgeNumBlocks: endBlockResp.ConsensusParamUpdates.Evidence.MaxAgeNumBlocks,
				MaxAgeDuration:  endBlockResp.ConsensusParamUpdates.Evidence.MaxAgeDuration,
				MaxBytes:        endBlockResp.ConsensusParamUpdates.Block.MaxBytes,
			},
			Validator: &tmproto.ValidatorParams{
				PubKeyTypes: endBlockResp.ConsensusParamUpdates.Validator.PubKeyTypes,
			},
			Version: &tmproto.VersionParams{
				AppVersion: endBlockResp.ConsensusParamUpdates.Version.AppVersion,
			},
		},
		AppHash: appHash,
	}, nil
}
```

**File:** store/mem/store.go (L20-21)
```go
// Store implements an in-memory only KVStore. Entries are persisted between
// commits and thus between blocks. State in Memory store is not committed as part of app state but maintained privately by each node
```

**File:** x/bank/keeper/send.go (L209-239)
```go
func (k BaseSendKeeper) SubUnlockedCoins(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Coins, checkNeg bool) error {
	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	lockedCoins := k.LockedCoins(ctx, addr)

	for _, coin := range amt {
		balance := k.GetBalance(ctx, addr, coin.Denom)
		if checkNeg {
			locked := sdk.NewCoin(coin.Denom, lockedCoins.AmountOf(coin.Denom))
			spendable := balance.Sub(locked)

			_, hasNeg := sdk.Coins{spendable}.SafeSub(sdk.Coins{coin})
			if hasNeg {
				return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "%s is smaller than %s", spendable, coin)
			}
		}

		var newBalance sdk.Coin
		if checkNeg {
			newBalance = balance.Sub(coin)
		} else {
			newBalance = balance.SubUnsafe(coin)
		}

		err := k.setBalance(ctx, addr, newBalance, checkNeg)
		if err != nil {
			return err
		}
	}
```

**File:** x/auth/ante/ante.go (L47-64)
```go
	anteDecorators := []sdk.AnteFullDecorator{
		sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()), // outermost AnteDecorator. SetUpContext must be called first
		sdk.DefaultWrappedAnteDecorator(NewRejectExtensionOptionsDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateBasicDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewTxTimeoutHeightDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateMemoDecorator(options.AccountKeeper)),
		NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ParamsKeeper.(paramskeeper.Keeper), options.TxFeeChecker),
		sdk.DefaultWrappedAnteDecorator(NewSetPubKeyDecorator(options.AccountKeeper)), // SetPubKeyDecorator must be called before all signature verification decorators
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
		NewIncrementSequenceDecorator(options.AccountKeeper),
	}
	anteHandler, anteDepGenerator := sdk.ChainAnteDecorators(anteDecorators...)

	return anteHandler, anteDepGenerator, nil
}
```

**File:** x/auth/ante/fee.go (L208-208)
```go
	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
```

**File:** types/module/module.go (L646-652)
```go
	for _, moduleName := range m.OrderEndBlockers {
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
		}
		moduleStartTime := time.Now()
		moduleValUpdates := module.EndBlock(ctx, req)
```

**File:** x/bank/keeper/invariants.go (L74-78)
```go
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
```

**File:** x/auth/ante/testutil_test.go (L176-177)
```go
		// Fee Collector actual account balance deposit coins into the fee collector account
		suite.app.BankKeeper.WriteDeferredBalances(suite.ctx)
```
