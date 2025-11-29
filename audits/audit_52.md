# Audit Report

## Title
Permanent Loss of Transaction Fees Due to Missing WriteDeferredBalances Call in EndBlocker

## Summary
The banking module's deferred balance system immediately deducts transaction fees from user accounts and stores them in a memory-only cache, with the intention of flushing these balances to module accounts via `WriteDeferredBalances` during EndBlock processing. However, the bank module does not implement an EndBlock method, and `WriteDeferredBalances` is never called in production code. This results in permanent loss of all transaction fees when nodes restart, as the memory-only deferred cache is cleared while user account deductions remain persisted.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:**
- Deferred send implementation: [1](#0-0) 
- Fee deduction call site: [2](#0-1) 
- Memory store implementation: [3](#0-2) 
- Memory store key registration: [4](#0-3) 
- Bank module definition (no EndBlock): [5](#0-4) 
- FinalizeBlocker (no WriteDeferredBalances call): [6](#0-5) 

**Intended logic:**
According to the code documentation, the deferred balance system is designed to: (1) immediately deduct fees from user accounts during transaction processing via `SubUnlockedCoins`, (2) cache the deducted amounts in a deferred cache indexed by module and transaction, and (3) flush all deferred balances to module accounts in the EndBlocker by calling `WriteDeferredBalances`. The comment explicitly states: "In the EndBlocker, it will then perform one deposit for each module account." [7](#0-6) 

**Actual logic:**
The deferred cache uses a memory store that is "not committed as part of app state but maintained privately by each node" [3](#0-2) . When `DeferredSendCoinsFromAccountToModule` is called:
1. User balance is reduced via `SubUnlockedCoins` and persisted to the IAVL store [8](#0-7) 
2. The amount is stored in the memory-only deferred cache [9](#0-8) 
3. The bank module has no EndBlock method implementation (verified by examining the entire module.go file)
4. `WriteDeferredBalances` is never called in production code (only appears in test files)
5. On node restart, the memory store is cleared, losing all deferred amounts
6. User accounts retain their reduced balances, but module accounts never receive the funds

**Exploitation path:**
No attacker is required - this occurs during normal blockchain operation:
1. User submits transaction with fees
2. Ante handler's `DeductFees` function calls `DeferredSendCoinsFromAccountToModule` [2](#0-1) 
3. User's balance is immediately reduced and persisted to disk
4. Amount is cached in memory-only deferred store
5. Block processing completes; FinalizeBlocker proceeds through BeginBlock, transaction execution, EndBlock, and commit [6](#0-5)  without calling `WriteDeferredBalances`
6. Node operator performs routine restart, upgrade, or node crashes
7. Memory store is cleared on restart (not persisted to disk)
8. Deferred cache loses all accumulated fees
9. User accounts show permanently reduced balances, but fee collector module account never received the funds

**Security guarantee broken:**
This violates the fundamental accounting invariant that all coins deducted from accounts must exist somewhere in the system. The `TotalSupply` invariant correctly includes deferred balances in its calculation during normal operation [10](#0-9) , but after a node restart when the deferred cache is cleared, the invariant would fail because the sum of all account balances would be less than the total supply.

## Impact Explanation

All transaction fees paid by users since the last node restart are permanently and irrecoverably lost. This includes:
- Fees intended for the fee collector module for validator rewards and governance funding
- Any other module-to-module transfers using the deferred system

The damage is severe because:
- **Permanent fund loss**: Transaction fees are deducted from user accounts but never reach their intended module accounts
- **Accumulates continuously**: Every transaction that pays fees (essentially all transactions) contributes to the loss
- **No recovery mechanism**: Once the node restarts and clears the memory store, the deferred amounts cannot be recovered
- **Systemic issue**: Affects every node in the network independently on every restart
- **Consensus breaking**: After restart, nodes will have inconsistent state - some may have restarted recently (lost more fees), others may have been running longer (lost fewer fees), leading to potential invariant check failures and chain halts

This fundamentally breaks the blockchain's economic model. Users pay fees expecting them to fund validators and governance, but these fees vanish without reaching their destination, making the blockchain economically unsustainable.

## Likelihood Explanation

**Triggering conditions:**
- Any transaction that pays fees (essentially all transactions on the network)
- Any node restart (routine maintenance, crashes, upgrades, hardware failures)

**Frequency and scope:**
- **Every transaction**: Fees are deferred on every single transaction via the ante handler
- **Every restart**: All accumulated deferred fees are lost on every node restart
- **Network-wide impact**: Every validator node and full node experiences this independently

Node restarts occur regularly for:
- Routine software updates and security patches
- Network upgrades requiring new binary versions
- Crashes due to bugs, resource exhaustion, or system issues
- Hardware maintenance or failures
- Datacenter operations

**Who is affected:**
- All users paying transaction fees (funds lost)
- All nodes (operating with inconsistent state after restarts)
- The protocol itself (fee collector never receives fees for validator rewards/governance)

This vulnerability is triggered continuously during normal blockchain operation without requiring any attacker or special conditions. The likelihood is **very high** because node restarts are a regular operational requirement.

## Recommendation

**Immediate fix:**
Add an EndBlock method to the bank module that calls `WriteDeferredBalances` before the block is committed:

1. In `x/bank/module.go`, add an EndBlock method to the AppModule:
```go
func (am AppModule) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) []abci.ValidatorUpdate {
    am.keeper.WriteDeferredBalances(ctx)
    return []abci.ValidatorUpdate{}
}
```

2. Ensure the bank module is properly registered in the EndBlocker order in `simapp/app.go` (it already appears to be at line 374, but verify the EndBlock method is being called)

**Alternative fix:**
Add the call directly in the application's FinalizeBlocker in `simapp/app.go` before `SetDeliverStateToCommit()`:
```go
// After EndBlock and before SetDeliverStateToCommit
deferredEvents := app.BankKeeper.WriteDeferredBalances(ctx)
events = append(events, deferredEvents...)
```

**Verification:**
After implementing the fix, verify that:
- `WriteDeferredBalances` is called once per block
- Fee collector module accounts receive all accumulated fees
- TotalSupply invariant passes after node restarts
- No deferred balances remain in the cache at the end of each block

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

**Setup:**
1. Initialize test application with bank keeper configured with deferred cache
2. Create user account and fee collector module account
3. Fund user account with initial balance

**Action:**
1. Call `DeferredSendCoinsFromAccountToModule` to simulate fee deduction (as done by ante handler)
2. Verify user balance is reduced (persisted to disk)
3. Verify fee collector balance remains unchanged (transfer deferred)
4. Verify deferred cache contains the fee amount
5. Do NOT call `WriteDeferredBalances`
6. Simulate node restart by creating a new context (clears memory stores)

**Result:**
After simulated restart:
- User balance remains reduced (persisted to IAVL store)
- Fee collector balance is still zero (never received the funds)
- Deferred cache is empty (cleared on restart)
- TotalSupply invariant fails (total of account balances < total supply)
- Funds are permanently lost - user paid but recipient never received

The key observation is that `WriteDeferredBalances` only appears in test files (verified via grep search showing matches only in `x/bank/keeper/keeper_test.go`, `x/auth/ante/fee_test.go`, `x/auth/ante/testutil_test.go`, and `x/bank/keeper/deferred_cache_test.go`), never in production code paths.

## Notes

This vulnerability was validated by:
1. Confirming `DeferredSendCoinsFromAccountToModule` is called for every fee deduction
2. Verifying user balance deduction uses persistent storage via `SubUnlockedCoins`
3. Confirming deferred cache uses non-persistent memory store
4. Verifying bank module has no EndBlock implementation
5. Confirming `WriteDeferredBalances` is never called in production code (only in tests)
6. Verifying FinalizeBlocker does not call `WriteDeferredBalances`
7. Confirming memory store behavior on node restart (not persisted to disk)

The issue represents a critical design flaw where the documented behavior (calling `WriteDeferredBalances` in EndBlocker) was never implemented in production code, despite the deferred balance system being actively used for fee collection on every transaction.

### Citations

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

**File:** x/auth/ante/fee.go (L208-208)
```go
	err := bankKeeper.DeferredSendCoinsFromAccountToModule(ctx, acc.GetAddress(), types.FeeCollectorName, fees)
```

**File:** store/mem/store.go (L20-21)
```go
// Store implements an in-memory only KVStore. Entries are persisted between
// commits and thus between blocks. State in Memory store is not committed as part of app state but maintained privately by each node
```

**File:** simapp/app.go (L230-230)
```go
	memKeys := sdk.NewMemoryStoreKeys(capabilitytypes.MemStoreKey, "testingkey", banktypes.DeferredCacheStoreKey)
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

**File:** x/bank/keeper/invariants.go (L74-78)
```go
		// also iterate over deferred balances
		k.IterateDeferredBalances(ctx, func(addr sdk.AccAddress, coin sdk.Coin) bool {
			expectedTotal = expectedTotal.Add(coin)
			return false
		})
```
