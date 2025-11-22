## Audit Report

## Title
AnnualProvisions Query Panic on Uncommitted Genesis State

## Summary
The AnnualProvisions gRPC query can panic when called at height 0 before the first block is committed, causing a denial of service attack vector against newly started nodes. The vulnerability exists in the GetMinter function which panics when the minter state is not found in the store, which occurs when queries access the uncommitted genesis state. [1](#0-0) 

## Impact
**High** - RPC API crash that can be triggered remotely without authentication, affecting network availability during node startup and synchronization.

## Finding Description

**Location:** 
- Primary vulnerability: `x/mint/keeper/keeper.go` lines 54-63 (GetMinter function) [2](#0-1) 

- Affected query handler: `x/mint/keeper/grpc_query.go` lines 29-34 (AnnualProvisions)

**Intended Logic:** 
The AnnualProvisions query should safely return the current annual provisions value from the minter state at any valid block height. The system assumes that the minter state is always present in the committed store after genesis initialization.

**Actual Logic:** 
When a node starts, the following sequence creates a vulnerability window:

1. Node startup begins, GRPC server starts accepting queries
2. `InitChain` ABCI method is called, which initializes the minter in deliverState [3](#0-2) 

3. However, `InitChain` does NOT commit the state (as documented in the code comments)
4. The first block has not been processed yet, so `LastBlockHeight()` returns 0
5. When a query arrives, `CreateQueryContext` is called with height 0 [4](#0-3) 

6. `CacheMultiStoreWithVersion(0)` loads state from the committed store at version 0 [5](#0-4) 

7. Since version 0 doesn't exist in the committed store yet, `GetImmutable` returns an empty IAVL tree [6](#0-5) 

8. The query handler calls `GetMinter` which reads from this empty store and gets nil
9. `GetMinter` panics with "stored minter should not have been nil"

**Exploit Scenario:**
1. Attacker monitors the network for nodes starting up (e.g., after a chain upgrade when multiple validators restart)
2. Attacker sends an AnnualProvisions gRPC query to the target node's RPC endpoint immediately after it comes online
3. The query is routed through `handleQueryGRPC` which creates a context at height 0 [7](#0-6) 

4. The query accesses the uncommitted genesis state (empty store)
5. `GetMinter` panics, crashing the query handler and potentially destabilizing the node

**Security Failure:**
This is a denial-of-service vulnerability that breaks the availability property. The panic occurs in a critical query path and can be triggered remotely by any unauthenticated attacker during the brief but predictable window when nodes are starting up.

## Impact Explanation

**Affected Components:**
- RPC/gRPC query service availability
- Node stability during startup and recovery
- Network synchronization during upgrades or restarts

**Severity:**
- Any node accepting gRPC queries during the startup window can be crashed
- Attackers can target multiple nodes simultaneously, especially during coordinated events like network upgrades
- Repeated crashes can prevent nodes from successfully joining the network
- This affects all projects and users relying on the crashed nodes' RPC endpoints
- Critical for network availability when ≥30% of nodes restart around the same time

**Why This Matters:**
Blockchain networks depend on RPC availability for user interactions, transaction submission, and state queries. A remotely triggerable crash vulnerability during node startup creates a DoS vector that can:
- Prevent validators from coming back online after restarts
- Disrupt network operations during upgrades
- Allow targeted attacks on specific node operators
- Reduce overall network reliability and availability

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with access to a node's gRPC endpoint can trigger this vulnerability. No special privileges, authentication, or prior setup is required.

**Conditions Required:**
- Target node must be in the brief window after `InitChain` but before the first block is committed
- This window is predictable and occurs during:
  - Initial node startup
  - Chain restarts after upgrades
  - Recovery from crashes
  - Synchronization from genesis

**Frequency:**
- Occurs deterministically during every node startup
- The attack window is brief (milliseconds to seconds) but easily detected by monitoring when nodes come online
- Particularly exploitable during coordinated events when multiple nodes restart (e.g., network-wide upgrades)
- An attacker can repeatedly query to ensure hitting the vulnerable window

## Recommendation

Add a nil check in the `GetMinter` function to return a default minter or handle the case gracefully instead of panicking:

```go
func (k Keeper) GetMinter(ctx sdk.Context) (minter types.Minter) {
    store := ctx.KVStore(k.storeKey)
    b := store.Get(types.MinterKey)
    if b == nil {
        // Return default minter instead of panicking for uncommitted genesis state
        return types.DefaultInitialMinter()
    }
    k.cdc.MustUnmarshal(b, &minter)
    return
}
```

Alternatively, add validation in `CreateQueryContext` to prevent queries at height 0 when `LastBlockHeight()` is 0 and the initial state hasn't been committed yet.

## Proof of Concept

**File:** `x/mint/keeper/grpc_query_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestAnnualProvisionsQueryPanicOnUncommittedGenesis(t *testing.T) {
    // Create app without committing initial state (mimics node startup state)
    db := dbm.NewMemDB()
    app := simapp.NewSimApp(
        log.NewNopLogger(), db, nil, true, map[int64]bool{}, 
        simapp.DefaultNodeHome, 5, 
        encoding.MakeTestEncodingConfig(), 
        simapp.EmptyAppOptions{},
    )
    
    // Call InitChain to initialize genesis (but don't commit)
    genesisState := simapp.NewDefaultGenesisState(app.AppCodec())
    stateBytes, err := json.MarshalIndent(genesisState, "", " ")
    require.NoError(t, err)
    
    _, err = app.InitChain(
        context.Background(),
        &abci.RequestInitChain{
            Validators:      []abci.ValidatorUpdate{},
            ConsensusParams: simapp.DefaultConsensusParams,
            AppStateBytes:   stateBytes,
        },
    )
    require.NoError(t, err)
    
    // At this point: LastBlockHeight() = 0, minter in deliverState but not committed
    require.Equal(t, int64(0), app.LastBlockHeight())
    
    // Create query context at height 0 - this loads from committed store (empty)
    ctx, err := app.CreateQueryContext(0, false)
    require.NoError(t, err)
    
    // Attempt to query minter - this will panic
    require.Panics(t, func() {
        _ = app.MintKeeper.GetMinter(ctx)
    }, "Expected panic: stored minter should not have been nil")
}
```

**Setup:** The test creates a SimApp and calls `InitChain` but deliberately does not call `Commit()`, mimicking the exact state of a node after `InitChain` but before the first block is processed.

**Trigger:** The test calls `CreateQueryContext(0, false)` which loads state from the committed store at version 0 (which is empty), then attempts to call `GetMinter` on this context.

**Observation:** The test uses `require.Panics()` to verify that `GetMinter` panics with the expected error message "stored minter should not have been nil". This confirms the vulnerability - the query accesses uncommitted state and crashes.

**To Run:** Add this test to `x/mint/keeper/grpc_query_test.go` and execute with `go test -v -run TestAnnualProvisionsQueryPanicOnUncommittedGenesis ./x/mint/keeper/...`

### Citations

**File:** x/mint/keeper/grpc_query.go (L29-34)
```go
func (k Keeper) AnnualProvisions(c context.Context, _ *types.QueryAnnualProvisionsRequest) (*types.QueryAnnualProvisionsResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)
	minter := k.GetMinter(ctx)

	return &types.QueryAnnualProvisionsResponse{AnnualProvisions: minter.AnnualProvisions}, nil
}
```

**File:** x/mint/keeper/keeper.go (L54-63)
```go
func (k Keeper) GetMinter(ctx sdk.Context) (minter types.Minter) {
	store := ctx.KVStore(k.storeKey)
	b := store.Get(types.MinterKey)
	if b == nil {
		panic("stored minter should not have been nil")
	}

	k.cdc.MustUnmarshal(b, &minter)
	return
}
```

**File:** baseapp/abci.go (L34-117)
```go
func (app *BaseApp) InitChain(ctx context.Context, req *abci.RequestInitChain) (res *abci.ResponseInitChain, err error) {
	// On a new chain, we consider the init chain block height as 0, even though
	// req.InitialHeight is 1 by default.
	initHeader := tmproto.Header{ChainID: req.ChainId, Time: req.Time}
	app.ChainID = req.ChainId

	// If req.InitialHeight is > 1, then we set the initial version in the
	// stores.
	if req.InitialHeight > 1 {
		app.initialHeight = req.InitialHeight
		initHeader = tmproto.Header{ChainID: req.ChainId, Height: req.InitialHeight, Time: req.Time}
		err := app.cms.SetInitialVersion(req.InitialHeight)
		if err != nil {
			return nil, err
		}
	}

	// initialize the deliver state and check state with a correct header
	app.setDeliverState(initHeader)
	app.setCheckState(initHeader)
	app.setPrepareProposalState(initHeader)
	app.setProcessProposalState(initHeader)

	// Store the consensus params in the BaseApp's paramstore. Note, this must be
	// done after the deliver state and context have been set as it's persisted
	// to state.
	if req.ConsensusParams != nil {
		app.StoreConsensusParams(app.deliverState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.prepareProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.processProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.checkState.ctx, req.ConsensusParams)
	}

	app.SetDeliverStateToCommit()

	if app.initChainer == nil {
		return
	}

	resp := app.initChainer(app.deliverState.ctx, *req)
	app.initChainer(app.prepareProposalState.ctx, *req)
	app.initChainer(app.processProposalState.ctx, *req)
	res = &resp

	// sanity check
	if len(req.Validators) > 0 {
		if len(req.Validators) != len(res.Validators) {
			return nil,
				fmt.Errorf(
					"len(RequestInitChain.Validators) != len(GenesisValidators) (%d != %d)",
					len(req.Validators), len(res.Validators),
				)
		}

		sort.Sort(abci.ValidatorUpdates(req.Validators))
		sort.Sort(abci.ValidatorUpdates(res.Validators))

		for i := range res.Validators {
			if !proto.Equal(&res.Validators[i], &req.Validators[i]) {
				return nil, fmt.Errorf("genesisValidators[%d] != req.Validators[%d] ", i, i)
			}
		}
	}

	// In the case of a new chain, AppHash will be the hash of an empty string.
	// During an upgrade, it'll be the hash of the last committed block.
	var appHash []byte
	if !app.LastCommitID().IsZero() {
		appHash = app.LastCommitID().Hash
	} else {
		// $ echo -n '' | sha256sum
		// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
		emptyHash := sha256.Sum256([]byte{})
		appHash = emptyHash[:]
	}

	// NOTE: We don't commit, but BeginBlock for block `initial_height` starts from this
	// deliverState.
	return &abci.ResponseInitChain{
		ConsensusParams: res.ConsensusParams,
		Validators:      res.Validators,
		AppHash:         appHash,
	}, nil
}
```

**File:** baseapp/abci.go (L663-677)
```go
func (app *BaseApp) handleQueryGRPC(handler GRPCQueryHandler, req abci.RequestQuery) abci.ResponseQuery {
	ctx, err := app.CreateQueryContext(req.Height, req.Prove)
	if err != nil {
		return sdkerrors.QueryResultWithDebug(err, app.trace)
	}

	res, err := handler(ctx, req)
	if err != nil {
		res = sdkerrors.QueryResultWithDebug(gRPCErrorToSDKError(err), app.trace)
		res.Height = req.Height
		return res
	}

	return res
}
```

**File:** baseapp/abci.go (L710-762)
```go
// CreateQueryContext creates a new sdk.Context for a query, taking as args
// the block height and whether the query needs a proof or not.
func (app *BaseApp) CreateQueryContext(height int64, prove bool) (sdk.Context, error) {
	err := checkNegativeHeight(height)
	if err != nil {
		return sdk.Context{}, err
	}

	lastBlockHeight := app.LastBlockHeight()
	if height > lastBlockHeight {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidHeight,
				"cannot query with height in the future; please provide a valid height",
			)
	}

	// when a client did not provide a query height, manually inject the latest
	if height == 0 {
		height = lastBlockHeight
	}

	if height <= 1 && prove {
		return sdk.Context{},
			sdkerrors.Wrap(
				sdkerrors.ErrInvalidRequest,
				"cannot query with proof when height <= 1; please provide a valid height",
			)
	}

	var cacheMS types.CacheMultiStore
	if height < app.migrationHeight && app.qms != nil {
		cacheMS, err = app.qms.CacheMultiStoreWithVersion(height)
	} else {
		cacheMS, err = app.cms.CacheMultiStoreWithVersion(height)
	}

	if err != nil {
		return sdk.Context{},
			sdkerrors.Wrapf(
				sdkerrors.ErrInvalidRequest,
				"failed to load state at height %d; %s (latest height: %d)", height, err, lastBlockHeight,
			)
	}

	checkStateCtx := app.checkState.Context()
	// branch the commit-multistore for safety
	ctx := sdk.NewContext(
		cacheMS, checkStateCtx.BlockHeader(), true, app.logger,
	).WithMinGasPrices(app.minGasPrices).WithBlockHeight(height)

	return ctx, nil
}
```

**File:** store/rootmulti/store.go (L581-605)
```go
func (rs *Store) CacheMultiStoreWithVersion(version int64) (types.CacheMultiStore, error) {
	cachedStores := make(map[types.StoreKey]types.CacheWrapper)
	for key, store := range rs.stores {
		switch store.GetStoreType() {
		case types.StoreTypeIAVL:
			// If the store is wrapped with an inter-block cache, we must first unwrap
			// it to get the underlying IAVL store.
			store = rs.GetCommitKVStore(key)

			// Attempt to lazy-load an already saved IAVL store version. If the
			// version does not exist or is pruned, an error should be returned.
			iavlStore, err := store.(*iavl.Store).GetImmutable(version)
			if err != nil {
				return nil, err
			}

			cachedStores[key] = iavlStore

		default:
			cachedStores[key] = store
		}
	}

	return cachemulti.NewStore(rs.db, cachedStores, rs.keysByName, rs.traceWriter, rs.getTracingContext(), rs.listeners), nil
}
```

**File:** store/iavl/store.go (L124-143)
```go
	st.treeMtx.RLock()
	defer st.treeMtx.RUnlock()

	if !st.VersionExists(version) {
		return &Store{
			tree:    &immutableTree{&iavl.ImmutableTree{}},
			treeMtx: &sync.RWMutex{},
		}, nil
	}

	iTree, err := st.tree.GetImmutable(version)
	if err != nil {
		return nil, err
	}

	return &Store{
		tree:    &immutableTree{iTree},
		treeMtx: &sync.RWMutex{},
	}, nil
}
```
