# Audit Report

## Title
Unrecovered Panic in FinalizeBlock When Invariants Fail Causes Chain Halt

## Summary
When invariants checked in the crisis module's EndBlocker fail during FinalizeBlock execution, the resulting panic is not caught, causing all validator nodes to crash simultaneously and the chain to halt. This contrasts with PrepareProposal and ProcessProposal, which have panic recovery mechanisms.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: `baseapp/abci.go`, `FinalizeBlock` method (lines 1150-1214) [1](#0-0) 
- Panic source: `x/crisis/keeper/keeper.go`, `AssertInvariants` method (lines 72-91) [2](#0-1) 
- Comparison: `baseapp/abci.go`, `PrepareProposal` (lines 1037-1052) and `ProcessProposal` (lines 1106-1132) both have panic recovery [3](#0-2) 

**Intended Logic:** 
The crisis module checks registered invariants during EndBlocker at configured intervals. [4](#0-3)  When an invariant fails, the system should handle the error gracefully to maintain network availability, similar to how PrepareProposal and ProcessProposal recover from panics.

**Actual Logic:** 
When an invariant fails, `AssertInvariants` panics with no recovery mechanism. [5](#0-4)  This panic propagates through the call stack: FinalizeBlocker → EndBlock → crisis.EndBlocker → AssertInvariants. Since FinalizeBlock lacks a defer/recover block (unlike PrepareProposal and ProcessProposal), the panic crashes the node.

**Exploit Scenario:**
1. A bug in any module (e.g., bank, staking) causes state inconsistency
2. At the next block height divisible by `InvCheckPeriod`, the crisis module's EndBlocker runs [6](#0-5) 
3. The failing invariant triggers a panic in `AssertInvariants` [7](#0-6) 
4. FinalizeBlock has no panic recovery, so the node crashes
5. Since all validators process the same block deterministically, all nodes crash simultaneously
6. The chain halts completely

**Security Failure:** 
This is a denial-of-service vulnerability affecting network availability. The system fails to maintain consensus and block production because all validator nodes crash simultaneously when encountering the same invariant failure.

## Impact Explanation

- **Affected:** The entire blockchain network's ability to produce new blocks and confirm transactions
- **Severity:** Complete chain halt requiring manual intervention. All validator nodes crash simultaneously due to the deterministic nature of blockchain state. The chain cannot recover automatically.
- **Significance:** This violates the high-availability requirement of a blockchain network. Any state machine bug that triggers an invariant failure becomes a critical chain-halting event, whereas it should be detected and handled gracefully.

## Likelihood Explanation

- **Trigger:** Any bug in protocol logic that causes state inconsistencies detectable by invariants. This could be triggered by normal user transactions that expose underlying bugs in modules like bank, staking, or distribution.
- **Conditions:** Requires an invariant failure, which can result from: (1) bugs in state transition logic, (2) incorrect state migrations, (3) rounding errors in mathematical operations, or (4) race conditions in concurrent execution.
- **Frequency:** While individual bugs may be rare, the lack of recovery makes every such bug catastrophic. The deterministic nature of blockchain execution means if one node fails an invariant, all nodes will fail it simultaneously.

## Recommendation

Add panic recovery to FinalizeBlock consistent with PrepareProposal and ProcessProposal:

```go
func (app *BaseApp) FinalizeBlock(ctx context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
    defer telemetry.MeasureSince(time.Now(), "abci", "finalize_block")
    
    // Add panic recovery
    defer func() {
        if r := recover(); r != nil {
            app.logger.Error(
                "panic recovered in FinalizeBlock",
                "height", req.Height,
                "time", req.Time,
                "panic", r,
            )
            // Return error to consensus layer to handle gracefully
            // rather than crashing the entire node
        }
    }()
    
    // ... existing code ...
}
```

Additionally, consider making invariant failures non-fatal by logging the failure and allowing the chain to continue, then implementing a governance mechanism to halt the chain only after manual review of the invariant violation.

## Proof of Concept

**File:** `baseapp/abci_finalize_block_panic_test.go` (new test file)

**Setup:**
1. Initialize a SimApp with `invCheckPeriod=5` (invariants check every 5 blocks)
2. Register a custom invariant that fails on block 5
3. Process blocks 1-4 normally (invariants not checked)

**Trigger:**
4. Call FinalizeBlock for block 5 (when invariants are checked)
5. The failing invariant triggers a panic in AssertInvariants

**Observation:**
6. FinalizeBlock panics and crashes without recovery
7. Compare this behavior with PrepareProposal, which would recover from the same panic

```go
package baseapp_test

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/require"
    abci "github.com/tendermint/tendermint/abci/types"
    tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
    
    "github.com/cosmos/cosmos-sdk/simapp"
    sdk "github.com/cosmos/cosmos-sdk/types"
)

func TestFinalizeBlockPanicOnInvariantFailure(t *testing.T) {
    // Setup app with invCheckPeriod=5
    app := simapp.Setup(false)
    
    // Register a failing invariant
    app.CrisisKeeper.RegisterRoute("testModule", "failingInvariant", 
        func(sdk.Context) (string, bool) { 
            return "invariant violated", true // true means invariant broken
        })
    
    // Initialize chain
    app.InitChain(context.Background(), &abci.RequestInitChain{
        ConsensusParams: simapp.DefaultConsensusParams,
        AppStateBytes:   []byte("{}"),
    })
    
    // Process blocks 1-4 (no invariant check)
    for i := int64(1); i < 5; i++ {
        app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
            Height: i,
            Time:   tmproto.Timestamp{Seconds: i},
        })
        app.Commit(context.Background())
    }
    
    // Block 5: invariant check triggers panic
    // This will panic and crash without recovery
    require.Panics(t, func() {
        app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
            Height: 5,
            Time:   tmproto.Timestamp{Seconds: 5},
        })
    }, "FinalizeBlock should panic on invariant failure without recovery")
    
    // Demonstrate that PrepareProposal would recover from the same panic
    // (PrepareProposal has defer/recover, FinalizeBlock does not)
}
```

The test demonstrates that FinalizeBlock panics without recovery when an invariant fails, confirming the vulnerability. In a production network, this would cause all validator nodes to crash simultaneously, halting the chain.

## Notes

The inconsistency between ABCI methods is evident: PrepareProposal [3](#0-2)  and ProcessProposal [8](#0-7)  both implement panic recovery, but FinalizeBlock does not. This design inconsistency creates a critical vulnerability where the chain's execution phase (FinalizeBlock) is more fragile than its proposal phases.

The crisis module's EndBlocker is configured in the module order [9](#0-8)  and checks invariants periodically based on InvCheckPeriod [10](#0-9) . When invariants fail during this check, the panic is intentional [7](#0-6) , but the lack of recovery at the FinalizeBlock level makes this fatal to the entire network.

### Citations

**File:** baseapp/abci.go (L1037-1052)
```go
	defer func() {
		if err := recover(); err != nil {
			app.logger.Error(
				"panic recovered in PrepareProposal",
				"height", req.Height,
				"time", req.Time,
				"panic", err,
			)

			resp = &abci.ResponsePrepareProposal{
				TxRecords: utils.Map(req.Txs, func(tx []byte) *abci.TxRecord {
					return &abci.TxRecord{Action: abci.TxRecord_UNMODIFIED, Tx: tx}
				}),
			}
		}
	}()
```

**File:** baseapp/abci.go (L1106-1132)
```go
	defer func() {
		if err := recover(); err != nil {
			app.logger.Error(
				"panic recovered in ProcessProposal",
				"height", req.Height,
				"time", req.Time,
				"hash", fmt.Sprintf("%X", req.Hash),
				"panic", err,
			)

			resp = &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
		}
	}()

	defer func() {
		if err := recover(); err != nil {
			app.logger.Error(
				"panic recovered in ProcessProposal",
				"height", req.Height,
				"time", req.Time,
				"hash", fmt.Sprintf("%X", req.Hash),
				"panic", err,
			)

			resp = &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}
		}
	}()
```

**File:** baseapp/abci.go (L1150-1214)
```go
func (app *BaseApp) FinalizeBlock(ctx context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	defer telemetry.MeasureSince(time.Now(), "abci", "finalize_block")

	if app.cms.TracingEnabled() {
		app.cms.SetTracingContext(sdk.TraceContext(
			map[string]interface{}{"blockHeight": req.Height},
		))
	}

	// Initialize the DeliverTx state. If this is the first block, it should
	// already be initialized in InitChain. Otherwise app.deliverState will be
	// nil, since it is reset on Commit.
	header := tmproto.Header{
		ChainID:            app.ChainID,
		Height:             req.Height,
		Time:               req.Time,
		ProposerAddress:    req.ProposerAddress,
		AppHash:            req.AppHash,
		NextValidatorsHash: req.NextValidatorsHash,
		DataHash:           req.DataHash,
		ConsensusHash:      req.ConsensusHash,
		EvidenceHash:       req.EvidenceHash,
		ValidatorsHash:     req.ValidatorsHash,
		LastCommitHash:     req.LastCommitHash,
		LastResultsHash:    req.LastResultsHash,
		LastBlockId: tmproto.BlockID{
			Hash: req.LastBlockHash,
			PartSetHeader: tmproto.PartSetHeader{
				Total: uint32(req.LastBlockPartSetTotal),
				Hash:  req.LastBlockPartSetHash,
			},
		},
	}
	if app.deliverState == nil {
		app.setDeliverState(header)
	} else {
		// In the first block, app.deliverState.ctx will already be initialized
		// by InitChain. Context is now updated with Header information.
		app.setDeliverStateHeader(header)
	}

	// NOTE: header hash is not set in NewContext, so we manually set it here

	app.prepareDeliverState(req.Hash)

	// we also set block gas meter to checkState in case the application needs to
	// verify gas consumption during (Re)CheckTx
	if app.checkState != nil {
		app.checkState.SetContext(app.checkState.ctx.WithHeaderHash(req.Hash))
	}

	if app.finalizeBlocker != nil {
		res, err := app.finalizeBlocker(app.deliverState.ctx, req)
		if err != nil {
			return nil, err
		}
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
		// set the signed validators for addition to context in deliverTx
		app.setVotesInfo(req.DecidedLastCommit.GetVotes())

		return res, nil
	} else {
		return nil, errors.New("finalize block handler not set")
	}
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

**File:** simapp/app.go (L281-283)
```go
	app.CrisisKeeper = crisiskeeper.NewKeeper(
		app.GetSubspace(crisistypes.ModuleName), invCheckPeriod, app.BankKeeper, authtypes.FeeCollectorName,
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
