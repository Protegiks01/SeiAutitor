## Title
Missing Automatic Genesis Validation Allows Chain Initialization DoS via Malformed Genesis Transactions

## Summary
The `DeliverGenTxs` function panics when encountering malformed genesis transactions that fail JSON decoding, but genesis validation is not automatically performed during chain initialization. An attacker who can influence the genesis file content (e.g., through social engineering, compromised distribution, or MITM attacks) can include malformed genesis transactions that cause all nodes to panic during `InitChain`, permanently preventing the network from starting. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** The vulnerability exists in the `DeliverGenTxs` function in `x/genutil/gentx.go` at lines 103-106, combined with the lack of automatic validation in the `InitChain` flow. [2](#0-1) 

**Intended Logic:** Genesis transactions should be validated before chain initialization to ensure they can be successfully decoded and executed. The system provides a `ValidateGenesis` function that checks each genesis transaction can be properly decoded. [3](#0-2) 

**Actual Logic:** While `ValidateGenesis` exists, it is only exposed as a manual CLI command and is NOT automatically called during the chain initialization process. During `InitChain`, the module manager directly calls `InitGenesis` for the genutil module, which then calls `DeliverGenTxs` without prior validation. [4](#0-3) 

When `DeliverGenTxs` encounters a genesis transaction that fails JSON decoding (e.g., malformed JSON structure, invalid protobuf data), it immediately panics rather than returning an error. This panic is not caught by any recovery mechanism in the `InitChain` flow. [5](#0-4) 

**Exploit Scenario:**
1. An attacker creates or modifies a genesis.json file to include malformed genesis transactions in the `GenTxs` field (e.g., invalid JSON structure, corrupted base64 data, missing required protobuf fields)
2. The attacker distributes this malformed genesis file to network participants through:
   - Social engineering (convincing validators to use a malicious genesis file)
   - Compromising the genesis file repository or distribution channel
   - Man-in-the-middle attacks during genesis file download
   - Providing a manually crafted genesis file that bypasses the `collect-gentxs` validation process
3. When validators start their nodes with this genesis file, Tendermint calls `InitChain`
4. `InitChain` calls the module manager's `InitGenesis`, which processes modules in order
5. When the genutil module's `InitGenesis` is called, it invokes `DeliverGenTxs`
6. `DeliverGenTxs` attempts to decode the malformed genesis transaction at line 103
7. The decoder returns an error, causing a panic at line 105
8. The panic propagates up through the call stack (no recovery exists)
9. The node process crashes during initialization
10. The chain cannot start, resulting in a permanent denial of service

**Security Failure:** This breaks the availability security property. The system fails to gracefully handle invalid genesis data, allowing an attacker to cause a complete network shutdown by distributing a malformed genesis file before chain launch.

## Impact Explanation

**Assets/Processes Affected:** The entire blockchain network's availability is affected. No transactions can be processed, no blocks can be produced, and the chain cannot achieve consensus.

**Severity of Damage:**
- **Total Network Shutdown:** If all validators use the same malformed genesis file (as is typical in coordinated network launches), the entire network fails to initialize
- **Permanent DoS:** Unlike runtime errors that might be recoverable through restarts, genesis initialization failures are permanent with that genesis file - the chain cannot start at all
- **No Recovery Without Coordination:** Fixing the issue requires re-distributing a corrected genesis file to all participants and coordinating a new launch, which is time-consuming and damages network credibility
- **Launch Window Exploit:** This is particularly critical during network launches when all validators are starting simultaneously with a coordinated genesis file

**System Reliability Impact:** This vulnerability allows a single malformed genesis file to prevent an entire blockchain network from ever starting, which is catastrophic for network availability. Unlike post-launch attacks that might affect a subset of nodes, this affects 100% of nodes attempting to start with the malformed genesis.

## Likelihood Explanation

**Who Can Trigger:** Any attacker who can influence the genesis.json file content that validators use. This includes:
- Attackers with access to genesis file distribution infrastructure
- Malicious insiders involved in genesis coordination
- Network attackers performing MITM on genesis file downloads
- Social engineers convincing validators to use a specific genesis file

**Required Conditions:**
- The attack must occur before or during the initial chain launch
- Validators must not run the optional `validate-genesis` CLI command before starting their nodes
- The malformed genesis transactions must be in the `GenTxs` array in the genesis.json file

**Frequency/Likelihood:**
- **Medium-High Likelihood:** During network launches, genesis files are often distributed through centralized channels (GitHub repos, official websites, coordination channels) which present attack opportunities
- **High Impact Window:** The vulnerability is most critical during the initial launch window when all validators are coordinating to start simultaneously
- **Realistic Attack Vector:** Genesis file tampering is a realistic threat model, especially for networks where genesis coordination happens through semi-trusted channels
- **Human Factor:** Node operators frequently skip manual validation steps, relying on the system to validate automatically

## Recommendation

Implement automatic genesis validation before processing genesis transactions during `InitChain`. Specifically:

1. **Modify `InitGenesis` to validate before delivery:** In `x/genutil/genesis.go`, call `ValidateGenesis` before calling `DeliverGenTxs`:

```go
func InitGenesis(
    ctx sdk.Context, stakingKeeper types.StakingKeeper,
    deliverTx deliverTxfn, genesisState types.GenesisState,
    txEncodingConfig client.TxEncodingConfig,
) (validators []abci.ValidatorUpdate, err error) {
    if len(genesisState.GenTxs) > 0 {
        // Validate genesis transactions before attempting delivery
        if err := types.ValidateGenesis(&genesisState, txEncodingConfig.TxJSONDecoder()); err != nil {
            return nil, fmt.Errorf("invalid genesis transactions: %w", err)
        }
        validators, err = DeliverGenTxs(ctx, genesisState.GenTxs, stakingKeeper, deliverTx, txEncodingConfig)
    }
    return
}
```

2. **Return errors instead of panicking:** Modify `DeliverGenTxs` to return errors instead of panicking, allowing graceful error handling:

```go
func DeliverGenTxs(...) ([]abci.ValidatorUpdate, error) {
    for _, genTx := range genTxs {
        tx, err := txEncodingConfig.TxJSONDecoder()(genTx)
        if err != nil {
            return nil, fmt.Errorf("failed to decode genesis transaction: %w", err)
        }
        // ... rest of the function
    }
    // ...
}
```

This ensures that malformed genesis transactions are caught early with proper error messages, preventing chain initialization with invalid genesis data while allowing operators to diagnose and fix the issue.

## Proof of Concept

**Test File:** `x/genutil/gentx_test.go`

Add the following test function to demonstrate the vulnerability:

```go
func (suite *GenTxTestSuite) TestDeliverGenTxsMalformedPanic() {
    suite.SetupTest()
    
    // Create a malformed genesis transaction that will fail JSON decoding
    // This simulates an attacker providing corrupted JSON in the genesis file
    malformedGenTx := json.RawMessage(`{"invalid_json_structure": true, "missing_required_fields`)
    
    genTxs := []json.RawMessage{malformedGenTx}
    
    ctx := suite.app.GetContextForDeliverTx([]byte{})
    
    // This should panic because the malformed GenTx cannot be decoded
    // In a real chain initialization, this panic would crash the node
    suite.Require().Panics(func() {
        genutil.DeliverGenTxs(
            ctx, 
            genTxs, 
            suite.app.StakingKeeper, 
            suite.app.BaseApp.DeliverTx,
            suite.encodingConfig.TxConfig,
        )
    }, "DeliverGenTxs should panic when encountering malformed genesis transaction")
}
```

**Setup:** The test uses the existing `GenTxTestSuite` setup which initializes a simapp instance with all necessary keepers and encoding configuration.

**Trigger:** The test creates a malformed JSON genesis transaction (incomplete/invalid JSON structure) and passes it to `DeliverGenTxs`. This simulates what would happen during chain initialization if an attacker included such malformed data in the genesis.json file.

**Observation:** The test verifies that `DeliverGenTxs` panics when encountering the malformed transaction. This panic demonstrates the vulnerability - in a real chain initialization scenario, this panic would crash the node and prevent the chain from starting. The existing test framework already has a similar test at lines 205-281 that validates the panic behavior, confirming this is the actual system behavior. [6](#0-5) 

**Notes:**
- The vulnerability is confirmed by the existing test suite which explicitly tests for panics in `DeliverGenTxs` (line 272-277)
- The `ValidateGenesis` CLI command exists but is optional and not automatically invoked during chain startup
- The attack window is during genesis file distribution before chain launch, making this a realistic threat model for new network deployments

### Citations

**File:** x/genutil/gentx.go (L96-117)
```go
func DeliverGenTxs(
	ctx sdk.Context, genTxs []json.RawMessage,
	stakingKeeper types.StakingKeeper, deliverTx deliverTxfn,
	txEncodingConfig client.TxEncodingConfig,
) ([]abci.ValidatorUpdate, error) {

	for _, genTx := range genTxs {
		tx, err := txEncodingConfig.TxJSONDecoder()(genTx)
		if err != nil {
			panic(err)
		}

		bz, err := txEncodingConfig.TxEncoder()(tx)
		if err != nil {
			panic(err)
		}

		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
	}
```

**File:** x/genutil/types/genesis_state.go (L98-120)
```go
// ValidateGenesis validates GenTx transactions
func ValidateGenesis(genesisState *GenesisState, txJSONDecoder sdk.TxDecoder) error {
	for i, genTx := range genesisState.GenTxs {
		var tx sdk.Tx
		tx, err := txJSONDecoder(genTx)
		if err != nil {
			return err
		}

		msgs := tx.GetMsgs()
		if len(msgs) != 1 {
			return errors.New(
				"must provide genesis Tx with exactly 1 CreateValidator message")
		}

		// TODO: abstract back to staking
		if _, ok := msgs[0].(*stakingtypes.MsgCreateValidator); !ok {
			return fmt.Errorf(
				"genesis transaction %v does not contain a MsgCreateValidator", i)
		}
	}
	return nil
}
```

**File:** x/genutil/genesis.go (L12-21)
```go
func InitGenesis(
	ctx sdk.Context, stakingKeeper types.StakingKeeper,
	deliverTx deliverTxfn, genesisState types.GenesisState,
	txEncodingConfig client.TxEncodingConfig,
) (validators []abci.ValidatorUpdate, err error) {
	if len(genesisState.GenTxs) > 0 {
		validators, err = DeliverGenTxs(ctx, genesisState.GenTxs, stakingKeeper, deliverTx, txEncodingConfig)
	}
	return
}
```

**File:** baseapp/abci.go (L32-117)
```go
// InitChain implements the ABCI interface. It runs the initialization logic
// directly on the CommitMultiStore.
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

**File:** x/genutil/gentx_test.go (L205-281)
```go
func (suite *GenTxTestSuite) TestDeliverGenTxs() {
	var (
		genTxs    []json.RawMessage
		txBuilder = suite.encodingConfig.TxConfig.NewTxBuilder()
	)

	testCases := []struct {
		msg      string
		malleate func()
		expPass  bool
	}{
		{
			"no signature supplied",
			func() {
				err := txBuilder.SetMsgs(suite.msg1)
				suite.Require().NoError(err)

				genTxs = make([]json.RawMessage, 1)
				tx, err := suite.encodingConfig.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
				suite.Require().NoError(err)
				genTxs[0] = tx
			},
			false,
		},
		{
			"success",
			func() {
				_ = suite.setAccountBalance(addr1, 50)
				_ = suite.setAccountBalance(addr2, 1)

				msg := banktypes.NewMsgSend(addr1, addr2, sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 1)})
				tx, err := helpers.GenTx(
					suite.encodingConfig.TxConfig,
					[]sdk.Msg{msg},
					sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)},
					helpers.DefaultGenTxGas,
					suite.ctx.ChainID(),
					[]uint64{0},
					[]uint64{0},
					priv1,
				)
				suite.Require().NoError(err)

				genTxs = make([]json.RawMessage, 1)
				genTx, err := suite.encodingConfig.TxConfig.TxJSONEncoder()(tx)
				suite.Require().NoError(err)
				genTxs[0] = genTx
			},
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest()

			tc.malleate()

			ctx := suite.app.GetContextForDeliverTx([]byte{})
			if tc.expPass {
				suite.Require().NotPanics(func() {
					genutil.DeliverGenTxs(
						ctx, genTxs, suite.app.StakingKeeper, suite.app.BaseApp.DeliverTx,
						suite.encodingConfig.TxConfig,
					)
				})
			} else {
				suite.Require().Panics(func() {
					genutil.DeliverGenTxs(
						ctx, genTxs, suite.app.StakingKeeper, suite.app.BaseApp.DeliverTx,
						suite.encodingConfig.TxConfig,
					)
				})
			}
		})
	}
}
```
