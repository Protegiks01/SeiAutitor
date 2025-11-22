# Audit Report

## Title
Genesis Transaction Validation Bypass Allows Panic or Arbitrary Message Execution During Chain Initialization

## Summary
The `ValidateGenesis` function in the genutil module, which safely validates that genesis transactions contain only `MsgCreateValidator` messages, is never called during chain initialization. [1](#0-0)  This allows a maliciously crafted genesis file with non-validator messages to bypass validation and either cause a chain-wide panic or execute arbitrary messages during genesis.

## Impact
High

## Finding Description

**Location:** 
- Validation logic: [2](#0-1) 
- Chain initialization: [3](#0-2) 
- Transaction delivery: [4](#0-3) 
- InitChain flow: [5](#0-4) 
- InitChainer: [6](#0-5) 

**Intended Logic:** 
Genesis transactions (gentxs) should only contain `MsgCreateValidator` messages to create initial validators. The `ValidateGenesis` function exists to enforce this invariant by checking message types with safe type assertions. [1](#0-0) 

**Actual Logic:** 
During chain initialization, the flow is: `InitChain` → `InitChainer` → `Manager.InitGenesis` → `genutil.InitGenesis` → `DeliverGenTxs`. None of these steps call `ValidateGenesis`. [7](#0-6)  The `DeliverGenTxs` function directly decodes and delivers gentxs without validating message types. [8](#0-7)  If a transaction fails, it panics. [9](#0-8) 

**Exploit Scenario:**
1. During coordinated chain launch, a malicious coordinator or compromised genesis generation process includes gentxs with non-`MsgCreateValidator` messages (e.g., `MsgSend`, `MsgDelegate`)
2. The genesis file is distributed to all validators
3. When validators start their nodes, `InitChain` is called
4. `DeliverGenTxs` processes the malicious gentxs without validation
5. Two outcomes:
   - If the message fails validation in `DeliverTx`, all nodes panic simultaneously [9](#0-8) 
   - If the message is valid (e.g., a properly funded `MsgSend`), it executes, violating the genesis invariant

**Security Failure:** 
The security invariant that "genesis transactions only create validators" is not enforced during chain initialization. This breaks both availability (panic scenario) and correctness (arbitrary message execution scenario).

## Impact Explanation

**Affected Components:**
- Network availability: All nodes in the network
- Genesis state integrity: Initial blockchain state

**Damage Severity:**
- **Panic scenario:** Total network shutdown - no node can initialize, preventing the chain from ever starting. This requires a hard fork to fix the genesis file and restart.
- **Execution scenario:** Arbitrary valid messages execute during genesis (e.g., token transfers, delegations), creating unintended initial state that violates protocol assumptions. The existing test suite confirms non-validator messages can be delivered successfully. [10](#0-9) 

**System Impact:**
This represents a critical gap between validation logic (which exists) and enforcement (which doesn't happen). Even in coordinated launches with trusted validators, this creates a single point of failure during genesis generation where a bug or compromise can cause catastrophic network failure.

## Likelihood Explanation

**Who can trigger:**
Anyone with the ability to influence the genesis file content during chain launch - typically the genesis coordinator or through compromise of the gentx collection/aggregation process.

**Conditions required:**
- Occurs during initial chain launch
- Requires a malicious or malformed gentx to be included in the distributed genesis file
- All validators using the same compromised genesis file would be affected

**Frequency:**
While this requires specific conditions during genesis creation, the impact is catastrophic (entire network fails to start). The vulnerability exists because validation is implemented but not enforced at the critical execution point. The `ValidateGenesis` CLI command exists [11](#0-10)  but is optional and not part of the mandatory InitChain flow.

## Recommendation

Enforce genesis validation during chain initialization by calling `ValidateGenesis` before processing gentxs:

1. In `genutil.InitGenesis` function [12](#0-11) , add validation before calling `InitGenesis`:
   - Call `types.ValidateGenesis(&genesisState, txJSONDecoder)` 
   - Panic with a clear error message if validation fails
   
2. Alternatively, add the check directly in `DeliverGenTxs` [4](#0-3)  before processing each gentx:
   - Decode the transaction
   - Verify messages contain exactly one `MsgCreateValidator`
   - Panic early with a descriptive error if validation fails

This ensures the safety check is enforced at the critical moment when genesis is actually processed, not just as an optional CLI validation.

## Proof of Concept

**File:** `x/genutil/gentx_test.go`

**Test Function:** Add new test `TestDeliverGenTxsWithNonValidatorMessage`

**Setup:**
1. Create a genesis state with a gentx containing a `MsgDelegate` instead of `MsgCreateValidator`
2. Set up accounts with sufficient balances
3. Initialize the application context

**Trigger:**
1. Encode the malicious gentx into JSON format
2. Call `genutil.DeliverGenTxs()` with the malicious gentx list
3. Observe that the function either:
   - Panics (if the message fails validation), demonstrating the DOS vulnerability
   - Succeeds (if the message is valid), demonstrating the arbitrary execution vulnerability

**Observation:**
The test demonstrates that `DeliverGenTxs` processes non-`MsgCreateValidator` messages without validation, confirming the vulnerability. The existing test at lines 230-254 already proves a `MsgSend` can be successfully delivered, violating the genesis invariant. [10](#0-9) 

To create an explicit panic scenario, craft a gentx with a message that will fail (e.g., `MsgDelegate` with invalid validator address or insufficient funds). The panic at line 115 of `gentx.go` [9](#0-8)  will crash the node, and since all nodes process the same genesis, the entire network fails to initialize.

### Citations

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

**File:** x/genutil/genesis.go (L11-21)
```go
// InitGenesis - initialize accounts and deliver genesis transactions
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

**File:** x/genutil/gentx.go (L96-129)
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

	legacyUpdates, err := stakingKeeper.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		return nil, err
	}
	return utils.Map(legacyUpdates, func(v abci.ValidatorUpdate) abci.ValidatorUpdate {
		return abci.ValidatorUpdate{
			PubKey: v.PubKey,
			Power:  v.Power,
		}
	}), nil
}
```

**File:** baseapp/abci.go (L34-76)
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
```

**File:** simapp/app.go (L591-599)
```go
// InitChainer application update at chain initialization
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
	return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
}
```

**File:** x/genutil/gentx_test.go (L230-254)
```go
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
```

**File:** x/genutil/client/cli/validate_genesis.go (L21-66)
```go
// ValidateGenesisCmd takes a genesis file, and makes sure that it is valid.
func ValidateGenesisCmd(mbm module.BasicManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate-genesis [file]",
		Args:  cobra.RangeArgs(0, 1),
		Short: "validates the genesis file at the default location or at the location passed as an arg",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			serverCtx := server.GetServerContextFromCmd(cmd)
			clientCtx := client.GetClientContextFromCmd(cmd)

			cdc := clientCtx.Codec

			isStream, err := cmd.Flags().GetBool(flagStreaming)
			if err != nil {
				panic(err)
			}

			if isStream {
				return validateGenesisStream(mbm, cmd, args)
			}

			// Load default if passed no args, otherwise load passed file
			var genesis string
			if len(args) == 0 {
				genesis = serverCtx.Config.GenesisFile()
			} else {
				genesis = args[0]
			}

			genDoc, err := validateGenDoc(genesis)
			if err != nil {
				return err
			}

			var genState map[string]json.RawMessage
			if err = json.Unmarshal(genDoc.AppState, &genState); err != nil {
				return fmt.Errorf("error unmarshalling genesis doc %s: %s", genesis, err.Error())
			}

			if err = mbm.ValidateGenesis(cdc, clientCtx.TxConfig, genState); err != nil {
				return fmt.Errorf("error validating genesis file %s: %s", genesis, err.Error())
			}

			fmt.Printf("File at %s is a valid genesis file\n", genesis)
			return nil
		},
```

**File:** x/genutil/module.go (L106-114)
```go
func (am AppModule) InitGenesis(ctx sdk.Context, cdc codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
	var genesisState types.GenesisState
	cdc.MustUnmarshalJSON(data, &genesisState)
	validators, err := InitGenesis(ctx, am.stakingKeeper, am.deliverTx, genesisState, am.txEncodingConfig)
	if err != nil {
		panic(err)
	}
	return validators
}
```
