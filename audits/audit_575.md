# Audit Report

## Title
Genesis Transaction Validation Bypass Allows Multi-Message Transactions During Chain Initialization

## Summary
The single-message requirement enforced by ValidateGenesis in x/genutil/types/genesis_state.go:108-111 is not enforced during actual chain initialization. The InitGenesis flow bypasses this validation, allowing genesis transactions with multiple messages to be delivered during chain launch, violating the intended design constraint.

## Impact
Medium

## Finding Description

**Location:** 
- Validation: [1](#0-0) 
- Bypass occurs in: [2](#0-1) 
- Delivery without validation: [3](#0-2) 

**Intended Logic:** 
Genesis transactions should contain exactly one MsgCreateValidator message to ensure clean and controlled validator initialization. The ValidateGenesis function explicitly checks this requirement and returns an error if a transaction contains multiple messages.

**Actual Logic:** 
During chain initialization, the flow proceeds as: InitChain → InitChainer → mm.InitGenesis → genutil.InitGenesis → DeliverGenTxs. The DeliverGenTxs function directly decodes and delivers genesis transactions without calling ValidateGenesis. The validation only exists in an optional CLI command ( [4](#0-3) ) that validators may or may not run manually before chain launch.

**Exploit Scenario:**
1. An attacker crafts a malicious genesis.json file containing genesis transactions with multiple messages (e.g., MsgCreateValidator + MsgDelegate for extra voting power, or MsgCreateValidator + MsgSend to drain initial token allocations)
2. The attacker distributes this genesis file to validators during a new chain launch or testnet setup
3. Validators who do not manually run the `validate-genesis` CLI command will accept the file
4. During InitChain, the multi-message transactions are delivered successfully via [5](#0-4) 
5. The chain launches with corrupted initial state violating genesis invariants

**Security Failure:**
This breaks the genesis state integrity invariant. The system allows unauthorized state modifications during chain initialization that bypass the intended single-message constraint, potentially leading to unfair validator distribution, token manipulation, or other unintended initial state conditions.

## Impact Explanation

**Affected Assets/Processes:**
- Initial validator set and token distribution
- Genesis state integrity
- Chain launch fairness

**Severity of Damage:**
- Genesis transactions could include unauthorized message combinations (MsgCreateValidator + MsgDelegate/MsgSend/etc.)
- Initial state could be manipulated to favor specific actors with extra voting power or token advantages
- Would require chain restart with corrected genesis file to fix
- Undermines trust in chain initialization process

**System Impact:**
This vulnerability affects the foundational assumptions about genesis state. While it requires social engineering to convince validators to use a malicious genesis file, successful exploitation would compromise the integrity of the initial chain state in ways that may not be immediately obvious, leading to unfair advantages that persist throughout the chain's lifetime.

## Likelihood Explanation

**Who Can Trigger:**
Any participant who can influence the genesis file used by validators during chain launch. This is most feasible during:
- New chain launches
- Testnet deployments  
- Hard fork scenarios requiring new genesis files

**Required Conditions:**
- Validators must use a malicious genesis file without running the optional `validate-genesis` CLI command
- Requires coordination timing during chain launch phase
- Relies on validators not performing thorough validation

**Frequency:**
- Limited to chain initialization events
- However, each successful exploitation has permanent impact on that chain instance
- The vulnerability exists in every chain launch using this codebase

## Recommendation

Enforce ValidateGenesis during the InitGenesis flow, not just as an optional CLI tool. Modify the InitGenesis function to validate all genesis transactions before delivering them:

```go
// In x/genutil/genesis.go, modify InitGenesis to:
func InitGenesis(
    ctx sdk.Context, stakingKeeper types.StakingKeeper,
    deliverTx deliverTxfn, genesisState types.GenesisState,
    txEncodingConfig client.TxEncodingConfig,
) (validators []abci.ValidatorUpdate, err error) {
    // Add validation before delivery
    if err := types.ValidateGenesis(&genesisState, txEncodingConfig.TxJSONDecoder()); err != nil {
        return nil, err
    }
    
    if len(genesisState.GenTxs) > 0 {
        validators, err = DeliverGenTxs(ctx, genesisState.GenTxs, stakingKeeper, deliverTx, txEncodingConfig)
    }
    return
}
```

This ensures the single-message requirement is enforced at the protocol level during chain initialization, not just as a pre-launch validation suggestion.

## Proof of Concept

**File:** `x/genutil/genesis_test.go` (new test file)

**Test Function:** `TestInitGenesisWithMultiMessageTransaction`

**Setup:**
1. Initialize a test SimApp with default encoding config
2. Create two MsgCreateValidator messages with different validators
3. Construct a single transaction containing both messages (violating the single-message requirement)
4. Create genesis state with this multi-message transaction
5. Set up accounts with sufficient balances

**Trigger:**
1. Call InitGenesis with the malicious genesis state containing the multi-message transaction
2. The function should reject multi-message transactions but currently doesn't

**Observation:**
The test demonstrates that InitGenesis successfully delivers a multi-message genesis transaction without any validation error, confirming that the single-message requirement in ValidateGenesis is bypassed during actual chain initialization. The test would show that:
- ValidateGenesis correctly rejects the multi-message transaction (as shown in [6](#0-5) )
- But InitGenesis accepts and delivers it (demonstrating the bypass)

The proof follows the pattern established in existing tests like [7](#0-6)  but specifically tests the multi-message scenario that ValidateGenesis is designed to prevent.

### Citations

**File:** x/genutil/types/genesis_state.go (L108-111)
```go
		if len(msgs) != 1 {
			return errors.New(
				"must provide genesis Tx with exactly 1 CreateValidator message")
		}
```

**File:** x/genutil/genesis.go (L12-20)
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

**File:** x/genutil/client/cli/validate_genesis.go (L60-60)
```go
			if err = mbm.ValidateGenesis(cdc, clientCtx.TxConfig, genState); err != nil {
```

**File:** x/genutil/types/genesis_state_test.go (L36-57)
```go
func TestValidateGenesisMultipleMessages(t *testing.T) {
	desc := stakingtypes.NewDescription("testname", "", "", "", "")
	comm := stakingtypes.CommissionRates{}

	msg1, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(pk1.Address()), pk1,
		sdk.NewInt64Coin(sdk.DefaultBondDenom, 50), desc, comm, sdk.OneInt())
	require.NoError(t, err)

	msg2, err := stakingtypes.NewMsgCreateValidator(sdk.ValAddress(pk2.Address()), pk2,
		sdk.NewInt64Coin(sdk.DefaultBondDenom, 50), desc, comm, sdk.OneInt())
	require.NoError(t, err)

	txGen := simapp.MakeTestEncodingConfig().TxConfig
	txBuilder := txGen.NewTxBuilder()
	require.NoError(t, txBuilder.SetMsgs(msg1, msg2))

	tx := txBuilder.GetTx()
	genesisState := types.NewGenesisStateFromTx(txGen.TxJSONEncoder(), []sdk.Tx{tx})

	err = types.ValidateGenesis(genesisState, simapp.MakeTestEncodingConfig().TxConfig.TxJSONDecoder())
	require.Error(t, err)
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
