# Audit Report

## Title
Genesis Validation Bypass Enables Network Shutdown via Zero-Message Gentx

## Summary
A genesis transaction (gentx) with zero messages can bypass the validation check in `genesis_state.go:108-111` because `ValidateGenesis` is not called during `InitChain`. This causes a panic during chain initialization, resulting in total network shutdown. The chain cannot start until the malformed genesis file is corrected. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Validation bypass: `x/genutil/types/genesis_state.go` lines 108-111
- Missing validation call: `simapp/app.go` lines 592-599 (InitChainer)
- Panic trigger: `x/genutil/gentx.go` line 115
- Secondary validation: `baseapp/baseapp.go` lines 789-791

**Intended Logic:** 
The `ValidateGenesis` function is intended to validate all genesis transactions before chain initialization, ensuring each gentx contains exactly one `MsgCreateValidator` message. [2](#0-1) 

**Actual Logic:** 
The `InitChainer` function directly calls `app.mm.InitGenesis()` without invoking `ValidateGenesis`. [3](#0-2)  This means the single-message check is never executed during actual chain initialization, only when the optional CLI command `validate-genesis` is manually run.

When a gentx with zero messages is processed during `InitGenesis`, it bypasses the intended validation and reaches `DeliverGenTxs`. [4](#0-3)  The transaction is then delivered via `BaseApp.DeliverTx`, which calls `validateBasicTxMsgs`. [5](#0-4)  This function returns an error for zero messages, causing `DeliverGenTxs` to panic. [6](#0-5) 

**Exploit Scenario:**
1. Attacker participates in genesis ceremony or obtains access to genesis file before distribution
2. Attacker manually crafts a gentx with zero messages (editing JSON directly or using custom tooling)
3. Genesis coordinator collects gentxs without running `validate-genesis` CLI command
4. Genesis file is distributed to all validators
5. All validators attempt to start the chain using `InitChain`
6. The malformed gentx reaches `DeliverGenTxs` and triggers panic at line 115 of `gentx.go`
7. Chain initialization fails - total network shutdown

**Security Failure:** 
This is a denial-of-service vulnerability. The security property broken is **availability** - the defense-in-depth validation architecture fails because the primary validation gate (`ValidateGenesis`) is not enforced during the critical initialization path.

## Impact Explanation

**Affected Components:**
- Network availability: Chain cannot initialize
- All validator nodes: Cannot start consensus
- Network launch: Complete failure

**Severity of Damage:**
This causes total network shutdown at genesis. The chain cannot process any transactions because it cannot start. All validators will experience panic during `InitChain`, preventing the network from ever reaching block height 1. Recovery requires manually editing and redistributing a corrected genesis file to all participants.

**Why This Matters:**
Chain launches (testnets, mainnets) are critical events where multiple untrusted parties contribute gentxs. Without mandatory validation enforcement, a single malicious or malformed gentx can prevent the entire network from launching, causing significant operational disruption and potential financial/reputational damage.

## Likelihood Explanation

**Who Can Trigger:**
Any participant in the genesis ceremony who can submit a gentx or anyone with access to modify the genesis file before distribution (e.g., malicious validator, compromised coordinator system).

**Required Conditions:**
- Genesis coordinator or validators must skip the `validate-genesis` CLI command before chain start
- This is realistic because validation is optional, not enforced

**Frequency:**
- Can occur once per chain launch/genesis ceremony
- Particularly likely during testnets where operational rigor may be lower
- Could be exploited during mainnet launches if proper validation procedures are not followed

## Recommendation

**Primary Fix:** Enforce genesis validation during `InitChain` by calling `ValidateGenesis` before processing gentxs.

Modify `simapp/app.go` `InitChainer` function to validate genesis state before calling `InitGenesis`:

```go
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
    var genesisState GenesisState
    if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
        panic(err)
    }
    
    // ADD VALIDATION HERE
    if err := app.mm.BasicManager.ValidateGenesis(app.appCodec, app.GetTxConfig(), genesisState); err != nil {
        panic(fmt.Errorf("genesis validation failed: %w", err))
    }
    
    app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
    return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
}
```

**Alternative/Additional Mitigation:** Document and enforce operational procedures requiring `validate-genesis` execution before chain start, though this is less reliable than code-level enforcement.

## Proof of Concept

**File:** `x/genutil/gentx_test.go`

**Test Function:** Add new test to `GenTxTestSuite`:

```go
func (suite *GenTxTestSuite) TestDeliverGenTxsWithZeroMessages() {
    suite.SetupTest()
    
    // Setup: Create a transaction builder with zero messages
    txBuilder := suite.encodingConfig.TxConfig.NewTxBuilder()
    // Intentionally do NOT call txBuilder.SetMsgs() to create empty message array
    
    // Encode the transaction
    tx := txBuilder.GetTx()
    txJSON, err := suite.encodingConfig.TxConfig.TxJSONEncoder()(tx)
    suite.Require().NoError(err)
    
    genTxs := []json.RawMessage{txJSON}
    
    // Trigger: Attempt to deliver the gentx with zero messages
    ctx := suite.app.GetContextForDeliverTx([]byte{})
    
    // Observation: This should panic because validateBasicTxMsgs rejects zero-message txs
    suite.Require().Panics(func() {
        genutil.DeliverGenTxs(
            ctx, 
            genTxs, 
            suite.app.StakingKeeper, 
            suite.app.BaseApp.DeliverTx,
            suite.encodingConfig.TxConfig,
        )
    }, "Expected panic when delivering gentx with zero messages")
}
```

**Observation:** 
The test demonstrates that a gentx with zero messages causes a panic during `DeliverGenTxs`. This confirms the vulnerability: while the check at `genesis_state.go:108-111` would catch this if `ValidateGenesis` were called, the check is bypassed during actual chain initialization, leading to a panic and total network shutdown.

To verify the complete attack scenario including the bypass of the validation check, an integration test at the `InitChain` level would show that `ValidateGenesis` is never invoked during normal chain initialization flow.

### Citations

**File:** x/genutil/types/genesis_state.go (L99-120)
```go
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

**File:** simapp/app.go (L592-599)
```go
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
	return app.mm.InitGenesis(ctx, app.appCodec, genesisState, genesistypes.GenesisImportConfig{})
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

**File:** baseapp/baseapp.go (L788-801)
```go
func validateBasicTxMsgs(msgs []sdk.Msg) error {
	if len(msgs) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "must contain at least one message")
	}

	for _, msg := range msgs {
		err := msg.ValidateBasic()
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```
