# Audit Report

## Title
Genesis Transaction Validation Gap Allows Chain Startup Failure via Invalid Commission Rate

## Summary
A validation gap in the genesis transaction (gentx) processing allows a `MsgCreateValidator` with commission rate below `MinCommissionRate` to pass collection but causes a panic during chain initialization, preventing the blockchain from starting.

## Impact
Medium

## Finding Description

**Location:**
- Validation gap: `x/staking/types/commission.go` (CommissionRates.Validate method)
- Runtime enforcement: `x/staking/keeper/msg_server.go` (CreateValidator handler)
- Panic trigger: `x/genutil/gentx.go` (DeliverGenTxs function)
- Gentx validation: `x/genutil/client/cli/gentx.go` and `x/genutil/collect.go`

**Intended Logic:**
All validators must have a commission rate at or above the chain's `MinCommissionRate` parameter (default 5%). [1](#0-0)  This parameter should be enforced at all stages of validator creation.

**Actual Logic:**
The `ValidateBasic()` function only validates that commission rates satisfy basic constraints (non-negative, within [0,1], rate ≤ maxRate, etc.) but does NOT check against `MinCommissionRate`. [2](#0-1) 

During gentx generation, only `ValidateBasic()` is called: [3](#0-2) 

During gentx collection, commission rates are not validated against `MinCommissionRate`: [4](#0-3) 

At runtime, the `CreateValidator` handler checks `MinCommissionRate` and returns an error if violated: [5](#0-4) 

When `DeliverGenTxs` processes gentxs during `InitChain`, any error causes a panic: [6](#0-5) 

**Exploitation Path:**
1. Genesis validator creates gentx with commission rate below `MinCommissionRate` (e.g., 0%)
2. Gentx passes `ValidateBasic()` validation (0% satisfies basic constraints)
3. Gentx is collected and included in genesis.json
4. Chain initialization begins via `InitChain` [7](#0-6) 
5. `InitGenesis` calls `DeliverGenTxs` [8](#0-7) 
6. `DeliverGenTxs` processes gentx through `CreateValidator` handler
7. Handler detects commission rate < `MinCommissionRate` and returns error
8. `DeliverGenTxs` panics with error message
9. Chain fails to initialize and cannot start

**Security Guarantee Broken:**
The blockchain's availability guarantee is violated. An invalid gentx that should have been rejected during collection prevents the entire network from starting.

## Impact Explanation

This vulnerability causes complete network shutdown:
- **Chain Startup Failure**: All nodes fail to initialize at genesis
- **No Transaction Processing**: The chain cannot start to process any transactions
- **Manual Intervention Required**: The only fix is to manually edit genesis.json to correct or remove the invalid gentx
- **Network-Wide Impact**: Affects all validators and users attempting to start the network

The damage is severe because it prevents the blockchain from functioning at all. This matches the acceptable impact category: "Network not being able to confirm new transactions (total network shutdown)" (Medium severity).

## Likelihood Explanation

**Who Can Trigger:**
Any participant submitting a gentx during genesis setup. In typical network launches, multiple validators submit gentx files.

**Conditions Required:**
- Occurs during network initialization (genesis setup)
- Requires creating gentx with commission rate below `MinCommissionRate`
- No additional privileges needed beyond genesis validator participation

**Likelihood Assessment:**
While this affects only genesis initialization, it is highly exploitable:
- The validation gap makes it easy to create invalid gentxs accidentally or intentionally
- A single invalid gentx from any genesis validator breaks the entire chain
- Could affect mainnet launches, testnet setups, or network reinitializations
- Even well-intentioned validators might set 0% commission without realizing the minimum

## Recommendation

Implement `MinCommissionRate` validation before accepting gentxs. Recommended approaches:

**Option 1:** Add validation during gentx CLI creation by reading `MinCommissionRate` from staking genesis state and checking commission rates before signing.

**Option 2:** Add validation in `CollectTxs` function where genesis app state is available, check commission rates against `MinCommissionRate` from staking params before accepting gentxs.

**Option 3 (Minimal):** Replace panic with graceful error handling in `DeliverGenTxs`, though this doesn't prevent the startup failure, it provides clearer error messages for debugging.

The preferred solution is Option 1 or 2 to prevent invalid gentxs from being created or collected in the first place.

## Proof of Concept

**File:** `x/genutil/gentx_test.go`

**Test Function:** Add `TestDeliverGenTxsWithInvalidCommissionRate`

**Setup:**
1. Initialize test app with default staking params (`MinCommissionRate` = 5%)
2. Create `MsgCreateValidator` with commission rate = 0% (below `MinCommissionRate`)
3. Fund validator account with sufficient balance
4. Sign the transaction to create valid gentx

**Action:**
1. Encode gentx as JSON
2. Call `DeliverGenTxs` with this gentx via `suite.app.BaseApp.DeliverTx`

**Result:**
The test should observe that `DeliverGenTxs` panics when processing the gentx. The existing test structure at [9](#0-8)  demonstrates panic detection. The test would show:
- `ValidateBasic()` passes (commission rate valid within [0,1])
- Runtime handler rejects commission rate (below `MinCommissionRate`)
- Chain initialization fails with panic

## Notes

The existing test setup uses empty `CommissionRates{}` [10](#0-9)  which would also trigger this issue if used in actual `DeliverGenTxs` tests with the staking keeper. The vulnerability is real and exploitable during any genesis initialization where a validator submits an invalid commission rate.

### Citations

**File:** x/staking/types/params.go (L36-38)
```go
	// DefaultMinCommissionRate is set to 0%
	DefaultMinCommissionRate = sdk.NewDecWithPrec(5, 2)
)
```

**File:** x/staking/types/commission.go (L51-79)
```go
func (cr CommissionRates) Validate() error {
	switch {
	case cr.MaxRate.IsNegative():
		// max rate cannot be negative
		return ErrCommissionNegative

	case cr.MaxRate.GT(sdk.OneDec()):
		// max rate cannot be greater than 1
		return ErrCommissionHuge

	case cr.Rate.IsNegative():
		// rate cannot be negative
		return ErrCommissionNegative

	case cr.Rate.GT(cr.MaxRate):
		// rate cannot be greater than the max rate
		return ErrCommissionGTMaxRate

	case cr.MaxChangeRate.IsNegative():
		// change rate cannot be negative
		return ErrCommissionChangeRateNegative

	case cr.MaxChangeRate.GT(cr.MaxRate):
		// change rate cannot be greater than the max rate
		return ErrCommissionChangeRateGTMaxRate
	}

	return nil
}
```

**File:** x/genutil/client/cli/gentx.go (L165-167)
```go
			if err = msg.ValidateBasic(); err != nil {
				return err
			}
```

**File:** x/genutil/collect.go (L139-172)
```go
		msg := msgs[0].(*stakingtypes.MsgCreateValidator)

		// validate delegator and validator addresses and funds against the accounts in the state
		delAddr := msg.DelegatorAddress
		valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
		if err != nil {
			return appGenTxs, persistentPeers, err
		}

		delBal, delOk := balancesMap[delAddr]
		if !delOk {
			_, file, no, ok := runtime.Caller(1)
			if ok {
				fmt.Printf("CollectTxs-1, called from %s#%d\n", file, no)
			}

			return appGenTxs, persistentPeers, fmt.Errorf("account %s balance not in genesis state: %+v", delAddr, balancesMap)
		}

		_, valOk := balancesMap[sdk.AccAddress(valAddr).String()]
		if !valOk {
			_, file, no, ok := runtime.Caller(1)
			if ok {
				fmt.Printf("CollectTxs-2, called from %s#%d - %s\n", file, no, sdk.AccAddress(msg.ValidatorAddress).String())
			}
			return appGenTxs, persistentPeers, fmt.Errorf("account %s balance not in genesis state: %+v", valAddr, balancesMap)
		}

		if delBal.GetCoins().AmountOf(msg.Value.Denom).LT(msg.Value.Amount) {
			return appGenTxs, persistentPeers, fmt.Errorf(
				"insufficient fund for delegation %v: %v < %v",
				delBal.GetAddress().String(), delBal.GetCoins().AmountOf(msg.Value.Denom), msg.Value.Amount,
			)
		}
```

**File:** x/staking/keeper/msg_server.go (L38-40)
```go
	if msg.Commission.Rate.LT(k.MinCommissionRate(ctx)) {
		return nil, sdkerrors.Wrapf(types.ErrCommissionLTMinRate, "cannot set validator commission=%s to less than minimum rate of %s", msg.Commission.Rate, k.MinCommissionRate(ctx))
	}
```

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```

**File:** baseapp/abci.go (L33-76)
```go
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
```

**File:** x/genutil/genesis.go (L17-20)
```go
	if len(genesisState.GenTxs) > 0 {
		validators, err = DeliverGenTxs(ctx, genesisState.GenTxs, stakingKeeper, deliverTx, txEncodingConfig)
	}
	return
```

**File:** x/genutil/gentx_test.go (L31-31)
```go
	comm  = stakingtypes.CommissionRates{}
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
