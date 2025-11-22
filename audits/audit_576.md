# Audit Report

## Title
Genesis Transaction with Commission Rate Below MinCommissionRate Causes Chain Startup Failure

## Summary
A MsgCreateValidator can be created in a genesis transaction (gentx) with a commission rate below the chain's MinCommissionRate parameter. This gentx passes validation during creation but causes a panic during chain initialization, preventing the blockchain from starting.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Validation gap: [1](#0-0) 
- Runtime check: [2](#0-1) 
- Panic point: [3](#0-2) 

**Intended Logic:** 
All validators must have a commission rate at or above the chain's MinCommissionRate parameter (default 5%). [4](#0-3) 

**Actual Logic:** 
The ValidateBasic() function only validates that commission rates are within [0, 1] and satisfy relative constraints (rate ≤ maxRate, etc.), but does NOT check against MinCommissionRate. [5](#0-4) 

During gentx generation, only ValidateBasic() is called: [6](#0-5) 

At runtime, the CreateValidator handler checks MinCommissionRate and returns an error if the rate is too low. [2](#0-1) 

When DeliverGenTxs processes gentxs during InitChain, any error causes a panic. [7](#0-6) 

**Exploit Scenario:**
1. Attacker creates a gentx with commission rate = 0% (or any value below MinCommissionRate)
2. The gentx passes ValidateBasic() since 0% satisfies the basic constraints
3. The gentx is collected and included in genesis.json
4. When the chain attempts to start, InitGenesis calls DeliverGenTxs
5. DeliverGenTxs processes the gentx through the CreateValidator handler
6. The handler detects commission rate < MinCommissionRate and returns an error
7. DeliverGenTxs panics with the error message
8. The chain fails to initialize and cannot start

**Security Failure:** 
This breaks the availability guarantee of the blockchain. An invalid gentx can prevent the entire network from starting, creating a complete denial of service.

## Impact Explanation

This vulnerability affects the fundamental availability of the blockchain network:
- **Network Availability**: The chain cannot start or process any transactions
- **Complete Network Shutdown**: All nodes fail to initialize at genesis
- **No Workaround**: The only fix is to manually edit the genesis.json file to correct or remove the invalid gentx
- **Scope**: This affects new networks at launch or any network restart from a fresh genesis state

The damage is severe because it prevents the blockchain from functioning at all. This is not a temporary issue or partial failure—it's a complete inability to start the network.

## Likelihood Explanation

**Who can trigger it:** 
Any participant in the genesis setup process who can submit a gentx. In typical network launches, multiple validators submit gentx files that are collected into the genesis state.

**Conditions required:**
- Occurs during network initialization (genesis setup)
- Only requires creating a gentx with commission rate below MinCommissionRate
- No special privileges needed beyond participating in genesis validator setup

**Frequency:**
While this only affects genesis initialization (not runtime transactions), it is highly exploitable because:
- The validation gap makes it easy to create invalid gentxs accidentally or maliciously
- Any single invalid gentx from any genesis validator will break the entire chain
- This could affect mainnet launches, testnet setups, or any network reinitialization

## Recommendation

Add MinCommissionRate validation to ValidateBasic() by accepting the commission rate parameter:

**Option 1:** Add runtime parameter check during gentx validation in the CLI layer where context is available to read staking params. [6](#0-5) 

**Option 2:** Add a separate validation function that checks MinCommissionRate and call it during CollectTxs where the genesis app state is available. [8](#0-7) 

**Option 3:** Return a more graceful error instead of panicking in DeliverGenTxs, though this doesn't prevent the startup failure, it makes debugging easier.

The recommended fix is Option 1 or 2: validate commission rates against MinCommissionRate before accepting a gentx, reading the MinCommissionRate from the staking genesis state.

## Proof of Concept

**File:** `x/genutil/gentx_test.go`

**Test Function:** Add `TestDeliverGenTxsWithInvalidCommissionRate`

**Setup:**
1. Initialize a test app with default staking params (MinCommissionRate = 5%)
2. Create a MsgCreateValidator with commission rate = 0% (below MinCommissionRate)
3. Fund the validator account with sufficient balance
4. Sign the transaction to create a valid gentx

**Trigger:**
1. Encode the gentx as JSON
2. Call DeliverGenTxs with this gentx
3. The CreateValidator handler will check MinCommissionRate and fail

**Observation:**
The test should observe that DeliverGenTxs panics when processing the gentx, demonstrating that:
- ValidateBasic() passes (commission rate is valid within [0,1])
- Runtime handler rejects the commission rate (below MinCommissionRate)
- Chain initialization fails with panic

The test should use the existing test structure similar to: [9](#0-8)  but create a MsgCreateValidator with commission rate below MinCommissionRate instead of the valid commission used at: [10](#0-9)

### Citations

**File:** x/staking/types/msg.go (L124-130)
```go
	if msg.Commission == (CommissionRates{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty commission")
	}

	if err := msg.Commission.Validate(); err != nil {
		return err
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
