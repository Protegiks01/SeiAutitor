# Audit Report

## Title
Genesis Transaction Validation Bypass Enables Chain Startup Denial-of-Service

## Summary
A validation gap exists in the genesis transaction collection process where `CollectTxs` does not call `ValidateBasic()` on transaction messages, while `DeliverGenTxs` does and panics on validation failure. This allows invalid genesis transactions to be included in genesis.json, causing complete network startup failure.

## Impact
Medium

## Finding Description

**Location:**
- Validation gap in `CollectTxs`: [1](#0-0) 
- Panic on validation failure: [2](#0-1) 
- Missing ValidateBasic call during collection: [3](#0-2) 

**Intended Logic:**
Genesis transactions should be thoroughly validated during the `collect-gentxs` phase to ensure only valid transactions are included in genesis.json. Pre-validated transactions should then execute successfully during chain initialization without errors.

**Actual Logic:**
The `CollectTxs` function extracts messages and validates account balances and delegation amounts [4](#0-3)  but does NOT call `ValidateBasic()` on the messages themselves. However, during chain startup, the transaction delivery pipeline calls `validateBasicTxMsgs` [5](#0-4)  which invokes `ValidateBasic()` on each message [6](#0-5) .

The `MsgCreateValidator.ValidateBasic()` performs critical validations including empty description and commission checks [7](#0-6)  that `CollectTxs` skips.

**Exploitation Path:**
1. Genesis participant creates a gentx JSON with empty `CommissionRates{}` or `Description{}`
2. Places file in gentxs directory before `collect-gentxs` execution
3. `CollectTxs` validates balances but skips `ValidateBasic()` call
4. Invalid gentx is included in genesis.json
5. During chain startup, `InitGenesis` is invoked [8](#0-7) 
6. `DeliverGenTxs` processes gentxs [9](#0-8) 
7. Delivery pipeline calls `ValidateBasic()` which returns error
8. Code unconditionally panics: `if !res.IsOK() { panic(res.Log) }` [10](#0-9) 
9. All nodes using same genesis.json experience identical panic
10. Network cannot start

**Security Guarantee Broken:**
The system fails defense-in-depth validation. Validation boundaries are inconsistent - some checks occur during collection (balances), while critical message validity checks only occur during delivery, allowing invalid data to bypass initial validation and cause catastrophic failure at genesis initialization.

## Impact Explanation

This vulnerability causes **complete network failure at genesis**:

- **Irrecoverable without manual intervention**: Chain cannot self-recover; requires identifying the malicious gentx, removing it, and regenerating genesis.json
- **Affects all nodes simultaneously**: All nodes using the same genesis.json fail to start
- **Network never reaches operational state**: No blocks produced, no transactions processed
- **Pre-consensus DoS**: Prevents chain from initializing consensus mechanisms

This matches the explicit impact criteria: "Network not being able to confirm new transactions (total network shutdown)" - classified as **Medium** severity.

## Likelihood Explanation

**Who Can Trigger:**
- Genesis participants who submit gentx files
- Could occur accidentally through human error (misconfigured gentx)

**Required Conditions:**
- Access to submit gentx file during genesis ceremony (standard for genesis participants)
- Empty commission or description fields in gentx
- Timing: before `collect-gentxs` execution

**Frequency:**
Exploitable only during genesis (one-time window), but impact is catastrophic. Attack requires minimal sophistication - simply creating a JSON file with empty fields. An honest participant could trigger this accidentally.

**Key Point:** Although genesis participants are somewhat privileged, this qualifies under the exception clause: "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority." A single participant's error should not prevent the entire network from starting.

## Recommendation

Add `ValidateBasic()` validation in `CollectTxs` after line 136 where messages are extracted:

```go
msgs := genTx.GetMsgs()
for _, msg := range msgs {
    if err := msg.ValidateBasic(); err != nil {
        return appGenTxs, persistentPeers, fmt.Errorf("gentx %s failed ValidateBasic: %w", fo.Name(), err)
    }
}
```

This ensures validation parity between collection-time and delivery-time, rejecting invalid gentxs during collection rather than causing panic during genesis.

## Proof of Concept

**Setup:**
The existing test suite demonstrates that empty `CommissionRates{}` can be constructed [11](#0-10) 

**Test Case:**
Add test to `TestDeliverGenTxs` in `x/genutil/gentx_test.go`:

```go
{
    "invalid gentx with empty commission causes panic",
    func() {
        _ = suite.setAccountBalance(addr1, 50)
        
        amount := sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)
        emptyComm := stakingtypes.CommissionRates{} // Invalid - empty commission
        desc := stakingtypes.NewDescription("validator", "", "", "", "")
        minSelfDel := sdk.OneInt()
        
        invalidMsg, err := stakingtypes.NewMsgCreateValidator(
            sdk.ValAddress(pk1.Address()), pk1, amount, desc, emptyComm, minSelfDel,
        )
        suite.Require().NoError(err)
        
        tx, err := helpers.GenTx(
            suite.encodingConfig.TxConfig,
            []sdk.Msg{invalidMsg},
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
    false, // expPass = false, expecting panic
},
```

**Expected Result:**
Test panics when `DeliverGenTxs` is called, confirming invalid gentx bypasses collection validation but causes panic during genesis delivery.

**Verification:**
Run: `go test -v ./x/genutil/... -run TestDeliverGenTxs`

## Notes

This represents a critical validation gap in the genesis process. While genesis participants have a special role, defense-in-depth principles require consistent validation at all boundaries. The fact that `CollectTxs` performs *some* validations (balances, funds) but not *all* validations (`ValidateBasic()`) creates an exploitable inconsistency that can prevent the entire network from starting.

### Citations

**File:** x/genutil/collect.go (L70-184)
```go
// CollectTxs processes and validates application's genesis Txs and returns
// the list of appGenTxs, and persistent peers required to generate genesis.json.
func CollectTxs(cdc codec.JSONCodec, txJSONDecoder sdk.TxDecoder, moniker, genTxsDir string,
	genDoc tmtypes.GenesisDoc, genBalIterator types.GenesisBalancesIterator,
) (appGenTxs []sdk.Tx, persistentPeers string, err error) {
	// prepare a map of all balances in genesis state to then validate
	// against the validators addresses
	var appState map[string]json.RawMessage
	if err := json.Unmarshal(genDoc.AppState, &appState); err != nil {
		return appGenTxs, persistentPeers, err
	}

	var fos []os.FileInfo
	fos, err = ioutil.ReadDir(genTxsDir)
	if err != nil {
		return appGenTxs, persistentPeers, err
	}

	balancesMap := make(map[string]bankexported.GenesisBalance)

	genBalIterator.IterateGenesisBalances(
		cdc, appState,
		func(balance bankexported.GenesisBalance) (stop bool) {
			balancesMap[balance.GetAddress().String()] = balance
			return false
		},
	)

	// addresses and IPs (and port) validator server info
	var addressesIPs []string

	for _, fo := range fos {
		if fo.IsDir() {
			continue
		}
		if !strings.HasSuffix(fo.Name(), ".json") {
			continue
		}

		// get the genTx
		jsonRawTx, err := ioutil.ReadFile(filepath.Join(genTxsDir, fo.Name()))
		if err != nil {
			return appGenTxs, persistentPeers, err
		}

		var genTx sdk.Tx
		if genTx, err = txJSONDecoder(jsonRawTx); err != nil {
			return appGenTxs, persistentPeers, err
		}

		appGenTxs = append(appGenTxs, genTx)

		// the memo flag is used to store
		// the ip and node-id, for example this may be:
		// "528fd3df22b31f4969b05652bfe8f0fe921321d5@192.168.2.37:26656"

		memoTx, ok := genTx.(sdk.TxWithMemo)
		if !ok {
			return appGenTxs, persistentPeers, fmt.Errorf("expected TxWithMemo, got %T", genTx)
		}
		nodeAddrIP := memoTx.GetMemo()
		if len(nodeAddrIP) == 0 {
			return appGenTxs, persistentPeers, fmt.Errorf("failed to find node's address and IP in %s", fo.Name())
		}

		// genesis transactions must be single-message
		msgs := genTx.GetMsgs()

		// TODO abstract out staking message validation back to staking
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

		// exclude itself from persistent peers
		if msg.Description.Moniker != moniker {
			addressesIPs = append(addressesIPs, nodeAddrIP)
		}
	}

	sort.Strings(addressesIPs)
	persistentPeers = strings.Join(addressesIPs, ",")

	return appGenTxs, persistentPeers, nil
}
```

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

**File:** baseapp/baseapp.go (L788-800)
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
```

**File:** baseapp/baseapp.go (L923-923)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
```

**File:** x/staking/types/msg.go (L120-126)
```go
	if msg.Description == (Description{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty description")
	}

	if msg.Commission == (CommissionRates{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty commission")
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

**File:** x/genutil/gentx_test.go (L30-32)
```go
	desc  = stakingtypes.NewDescription("testname", "", "", "", "")
	comm  = stakingtypes.CommissionRates{}
)
```
