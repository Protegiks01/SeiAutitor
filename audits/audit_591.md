## Audit Report

### Title
Genesis Transaction Validation Bypass Enables Chain Startup Denial-of-Service

### Summary
A validation gap between the `collect-gentxs` phase and chain genesis allows an attacker to include invalid genesis transactions that pass initial validation but cause an unconditional panic during chain startup, preventing the network from ever starting.

### Impact
**High** - Network not being able to confirm new transactions (total network shutdown). The chain cannot complete genesis and start.

### Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Validation gap: [2](#0-1) 
- Missing validation call: [3](#0-2) 

**Intended Logic:** 
Genesis transactions should be thoroughly validated during the `collect-gentxs` phase to ensure only valid transactions are included in the genesis file. During chain startup, these pre-validated transactions should execute successfully.

**Actual Logic:** 
The `CollectTxs` function validates genesis transactions but does NOT call `ValidateBasic()` on the messages within those transactions. It only performs these checks: transaction decoding, memo existence, message type assertion, account balance verification, and delegation fund sufficiency. [4](#0-3) 

However, during chain startup in `DeliverGenTxs`, each genesis transaction goes through the normal transaction processing pipeline which calls `validateBasicTxMsgs` [5](#0-4) , which in turn calls `ValidateBasic()` on each message [6](#0-5) .

The `MsgCreateValidator.ValidateBasic()` method performs multiple stateless validations that are NOT checked during `CollectTxs`, including:
- Empty or invalid description
- Empty or invalid commission rates
- Invalid commission rate values
- MinSelfDelegation not positive
- Delegation amount less than MinSelfDelegation
- Nil public key [7](#0-6) 

**Exploit Scenario:**
1. An attacker participating in the genesis process crafts a malicious gentx JSON file with invalid message fields (e.g., empty description: `Description{}`  or empty commission: `CommissionRates{}`)
2. The attacker places this file in the gentxs directory
3. During `collect-gentxs`, the `CollectTxs` function processes the transaction and validates balances/funds but does NOT call `ValidateBasic()`, so the invalid gentx passes validation
4. The invalid gentx is included in the final `genesis.json` file
5. When any node attempts to start the chain, `InitGenesis` is called [8](#0-7) 
6. `InitGenesis` calls `DeliverGenTxs` which iterates through each gentx [9](#0-8) 
7. For the invalid gentx, `deliverTx` processes it through the normal transaction pipeline and calls `ValidateBasic()` on the message
8. `ValidateBasic()` returns an error due to the invalid fields
9. The response has `!res.IsOK()` and the code unconditionally panics [10](#0-9) 
10. The panic halts the node and prevents genesis from completing
11. Since all nodes use the same `genesis.json`, the entire network cannot start

**Security Failure:** 
This is a denial-of-service vulnerability that breaks network availability. The unconditional panic prevents the chain from completing genesis, effectively preventing the network from ever starting.

### Impact Explanation

**Affected Components:**
- The entire network's ability to start and operate
- All validator nodes attempting to initialize from the compromised genesis file
- Chain availability and transaction processing capability

**Severity of Damage:**
- Complete network failure - the chain cannot start at all
- Unlike a regular network shutdown, this prevents genesis completion, which is irrecoverable without regenerating genesis
- All participating validators are affected simultaneously
- Requires manual intervention to identify the malicious gentx, remove it, and regenerate genesis.json
- Delays network launch and erodes trust in the genesis process

**System Impact:**
This vulnerability represents a critical failure mode worse than a typical network shutdown. The network cannot even reach a state where it can process transactions or reach consensus. It's a pre-consensus denial of service that affects the foundational initialization of the blockchain.

### Likelihood Explanation

**Who Can Trigger:**
Any participant in the genesis process who can place a gentx file in the gentxs directory before `collect-gentxs` is executed. This typically includes:
- Initial validator participants
- Anyone with file system access during genesis preparation
- Malicious or compromised genesis coordinators

**Required Conditions:**
- Access to add a gentx file during the genesis ceremony
- Knowledge of which message fields are not validated by `CollectTxs` but are validated by `ValidateBasic()`
- Timing: must occur before `collect-gentxs` is executed

**Frequency:**
While this is a one-time attack during genesis (not exploitable post-genesis), the impact is catastrophic. Once a malicious gentx is included in genesis.json, every node attempting to start will panic. The attack requires minimal sophistication - simply creating a JSON file with invalid but structurally correct fields.

### Recommendation

Add `ValidateBasic()` call in the `CollectTxs` function to ensure all genesis transactions undergo the same validation checks that will be performed during `DeliverGenTxs`. 

Specifically, after successfully decoding a gentx and asserting the message type, call `ValidateBasic()` on each message:

```go
// In x/genutil/collect.go, after line 139
msgs := genTx.GetMsgs()
for _, msg := range msgs {
    if err := msg.ValidateBasic(); err != nil {
        return appGenTxs, persistentPeers, fmt.Errorf("gentx %s failed ValidateBasic: %w", fo.Name(), err)
    }
}
```

This ensures parity between collect-time validation and delivery-time validation, closing the validation gap.

### Proof of Concept

**File:** `x/genutil/gentx_test.go`

**Test Function:** Add the following test case to the existing `TestDeliverGenTxs` test suite:

```go
{
    "invalid gentx with empty commission fails ValidateBasic and causes panic",
    func() {
        _ = suite.setAccountBalance(addr1, 50)
        
        // Create a MsgCreateValidator with empty commission (invalid)
        amount := sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)
        emptyComm := stakingtypes.CommissionRates{} // Empty commission - will fail ValidateBasic
        desc := stakingtypes.NewDescription("validator", "", "", "", "")
        minSelfDel := sdk.OneInt()
        
        invalidMsg, err := stakingtypes.NewMsgCreateValidator(
            sdk.ValAddress(pk1.Address()), 
            pk1, 
            amount, 
            desc, 
            emptyComm, // Invalid: empty commission
            minSelfDel,
        )
        suite.Require().NoError(err) // Constructor doesn't validate
        
        // Create and sign the transaction
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

**Setup:**
- Uses existing test suite infrastructure from `gentx_test.go`
- Creates an account with sufficient balance
- Constructs a `MsgCreateValidator` with an empty `CommissionRates{}` struct

**Trigger:**
- The empty commission passes the constructor (no validation at creation time)
- During `DeliverGenTxs`, the transaction is delivered through the normal pipeline
- `validateBasicTxMsgs` calls `ValidateBasic()` on the message
- `ValidateBasic()` detects the empty commission and returns an error (line 124-126 of msg.go)
- DeliverTx returns a non-OK response
- The unconditional panic is triggered at line 115 of gentx.go

**Observation:**
The test expects a panic (line 272: `suite.Require().Panics(...)`), confirming that an invalid gentx that passes initial validation causes a panic during delivery, preventing genesis from completing. This demonstrates the validation gap between `CollectTxs` and `DeliverGenTxs`.

Running this test will show that a carefully crafted invalid gentx can bypass collection-time validation but trigger a panic at genesis time, proving the exploitability of this vulnerability.

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

**File:** x/staking/types/msg.go (L89-143)
```go
// ValidateBasic implements the sdk.Msg interface.
func (msg MsgCreateValidator) ValidateBasic() error {
	// note that unmarshaling from bech32 ensures either empty or valid
	delAddr, err := sdk.AccAddressFromBech32(msg.DelegatorAddress)
	if err != nil {
		return err
	}
	if delAddr.Empty() {
		return ErrEmptyDelegatorAddr
	}

	if msg.ValidatorAddress == "" {
		return ErrEmptyValidatorAddr
	}

	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return err
	}
	if !sdk.AccAddress(valAddr).Equals(delAddr) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "validator address is invalid")
	}

	if msg.Pubkey == nil {
		return ErrEmptyValidatorPubKey
	}

	if !msg.Value.IsValid() || !msg.Value.Amount.IsPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid delegation amount")
	}

	if msg.Description == (Description{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty description")
	}

	if msg.Commission == (CommissionRates{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty commission")
	}

	if err := msg.Commission.Validate(); err != nil {
		return err
	}

	if !msg.MinSelfDelegation.IsPositive() {
		return sdkerrors.Wrap(
			sdkerrors.ErrInvalidRequest,
			"minimum self delegation must be a positive integer",
		)
	}

	if msg.Value.Amount.LT(msg.MinSelfDelegation) {
		return ErrSelfDelegationBelowMinimum
	}

	return nil
```

**File:** baseapp/baseapp.go (L787-800)
```go
// validateBasicTxMsgs executes basic validator calls for messages.
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

**File:** baseapp/baseapp.go (L923-925)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
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
