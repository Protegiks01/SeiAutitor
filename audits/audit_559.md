# Audit Report

## Title
Missing Chain ID Validation in Genesis Transaction Collection Causes Network Initialization Failure

## Summary
The `collect-gentxs` command does not validate that all collected genesis transactions (gentxs) were signed with the same chain ID as specified in the genesis file. This allows gentxs signed with mismatched chain IDs to be included in the final genesis file, causing the network to panic during initialization when signature verification fails, resulting in a complete network shutdown.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Missing validation in: [2](#0-1) 

**Intended Logic:** 
The genesis transaction collection process should ensure all gentxs are valid and can be successfully processed during chain initialization. Each gentx should be signed with the correct chain ID to ensure signature verification passes when the network starts.

**Actual Logic:** 
The `CollectTxs` function validates account balances but does not perform signature verification or chain ID validation. [1](#0-0) 

Similarly, `ValidateGenesis` only checks structural validity (single message, correct message type) without verifying signatures or chain IDs. [2](#0-1) 

**Exploit Scenario:**
1. Multiple validators create gentxs for a new network
2. Due to coordination issues or malicious intent, some validators use genesis templates with different chain IDs (e.g., "chain-alpha" vs "chain-beta")
3. Each validator creates their gentx, which gets signed with their respective chain ID
4. A coordinator runs `collect-gentxs` which collects all gentx files without validating chain ID consistency
5. The final genesis file is created with a single chain ID (e.g., "chain-alpha")
6. Genesis file is distributed to all validators
7. When validators start their nodes, `InitChain` is called with the genesis file's chain ID
8. During `DeliverGenTxs`, signature verification runs using `ctx.ChainID()` from the context: [3](#0-2) 
9. Gentxs signed with "chain-alpha" pass verification
10. Gentxs signed with "chain-beta" fail signature verification with `ErrUnauthorized`
11. The failure causes a panic in `DeliverGenTxs`: [4](#0-3) 
12. Network cannot initialize

**Security Failure:** 
This breaks the **availability** security property. The network cannot start because the genesis initialization process panics when encountering gentxs with mismatched chain IDs. All validator nodes will fail to initialize, preventing the network from ever becoming operational.

## Impact Explanation

**Affected Components:**
- Network availability: The entire network cannot initialize or process any transactions
- Chain initialization: Genesis state cannot be applied

**Severity:**
- **Complete network shutdown**: The network cannot start at all until the genesis file is manually corrected and redistributed
- **No transactions possible**: Since initialization fails, the network never becomes operational
- **Coordination overhead**: Requires re-collecting valid gentxs and redistributing a corrected genesis file to all validators

**Why This Matters:**
This vulnerability can completely prevent a new blockchain network from launching. Even a single gentx with a mismatched chain ID will cause initialization failure for all nodes. This affects the fundamental ability of the network to exist and operate, making it a critical availability issue.

## Likelihood Explanation

**Who Can Trigger It:**
- Any validator participating in genesis creation can accidentally trigger this by using a genesis template with a different chain ID
- A malicious validator could intentionally create a gentx with the wrong chain ID
- A malicious coordinator could mix gentxs from different chains

**Conditions Required:**
- Occurs during the genesis creation and collection phase, before network launch
- Requires at least one gentx to be signed with a different chain ID than the final genesis file
- No special privileges beyond being a genesis validator

**Likelihood:**
- **High** in scenarios with poor coordination between validators
- **Moderate** to **High** if multiple genesis templates are circulating
- Can occur **accidentally** through miscommunication or using outdated templates
- Can be **exploited intentionally** by a malicious participant in the genesis process

The vulnerability is particularly likely because there's no validation mechanism to catch the error before distributing the final genesis file. The error only manifests during node startup, when it's too late to prevent the issue.

## Recommendation

Add chain ID validation during the gentx collection process. Specifically:

1. **In `CollectTxs` function**: After decoding each gentx, verify its signature against the genesis document's chain ID before adding it to the collection. This would catch mismatched chain IDs immediately during collection.

2. **Add signature verification to `ValidateGenesis`**: Extend the validation to verify signatures using the genesis file's chain ID, so the `validate-genesis` command can detect this issue before node startup.

3. **Implementation approach**:
   - Extract the chain ID from the genesis document
   - Create a temporary context with the correct chain ID
   - Call signature verification for each gentx during collection
   - Reject any gentx that fails signature verification
   - Return a clear error message indicating which gentx has a chain ID mismatch

This would shift the validation from the initialization phase (where failure causes panic) to the collection phase (where errors can be caught and reported gracefully).

## Proof of Concept

**Test File**: `x/genutil/gentx_mixed_chainid_test.go` (new file)

**Setup:**
1. Initialize a test application with chain ID "test-chain-1"
2. Create two validators with funded accounts
3. Create two gentxs:
   - First gentx signed with chain ID "test-chain-1" (correct)
   - Second gentx signed with chain ID "wrong-chain-2" (incorrect)
4. Collect both gentxs into genesis state (simulating what `collect-gentxs` does)
5. Set the genesis document's chain ID to "test-chain-1"

**Trigger:**
1. Call `InitGenesis` with a context having chain ID "test-chain-1"
2. This will invoke `DeliverGenTxs` which processes each gentx through the ante handlers
3. The ante handler's signature verification will use "test-chain-1" from the context

**Observation:**
- The first gentx (signed with "test-chain-1") should verify successfully
- The second gentx (signed with "wrong-chain-2") should fail signature verification
- The test should panic with signature verification failure, demonstrating that mixed chain IDs cause network initialization failure

**Test Code Structure**:
```go
// In x/genutil/gentx_mixed_chainid_test.go
func TestMixedChainIDsInGenTxsCausesInitFailure(t *testing.T) {
    // Setup app and accounts
    // Create gentx1 with correct chain ID
    // Create gentx2 with wrong chain ID  
    // Collect both into genesis state
    // Attempt InitGenesis - should panic
}
```

This test demonstrates that the absence of chain ID validation during collection allows invalid gentxs into the genesis state, causing initialization failure as shown in the existing test case "test wrong chainID": [5](#0-4) 

**Notes**

The vulnerability exists because signature verification with chain ID validation only occurs during `DeliverGenTxs` at initialization time [6](#0-5) , not during the collection phase. The `collect-gentxs` command creates the genesis file without validating that all gentxs use the correct chain ID [7](#0-6) , allowing this failure mode to occur.

### Citations

**File:** x/genutil/collect.go (L72-183)
```go
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

**File:** x/auth/ante/sigverify.go (L280-291)
```go
		// retrieve signer data
		genesis := ctx.BlockHeight() == 0
		chainID := ctx.ChainID()
		var accNum uint64
		if !genesis {
			accNum = acc.GetAccountNumber()
		}
		signerData := authsigning.SignerData{
			ChainID:       chainID,
			AccountNumber: accNum,
			Sequence:      acc.GetSequence(),
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

**File:** x/auth/ante/ante_test.go (L700-709)
```go
		{
			"test wrong chainID",
			func() {
				accSeqs = []uint64{1} // Back to correct accSeqs
				chainID = "chain-foo"
			},
			false,
			false,
			sdkerrors.ErrUnauthorized,
		},
```

**File:** x/genutil/client/cli/collect.go (L21-63)
```go
func CollectGenTxsCmd(genBalIterator types.GenesisBalancesIterator, defaultNodeHome string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect-gentxs",
		Short: "Collect genesis txs and output a genesis.json file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			serverCtx := server.GetServerContextFromCmd(cmd)
			config := serverCtx.Config

			clientCtx := client.GetClientContextFromCmd(cmd)
			cdc := clientCtx.Codec

			config.SetRoot(clientCtx.HomeDir)

			nodeID, valPubKey, err := genutil.InitializeNodeValidatorFiles(config)
			if err != nil {
				return errors.Wrap(err, "failed to initialize node validator files")
			}

			genDoc, err := tmtypes.GenesisDocFromFile(config.GenesisFile())
			if err != nil {
				return errors.Wrap(err, "failed to read genesis doc from file")
			}

			genTxDir, _ := cmd.Flags().GetString(flagGenTxDir)
			genTxsDir := genTxDir
			if genTxsDir == "" {
				genTxsDir = filepath.Join(config.RootDir, "config", "gentx")
			}

			toPrint := newPrintInfo(config.Moniker, genDoc.ChainID, nodeID, genTxsDir, json.RawMessage(""))
			initCfg := types.NewInitConfig(genDoc.ChainID, genTxsDir, nodeID, valPubKey)

			appMessage, err := genutil.GenAppStateFromConfig(cdc,
				clientCtx.TxConfig,
				config, initCfg, *genDoc, genBalIterator)
			if err != nil {
				return errors.Wrap(err, "failed to get genesis app state from config")
			}

			toPrint.AppMessage = appMessage

			return displayInfo(toPrint)
		},
```
