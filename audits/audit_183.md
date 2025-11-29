# Audit Report

## Title
Missing Duplicate Validator Validation in Genesis Transaction Collection Causes Total Network Shutdown

## Summary
The `CollectTxs` function in the genutil module lacks validation for duplicate validator operator addresses and consensus public keys when collecting genesis transactions. This allows a malicious genesis participant to submit a gentx with duplicate validator keys, causing all network nodes to panic during chain initialization and preventing the blockchain from starting.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
During genesis ceremony, `CollectTxs` should validate all genesis transactions comprehensively to ensure they can be successfully applied during chain initialization. This should include checking that validator operator addresses and consensus public keys are unique across all gentx files, as validators must be uniquely identifiable in the network.

**Actual Logic:** 
The `CollectTxs` function only validates account balances (lines 148-172) but does not check for duplicate validator operator addresses or consensus public keys across multiple gentx files. [2](#0-1) 

The duplicate validation only occurs during transaction delivery in the `MsgCreateValidator` handler, which checks for existing validators and returns errors. [3](#0-2) 

**Exploitation Path:**
1. Multiple validators independently generate and submit their gentx files during genesis ceremony
2. Attacker (a genesis participant) creates a gentx intentionally using the same validator operator address OR consensus public key as another validator
3. Genesis coordinator runs `simd collect-gentxs` which calls `CollectTxs`
4. `CollectTxs` validates both gentxs successfully (only checking account balances)
5. Both gentxs are included in the final genesis.json and distributed to all validators
6. All validators attempt to start their nodes, triggering `InitChain` → `InitGenesis` → `DeliverGenTxs` [4](#0-3) 
7. `DeliverGenTxs` processes gentxs sequentially - first gentx creates validator successfully, second gentx (duplicate) triggers the `MsgCreateValidator` handler which detects the duplicate and returns an error
8. `DeliverGenTxs` panics on the error response [5](#0-4) 
9. All nodes crash during initialization before producing any blocks

**Security Guarantee Broken:** 
Network availability - a single semi-trusted genesis participant can prevent the entire network from ever becoming operational through a validation gap that allows malicious gentxs to pass collection but fail during delivery.

## Impact Explanation

This vulnerability causes total network shutdown at genesis. All network nodes (100%) fail to complete chain initialization, meaning:
- The blockchain cannot start and never becomes operational
- No blocks can be produced
- No transactions can be processed
- The network remains completely non-functional

Recovery requires manual intervention: identifying the malicious duplicate gentx, coordinating among all validators to use a corrected genesis.json, and restarting the entire genesis process. This effectively requires a "pre-genesis hard fork" before the chain exists.

This matches the in-scope impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who can trigger it:** 
Any participant in the genesis ceremony authorized to submit a gentx (typically initial validators). The attacker must be one of the genesis participants or compromise one validator's gentx submission.

**Conditions required:** 
- Attack occurs during genesis setup phase
- Attacker participates in genesis ceremony
- Genesis coordinator runs `collect-gentxs` including the malicious gentx
- No additional validation occurs before distributing genesis.json

**Likelihood:** 
While this requires genesis participation, genesis ceremonies often involve multiple independent parties with varying trust levels. The likelihood increases in:
- Public/permissionless chain launches with many genesis validators
- Testnets where validator vetting is less rigorous  
- Contentious forks where participants may want to sabotage the launch

Once genesis.json contains duplicate validators, the attack succeeds with 100% reliability - every node will crash on startup. The window of vulnerability is limited to the genesis ceremony phase.

## Recommendation

Add duplicate validator validation to `CollectTxs` before genesis transactions are included in genesis.json:

1. Create maps to track seen validator operator addresses and consensus public keys
2. During the gentx processing loop (lines 101-178), after extracting the `MsgCreateValidator` at line 139:
   - Check if the validator operator address already exists in the tracking map
   - Check if the consensus public key already exists in the tracking map
   - Return an error immediately if a duplicate is detected

This ensures duplicates are caught during collection (preventing them from entering genesis.json) rather than during chain initialization (where they cause panic).

## Proof of Concept

The report provides a comprehensive Go test demonstrating the vulnerability. The test creates two genesis transactions with duplicate validator keys and shows that `DeliverGenTxs` panics when processing them, as would occur during `InitChain`.

**Test demonstrates:**
- Setup: Two different accounts with valid balances
- Action: Create two `MsgCreateValidator` messages using the same validator operator address (or same consensus pubkey in variant test)
- Result: `DeliverGenTxs` panics when the second duplicate validator is processed, confirming the vulnerability causes node crashes during initialization

The panic occurs because the `MsgCreateValidator` handler returns an error for duplicates, which `DeliverGenTxs` handles by panicking. [5](#0-4) 

## Notes

The vulnerability exists because validation is split between two phases with a critical gap:
1. **Collection phase** (`CollectTxs`) - validates account balances only
2. **Delivery phase** (`DeliverGenTxs`) - validates validator uniqueness but panics on errors

The staking module's `ValidateGenesis` function does check for duplicate validators, but it validates the staking genesis state's Validators array, not the genutil genesis state's GenTxs array. The gentxs are converted to validators during `DeliverGenTxs` execution, after the staking genesis validation has completed.

This is a validation gap specific to genesis transaction processing that allows malicious gentxs to bypass collection-time validation and cause runtime panics during initialization.

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

**File:** x/staking/keeper/msg_server.go (L42-54)
```go
	// check to see if the pubkey or sender has been registered before
	if _, found := k.GetValidator(ctx, valAddr); found {
		return nil, types.ErrValidatorOwnerExists
	}

	pk, ok := msg.Pubkey.GetCachedValue().(cryptotypes.PubKey)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "Expecting cryptotypes.PubKey, got %T", pk)
	}

	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
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

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```
