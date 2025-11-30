# Audit Report

## Title
Missing Duplicate Validator Validation in Genesis Transaction Collection Causes Total Network Shutdown

## Summary
The `CollectTxs` function in the genutil module fails to validate for duplicate validator operator addresses or consensus public keys when collecting genesis transactions. This allows duplicate validators to be included in genesis.json, causing all network nodes to panic during chain initialization and preventing the blockchain from starting.

## Impact
Medium

## Finding Description

**Location:** `x/genutil/collect.go` (lines 101-178), `x/genutil/gentx.go` (lines 113-116), `x/staking/keeper/msg_server.go` (lines 43-44, 52-54) [1](#0-0) 

**Intended Logic:** 
During genesis ceremony, the `collect-gentxs` command should validate all genesis transactions comprehensively to ensure they can be successfully applied during chain initialization. This includes checking that no two validators share the same operator address or consensus public key, as validators must be uniquely identifiable. Invalid genesis transactions should be rejected during collection with proper error messages before being committed to genesis.json.

**Actual Logic:** 
The `CollectTxs` function only validates account balances and account existence. After extracting each `MsgCreateValidator` message at line 139, the function never maintains tracking maps for validator addresses or consensus public keys to detect duplicates across multiple gentx files. The function simply appends all gentxs to the result set without duplicate checking. [2](#0-1) 

**Exploitation Path:**
1. During genesis ceremony, multiple validators independently generate gentx files
2. A malicious genesis participant or configuration error causes a gentx to use the same validator operator address OR consensus public key as another validator
3. Genesis coordinator runs `collect-gentxs` which calls `CollectTxs`
4. `CollectTxs` validates both gentxs successfully (only checking account balances)
5. Both duplicate gentxs are included in the final genesis.json file
6. All validators download genesis.json and attempt to start their nodes
7. During `InitChain` ABCI call, the chain initialization proceeds via `app.initChainer`
8. The genutil module's `InitGenesis` function invokes `DeliverGenTxs` to process genesis transactions
9. First gentx successfully creates the validator
10. Second gentx (duplicate) attempts to create the validator, but the staking handler detects the duplicate and returns `ErrValidatorOwnerExists` or `ErrValidatorPubKeyExists` [3](#0-2) 

11. In `DeliverGenTxs`, the error result causes an immediate panic [4](#0-3) 

12. The panic propagates through the InitChain call stack with no recovery mechanism [5](#0-4) 

13. All nodes crash during initialization - complete network shutdown

**Security Guarantee Broken:** 
The network availability guarantee is violated. A single malicious or misconfigured genesis participant can prevent the entire network from ever becoming operational, constituting a denial-of-service vulnerability at the genesis level that exceeds their intended authority.

## Impact Explanation

**Affected Systems:**
All network nodes fail to complete chain initialization. The blockchain cannot start, meaning:
- No blocks can be produced
- No transactions can be processed  
- No consensus rounds can occur
- The network remains completely non-operational

**Severity Justification:**
This represents a total network shutdown scenario where:
- The chain is prevented from ever becoming operational
- 100% of network nodes fail simultaneously
- Failure occurs before any normal consensus or transaction processing begins
- No self-recovery mechanism exists
- Manual remediation is required: identifying the problematic gentx, removing it from genesis.json, regenerating the genesis file, redistributing to all validators, and coordinating a restart

This matches the specified Medium severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who can trigger it:**
Any participant in the genesis ceremony who submits a gentx. While this is a privileged role, the vulnerability qualifies under the exception rule because even a trusted role can inadvertently trigger an unrecoverable security failure that exceeds their intended authority.

**Realistic Scenarios:**
1. **Accidental triggers:**
   - Key generation software bugs producing duplicate keys
   - Configuration file copy-paste errors  
   - Manual setup mistakes in multi-validator environments
   - Backup/restore operations using outdated configurations

2. **Malicious triggers:**
   - Disgruntled genesis participant intentionally submitting duplicate validator
   - Contentious fork scenario where participant wants to sabotage launch
   - Compromised genesis participant's system

3. **High-probability contexts:**
   - Public/permissionless chain launches with many genesis validators
   - Testnets where validator vetting is less rigorous
   - Chains with decentralized genesis ceremony processes

**Likelihood Assessment:**
Once genesis.json contains duplicate validators, the attack succeeds with 100% reliability - every single node will fail to start. The impact (total network shutdown) vastly exceeds the intended authority of a genesis participant, who should only be able to control their own validator submission, not prevent the entire network from launching.

## Recommendation

Implement duplicate validator validation in the `CollectTxs` function:

1. **Before the gentx processing loop** (before line 101), initialize tracking maps:
   ```go
   seenValidatorAddrs := make(map[string]bool)
   seenConsensusPubKeys := make(map[string]bool)
   ```

2. **During the loop** (after extracting `MsgCreateValidator` at line 139):
   - Check if `msg.ValidatorAddress` already exists in `seenValidatorAddrs`
   - Extract the consensus public key from `msg.Pubkey` and check if it exists in `seenConsensusPubKeys`
   - Return a descriptive error if either duplicate is detected
   - Add both to their respective maps after validation passes

3. **Error message format:**
   ```go
   return appGenTxs, persistentPeers, fmt.Errorf(
       "duplicate validator detected in gentx %s: validator address %s already exists",
       fo.Name(), msg.ValidatorAddress)
   ```

This ensures duplicate validators are caught during the collection phase (where they fail gracefully with an error message) rather than during chain initialization (where they cause a panic and total network failure).

Additionally, consider enhancing the `ValidateGenesis` function to perform similar checks as a secondary validation layer. [6](#0-5) 

## Proof of Concept

While no executable test is provided in the claim, the vulnerability can be reproduced with the following test structure in `x/genutil/gentx_test.go`:

**Setup:**
1. Create test application context with simapp
2. Fund two different accounts (addr1, addr2) with sufficient token balances
3. Create two `MsgCreateValidator` messages:
   - First: uses addr1 as delegator, valAddr1 as operator, pubkey1 as consensus key
   - Second: uses addr2 as delegator, valAddr1 as operator (duplicate), pubkey2 as consensus key
4. Encode both messages as properly signed genesis transactions
5. Create a genesis state containing both gentxs

**Action:**
```go
validators, err := genutil.DeliverGenTxs(
    ctx, 
    genesisState.GenTxs, 
    app.StakingKeeper, 
    app.BaseApp.DeliverTx,
    encodingConfig.TxConfig,
)
```

**Expected Result:**
The function panics when processing the second gentx because:
1. First gentx successfully creates validator with valAddr1
2. Second gentx attempts to create validator with same valAddr1
3. `CreateValidator` handler returns `ErrValidatorOwnerExists`
4. `DeliverGenTxs` executes `panic(res.Log)` at line 115

The test should use `require.Panics()` to verify the panic occurs, confirming that duplicate validators in genesis transactions cause total initialization failure.

**Alternative PoC** (testing duplicate consensus pubkey):
Repeat the above but use the same consensus pubkey (pubkey1) in both `MsgCreateValidator` messages while keeping different operator addresses. This triggers `ErrValidatorPubKeyExists` with the same panic result.

## Notes

The vulnerability exists due to validation being improperly split across two phases:

1. **Collection phase** (`CollectTxs`) - Only validates account balances and account existence, missing validator uniqueness checks
2. **Delivery phase** (`DeliverGenTxs`) - Validates validator uniqueness through the staking handler, but uses panic for failure handling

This architectural gap allows malicious gentxs to pass initial validation but trigger unrecoverable panics during deployment. The proper solution is to move validator uniqueness validation to the collection phase where errors can be returned gracefully, preventing problematic genesis files from being created in the first place.

The TODO comment at line 138 of collect.go ("TODO abstract out staking message validation back to staking") suggests the developers recognized that staking validation is incomplete in the current implementation.

### Citations

**File:** x/genutil/collect.go (L101-178)
```go
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

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```

**File:** baseapp/abci.go (L73-73)
```go
	resp := app.initChainer(app.deliverState.ctx, *req)
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
