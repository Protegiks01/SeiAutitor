# Audit Report

## Title
Missing Duplicate Validator Validation in Genesis Transaction Collection Causes Total Network Shutdown

## Summary
The `CollectTxs` function in the genutil module lacks validation for duplicate validator keys (operator addresses or consensus public keys) when collecting genesis transactions. This allows duplicate validators to be included in genesis.json, which causes all network nodes to panic during chain initialization, resulting in complete network failure before the blockchain can start.

## Impact
High

## Finding Description

**Location:** `x/genutil/collect.go` (lines 70-184), specifically the loop at lines 101-178

**Intended Logic:** 
During genesis ceremony, the `collect-gentxs` command should validate all genesis transactions to ensure they can be successfully applied during chain initialization. This includes verifying that no two validators use the same operator address or consensus public key, as validators must be uniquely identifiable. Invalid genesis transactions should be rejected during collection, before being committed to genesis.json.

**Actual Logic:** 
The `CollectTxs` function only validates account balances but does NOT check for duplicate validator operator addresses or consensus public keys across multiple gentx files. [1](#0-0)  The function extracts each `MsgCreateValidator` message at line 139 but never maintains a map of seen validator addresses or pubkeys to detect duplicates. The duplicate validation only occurs later during `DeliverGenTxs` when transactions are actually applied.

**Exploitation Path:**
1. During genesis ceremony, multiple validators generate gentxs independently
2. Attacker (malicious genesis participant) creates a gentx using the same validator operator address OR consensus public key as another validator
3. Genesis coordinator runs `collect-gentxs` which calls `CollectTxs`
4. `CollectTxs` validates both gentxs successfully (only checks account balances)
5. Both gentxs are included in the final genesis.json
6. All validators download genesis.json and start their nodes
7. During `InitChain`, genesis transactions are delivered via `DeliverGenTxs`
8. First gentx creates validator successfully
9. Second gentx (duplicate) attempts to create validator, but the handler detects the duplicate and returns `ErrValidatorOwnerExists` or `ErrValidatorPubKeyExists` [2](#0-1) 
10. In `DeliverGenTxs`, any non-OK result triggers a panic [3](#0-2) 
11. All nodes crash during initialization - total network shutdown

**Security Guarantee Broken:** 
The network availability guarantee is violated. A single malicious or misconfigured genesis participant can prevent the entire network from ever becoming operational, constituting a denial-of-service attack at the genesis level.

## Impact Explanation

**Affected Systems:** 
All network nodes fail to complete chain initialization. The blockchain cannot start, meaning no blocks can be produced, no transactions can be processed, and the network remains completely non-operational.

**Severity:** 
This represents a total network shutdown scenario that:
- Prevents the chain from ever becoming operational
- Affects 100% of network nodes simultaneously  
- Occurs before any normal consensus or transaction processing begins
- Cannot self-recover without manual intervention
- Requires coordinated manual remediation: identifying the malicious gentx, removing it, regenerating genesis.json, redistributing to all validators, and restarting the process

This matches the specified High severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who can trigger it:** 
Any participant in the genesis ceremony who submits a gentx. While this is a "privileged" role, the likelihood is significant because:

**Conditions required:** 
- Attacker must participate in genesis ceremony (or compromise one validator's gentx submission)
- Genesis coordinator runs `collect-gentxs` which includes the malicious/duplicate gentx
- No additional validation occurs before distributing genesis.json

**Likelihood Assessment:**
While requiring genesis participant access, this is realistic in:
- Public/permissionless chain launches with many genesis validators
- Testnets where validator vetting may be less rigorous  
- Contentious forks where participants may want to sabotage the launch
- Accidental scenarios: key generation bugs, configuration errors, copy-paste mistakes

Once genesis.json contains duplicate validators, the attack succeeds with 100% reliability - every node will fail to start. The impact (total network shutdown) far exceeds the intended authority of a genesis participant, who should be able to submit their gentx without preventing the entire network from starting.

## Recommendation

Add duplicate validator validation to the `CollectTxs` function before genesis transactions are included in genesis.json:

1. Create maps to track seen validator operator addresses and consensus public keys outside the loop (before line 101)
2. During the loop that processes each gentx file, after extracting the `MsgCreateValidator` at line 139:
   - Check if `msg.ValidatorAddress` already exists in the validator address map
   - Extract the consensus public key and check if it already exists in the pubkey map
   - Return an error if a duplicate is detected, preventing the gentx from being included
3. Add both the validator address and consensus pubkey to their respective maps after validation

This ensures duplicate validators are caught during collection (where they should fail gracefully with an error) rather than during chain initialization (where they cause a panic and total network failure).

## Proof of Concept

The report provides comprehensive test cases in `TestDuplicateValidatorInGenTxsCausesPanic` and `TestDuplicateValidatorPubKeyInGenTxsCausesPanic` that demonstrate:

**Setup:**
- Create two different accounts with sufficient balances
- Create two `MsgCreateValidator` messages with the same validator operator address (first test) or same consensus pubkey (second test)  
- Encode both as genesis transactions

**Action:**
- Call `DeliverGenTxs` with both transactions (simulating what happens during `InitChain`)

**Result:**
- First gentx succeeds in creating the validator
- Second gentx fails with `ErrValidatorOwnerExists` or `ErrValidatorPubKeyExists`
- `DeliverGenTxs` panics on the error (line 115: `panic(res.Log)`)
- Test confirms the panic with `require.Panics()`

The tests would run with: `cd x/genutil && go test -v -run TestDuplicateValidator`

These tests confirm that duplicate validators in gentxs cause chain initialization failure through a panic, validating the vulnerability claim.

## Notes

The vulnerability exists because validation is improperly split between two phases:
1. **Collection phase** (`CollectTxs`) - only validates account balances
2. **Delivery phase** (`DeliverGenTxs`) - validates validator uniqueness but uses panic on failure

This creates a critical gap where malicious gentxs pass collection but trigger a panic during delivery. The appropriate fix is to perform validator uniqueness validation during collection, using proper error returns rather than panics. The `ValidateGenesis` function at [4](#0-3)  also lacks duplicate checking, only verifying that each gentx contains a `MsgCreateValidator`.

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
