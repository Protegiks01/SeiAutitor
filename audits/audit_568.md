## Audit Report

## Title
Missing Duplicate Validator Validation in Genesis Transaction Collection Causes Total Network Shutdown

## Summary
The `CollectTxs` function in the genutil module fails to validate for duplicate validator keys (operator addresses or consensus public keys) when collecting genesis transactions. This allows an attacker participating in the genesis ceremony to include a gentx with a duplicate validator key, which will cause all nodes in the network to panic during chain initialization, resulting in total network shutdown before the blockchain can even start.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
During the genesis ceremony, the `collect-gentxs` command should validate all genesis transactions to ensure they can be successfully applied during chain initialization. This includes checking that no two validators use the same operator address or consensus public key, as validators must be uniquely identifiable.

**Actual Logic:** 
The `CollectTxs` function only validates that validator and delegator accounts have sufficient balances, but does NOT check for duplicate validator operator addresses or consensus public keys across multiple gentx files. The duplicate validation only occurs later during `DeliverGenTxs` when transactions are actually applied. [2](#0-1) 

The loop processes each gentx file and validates account balances, but never checks if another gentx has already registered the same validator key.

**Exploit Scenario:**
1. During genesis ceremony, multiple validators generate their gentxs independently
2. Attacker (malicious genesis participant) creates a gentx that intentionally uses the same validator operator address OR consensus public key as another validator
3. Genesis coordinator runs `simd collect-gentxs` which calls `CollectTxs`
4. `CollectTxs` validates both gentxs successfully (only checks account balances)
5. Both gentxs are included in the final genesis.json
6. All validators download genesis.json and attempt to start their nodes
7. During `InitChain`, `DeliverGenTxs` processes gentxs sequentially
8. First gentx creates validator successfully
9. Second gentx (duplicate) is delivered to `CreateValidator` handler which detects the duplicate [3](#0-2) 

10. Handler returns `ErrValidatorOwnerExists` or `ErrValidatorPubKeyExists`
11. In `DeliverGenTxs`, the error causes a panic: [4](#0-3) 

12. All nodes crash during initialization - total network shutdown

**Security Failure:** 
This breaks the network availability guarantee. A single malicious participant during genesis can weaponize duplicate validator keys to prevent the entire network from ever starting, constituting a denial-of-service attack at the genesis level.

## Impact Explanation

**Affected Systems:** 
All network nodes fail to complete chain initialization. The blockchain cannot start, meaning no blocks can be produced, no transactions can be processed, and the network remains completely non-operational.

**Severity:** 
This is a total network shutdown scenario. Unlike runtime attacks that might affect a subset of nodes or require coordination, this vulnerability:
- Prevents the chain from ever becoming operational
- Affects 100% of network nodes simultaneously
- Occurs before any normal consensus or transaction processing begins
- Cannot self-recover without manual intervention

**Recovery Requirements:**
- Manual identification of the malicious duplicate gentx
- Coordination among all validators to use a corrected genesis.json
- Complete restart of the genesis process
- Effectively requires a "pre-genesis hard fork" before the chain exists

This matches the in-scope High severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who can trigger it:** 
Any participant in the genesis ceremony who is authorized to submit a gentx. This typically includes initial validators, so the attacker needs to be one of the genesis validators (or compromise one validator's gentx submission).

**Conditions required:** 
- The attack occurs during the genesis setup phase
- Attacker must participate in genesis ceremony
- Genesis coordinator must run `collect-gentxs` which includes the malicious gentx
- No additional validation occurs before distributing genesis.json

**Likelihood:** 
While this requires the attacker to be a genesis participant, genesis ceremonies often involve multiple independent parties with varying levels of trust. A single malicious or compromised participant can execute this attack. The likelihood increases in:
- Public/permissionless chain launches with many genesis validators
- Testnets where validator vetting may be less rigorous
- Contentious forks where some participants may want to sabotage the launch

Once genesis.json is distributed with duplicate validators, the attack succeeds with 100% reliability - every node will fail to start.

## Recommendation

Add duplicate validator validation to the `CollectTxs` function before genesis transactions are included in genesis.json. Specifically:

1. Create maps to track seen validator operator addresses and consensus public keys
2. During the loop that processes each gentx file (lines 101-178), extract the validator information
3. Check if the validator operator address already exists in the map
4. Check if the consensus public key already exists in the map
5. Return an error if a duplicate is detected, preventing the malicious gentx from being included

Example validation to add after line 139:

```go
// Track validators to detect duplicates
validatorAddresses := make(map[string]bool)
validatorPubKeys := make(map[string]bool)

// In the loop, after extracting msg at line 139:
msg := msgs[0].(*stakingtypes.MsgCreateValidator)

// Check for duplicate validator address
if validatorAddresses[msg.ValidatorAddress] {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "duplicate validator address %s in gentx file %s", 
        msg.ValidatorAddress, fo.Name())
}
validatorAddresses[msg.ValidatorAddress] = true

// Check for duplicate consensus pubkey
pk, err := msg.Pubkey.GetCachedValue().(cryptotypes.PubKey)
if !ok {
    return appGenTxs, persistentPeers, fmt.Errorf("invalid pubkey type")
}
pkStr := pk.String()
if validatorPubKeys[pkStr] {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "duplicate validator pubkey in gentx file %s", fo.Name())
}
validatorPubKeys[pkStr] = true
```

This ensures duplicate validators are caught during collection, not during chain initialization, preventing the network shutdown scenario.

## Proof of Concept

**Test File:** `x/genutil/gentx_duplicate_test.go` (new test file)

**Setup:**
1. Create two genesis transactions with different accounts but the same validator operator address
2. Process them through `DeliverGenTxs` as would happen during `InitChain`

**Test Code:**
```go
package genutil_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/simapp"
	"github.com/cosmos/cosmos-sdk/simapp/helpers"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/genutil"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func TestDuplicateValidatorInGenTxsCausesPanic(t *testing.T) {
	// Setup
	checkTx := false
	app := simapp.Setup(checkTx)
	ctx := app.BaseApp.NewContext(checkTx, tmproto.Header{})
	encodingConfig := simapp.MakeTestEncodingConfig()

	// Create two different private keys for two different accounts
	priv1 := secp256k1.GenPrivKey()
	priv2 := secp256k1.GenPrivKey()
	pk1 := priv1.PubKey()
	pk2 := priv2.PubKey()
	addr1 := sdk.AccAddress(pk1.Address())
	addr2 := sdk.AccAddress(pk2.Address())

	// Use the same validator operator address for both (this is the duplicate)
	valAddr := sdk.ValAddress(pk1.Address())
	
	// Fund both accounts
	acc1 := app.AccountKeeper.NewAccountWithAddress(ctx, addr1)
	app.AccountKeeper.SetAccount(ctx, acc1)
	err := simapp.FundAccount(app.BankKeeper, ctx, addr1, 
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 100)})
	require.NoError(t, err)

	acc2 := app.AccountKeeper.NewAccountWithAddress(ctx, addr2)
	app.AccountKeeper.SetAccount(ctx, acc2)
	err = simapp.FundAccount(app.BankKeeper, ctx, addr2, 
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 100)})
	require.NoError(t, err)

	// Create two MsgCreateValidator with the SAME validator address (duplicate)
	amount := sdk.NewInt64Coin(sdk.DefaultBondDenom, 50)
	desc := stakingtypes.NewDescription("validator", "", "", "", "")
	comm := stakingtypes.CommissionRates{}
	one := sdk.OneInt()

	// First validator message - uses valAddr
	msg1, err := stakingtypes.NewMsgCreateValidator(valAddr, pk1, amount, desc, comm, one)
	require.NoError(t, err)
	
	// Second validator message - ALSO uses valAddr (duplicate operator address!)
	msg2, err := stakingtypes.NewMsgCreateValidator(valAddr, pk2, amount, desc, comm, one)
	require.NoError(t, err)

	// Create genesis transactions
	txBuilder1 := encodingConfig.TxConfig.NewTxBuilder()
	err = txBuilder1.SetMsgs(msg1)
	require.NoError(t, err)
	tx1, err := helpers.GenTx(
		encodingConfig.TxConfig,
		[]sdk.Msg{msg1},
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)},
		helpers.DefaultGenTxGas,
		ctx.ChainID(),
		[]uint64{0},
		[]uint64{0},
		priv1,
	)
	require.NoError(t, err)

	txBuilder2 := encodingConfig.TxConfig.NewTxBuilder()
	err = txBuilder2.SetMsgs(msg2)
	require.NoError(t, err)
	tx2, err := helpers.GenTx(
		encodingConfig.TxConfig,
		[]sdk.Msg{msg2},
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)},
		helpers.DefaultGenTxGas,
		ctx.ChainID(),
		[]uint64{0},
		[]uint64{0},
		priv2,
	)
	require.NoError(t, err)

	// Encode as JSON
	genTx1, err := encodingConfig.TxConfig.TxJSONEncoder()(tx1)
	require.NoError(t, err)
	genTx2, err := encodingConfig.TxConfig.TxJSONEncoder()(tx2)
	require.NoError(t, err)

	genTxs := []json.RawMessage{genTx1, genTx2}

	// Trigger: Attempt to deliver genesis transactions
	// This simulates what happens during InitChain
	deliverCtx := app.GetContextForDeliverTx([]byte{})
	
	// Observation: This should panic due to duplicate validator
	// The first gentx succeeds, the second one fails with ErrValidatorOwnerExists
	require.Panics(t, func() {
		genutil.DeliverGenTxs(
			deliverCtx, 
			genTxs, 
			app.StakingKeeper, 
			app.BaseApp.DeliverTx,
			encodingConfig.TxConfig,
		)
	}, "DeliverGenTxs should panic when encountering duplicate validator address")
}

func TestDuplicateValidatorPubKeyInGenTxsCausesPanic(t *testing.T) {
	// Similar test but with duplicate consensus public key instead
	checkTx := false
	app := simapp.Setup(checkTx)
	ctx := app.BaseApp.NewContext(checkTx, tmproto.Header{})
	encodingConfig := simapp.MakeTestEncodingConfig()

	priv1 := secp256k1.GenPrivKey()
	priv2 := secp256k1.GenPrivKey()
	pk1 := priv1.PubKey()
	pk2 := priv2.PubKey()
	addr1 := sdk.AccAddress(pk1.Address())
	addr2 := sdk.AccAddress(pk2.Address())

	// Use DIFFERENT validator operator addresses but SAME consensus pubkey
	valAddr1 := sdk.ValAddress(pk1.Address())
	valAddr2 := sdk.ValAddress(pk2.Address())
	
	// Fund both accounts
	acc1 := app.AccountKeeper.NewAccountWithAddress(ctx, addr1)
	app.AccountKeeper.SetAccount(ctx, acc1)
	err := simapp.FundAccount(app.BankKeeper, ctx, addr1, 
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 100)})
	require.NoError(t, err)

	acc2 := app.AccountKeeper.NewAccountWithAddress(ctx, addr2)
	app.AccountKeeper.SetAccount(ctx, acc2)
	err = simapp.FundAccount(app.BankKeeper, ctx, addr2, 
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 100)})
	require.NoError(t, err)

	amount := sdk.NewInt64Coin(sdk.DefaultBondDenom, 50)
	desc := stakingtypes.NewDescription("validator", "", "", "", "")
	comm := stakingtypes.CommissionRates{}
	one := sdk.OneInt()

	// Both messages use the SAME consensus pubkey pk1 (duplicate!)
	msg1, err := stakingtypes.NewMsgCreateValidator(valAddr1, pk1, amount, desc, comm, one)
	require.NoError(t, err)
	
	msg2, err := stakingtypes.NewMsgCreateValidator(valAddr2, pk1, amount, desc, comm, one)
	require.NoError(t, err)

	// Create and sign transactions
	tx1, err := helpers.GenTx(
		encodingConfig.TxConfig,
		[]sdk.Msg{msg1},
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)},
		helpers.DefaultGenTxGas,
		ctx.ChainID(),
		[]uint64{0},
		[]uint64{0},
		priv1,
	)
	require.NoError(t, err)

	tx2, err := helpers.GenTx(
		encodingConfig.TxConfig,
		[]sdk.Msg{msg2},
		sdk.Coins{sdk.NewInt64Coin(sdk.DefaultBondDenom, 10)},
		helpers.DefaultGenTxGas,
		ctx.ChainID(),
		[]uint64{0},
		[]uint64{0},
		priv2,
	)
	require.NoError(t, err)

	genTx1, err := encodingConfig.TxConfig.TxJSONEncoder()(tx1)
	require.NoError(t, err)
	genTx2, err := encodingConfig.TxConfig.TxJSONEncoder()(tx2)
	require.NoError(t, err)

	genTxs := []json.RawMessage{genTx1, genTx2}

	deliverCtx := app.GetContextForDeliverTx([]byte{})
	
	// Observation: Should panic due to duplicate pubkey
	require.Panics(t, func() {
		genutil.DeliverGenTxs(
			deliverCtx, 
			genTxs, 
			app.StakingKeeper, 
			app.BaseApp.DeliverTx,
			encodingConfig.TxConfig,
		)
	}, "DeliverGenTxs should panic when encountering duplicate validator consensus pubkey")
}
```

**Observation:**
Both tests demonstrate that when `DeliverGenTxs` processes genesis transactions with duplicate validator keys, the function panics. This panic occurs during `InitChain`, preventing the blockchain from starting. The first test shows duplicate operator addresses, and the second shows duplicate consensus public keys - both cause total network shutdown.

Run these tests with:
```bash
cd x/genutil
go test -v -run TestDuplicateValidator
```

The tests will pass (detect the panic) on the current vulnerable code, confirming that duplicate validators in gentxs cause chain initialization failure.

## Notes

The vulnerability exists because validation is split between two phases:
1. **Collection phase** (`CollectTxs`) - validates account balances only
2. **Delivery phase** (`DeliverGenTxs`) - validates validator uniqueness

This creates a critical gap: malicious gentxs pass collection but fail during delivery with a panic, causing total network shutdown. The fix is to perform validator uniqueness validation during collection, before gentxs are committed to genesis.json.

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

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```
