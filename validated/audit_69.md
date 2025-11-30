# Audit Report

## Title
Genesis Transaction Validation Bypass Enables Chain Startup Denial-of-Service

## Summary
The `CollectTxs` function in the genesis transaction collection process fails to call `ValidateBasic()` on transaction messages, while `DeliverGenTxs` does call it and panics on validation failure. This validation gap allows invalid genesis transactions containing empty `CommissionRates` or `Description` structs to be included in genesis.json, causing complete network startup failure when all nodes attempt initialization.

## Impact
Medium

## Finding Description

**Location:**
- Validation gap: [1](#0-0) 
- Panic on delivery failure: [2](#0-1) 
- ValidateBasic enforcement in delivery: [3](#0-2) 
- Empty struct validation: [4](#0-3) 

**Intended Logic:**
Genesis transactions should undergo thorough validation during the `collect-gentxs` phase to ensure only valid transactions enter genesis.json. Pre-validated transactions should then execute successfully during chain initialization without errors.

**Actual Logic:**
The `CollectTxs` function validates account balances and delegation amounts [1](#0-0)  but omits calling `ValidateBasic()` on the message objects themselves. During chain startup, the transaction delivery pipeline calls `validateBasicTxMsgs` [5](#0-4)  which invokes `ValidateBasic()` on each message. The `MsgCreateValidator.ValidateBasic()` method explicitly checks for empty `CommissionRates{}` and `Description{}` structs and returns errors for them [4](#0-3) .

**Exploitation Path:**
1. Genesis participant creates a gentx JSON file with empty `CommissionRates{}` or `Description{}`
2. Places file in the gentxs directory before `collect-gentxs` execution
3. `CollectTxs` validates balances and delegation amounts but skips `ValidateBasic()` call
4. Invalid gentx is included in genesis.json
5. During chain startup, `InitGenesis` is invoked [6](#0-5) 
6. `DeliverGenTxs` processes each gentx and calls `deliverTx` (BaseApp.DeliverTx)
7. The delivery pipeline calls `validateBasicTxMsgs` which invokes `ValidateBasic()`
8. `ValidateBasic()` returns error for empty commission or description
9. Code unconditionally panics: `if !res.IsOK() { panic(res.Log) }` [2](#0-1) 
10. All nodes using the same genesis.json experience identical panic
11. Network cannot start

**Security Guarantee Broken:**
Defense-in-depth validation is violated. The system performs inconsistent validation across boundaries - some checks (balances, delegation amounts) occur during collection, while critical message validity checks only occur during delivery. This allows invalid data to bypass initial validation gates and cause catastrophic failure at genesis initialization.

## Impact Explanation

This vulnerability causes **complete network failure at genesis initialization**:

- **Irrecoverable without manual intervention**: The chain cannot self-recover. Recovery requires identifying the malicious or misconfigured gentx, removing it from the gentxs directory, and regenerating genesis.json
- **Affects all nodes simultaneously**: Every node using the same genesis.json file will experience the identical panic, preventing network formation
- **Network never reaches operational state**: No blocks can be produced, no transactions processed, no consensus achieved
- **Pre-consensus DoS**: The failure occurs before consensus mechanisms can initialize

This precisely matches the impact criterion: "Network not being able to confirm new transactions (total network shutdown)" which is classified as **Medium** severity.

## Likelihood Explanation

**Who Can Trigger:**
- Genesis ceremony participants who have authority to submit gentx files
- Could occur accidentally through configuration errors or incomplete validation of gentx parameters

**Required Conditions:**
- Access to submit a gentx file during genesis ceremony (standard for genesis participants)
- Empty commission rates or description fields in the gentx structure
- Timing: before `collect-gentxs` command execution

**Frequency:**
While exploitable only during the one-time genesis window, the impact is catastrophic and network-wide. The attack requires minimal sophistication - simply creating a JSON file with empty struct fields. Importantly, an honest participant could trigger this accidentally through misconfiguration.

**Privilege Exception Justification:**
Although genesis participants have a privileged role, this qualifies under the stated exception: "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority." A genesis participant's intended authority is to configure their own validator, not to prevent the entire network from starting. A single participant's error (intentional or accidental) causing complete network failure that affects all participants and requires manual intervention to resolve clearly exceeds their intended privilege scope.

## Recommendation

Add `ValidateBasic()` validation in the `CollectTxs` function after message extraction:

```go
msgs := genTx.GetMsgs()
for _, msg := range msgs {
    if err := msg.ValidateBasic(); err != nil {
        return appGenTxs, persistentPeers, fmt.Errorf("gentx %s failed ValidateBasic: %w", fo.Name(), err)
    }
}
```

This ensures validation parity between collection-time and delivery-time checks, rejecting invalid gentxs during the collection phase rather than causing panic during genesis initialization. Insert this validation immediately after line 136 in `x/genutil/collect.go` where messages are extracted.

## Proof of Concept

**Setup:**
The existing test suite demonstrates that empty `CommissionRates{}` can be constructed [7](#0-6) 

**Test Case:**
Add the following test case to `TestDeliverGenTxs` in `x/genutil/gentx_test.go`:

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
The test will panic when `DeliverGenTxs` is called, confirming that an invalid gentx with empty commission rates bypasses collection-phase validation but causes a panic during genesis delivery.

**Verification:**
Run: `go test -v ./x/genutil/... -run TestDeliverGenTxs`

## Notes

This represents a defense-in-depth validation failure in the genesis initialization process. While genesis participants hold a special trusted role, security principles require consistent validation at all trust boundaries. The fact that `CollectTxs` performs some validations (account balances, delegation amounts) but omits others (`ValidateBasic()`) creates an exploitable inconsistency that can prevent the entire network from initializing.

The vulnerability qualifies as valid under the privilege exception because a single genesis participant's error - whether intentional or accidental - causes an unrecoverable network-wide failure that exceeds their intended authority scope. The impact precisely matches the Medium severity criterion: "Network not being able to confirm new transactions (total network shutdown)."

### Citations

**File:** x/genutil/collect.go (L136-177)
```go
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
```

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```

**File:** baseapp/baseapp.go (L787-801)
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
}
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

**File:** x/genutil/genesis.go (L17-18)
```go
	if len(genesisState.GenTxs) > 0 {
		validators, err = DeliverGenTxs(ctx, genesisState.GenTxs, stakingKeeper, deliverTx, txEncodingConfig)
```

**File:** x/genutil/gentx_test.go (L30-32)
```go
	desc  = stakingtypes.NewDescription("testname", "", "", "", "")
	comm  = stakingtypes.CommissionRates{}
)
```
