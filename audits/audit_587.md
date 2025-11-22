## Audit Report

## Title
Insufficient Validation in Genesis Transaction Collection Allows Chain Startup DoS

## Summary
The `CollectTxs` function in `x/genutil/collect.go` validates that both delegator and validator addresses exist in the genesis balances map but fails to verify they represent the same account. This allows an attacker to submit a malicious genesis transaction (gentx) with mismatched addresses that passes collection but causes chain initialization to fail, resulting in a permanent denial of service.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The `CollectTxs` function should validate that genesis transactions are valid and can be executed successfully when the chain starts. According to the staking module's invariant, a validator's operator address must equal the delegator address for `MsgCreateValidator` messages used in genesis transactions. [2](#0-1) 

**Actual Logic:**
The `CollectTxs` function only checks that both the delegator address and validator address independently exist in the genesis balances map, without verifying they are equal:
- Line 148 checks: `delBal, delOk := balancesMap[delAddr]`
- Line 158 checks: `_, valOk := balancesMap[sdk.AccAddress(valAddr).String()]`

These checks allow a gentx where the delegator address (Address A) and validator address (Address B) are different, as long as both exist in the balances map.

**Exploit Scenario:**
1. An attacker creates two accounts (A and B) in the genesis balances
2. The attacker manually crafts a gentx JSON file with:
   - `DelegatorAddress` = Address A (exists in genesis balances)
   - `ValidatorAddress` = Address B (exists in genesis balances, but B ≠ A)
3. The attacker places this malicious gentx file in the gentx directory
4. When the network coordinator runs `collect-gentxs`, the `CollectTxs` function validates both addresses exist in balances and includes the malicious gentx in the final genesis file
5. When the chain attempts to start, `DeliverGenTxs` processes the gentx through the transaction delivery pipeline [3](#0-2) 
6. The `validateBasicTxMsgs` function calls `ValidateBasic()` on the `MsgCreateValidator` message [4](#0-3) 
7. `ValidateBasic()` detects that validator address ≠ delegator address and returns an error
8. The transaction delivery fails, causing a panic that prevents chain initialization [5](#0-4) 

**Security Failure:**
This breaks the availability property of the blockchain. The chain cannot start with a malicious gentx in the genesis file, creating a permanent denial of service until manual intervention removes or corrects the invalid transaction.

## Impact Explanation

**Affected Processes:** 
- Chain initialization and startup
- Network availability
- Validator onboarding process

**Severity of Damage:**
- The entire network cannot start if even one malicious gentx is included in the genesis file
- This is a permanent DoS that requires manual intervention (editing the genesis file to remove the malicious gentx)
- All validator nodes attempting to start the network will panic and halt
- The attack prevents the blockchain from ever producing its first block

**Why This Matters:**
During the genesis phase of a new blockchain network, validators submit gentx files to be collected into the final genesis file. An attacker who can submit a gentx (either as a malicious validator or by compromising the gentx submission process) can permanently prevent the network from launching. This is particularly critical during mainnet launches where coordination among many parties is required.

## Likelihood Explanation

**Who Can Trigger:**
Any participant in the genesis ceremony who can submit a gentx file to the collection directory. This typically includes:
- Validators participating in the network launch
- Anyone with write access to the gentx directory during genesis preparation

**Required Conditions:**
- The attacker must have at least two accounts with balances in the genesis state
- The attacker must be able to place a crafted gentx JSON file in the gentx collection directory
- The malicious gentx must be included before the `collect-gentxs` command is run

**Frequency:**
This vulnerability can be exploited once during the genesis phase. However, its impact is total network failure, making it a critical single-point-of-failure. The attack is straightforward to execute and doesn't require sophisticated techniques.

## Recommendation

Add validation in `CollectTxs` to verify that the delegator address equals the validator address before accepting a gentx. The fix should be implemented at line 158-165 in `collect.go`:

```go
// After line 158, add:
if !sdk.AccAddress(valAddr).Equals(sdk.AccAddress([]byte(delAddr))) {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "validator address %s must equal delegator address %s in genesis transaction",
        sdk.AccAddress(valAddr).String(), delAddr,
    )
}
```

Alternatively, call `msg.ValidateBasic()` on the extracted `MsgCreateValidator` message before line 148 to ensure all message-level validations are performed during collection:

```go
// After line 139, add:
if err := msg.ValidateBasic(); err != nil {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "invalid genesis transaction in %s: %w", fo.Name(), err,
    )
}
```

## Proof of Concept

**File:** `x/genutil/collect_test.go`

**Test Function:** `TestCollectTxsMismatchedAddresses`

**Setup:**
1. Create a temporary directory for gentx files
2. Generate two different key pairs (pk1 and pk2) with corresponding addresses (addr1 and addr2)
3. Create a genesis document with both addr1 and addr2 having balances
4. Manually construct a `MsgCreateValidator` with:
   - `DelegatorAddress` = addr1
   - `ValidatorAddress` = sdk.ValAddress(pk2.Address()).String() (which converts to addr2)
5. Create a valid transaction containing this message, sign it, and save as a gentx JSON file

**Trigger:**
Call `CollectTxs` with the crafted gentx file in the collection directory

**Observation:**
The test should demonstrate that:
1. `CollectTxs` returns successfully without error (the malicious gentx passes collection)
2. The returned gentx list includes the malicious transaction
3. When attempting to execute the gentx via `DeliverGenTxs` or calling `ValidateBasic()` on the message, it fails with "validator address is invalid" error

This proves that the collection phase accepts invalid gentxs that will cause chain initialization to fail, confirming the denial-of-service vulnerability.

**Test Code Structure:**
```go
func TestCollectTxsMismatchedAddresses(t *testing.T) {
    // 1. Setup: Create two accounts with different addresses
    // 2. Create genesis state with both accounts having balances
    // 3. Craft MsgCreateValidator with mismatched delegator/validator addresses
    // 4. Save as gentx JSON file
    // 5. Call CollectTxs and verify it succeeds (vulnerability)
    // 6. Verify ValidateBasic on the message fails (proving it's invalid)
    // 7. Demonstrate chain would panic during DeliverGenTxs
}
```

### Citations

**File:** x/genutil/collect.go (L148-165)
```go
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
```

**File:** x/staking/types/msg.go (L108-110)
```go
	if !sdk.AccAddress(valAddr).Equals(delAddr) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "validator address is invalid")
	}
```

**File:** x/genutil/gentx.go (L113-116)
```go
		res := deliverTx(ctx, abci.RequestDeliverTx{Tx: bz}, tx, sha256.Sum256(bz))
		if !res.IsOK() {
			panic(res.Log)
		}
```

**File:** baseapp/baseapp.go (L923-925)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```
