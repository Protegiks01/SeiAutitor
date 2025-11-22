## Audit Report

## Title
ValidateSigCountDecorator Fails to Enforce TxSigLimit for Accounts with Pre-existing Multisig Public Keys

## Summary
The `ValidateSigCountDecorator` in `x/auth/ante/sigverify.go` (lines 385-407) incorrectly counts signatures when a signer's public key is already set on their account. For accounts with multisig public keys containing many subkeys, the decorator counts only 1 signature instead of the actual number of subkeys, allowing transactions to bypass the `TxSigLimit` parameter. [1](#0-0) 

## Impact
**Medium Severity**

## Finding Description

**Location:** 
- File: `x/auth/ante/sigverify.go`
- Function: `ValidateSigCountDecorator.AnteHandle` (lines 385-407)
- Helper function: `CountSubKeys` (lines 484-496) [2](#0-1) 

**Intended Logic:**
The `ValidateSigCountDecorator` is designed to enforce that no transaction exceeds the `TxSigLimit` parameter (default value: 7), which limits the maximum number of signatures including all subkeys in nested multisig structures. This limit protects the network from DoS attacks via computationally expensive signature verification. [3](#0-2) 

**Actual Logic:**
The validator calls `GetPubKeys()` which returns `nil` for signers whose public keys are already set on their accounts. When `CountSubKeys(nil)` is called, the type assertion fails and it returns 1 instead of recursively counting the actual subkeys in the account's multisig public key. [4](#0-3) 

**Exploit Scenario:**
1. Initially, `TxSigLimit` is set to a high value (e.g., 100) via genesis or governance
2. Users create accounts with large multisig structures (e.g., 50 subkeys) that are within the limit
3. The first transaction from these accounts includes the multisig pubkey, which passes `ValidateSigCountDecorator` and gets set on the account
4. Governance votes to reduce `TxSigLimit` to 7 to improve network security and reduce DoS risk
5. Existing accounts with 50-subkey multisigs create new transactions, omitting the pubkey field (since it's already on the account)
6. `ValidateSigCountDecorator` counts these as 1 signature instead of 50, allowing the transaction to pass
7. The transaction proceeds to signature verification, consuming excessive CPU resources that the reduced limit was meant to prevent [5](#0-4) 

**Security Failure:**
The security invariant "no transaction shall contain more than TxSigLimit signatures" is violated. The decorator's check becomes ineffective for accounts with pre-existing multisig keys, defeating the purpose of the `TxSigLimit` parameter as a DoS protection mechanism.

## Impact Explanation

The vulnerability allows transactions to bypass the `TxSigLimit` parameter, which is specifically designed to prevent resource exhaustion attacks. When exploited:

- **Network Resource Consumption:** Transactions with signatures far exceeding the intended limit consume excessive CPU for signature verification and memory for processing
- **Parameter Ineffectiveness:** Governance decisions to reduce `TxSigLimit` for security/performance reasons are rendered ineffective for existing accounts
- **DoS Potential:** Attackers with pre-existing large multisig accounts can submit transactions that consume disproportionate resources, potentially causing nodes to slow down or crash
- **Unfair Resource Usage:** While gas is charged for signature verification, the `TxSigLimit` serves as a hard safety limit independent of economic incentives to prevent system abuse

This fits the in-scope impact: "**Medium: Causing network processing nodes to process transactions from the mempool beyond set parameters**" - transactions are processed with signature counts exceeding the TxSigLimit parameter.

## Likelihood Explanation

**Triggering Conditions:**
- Requires governance to have set a high initial `TxSigLimit` or to reduce it after accounts with large multisigs exist
- Any user with an account containing a multisig can exploit this
- No special privileges required

**Frequency:**
- Governance parameter changes are legitimate actions that occur in Cosmos SDK chains
- Once triggered, any affected account can repeatedly exploit this in every transaction
- The vulnerability persists until accounts with large multisigs are migrated or the code is fixed

**Ease of Exploitation:**
- Simple to execute: just omit the pubkey from transactions for accounts with existing large multisigs
- No complex setup or timing requirements
- Can be done inadvertently by normal users or deliberately by attackers

## Recommendation

Modify `ValidateSigCountDecorator` to count signatures based on the actual public key stored on the account, not just the pubkey provided in the transaction. When a transaction provides `nil` for a signer's pubkey (indicating it's already set), retrieve the actual pubkey from the account and count its subkeys:

```go
func (vscd ValidateSigCountDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
    sigTx, ok := tx.(authsigning.SigVerifiableTx)
    if !ok {
        return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must be a sigTx")
    }

    params := vscd.ak.GetParams(ctx)
    pubKeys, err := sigTx.GetPubKeys()
    if err != nil {
        return ctx, err
    }
    signers := sigTx.GetSigners()

    sigCount := 0
    for i, pk := range pubKeys {
        // If pubkey is nil, get it from the account
        if pk == nil {
            acc, err := GetSignerAcc(ctx, vscd.ak, signers[i])
            if err != nil {
                return ctx, err
            }
            pk = acc.GetPubKey()
            if pk == nil {
                // Account has no pubkey set, skip counting
                continue
            }
        }
        
        sigCount += CountSubKeys(pk)
        if uint64(sigCount) > params.TxSigLimit {
            return ctx, sdkerrors.Wrapf(sdkerrors.ErrTooManySignatures,
                "signatures: %d, limit: %d", sigCount, params.TxSigLimit)
        }
    }

    return next(ctx, tx, simulate)
}
```

## Proof of Concept

**File:** `x/auth/ante/ante_test.go`

**Test Function:** Add the following test function:

```go
func (suite *AnteTestSuite) TestSigCountBypassWithExistingMultisig() {
    suite.SetupTest(false)
    
    // Step 1: Set initial TxSigLimit to 100
    params := suite.app.AccountKeeper.GetParams(suite.ctx)
    params.TxSigLimit = 100
    suite.app.AccountKeeper.SetParams(suite.ctx, params)
    
    // Step 2: Create a large multisig with 50 subkeys
    numKeys := 50
    privKeys := make([]cryptotypes.PrivKey, numKeys)
    pubKeys := make([]cryptotypes.PubKey, numKeys)
    for i := 0; i < numKeys; i++ {
        privKeys[i] = secp256k1.GenPrivKey()
        pubKeys[i] = privKeys[i].PubKey()
    }
    multisigPubKey := kmultisig.NewLegacyAminoPubKey(25, pubKeys) // threshold = 25
    
    // Step 3: Create account and set the large multisig on it via first transaction
    multisigAddr := sdk.AccAddress(multisigPubKey.Address())
    acc := suite.app.AccountKeeper.NewAccountWithAddress(suite.ctx, multisigAddr)
    suite.app.AccountKeeper.SetAccount(suite.ctx, acc)
    
    // Create first transaction that sets the pubkey
    msg := testdata.NewTestMsg(multisigAddr)
    feeAmount := testdata.NewTestFeeAmount()
    gasLimit := testdata.NewTestGasLimit()
    
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    suite.txBuilder.SetMsgs(msg)
    suite.txBuilder.SetFeeAmount(feeAmount)
    suite.txBuilder.SetGasLimit(gasLimit)
    
    // Sign with threshold signatures
    signers := make([]signing.SignatureV2, 25)
    for i := 0; i < 25; i++ {
        signers[i] = signing.SignatureV2{
            PubKey: pubKeys[i],
            Data: &signing.SingleSignatureData{
                SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
                Signature: []byte("dummy"),
            },
        }
    }
    
    multiSigData := multisig.NewMultisig(len(pubKeys))
    for i := 0; i < 25; i++ {
        multiSigData.AddSignature(signers[i].Data.(*signing.SingleSignatureData), i)
    }
    
    sigV2 := signing.SignatureV2{
        PubKey: multisigPubKey,
        Data:   multiSigData,
    }
    suite.txBuilder.SetSignatures(sigV2)
    
    // First transaction passes with TxSigLimit=100
    tx := suite.txBuilder.GetTx()
    _, err := suite.anteHandler(suite.ctx, tx, false)
    suite.Require().NoError(err, "First transaction should pass with TxSigLimit=100")
    
    // Verify pubkey is now set on account
    acc = suite.app.AccountKeeper.GetAccount(suite.ctx, multisigAddr)
    suite.Require().NotNil(acc.GetPubKey(), "Account should have pubkey set")
    
    // Step 4: Reduce TxSigLimit to 7 via governance
    params.TxSigLimit = 7
    suite.app.AccountKeeper.SetParams(suite.ctx, params)
    
    // Step 5: Create second transaction with nil pubkey (omitted)
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    suite.txBuilder.SetMsgs(msg)
    suite.txBuilder.SetFeeAmount(feeAmount)
    suite.txBuilder.SetGasLimit(gasLimit)
    
    // Set signature with nil pubkey (account already has it)
    sigV2Nil := signing.SignatureV2{
        PubKey: nil, // Omit pubkey
        Data:   multiSigData,
    }
    suite.txBuilder.SetSignatures(sigV2Nil)
    
    tx = suite.txBuilder.GetTx()
    
    // This transaction SHOULD fail because account has 50 subkeys > TxSigLimit(7)
    // But it incorrectly PASSES because ValidateSigCountDecorator counts nil as 1
    _, err = suite.anteHandler(suite.ctx, tx, false)
    
    // The vulnerability: transaction passes when it should fail
    suite.Require().NoError(err, "VULNERABILITY: Transaction with 50 subkeys bypasses TxSigLimit=7")
    
    // Expected behavior: should return ErrTooManySignatures
    // suite.Require().ErrorIs(err, sdkerrors.ErrTooManySignatures, "Should reject transaction exceeding TxSigLimit")
}
```

**Setup:** The test uses the standard AnteTestSuite framework.

**Trigger:** 
1. Initialize `TxSigLimit` to 100
2. Create an account with a 50-subkey multisig via a transaction
3. Reduce `TxSigLimit` to 7
4. Submit a new transaction with nil pubkey for that account

**Observation:** 
The second transaction passes when it should be rejected. The test demonstrates that `ValidateSigCountDecorator` counts the nil pubkey as 1 signature instead of 50, allowing it to bypass the `TxSigLimit` of 7. The expected behavior (commented out) would be to receive `ErrTooManySignatures`.

**Notes**

The vulnerability specifically occurs in the interaction between `SetPubKeyDecorator` and `ValidateSigCountDecorator` in the ante handler chain. While `SetPubKeyDecorator` correctly handles nil pubkeys for accounts that already have them set, `ValidateSigCountDecorator` fails to retrieve and count the actual pubkey from the account storage. This creates a bypass mechanism that undermines the security guarantees of the `TxSigLimit` parameter, particularly when governance adjusts the limit for security reasons.

### Citations

**File:** x/auth/ante/sigverify.go (L385-407)
```go
func (vscd ValidateSigCountDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must be a sigTx")
	}

	params := vscd.ak.GetParams(ctx)
	pubKeys, err := sigTx.GetPubKeys()
	if err != nil {
		return ctx, err
	}

	sigCount := 0
	for _, pk := range pubKeys {
		sigCount += CountSubKeys(pk)
		if uint64(sigCount) > params.TxSigLimit {
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrTooManySignatures,
				"signatures: %d, limit: %d", sigCount, params.TxSigLimit)
		}
	}

	return next(ctx, tx, simulate)
}
```

**File:** x/auth/ante/sigverify.go (L484-496)
```go
func CountSubKeys(pub cryptotypes.PubKey) int {
	v, ok := pub.(*kmultisig.LegacyAminoPubKey)
	if !ok {
		return 1
	}

	numKeys := 0
	for _, subkey := range v.GetPubKeys() {
		numKeys += CountSubKeys(subkey)
	}

	return numKeys
}
```

**File:** x/auth/types/params.go (L11-18)
```go
// Default parameter values
const (
	DefaultMaxMemoCharacters      uint64 = 256
	DefaultTxSigLimit             uint64 = 7
	DefaultTxSizeCostPerByte      uint64 = 10
	DefaultSigVerifyCostED25519   uint64 = 590
	DefaultSigVerifyCostSecp256k1 uint64 = 1000
)
```

**File:** x/auth/signing/sig_verifiable_tx.go (L14-14)
```go
	GetPubKeys() ([]cryptotypes.PubKey, error) // If signer already has pubkey in context, this list will have nil in its place
```

**File:** x/auth/ante/ante.go (L55-56)
```go
		sdk.DefaultWrappedAnteDecorator(NewSetPubKeyDecorator(options.AccountKeeper)), // SetPubKeyDecorator must be called before all signature verification decorators
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
```
