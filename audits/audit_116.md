# Audit Report

## Title
Array Index Out of Bounds Panic in Multisignature Gas Consumption Leading to Network-Wide Denial of Service

## Summary
Malformed MultiSignatureData with mismatched BitArray size and pubkey count can cause an index out of bounds panic in `ConsumeMultisignatureVerificationGas`, crashing validator nodes before validation occurs. While the security question references `signatureDataToBz` at lines 502-535, the actual vulnerability exists in the gas consumption logic at lines 445-470 of the same file, which processes malformed signature data in the ante handler chain. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- File: `x/auth/ante/sigverify.go`
- Function: `ConsumeMultisignatureVerificationGas`
- Lines: 459-460 (critical indexing operations) [1](#0-0) 

**Intended Logic:**
The `ConsumeMultisignatureVerificationGas` function should consume gas for each signature in a multisignature transaction by iterating through the BitArray and accessing corresponding pubkeys and signatures. Validation of array bounds should occur before any indexing operations.

**Actual Logic:**
The function iterates based on `size := sig.BitArray.Count()` without validating that:
1. `size <= len(pubkey.GetPubKeys())` before accessing `pubkey.GetPubKeys()[i]` at line 459
2. The number of set bits matches `len(sig.Signatures)` before accessing `sig.Signatures[sigIndex]` at line 460

The validation that checks these invariants exists in `VerifyMultisignature`, but it executes LATER in the ante handler chain. [2](#0-1) 

**Exploit Scenario:**
1. Attacker constructs a transaction with a multisig account containing N pubkeys (e.g., N=2)
2. Attacker crafts a `MultiSignatureData` via `ModeInfoAndSigToSignatureData` with:
   - A BitArray with size M > N (e.g., M=10) 
   - Some bits set beyond index N-1
   - Signatures array with fewer elements than set bits [3](#0-2) 

3. Transaction flows through the ante handler chain in this order:
   - SetPubKeyDecorator (line 55)
   - **SigGasConsumeDecorator (line 57)** ← Panics here
   - SigVerificationDecorator (line 58) ← Validation happens here (never reached) [4](#0-3) 

4. When `SigGasConsumeDecorator` calls `ConsumeMultisignatureVerificationGas`:
   - Loop executes with `i` from 0 to M-1
   - When `i >= N` and `BitArray.GetIndex(i)` is true, accessing `pubkey.GetPubKeys()[i]` causes panic
   - OR if set bits exceed `len(sig.Signatures)`, accessing `sig.Signatures[sigIndex]` causes panic

**Security Failure:**
The system fails to validate multisignature data bounds before performing array indexing operations, violating the memory safety invariant. This causes an unrecoverable panic that crashes the validator node.

## Impact Explanation

**Affected Components:**
- All validator nodes processing transactions
- Network consensus and transaction finality
- Block production capability

**Severity of Damage:**
- A single malformed transaction broadcast to the network causes ALL validator nodes to panic and crash simultaneously
- Network enters total shutdown - no new blocks can be produced
- Requires coordinated manual intervention to restart nodes
- Attacker can repeatedly broadcast malformed transactions to maintain the denial of service

**Systemic Impact:**
This constitutes a critical availability vulnerability enabling any unprivileged attacker to halt the entire blockchain network with a single transaction. The attack requires no special permissions, no capital/stake, and minimal technical sophistication.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can broadcast a malformed transaction. No special privileges, staking, or validator status required.

**Conditions Required:**
- Attacker constructs a multisig transaction with malformed `MultiSignatureData`
- Transaction must pass basic decoding and reach the ante handler chain
- No other prerequisites - can occur during normal network operation

**Frequency:**
- Can be exploited immediately and repeatedly
- Single transaction affects all validators simultaneously  
- Attacker can maintain persistent DoS by continuously broadcasting malformed transactions
- High probability of exploitation given low barrier to entry

## Recommendation

Add validation in `ConsumeMultisignatureVerificationGas` before the indexing loop to check array bounds:

```go
func ConsumeMultisignatureVerificationGas(
    meter sdk.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
    params types.Params, accSeq uint64,
) error {
    size := sig.BitArray.Count()
    pubKeys := pubkey.GetPubKeys()
    
    // ADD THIS VALIDATION:
    if len(pubKeys) != size {
        return fmt.Errorf("bit array size %d does not match pubkey count %d", size, len(pubKeys))
    }
    
    numSetBits := sig.BitArray.NumTrueBitsBefore(size)
    if len(sig.Signatures) != numSetBits {
        return fmt.Errorf("signature count %d does not match number of set bits %d", len(sig.Signatures), numSetBits)
    }
    
    sigIndex := 0
    for i := 0; i < size; i++ {
        // ... rest of existing logic
    }
    return nil
}
```

Alternatively, reorder the ante handler chain so `SigVerificationDecorator` (which calls `VerifyMultisignature` with proper validation) executes before `SigGasConsumeDecorator`, though this may have gas accounting implications.

## Proof of Concept

**File:** `x/auth/ante/sigverify_test.go`
**Test Function:** Add new test `TestMalformedMultisigCrash`

**Setup:**
1. Create a multisig public key with 2 sub-keys
2. Initialize test accounts and context
3. Construct a MultiSignatureData with mismatched BitArray size

**Trigger:**
```go
func (suite *AnteTestSuite) TestMalformedMultisigCrash() {
    // Create 2-of-2 multisig
    priv1, pub1, _ := testdata.KeyTestPubAddr()
    priv2, pub2, _ := testdata.KeyTestPubAddr()
    pubkeys := []cryptotypes.PubKey{pub1, pub2}
    multisigPubKey := kmultisig.NewLegacyAminoPubKey(2, pubkeys)
    
    // Create malformed MultiSignatureData:
    // BitArray with size 10 (> 2 pubkeys)
    // Set bit at index 5 (beyond pubkey array bounds)
    malformedSig := &signing.MultiSignatureData{
        BitArray: types.NewCompactBitArray(10), // Size 10, but only 2 pubkeys!
        Signatures: []signing.SignatureData{
            &signing.SingleSignatureData{
                SignMode: signing.SignMode_SIGN_MODE_DIRECT,
                Signature: []byte("dummy"),
            },
        },
    }
    malformedSig.BitArray.SetIndex(5, true) // Set bit beyond pubkey array
    
    // Create SignatureV2
    sigV2 := signing.SignatureV2{
        PubKey: multisigPubKey,
        Data: malformedSig,
        Sequence: 0,
    }
    
    params := types.DefaultParams()
    meter := sdk.NewInfiniteGasMeter(1, 1)
    
    // This should panic with index out of bounds
    suite.Require().Panics(func() {
        ante.ConsumeMultisignatureVerificationGas(meter, malformedSig, multisigPubKey, params, 0)
    })
}
```

**Observation:**
The test will panic when `ConsumeMultisignatureVerificationGas` attempts to access `pubkey.GetPubKeys()[5]` but the pubkey array only has 2 elements. This demonstrates the vulnerability that allows an attacker to crash validator nodes.

### Citations

**File:** x/auth/ante/sigverify.go (L445-470)
```go
// ConsumeMultisignatureVerificationGas consumes gas from a GasMeter for verifying a multisig pubkey signature
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
```

**File:** crypto/keys/multisig/multisig.go (L50-66)
```go
func (m *LegacyAminoPubKey) VerifyMultisignature(getSignBytes multisigtypes.GetSignBytesFunc, sig *signing.MultiSignatureData) error {
	bitarray := sig.BitArray
	sigs := sig.Signatures
	size := bitarray.Count()
	pubKeys := m.GetPubKeys()
	// ensure bit array is the correct size
	if len(pubKeys) != size {
		return fmt.Errorf("bit array size is incorrect, expecting: %d", len(pubKeys))
	}
	// ensure size of signature list
	if len(sigs) < int(m.Threshold) || len(sigs) > size {
		return fmt.Errorf("signature size is incorrect %d", len(sigs))
	}
	// ensure at least k signatures are set
	if bitarray.NumTrueBitsBefore(size) < int(m.Threshold) {
		return fmt.Errorf("not enough signatures set, have %d, expected %d", bitarray.NumTrueBitsBefore(size), int(m.Threshold))
	}
```

**File:** x/auth/tx/sigs.go (L66-85)
```go
	case *tx.ModeInfo_Multi_:
		multi := modeInfo.Multi

		sigs, err := decodeMultisignatures(sig)
		if err != nil {
			return nil, err
		}

		sigv2s := make([]signing.SignatureData, len(sigs))
		for i, mi := range multi.ModeInfos {
			sigv2s[i], err = ModeInfoAndSigToSignatureData(mi, sigs[i])
			if err != nil {
				return nil, err
			}
		}

		return &signing.MultiSignatureData{
			BitArray:   multi.Bitarray,
			Signatures: sigv2s,
		}, nil
```

**File:** x/auth/ante/ante.go (L47-60)
```go
	anteDecorators := []sdk.AnteFullDecorator{
		sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()), // outermost AnteDecorator. SetUpContext must be called first
		sdk.DefaultWrappedAnteDecorator(NewRejectExtensionOptionsDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateBasicDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewTxTimeoutHeightDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateMemoDecorator(options.AccountKeeper)),
		NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ParamsKeeper.(paramskeeper.Keeper), options.TxFeeChecker),
		sdk.DefaultWrappedAnteDecorator(NewSetPubKeyDecorator(options.AccountKeeper)), // SetPubKeyDecorator must be called before all signature verification decorators
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
		NewIncrementSequenceDecorator(options.AccountKeeper),
	}
```
