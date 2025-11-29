# Audit Report

## Title
Out-of-Bounds Panic in Multisig Verification Due to Missing Signature Count Validation

## Summary
The multisig verification functions `VerifyMultisignature` and `ConsumeMultisignatureVerificationGas` fail to validate that the number of signatures equals the number of true bits in the bit array. This allows an attacker to craft a transaction with mismatched counts, causing an out-of-bounds array access that panics the node, resulting in a denial-of-service attack.

## Impact
Medium

## Finding Description

**Location:**
- Primary: `crypto/keys/multisig/multisig.go`, function `VerifyMultisignature`, lines 50-96 [1](#0-0) 
- Secondary: `x/auth/ante/sigverify.go`, function `ConsumeMultisignatureVerificationGas`, lines 446-471 [2](#0-1) 

**Intended Logic:**
The signature count validation should ensure that the number of signatures provided matches exactly the number of signers indicated by true bits in the bit array, preventing any mismatch that could lead to out-of-bounds access during verification.

**Actual Logic:**
The validation only checks that the signature count is between the threshold and the total number of public keys. [3](#0-2)  It does NOT validate that `len(sigs)` equals `bitarray.NumTrueBitsBefore(size)`. During the verification loop, when iterating through true bits, the code accesses `sig.Signatures[sigIndex]` without bounds checking. [4](#0-3)  If there are more true bits than signatures, this causes a panic.

**Exploitation Path:**
1. Attacker constructs a transaction with a multisig signature where the protobuf `ModeInfo_Multi` contains independently specified `Bitarray` (N true bits) and `ModeInfos` (M elements where M < N). [5](#0-4) 
2. During transaction decoding in `ModeInfoAndSigToSignatureData`, the `MultiSignatureData` is constructed with the bitarray having more true bits than the signatures array has elements. [6](#0-5) 
3. The ante handler chain processes the transaction, with `SigGasConsumeDecorator` running before signature verification. [7](#0-6) 
4. In `ConsumeMultisignatureVerificationGas`, the loop iterates through all true bits and attempts to access `sig.Signatures[sigIndex]`. [8](#0-7)  When sigIndex exceeds the array bounds, Go runtime panics with an index out of range error.
5. The panic crashes the validator node processing the transaction.

**Security Guarantee Broken:**
Memory safety and availability guarantees are violated. The code assumes the signatures array has an element for every true bit in the bitarray, but this invariant is not enforced through validation.

## Impact Explanation

Any validator node that processes the malicious transaction will panic and crash. The crash occurs during transaction processing in the ante handler, which is part of the critical transaction validation path. An attacker can repeatedly broadcast such transactions to continuously crash nodes. If enough validators crash simultaneously, the network cannot reach consensus and halts. While no funds are directly at risk, network functionality is completely compromised, preventing transaction processing and potentially causing a network-wide denial of service.

## Likelihood Explanation

**Who Can Trigger:** Any network participant who can submit transactions. No special privileges, stake, or resources are required beyond the ability to craft and broadcast a transaction.

**Required Conditions:** The attacker needs to craft a transaction with a multisig signature containing mismatched bit array and signature counts. No special timing or network state is required. The vulnerability is triggered during normal transaction validation flow.

**Frequency:** Can be exploited at any time during normal network operation. Each malicious transaction will crash any node that attempts to process it. The attack can be repeated continuously by broadcasting multiple malicious transactions. With automated tooling, an attacker could potentially crash nodes faster than they can restart.

This vulnerability has high likelihood of exploitation because: (1) it's trivial to trigger with one malicious transaction, (2) the impact is immediate and deterministic, (3) there are no inherent rate limits or costs preventing repeated exploitation, and (4) the attack surface is available to all network participants.

## Recommendation

Add validation to ensure the number of signatures exactly equals the number of true bits in the bit array. In `VerifyMultisignature` after line 64:

```go
numTrueBits := bitarray.NumTrueBitsBefore(size)
if len(sigs) != numTrueBits {
    return fmt.Errorf("signature count %d does not match number of signers %d indicated by bit array", len(sigs), numTrueBits)
}
```

Apply the same validation in `ConsumeMultisignatureVerificationGas` before line 454. This ensures the invariant that every true bit has a corresponding signature, preventing out-of-bounds access.

## Proof of Concept

**Test Location:** `crypto/keys/multisig/multisig_test.go`

**Setup:**
- Create 5 public/private key pairs and corresponding signatures
- Create a multisig public key with threshold 3 out of 5 keys

**Action:**
- Construct a malicious `MultiSignatureData` with:
  - BitArray having 4 true bits (positions 0, 1, 2, 3)
  - Signatures array containing only 3 signature elements
- Call `VerifyMultisignature` with this malicious data

**Result:**
- The function panics when attempting to access `sig.Signatures[3]` (the 4th element) which doesn't exist
- The panic occurs at line 71 when `sigIndex=3` and the code tries to access the non-existent array element
- This demonstrates that a transaction with this signature structure will crash any node attempting to verify it

The test can be run with: `go test -v -run TestVerifyMultisignaturePanicOnMismatchedSigCount` in the `crypto/keys/multisig` directory.

**Notes:**
This vulnerability is present in two locations: the gas consumption phase (which runs first) and the actual signature verification phase. The panic would occur during gas consumption in `ConsumeMultisignatureVerificationGas` before reaching `VerifyMultisignature`. Both locations require the same fix to ensure the signatures count matches the true bits count.

### Citations

**File:** crypto/keys/multisig/multisig.go (L50-96)
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
	// index in the list of signatures which we are concerned with.
	sigIndex := 0
	for i := 0; i < size; i++ {
		if bitarray.GetIndex(i) {
			si := sig.Signatures[sigIndex]
			switch si := si.(type) {
			case *signing.SingleSignatureData:
				msg, err := getSignBytes(si.SignMode)
				if err != nil {
					return err
				}
				if !pubKeys[i].VerifySignature(msg, si.Signature) {
					return fmt.Errorf("unable to verify signature at index %d", i)
				}
			case *signing.MultiSignatureData:
				nestedMultisigPk, ok := pubKeys[i].(multisigtypes.PubKey)
				if !ok {
					return fmt.Errorf("unable to parse pubkey of index %d", i)
				}
				if err := nestedMultisigPk.VerifyMultisignature(getSignBytes, si); err != nil {
					return err
				}
			default:
				return fmt.Errorf("improper signature data type for index %d", sigIndex)
			}
			sigIndex++
		}
	}
	return nil
}
```

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

**File:** types/tx/tx.pb.go (L612-618)
```go
type ModeInfo_Multi struct {
	// bitarray specifies which keys within the multisig are signing
	Bitarray *types1.CompactBitArray `protobuf:"bytes,1,opt,name=bitarray,proto3" json:"bitarray,omitempty"`
	// mode_infos is the corresponding modes of the signers of the multisig
	// which could include nested multisig public keys
	ModeInfos []*ModeInfo `protobuf:"bytes,2,rep,name=mode_infos,json=modeInfos,proto3" json:"mode_infos,omitempty"`
}
```

**File:** x/auth/tx/sigs.go (L82-85)
```go
		return &signing.MultiSignatureData{
			BitArray:   multi.Bitarray,
			Signatures: sigv2s,
		}, nil
```

**File:** x/auth/ante/ante.go (L57-58)
```go
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
```
