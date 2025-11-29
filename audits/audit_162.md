# Audit Report

## Title
Out-of-Bounds Panic in Multisig Verification Due to Missing Signature Count Validation Against True Bits

## Summary
The `VerifyMultisignature` function in `crypto/keys/multisig/multisig.go` fails to validate that the number of provided signatures matches the number of true bits in the bit array. This allows an attacker to craft a malicious multisig transaction that triggers an out-of-bounds array access, causing a node panic and denial of service. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:**
- Primary: `crypto/keys/multisig/multisig.go`, function `VerifyMultisignature`, lines 50-96
- Secondary: `x/auth/ante/sigverify.go`, function `ConsumeMultisignatureVerificationGas`, lines 446-471 [2](#0-1) 

**Intended Logic:**
The signature count validation should ensure that the number of signatures provided exactly matches the number of signers indicated by true bits in the bit array, preventing any mismatch that could lead to out-of-bounds access during verification.

**Actual Logic:**
The validation only checks that signatures are between threshold and total pubkeys (`len(sigs) >= int(m.Threshold) && len(sigs) <= size`), and that true bits meet threshold (`bitarray.NumTrueBitsBefore(size) >= int(m.Threshold)`). However, it does NOT validate that `len(sigs)` equals `NumTrueBitsBefore(size)`. During the verification loop (lines 69-94), when iterating through bit positions, the code accesses `sig.Signatures[sigIndex]` without bounds checking, assuming every true bit has a corresponding signature.

**Exploitation Path:**
1. Attacker crafts a transaction with a multisig signature containing independently-specified fields in the protobuf `ModeInfo_Multi` structure
2. The attacker sets the `Bitarray` field to have N true bits (e.g., 4 bits at positions 0,1,2,3)
3. The attacker provides only M signatures where M < N (e.g., only 3 signatures) through the `ModeInfos` field
4. During transaction decoding in `ModeInfoAndSigToSignatureData`, a `MultiSignatureData` is created with the mismatched bit array and signatures [3](#0-2) 

5. When the transaction enters the ante handler for processing, either `ConsumeMultisignatureVerificationGas` or `VerifyMultisignature` is called
6. The loop iterates through bit positions; when it encounters the 4th true bit but only 3 signatures exist, accessing `sig.Signatures[3]` triggers an out-of-bounds panic
7. The Go panic crashes the validator node

**Security Guarantee Broken:**
This violates memory safety (accessing array out of bounds) and availability guarantees (node crashes should not be triggerable by untrusted transactions).

## Impact Explanation

**Consequences:**
- Any validator node that processes the malicious transaction will panic and crash
- The crash occurs during signature verification in the ante handler, part of the critical transaction validation path
- An attacker can repeatedly broadcast such transactions to continuously crash nodes
- If enough validators crash simultaneously, the network cannot reach consensus and may halt
- No funds are directly stolen, but network functionality is completely compromised

This qualifies as "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions" (Medium severity) according to the provided impact criteria. If orchestrated effectively to crash a supermajority of validators, it could escalate to "Network not being able to confirm new transactions (total network shutdown)" (also Medium).

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who can submit transactions. No special privileges, stake, or resources required beyond the ability to craft and broadcast a transaction.

**Required Conditions:**
- Attacker crafts a transaction with mismatched bit array (more true bits) and signature count (fewer signatures)
- No special timing, network state, or coordination required
- The vulnerability triggers during normal transaction validation flow

**Frequency:**
- Exploitable at any time during normal network operation
- Each malicious transaction crashes any node attempting to process it
- Attack is repeatable indefinitely by broadcasting multiple malicious transactions
- With automation, attacker can crash nodes faster than restart time

The likelihood is high because:
1. Trivial to trigger (craft one malicious transaction)
2. Impact is immediate and deterministic (guaranteed crash)
3. No rate limits or economic costs prevent repeated exploitation
4. Attack surface available to all network participants

## Recommendation

Add validation to ensure the number of signatures exactly equals the number of true bits in the bit array. In `crypto/keys/multisig/multisig.go` after line 64, insert:

```go
numTrueBits := bitarray.NumTrueBitsBefore(size)
if len(sigs) != numTrueBits {
    return fmt.Errorf("signature count %d does not match number of signers %d indicated by bit array", len(sigs), numTrueBits)
}
```

Apply the same validation in `x/auth/ante/sigverify.go` in the `ConsumeMultisignatureVerificationGas` function before the loop at line 454.

This ensures the invariant that every true bit in the array has a corresponding signature, preventing out-of-bounds access.

## Proof of Concept

**File:** `crypto/keys/multisig/multisig_test.go`

**Setup:**
- Create 5 public/private key pairs and their corresponding signatures for a test message
- Create a multisig public key with threshold 3 and the 5 public keys
- Create a bit array with 5 positions and set 4 bits to true (positions 0, 1, 2, 3)

**Action:**
- Construct a `MultiSignatureData` with the 4-bit true bit array but only 3 signatures
- Call `pk.VerifyMultisignature(signBytesFn, maliciousSig)`

**Result:**
- The function panics with an out-of-bounds error when attempting to access `sig.Signatures[3]`
- The panic occurs at line 71 in `VerifyMultisignature` when `sigIndex=3` but only indices 0-2 exist
- This confirms the vulnerability: a malicious transaction with this structure will crash any node attempting to verify it

The test demonstrates that validations at lines 56, 60, and 64 all pass, but the missing check for signature count matching true bits allows the out-of-bounds access to occur.

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
