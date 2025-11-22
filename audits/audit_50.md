# Audit Report

## Title
Out-of-Bounds Panic in Multisig Verification Due to Missing Signature Count Validation Against True Bits

## Summary
The signature count validation in `VerifyMultisignature` only checks that the number of signatures is between the threshold and the total number of public keys, but fails to validate that it equals the number of true bits in the bit array. This allows an attacker to craft a malicious multisig transaction that causes an out-of-bounds array access, resulting in a node panic and denial of service. [1](#0-0) 

## Impact
**High** - This vulnerability enables a denial-of-service attack that can crash validator nodes and halt the network's ability to process transactions.

## Finding Description

**Location:** 
- Primary: `crypto/keys/multisig/multisig.go`, function `VerifyMultisignature`, lines 59-94
- Secondary: `x/auth/ante/sigverify.go`, function `ConsumeMultisignatureVerificationGas`, lines 446-471 [2](#0-1) 

**Intended Logic:** 
The signature count validation should ensure that the number of signatures provided matches the number of signers indicated by the bit array, preventing any mismatch that could lead to out-of-bounds access during verification.

**Actual Logic:** 
The validation at line 60 only checks:
1. `len(sigs) >= int(m.Threshold)` - at least threshold signatures
2. `len(sigs) <= size` - at most as many signatures as public keys

However, it does NOT validate that `len(sigs)` equals the number of true bits in the bit array (`bitarray.NumTrueBitsBefore(size)`).

The verification loop (lines 69-94) iterates through each bit in the array and when a bit is true, accesses `sig.Signatures[sigIndex]` then increments `sigIndex`. If there are more true bits than signatures available, this causes a panic due to out-of-bounds array access. [3](#0-2) 

**Exploit Scenario:**
1. An attacker crafts a transaction with a multisig signature where:
   - The multisig public key has 5 public keys with threshold 3
   - The bit array has 4 bits set to true (e.g., positions 0, 1, 2, 3)
   - The signatures array contains only 3 signatures
   
2. The transaction passes all validation checks:
   - Line 56: bit array size equals number of public keys ✓
   - Line 60: `3 >= 3 && 3 <= 5` ✓
   - Line 64: 4 true bits >= 3 threshold ✓

3. During verification loop execution:
   - Iterations 0-2: Successfully verify signatures at indices 0, 1, 2
   - Iteration 3: Attempts to access `sig.Signatures[3]` which doesn't exist
   - Result: Panic with out-of-bounds error

4. The attacker can submit this transaction to the network, causing any validator node that attempts to verify it to crash. [4](#0-3) 

The attacker controls the transaction structure through the protobuf `ModeInfo.Multi` fields, where `Bitarray` and `ModeInfos` (which determines signature count) can be independently specified. [5](#0-4) 

**Security Failure:** 
This breaks memory safety and availability guarantees. The panic occurs during transaction processing in the ante handler, causing the node to crash. This is a denial-of-service vulnerability that can be exploited to disrupt network consensus.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability and consensus
- Validator node uptime
- Transaction processing capability

**Severity of Damage:**
- Any validator node processing the malicious transaction will panic and crash
- The crash occurs during signature verification in the ante handler, which is part of the critical transaction validation path
- An attacker can repeatedly broadcast such transactions to continuously crash nodes
- If enough validators crash simultaneously, the network cannot reach consensus and halts
- No funds are directly at risk, but network functionality is completely compromised

**Why This Matters:**
This vulnerability allows an unprivileged attacker (anyone who can submit transactions) to cause a network-wide denial of service without requiring significant resources or brute force. The attack is deterministic and can be repeated indefinitely, making it a critical availability threat to the blockchain network.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant who can submit transactions. No special privileges, stake, or resources required beyond the ability to craft and broadcast a transaction.

**Required Conditions:**
- The attacker needs to craft a transaction with a multisig signature containing the mismatched bit array and signature count
- No special timing or network state is required
- The vulnerability is triggered during normal transaction validation flow

**Frequency:**
- Can be exploited at any time during normal network operation
- Each malicious transaction will crash any node that attempts to process it
- The attack can be repeated continuously by broadcasting multiple malicious transactions
- With automated tooling, an attacker could potentially crash nodes faster than they can restart

This vulnerability has high likelihood of exploitation because:
1. It's trivial to trigger (just craft one malicious transaction)
2. The impact is immediate and guaranteed (deterministic crash)
3. There are no rate limits or costs that prevent repeated exploitation
4. The attack surface is available to all network participants

## Recommendation

Add validation to ensure the number of signatures exactly equals the number of true bits in the bit array. Insert this check after line 64 in `VerifyMultisignature`:

```go
// Ensure the number of signatures matches the number of true bits
numTrueBits := bitarray.NumTrueBitsBefore(size)
if len(sigs) != numTrueBits {
    return fmt.Errorf("signature count %d does not match number of signers %d indicated by bit array", len(sigs), numTrueBits)
}
```

Apply the same fix to `ConsumeMultisignatureVerificationGas` in `x/auth/ante/sigverify.go` before line 454.

This validation ensures the invariant that every true bit in the array has a corresponding signature, preventing the out-of-bounds access.

## Proof of Concept

**File:** `crypto/keys/multisig/multisig_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestVerifyMultisignaturePanicOnMismatchedSigCount(t *testing.T) {
	// This test demonstrates the vulnerability where a bit array with more true bits
	// than signatures causes a panic due to out-of-bounds array access
	
	msg := []byte{1, 2, 3, 4}
	pubKeys, sigs := generatePubKeysAndSignatures(5, msg)
	
	// Create a multisig key with 5 public keys, threshold 3
	pk := kmultisig.NewLegacyAminoPubKey(3, pubKeys)
	
	// Create a bit array with 5 positions
	bitArray := cryptotypes.NewCompactBitArray(5)
	
	// Set 4 bits to true (positions 0, 1, 2, 3)
	bitArray.SetIndex(0, true)
	bitArray.SetIndex(1, true)
	bitArray.SetIndex(2, true)
	bitArray.SetIndex(3, true)
	
	// Create MultiSignatureData with only 3 signatures (less than 4 true bits)
	// This creates a mismatch between true bits (4) and signature count (3)
	maliciousSig := &signing.MultiSignatureData{
		BitArray:   bitArray,
		Signatures: []signing.SignatureData{sigs[0], sigs[1], sigs[2]},
	}
	
	signBytesFn := func(mode signing.SignMode) ([]byte, error) { return msg, nil }
	
	// This should panic with out-of-bounds error when trying to access sig.Signatures[3]
	// The panic occurs because the loop finds 4 true bits but only 3 signatures exist
	require.Panics(t, func() {
		_ = pk.VerifyMultisignature(signBytesFn, maliciousSig)
	}, "Expected panic due to out-of-bounds access, but no panic occurred")
}
```

**Setup:**
- Creates 5 public/private key pairs and corresponding signatures
- Creates a multisig public key with threshold 3

**Trigger:**
- Constructs a malicious `MultiSignatureData` with 4 true bits in the bit array but only 3 signatures
- Calls `VerifyMultisignature` with this malicious data

**Observation:**
- The test expects a panic when `VerifyMultisignature` attempts to access the non-existent 4th signature
- On vulnerable code, the panic occurs at line 71 when `sigIndex=3` and `sig.Signatures[3]` is accessed
- The panic confirms the out-of-bounds vulnerability

**To Run:**
```bash
cd crypto/keys/multisig
go test -v -run TestVerifyMultisignaturePanicOnMismatchedSigCount
```

The test will panic on the vulnerable code, demonstrating that a malicious transaction with this signature structure will crash any node that attempts to verify it.

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
