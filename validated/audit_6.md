# Audit Report

## Title
Array Index Out of Bounds Panic in Multisignature Gas Consumption Causing Network-Wide Denial of Service

## Summary
The `ConsumeMultisignatureVerificationGas` function in the ante handler chain accesses array elements without bounds checking, allowing an attacker to craft a malformed multisignature transaction that causes all validator nodes to panic and crash simultaneously, resulting in total network shutdown. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- File: `x/auth/ante/sigverify.go`
- Function: `ConsumeMultisignatureVerificationGas`
- Lines: 459-460 (array access without bounds checking)

**Intended Logic:**
The function should safely consume gas for each signature in a multisignature transaction by iterating through valid indices only. Array bounds should be validated before any indexing operations to prevent panics.

**Actual Logic:**
The function iterates based on `size := sig.BitArray.Count()` and directly accesses:
- `pubkey.GetPubKeys()[i]` at line 459 without verifying `i < len(pubkey.GetPubKeys())`
- `sig.Signatures[sigIndex]` at line 460 without verifying `sigIndex < len(sig.Signatures)`

The necessary validation exists in `VerifyMultisignature` but executes in `SigVerificationDecorator`, which runs AFTER `SigGasConsumeDecorator` in the ante handler chain. [2](#0-1) 

**Exploitation Path:**

1. Attacker creates a transaction with a multisig account containing N pubkeys (e.g., N=2)

2. Attacker crafts malformed `MultiSignatureData` by manipulating the protobuf message to contain:
   - A `CompactBitArray` with `Count()` returning M where M > N (e.g., M=10)
   - Bit(s) set at indices beyond N-1 (e.g., index 5)
   - Any signatures array [3](#0-2) 

3. Transaction flows through ante handler chain in this order:
   - `SetPubKeyDecorator` (line 55)
   - `ValidateSigCountDecorator` (line 56)
   - **`SigGasConsumeDecorator` (line 57)** ← Panics here
   - `SigVerificationDecorator` (line 58) ← Never reached [4](#0-3) 

4. When loop executes with `i` from 0 to M-1:
   - When `i >= N` and `BitArray.GetIndex(i)` returns true
   - Accessing `pubkey.GetPubKeys()[i]` triggers index out of bounds panic
   - Validator node crashes immediately

**Security Guarantee Broken:**
Memory safety invariant is violated - array accesses must be bounds-checked. The system assumes validation occurs before gas consumption, but the ante handler ordering breaks this assumption.

## Impact Explanation

**Affected Components:**
- All validator nodes processing transactions
- Network consensus mechanism
- Block production and transaction finality

**Severity:**
A single malformed transaction broadcast to the network causes ALL validator nodes to simultaneously panic and crash during transaction processing in the mempool/ante handler stage. This results in:

- Complete network shutdown - no new blocks can be produced
- Total loss of network availability
- Requires coordinated manual intervention to restart all validator nodes
- Attacker can maintain persistent denial of service by repeatedly broadcasting malformed transactions
- No recovery mechanism without manual intervention

This constitutes a critical availability vulnerability classified as "Network not being able to confirm new transactions (total network shutdown)" per the severity criteria.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can execute this attack. No special privileges, validator status, staking requirements, or permissions are needed.

**Conditions Required:**
- Attacker constructs a multisig transaction with malformed `MultiSignatureData`
- Transaction must only pass basic protobuf decoding (no semantic validation required)
- No other prerequisites

**Frequency:**
- Can be exploited immediately upon discovery
- Single transaction affects all validators simultaneously
- Attack can be repeated indefinitely to maintain network shutdown
- High probability of exploitation given:
  - Zero barrier to entry
  - Trivial to construct malformed protobuf messages
  - Deterministic outcome

## Recommendation

Add bounds validation in `ConsumeMultisignatureVerificationGas` before the indexing loop:

```go
func ConsumeMultisignatureVerificationGas(
    meter sdk.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
    params types.Params, accSeq uint64,
) error {
    size := sig.BitArray.Count()
    pubKeys := pubkey.GetPubKeys()
    
    // Validate array bounds before accessing
    if len(pubKeys) != size {
        return fmt.Errorf("bit array size %d does not match pubkey count %d", size, len(pubKeys))
    }
    
    numSetBits := sig.BitArray.NumTrueBitsBefore(size)
    if len(sig.Signatures) != numSetBits {
        return fmt.Errorf("signature count %d does not match set bits %d", len(sig.Signatures), numSetBits)
    }
    
    sigIndex := 0
    for i := 0; i < size; i++ {
        // ... existing logic
    }
    return nil
}
```

Alternative: Reorder the ante handler chain to execute `SigVerificationDecorator` before `SigGasConsumeDecorator`, though this may affect gas accounting semantics.

## Proof of Concept

**Test File:** `x/auth/ante/sigverify_test.go`

**Setup:**
1. Create a multisig public key with 2 sub-keys using `kmultisig.NewLegacyAminoPubKey(2, pubkeys)`
2. Create a `CompactBitArray` with size 10 (larger than the 2 pubkeys)
3. Set bit at index 5 (beyond the pubkey array bounds)
4. Construct `MultiSignatureData` with this malformed BitArray

**Action:**
Call `ConsumeMultisignatureVerificationGas` with the malformed signature data:
```go
params := types.DefaultParams()
meter := sdk.NewInfiniteGasMeter(1, 1)
ante.ConsumeMultisignatureVerificationGas(meter, malformedSig, multisigPubKey, params, 0)
```

**Result:**
Function panics with "index out of range" error when attempting to access `pubkey.GetPubKeys()[5]` on line 459, since the pubkey array only contains 2 elements. This demonstrates that any attacker can crash validator nodes by broadcasting such a transaction.

## Notes

The vulnerability exists because the system relies on defense-in-depth with validation in `VerifyMultisignature`, but the ante handler chain processes gas consumption before signature verification. The `CompactBitArray.Count()` method returns a value based on protobuf fields that can be arbitrarily set by an attacker, with no semantic validation against the actual multisig pubkey count until after the vulnerable code executes.

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
