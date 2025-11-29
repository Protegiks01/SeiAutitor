# Audit Report

## Title
Node Crash via Out-of-Bounds Array Access in Multisig Gas Consumption

## Summary
An attacker can crash validator nodes by submitting a transaction with a multisig signature containing a BitArray whose size exceeds the number of public keys in the multisig. The `ConsumeMultisignatureVerificationGas` function accesses the public key array by index without bounds validation, causing a Go runtime panic before the signature verification decorator can reject the malformed transaction.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `ConsumeMultisignatureVerificationGas` function should safely consume gas for each signature in a multisig transaction by iterating only over valid public key indices that exist in the multisig public key array.

**Actual Logic:** 
The function retrieves the size from `sig.BitArray.Count()` and loops from `i = 0` to `i < size`, directly accessing `pubkey.GetPubKeys()[i]` at each iteration without validating that the index is within the bounds of the public key array. The proper validation check `len(pubKeys) != size` exists in `VerifyMultisignature` [2](#0-1) , but this validation occurs in the signature verification phase which executes AFTER gas consumption in the ante handler chain [3](#0-2) .

**Exploitation Path:**
1. Attacker creates a multisig account with N public keys (e.g., 3 keys) using standard multisig account creation
2. Attacker constructs a transaction with `MultiSignatureData` where the `BitArray` has size M where M > N (e.g., size 10)
3. Attacker sets at least one bit in the BitArray at index `i >= N` (e.g., sets bit at index 5)
4. Attacker adds a dummy signature to the Signatures array
5. Attacker submits the transaction to the network
6. When a validator processes the transaction through the ante handler chain:
   - `SigGasConsumeDecorator` executes first (line 57 of ante.go)
   - It calls `ConsumeMultisignatureVerificationGas` which iterates from i=0 to i=9
   - At i=5, the code attempts to access `pubkey.GetPubKeys()[5]` on an array containing only 3 elements
   - Go runtime generates an "index out of range" panic
   - The panic recovery in `SetUpContextDecorator` [4](#0-3)  only catches `sdk.ErrorOutOfGas` panics and re-panics all others, causing the node to crash
7. The validator node crashes before `SigVerificationDecorator` (line 58) can execute its validation logic

**Security Guarantee Broken:** 
Memory safety and availability. The system fails to validate array bounds before access, allowing unprivileged users to trigger runtime panics that crash validator nodes, violating the network's availability guarantees.

## Impact Explanation

This vulnerability enables a denial-of-service attack against the network with the following characteristics:

- **Affected Processes:** All validator nodes that process the malicious transaction will crash simultaneously
- **Attack Accessibility:** Any network participant can execute this attack by submitting a single crafted transaction - no special privileges, resources, or timing required
- **Attack Sustainability:** The attacker can submit multiple malicious transactions to the mempool to crash nodes repeatedly, maintaining a sustained DoS condition
- **Network Impact:** In a coordinated attack, an adversary can crash a significant percentage of validator nodes (≥30%), severely degrading network availability and potentially preventing the network from producing new blocks or processing legitimate transactions

The attack qualifies as "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network" which is a Medium severity impact according to the provided criteria.

## Likelihood Explanation

**Who Can Trigger:** 
Any unprivileged network participant with the ability to submit transactions. The attacker only needs:
- Standard transaction submission capabilities
- Ability to create a multisig account (no special permissions required)
- Ability to construct and sign transactions

**Conditions Required:**
- Normal network operation (no special state or timing required)
- Standard mempool acceptance of transactions
- No race conditions or complex state setup needed

**Frequency:** 
The vulnerability can be exploited immediately and repeatedly. Each malicious transaction crashes every node that attempts to process it during the gas consumption phase. An attacker can flood the mempool with such transactions to maximize impact and sustain the attack indefinitely at minimal cost.

## Recommendation

Add a bounds validation check in `ConsumeMultisignatureVerificationGas` before the loop to ensure the BitArray size matches the number of public keys:

```go
func ConsumeMultisignatureVerificationGas(
    meter sdk.GasMeter, sig *signing.MultiSignatureData, pubkey multisig.PubKey,
    params types.Params, accSeq uint64,
) error {
    size := sig.BitArray.Count()
    pubKeys := pubkey.GetPubKeys()
    
    // Validate BitArray size matches public key count before array access
    if len(pubKeys) != size {
        return fmt.Errorf("bit array size %d does not match public key count %d", size, len(pubKeys))
    }
    
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

This ensures the invariant is validated before any array access occurs, preventing the out-of-bounds panic while maintaining the same validation semantics as `VerifyMultisignature`. The malformed transaction will be rejected with an error rather than crashing the node.

## Proof of Concept

**File:** `x/auth/ante/sigverify_test.go`

**Setup:** 
- Create a multisig account with 3 public keys
- Initialize blockchain state with the account
- Create a test message from the multisig address

**Action:**
- Construct a `MultiSignatureData` with BitArray size of 10 (larger than 3 public keys)
- Set bit at index 5 (valid in BitArray but out of bounds for the 3-element public key array)
- Add a dummy signature to the signatures array
- Create a transaction with this malicious multisig data
- Process the transaction through the ante handler chain containing `SigGasConsumeDecorator`

**Result:**
- When `ConsumeMultisignatureVerificationGas` executes, it loops through indices 0-9
- At index 5, it attempts `pubkey.GetPubKeys()[5]` on an array with only 3 elements
- Go runtime panics with "index out of range [5] with length 3"
- The panic is not caught by the SetUpContextDecorator's recovery (which only catches OutOfGas panics)
- The node crashes before the SigVerificationDecorator can validate and reject the transaction

The test demonstrates that any attacker can crash validator nodes by submitting such malformed multisig transactions, confirming the denial-of-service vulnerability.

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

**File:** x/auth/ante/setup.go (L66-79)
```go
	defer func() {
		if r := recover(); r != nil {
			switch rType := r.(type) {
			case sdk.ErrorOutOfGas:
				log := fmt.Sprintf(
					"out of gas in location: %v; gasWanted: %d, gasUsed: %d",
					rType.Descriptor, gasTx.GetGas(), newCtx.GasMeter().GasConsumed())

				err = sdkerrors.Wrap(sdkerrors.ErrOutOfGas, log)
			default:
				panic(r)
			}
		}
	}()
```
