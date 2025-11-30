# Audit Report

## Title
Authentication Bypass via Zero-Threshold Multisig Public Key Deserialization

## Summary
The `LegacyAminoPubKey` protobuf deserialization bypasses constructor validation that enforces threshold > 0, allowing creation of multisig accounts that accept transactions without any valid signatures. This creates "anyone can spend" addresses where funds can be stolen without possessing any private keys.

## Impact
High - Direct loss of funds

## Finding Description

**Location:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Intended logic:**
The constructor enforces that multisig threshold must be greater than 0 to ensure at least one signature is required for transaction authorization. [5](#0-4) 

**Actual logic:**
The protobuf `Unmarshal` method directly deserializes the `Threshold` field without any validation. When `threshold=0`, signature verification checks become ineffective:
- At line 60: `if len(sigs) < int(m.Threshold)` becomes `if len(sigs) < 0` which is always false (array length is non-negative)
- At line 64: `if bitarray.NumTrueBitsBefore(size) < int(m.Threshold)` becomes checking against 0, always false for non-negative counts
- The verification loop only processes set bits in the bitarray; with no bits set, it returns success without verifying any signatures

**Exploitation path:**
1. Attacker creates a `LegacyAminoPubKey` with `Threshold: 0` by directly instantiating the struct or using protobuf marshal/unmarshal (bypassing the constructor)
2. Attacker computes the address from this malicious key using `Address()` method
3. Victim sends funds to this address (via exchange withdrawal, DAO treasury setup, protocol integration, or social engineering)
4. Attacker creates a transaction with the threshold=0 pubkey in SignerInfo and an empty `MultiSignatureData` with zero actual signatures
5. Transaction passes `ValidateBasic` which only checks outer signatures array length > 0 [6](#0-5) 
6. `SetPubKeyDecorator` sets the malicious pubkey on the account without validation
7. `VerifyMultisignature` passes all checks due to threshold=0
8. Transaction executes without any valid cryptographic signatures, enabling fund theft

**Security guarantee broken:**
Transactions must be cryptographically signed by authorized private key holders. This vulnerability creates addresses where NO private keys are needed—anyone who knows the public keys can spend funds, violating blockchain's fundamental signature-based authentication model.

## Impact Explanation

This vulnerability enables direct fund theft through multiple attack vectors:

1. **Social engineering**: Attackers can promote "secure multisig addresses" for DAOs, treasuries, or escrows that appear legitimate but are threshold=0 and completely insecure

2. **Protocol integration risks**: Smart contracts or off-chain systems that verify multisig structure but don't validate the threshold could inadvertently use these insecure addresses

3. **Immediate theft**: Anyone who discovers a threshold=0 multisig address and knows its public key composition can immediately steal all funds sent to it

4. **Systemic authentication failure**: Violates the core blockchain security model where transaction authorization requires cryptographic proof of private key possession

All funds sent to threshold=0 multisig addresses are at immediate risk of theft by any party that discovers the public key composition.

## Likelihood Explanation

**Who can trigger:** Any unprivileged user can create and exploit threshold=0 multisig addresses.

**Conditions required:**
- Attacker creates a threshold=0 multisig key (trivial - direct struct instantiation or protobuf manipulation)
- Funds are sent to the derived address (could occur through legitimate channels: exchange withdrawals, DAO setups, protocol integrations, user transfers)
- No special timing, network conditions, or privileges required

**Frequency:** The vulnerability is exploitable on-demand during normal network operation. The attack is deterministic and reliable—once funds arrive at a threshold=0 address, they can be stolen immediately by anyone who knows the public key composition.

## Recommendation

Implement comprehensive validation for multisig threshold values:

1. **Add post-deserialization validation in `VerifyMultisignature`:**
Add threshold validation at the beginning of the method before any signature checks.

2. **Add validation in `SetPubKey`:**
Validate that multisig pubkeys have valid threshold values before setting them on accounts.

3. **Add interface-level validation:**
Add a `Validate()` method to the `cryptotypes.PubKey` interface that all implementations must provide, ensuring no invalid pubkeys enter the system through any deserialization path.

Example validation:
```go
func (m *LegacyAminoPubKey) Validate() error {
    if m.Threshold == 0 {
        return fmt.Errorf("threshold must be greater than 0")
    }
    if int(m.Threshold) > len(m.PubKeys) {
        return fmt.Errorf("threshold cannot exceed number of pubkeys")
    }
    return nil
}
```

## Proof of Concept

**Test location:** `crypto/keys/multisig/multisig_test.go`

**Setup:**
Create a threshold=0 multisig directly (bypassing constructor) and an empty MultiSignatureData:
- Generate pubkeys using existing `generatePubKeys` helper
- Pack them into Any types
- Create `LegacyAminoPubKey` struct directly with `Threshold: 0`
- Create `MultiSignatureData` with correct BitArray size but empty Signatures array

**Action:**
Call `VerifyMultisignature` with the threshold=0 pubkey and empty signature data.

**Expected result:**
- Verification should fail with an error about invalid threshold
- **Actual result**: Verification returns `nil` (success) without any error
- This confirms threshold=0 bypasses all signature checks
- Demonstrates complete authentication bypass where transactions succeed without any valid cryptographic signatures

## Notes

This vulnerability stems from a fundamental mismatch between constructor validation and protobuf deserialization paths. The constructor's explicit panic on `threshold <= 0` clearly indicates this was never intended behavior. The issue affects the core authentication mechanism and represents a critical security failure that violates blockchain's fundamental trust model—that transactions must be cryptographically authorized by private key holders. This creates exploitable "anyone can spend" addresses where funds can be stolen by any party that knows the public key composition, without needing any private keys whatsoever.

### Citations

**File:** crypto/keys/multisig/keys.pb.go (L206-220)
```go
			m.Threshold = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Threshold |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
```

**File:** crypto/keys/multisig/multisig.go (L21-24)
```go
func NewLegacyAminoPubKey(threshold int, pubKeys []cryptotypes.PubKey) *LegacyAminoPubKey {
	if threshold <= 0 {
		panic("threshold k of n multisignature: k <= 0")
	}
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

**File:** x/auth/types/account.go (L87-97)
```go
func (acc *BaseAccount) SetPubKey(pubKey cryptotypes.PubKey) error {
	if pubKey == nil {
		acc.PubKey = nil
		return nil
	}
	any, err := codectypes.NewAnyWithValue(pubKey)
	if err == nil {
		acc.PubKey = any
	}
	return err
}
```

**File:** x/auth/ante/sigverify.go (L89-97)
```go
		// account already has pubkey set,no need to reset
		if acc.GetPubKey() != nil {
			continue
		}
		err = acc.SetPubKey(pk)
		if err != nil {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidPubKey, err.Error())
		}
		spkd.ak.SetAccount(ctx, acc)
```

**File:** types/tx/types.go (L88-92)
```go
	sigs := t.Signatures

	if len(sigs) == 0 {
		return sdkerrors.ErrNoSignatures
	}
```
