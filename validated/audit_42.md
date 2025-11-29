# Audit Report

## Title
Authentication Bypass via Zero-Threshold Multisig Public Key Deserialization

## Summary
The `LegacyAminoPubKey` protobuf deserialization bypasses constructor validation that enforces threshold > 0, allowing creation of multisig accounts that accept transactions without any valid signatures. This enables complete authentication bypass and creation of "anyone can spend" addresses where funds can be stolen without possessing any private keys.

## Impact
High - Direct loss of funds

## Finding Description

**Location:** 
- `crypto/keys/multisig/keys.pb.go` (Unmarshal method)
- `crypto/keys/multisig/multisig.go` (VerifyMultisignature method)
- `x/auth/types/account.go` (SetPubKey method)
- `x/auth/ante/sigverify.go` (SetPubKeyDecorator) [1](#0-0) [2](#0-1) 

**Intended Logic:**
The constructor enforces that multisig threshold must be greater than 0 to ensure at least one signature is required for transaction authorization. This is explicitly checked with a panic condition at line 22-23. [3](#0-2) 

**Actual Logic:**
The protobuf `Unmarshal` method directly deserializes the `Threshold` field (lines 206-220) without any validation. When `threshold=0`, the signature verification checks in `VerifyMultisignature` become ineffective: [4](#0-3) 

At line 60: `if len(sigs) < int(m.Threshold)` becomes `if len(sigs) < 0` which is always false (length is non-negative)

At line 64: `if bitarray.NumTrueBitsBefore(size) < int(m.Threshold)` becomes checking against 0, which is always false for any non-negative count

**Exploitation Path:**
1. Attacker creates a `LegacyAminoPubKey` with `Threshold: 0` by directly instantiating the struct or using protobuf marshal/unmarshal
2. Attacker computes the address derived from this malicious key using the `Address()` method
3. Victim sends funds to this address (via exchange withdrawal, DAO treasury setup, smart contract interaction, or user error)
4. Attacker creates a transaction with the threshold=0 pubkey in SignerInfo and an empty `MultiSignatureData` (zero signatures in the Signatures array)
5. Transaction passes `ValidateBasic` which only checks that the outer signatures array has length > 0: [5](#0-4) 

6. `SetPubKeyDecorator` sets the malicious pubkey on the account without any validation: [6](#0-5) [7](#0-6) 

7. `SigVerificationDecorator` calls `VerifyMultisignature`, which passes all checks due to threshold=0
8. Transaction executes without any valid signatures, enabling fund theft by anyone who knows the public key composition

**Security Guarantee Broken:**
Transactions must be cryptographically signed by authorized private key holders. This vulnerability creates addresses where NO private keys are needed—anyone who knows the public keys can spend funds, violating the fundamental blockchain security property of signature-based authentication.

## Impact Explanation

This vulnerability enables direct fund theft through multiple attack vectors:

1. **Immediate theft**: Anyone who discovers a threshold=0 multisig address and knows its public key composition can immediately steal all funds sent to it, without possessing any private keys

2. **Social engineering**: Attackers can promote "secure multisig addresses" for DAOs, treasuries, or escrows that appear legitimate but are actually threshold=0 and completely insecure

3. **Protocol integration risks**: Smart contracts or off-chain systems that verify multisig structure but don't validate the threshold could inadvertently use these insecure addresses

4. **Systemic authentication failure**: Violates the core blockchain security model where transaction authorization requires cryptographic proof of private key possession

All funds sent to threshold=0 multisig addresses are at immediate risk of theft by any party that discovers the public key composition.

## Likelihood Explanation

**Who Can Trigger:** Any unprivileged user can create and exploit threshold=0 multisig addresses.

**Conditions Required:**
- Attacker creates a threshold=0 multisig key (trivial - direct struct instantiation or protobuf manipulation)
- Funds are sent to the derived address (could occur through legitimate channels: exchange withdrawals, DAO setups, smart contract interactions, user transfers)
- No special timing, network conditions, or privileges required

**Frequency:** The vulnerability is exploitable on-demand during normal network operation. The attack is deterministic and reliable—once funds arrive at a threshold=0 address, they can be stolen immediately by anyone who knows the public key composition. Multiple attackers could even compete to steal the same funds.

## Recommendation

Implement comprehensive validation for multisig threshold values:

1. **Add post-deserialization validation method:**
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

2. **Call validation at critical points:**
   - In `BaseAccount.SetPubKey()` before accepting any public key
   - At the beginning of `VerifyMultisignature()` before signature verification
   - In transaction `ValidateBasic()` to check all public keys in SignerInfo structures

3. **Add interface-level validation:**
   Add a `Validate()` method to the `cryptotypes.PubKey` interface that all implementations must provide for structural validation, ensuring no invalid pubkeys can enter the system through any path.

## Proof of Concept

**Test Location:** Can be added to `crypto/keys/multisig/multisig_test.go`

**Setup:**
```go
// Create a threshold=0 multisig directly (bypassing constructor)
pubKeys := generatePubKeys(1)
anyPubKeys, _ := packPubKeys(pubKeys)
maliciousKey := &kmultisig.LegacyAminoPubKey{
    Threshold: 0,
    PubKeys:   anyPubKeys,
}

// Create empty MultiSignatureData with no signatures
multiSig := multisig.NewMultisig(1)  // BitArray size 1, but Signatures array empty
```

**Action:**
```go
// Verify signature with zero signatures
msg := []byte{1, 2, 3, 4}
signBytesFn := func(mode signing.SignMode) ([]byte, error) { 
    return msg, nil 
}

err := maliciousKey.VerifyMultisignature(signBytesFn, multiSig)
```

**Result:**
- Verification returns `nil` (success) instead of error
- Confirms that threshold=0 bypasses all signature checks
- Demonstrates complete authentication bypass where transactions succeed without any valid cryptographic signatures
- Proves funds can be stolen from such addresses without possessing any private keys

## Notes

This vulnerability stems from the fundamental mismatch between constructor validation and protobuf deserialization paths. The constructor's explicit panic on `threshold <= 0` clearly indicates this was never intended behavior. The issue affects the core authentication mechanism and represents a critical security failure that violates blockchain's fundamental trust model—that transactions must be cryptographically authorized by private key holders. This is not theoretical; it creates exploitable "anyone can spend" addresses where funds can be stolen by any party that knows the public key composition, without needing any private keys whatsoever.

### Citations

**File:** crypto/keys/multisig/keys.pb.go (L173-274)
```go
func (m *LegacyAminoPubKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowKeys
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LegacyAminoPubKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LegacyAminoPubKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Threshold", wireType)
			}
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
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKeys", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthKeys
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PubKeys = append(m.PubKeys, &types.Any{})
			if err := m.PubKeys[len(m.PubKeys)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipKeys(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthKeys
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
```

**File:** crypto/keys/multisig/multisig.go (L21-33)
```go
func NewLegacyAminoPubKey(threshold int, pubKeys []cryptotypes.PubKey) *LegacyAminoPubKey {
	if threshold <= 0 {
		panic("threshold k of n multisignature: k <= 0")
	}
	if len(pubKeys) < threshold {
		panic("threshold k of n multisignature: len(pubKeys) < k")
	}
	anyPubKeys, err := packPubKeys(pubKeys)
	if err != nil {
		panic(err)
	}
	return &LegacyAminoPubKey{Threshold: uint32(threshold), PubKeys: anyPubKeys}
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

**File:** types/tx/types.go (L88-92)
```go
	sigs := t.Signatures

	if len(sigs) == 0 {
		return sdkerrors.ErrNoSignatures
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
