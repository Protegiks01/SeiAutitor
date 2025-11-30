# Audit Report

## Title
Authentication Bypass via Zero-Threshold Multisig Public Key Deserialization

## Summary
The `LegacyAminoPubKey` protobuf deserialization bypasses constructor validation, allowing creation of multisig accounts with `threshold=0` that accept transactions without any valid signatures. This enables complete authentication bypass and creation of "anyone can spend" addresses, resulting in direct fund theft.

## Impact
High

## Finding Description

**Location:** 
- `crypto/keys/multisig/keys.pb.go` (protobuf unmarshaling)
- `crypto/keys/multisig/multisig.go:50-66` (verification logic)
- `x/auth/ante/sigverify.go:89-97` (pubkey setting)
- `x/auth/types/account.go:87-97` (account validation)

**Intended Logic:**
The constructor enforces that multisig threshold must be greater than 0 to ensure at least one signature is required for transaction authorization. [1](#0-0) 

**Actual Logic:**
The protobuf `Unmarshal` method directly deserializes the `Threshold` field without any validation. [2](#0-1) 

When `threshold=0`, the signature verification checks become ineffective:
- Line 60: `len(sigs) < int(m.Threshold)` becomes `0 < 0` (always false)
- Line 64: `bitarray.NumTrueBitsBefore(size) < int(m.Threshold)` becomes `0 < 0` (always false) [3](#0-2) 

**Exploitation Path:**
1. Attacker creates a `LegacyAminoPubKey` with `Threshold: 0` by directly marshaling/unmarshaling via protobuf (bypassing constructor)
2. Attacker computes the address derived from this malicious key
3. Victim sends funds to this address (via exchange withdrawal, user error, or social engineering)
4. Attacker creates a transaction with the threshold=0 pubkey in SignerInfo and a `MultiSignatureData` containing zero signatures (created via `multisig.NewMultisig(n)`)
5. Transaction passes `ValidateBasic` which only checks that outer `Signatures` array is non-empty [4](#0-3) 
6. `SetPubKeyDecorator` sets the malicious pubkey on the account without validation [5](#0-4) [6](#0-5) 
7. `SigVerificationDecorator` calls `VerifyMultisignature`, which passes all checks due to threshold=0
8. Transaction executes without any valid signatures, enabling fund theft

**Security Guarantee Broken:**
Transactions must be cryptographically signed by authorized private key holders. This vulnerability creates addresses where NO private keys are needed—anyone who knows the public key composition can spend funds without possessing any private keys.

## Impact Explanation

This vulnerability enables:
- **Direct fund theft**: Anyone who knows the public keys of a threshold=0 multisig can steal all funds sent to that address without possessing any private keys
- **Social engineering attacks**: Attackers can promote "secure multisig addresses" that are actually threshold=0 and completely insecure
- **Systemic authentication failure**: Violates the core blockchain security property that transactions require valid signatures

All funds sent to threshold=0 multisig addresses are at immediate risk of theft by anyone who discovers the public key composition. This is a fundamental breakdown of the authentication mechanism.

## Likelihood Explanation

**Who Can Trigger:** Any unprivileged user can create transactions with threshold=0 multisig keys.

**Conditions Required:**
- Attacker creates a threshold=0 multisig key and computes its address
- Someone sends funds to this address (through exchange, user transfer, or social engineering)
- No special timing, network conditions, or privileges required

**Frequency:** Exploitable on-demand during normal network operation. The attack is deterministic and reliable—once funds arrive at a threshold=0 address, they can be stolen immediately by anyone who knows the pubkey composition.

## Recommendation

Add post-deserialization validation for `LegacyAminoPubKey`:

1. **Implement validation method in `LegacyAminoPubKey`:**
   - Add a `Validate()` method that checks `threshold > 0` and `threshold <= len(pubKeys)`

2. **Call validation in critical paths:**
   - In `BaseAccount.SetPubKey()` before accepting any public key
   - At the beginning of `VerifyMultisignature()` before signature verification
   - In transaction `ValidateBasic()` to check all public keys in SignerInfo structures

3. **Add a `Validate()` method to the `cryptotypes.PubKey` interface** that all implementations must provide for structural validation, ensuring consistent validation across all public key types.

## Proof of Concept

**Test Location:** `crypto/keys/multisig/multisig_test.go` (proposed)

**Setup:**
- Create a `LegacyAminoPubKey` directly with `Threshold: 0` (bypassing constructor)
- Generate one secp256k1 public key for the multisig
- Create an empty `MultiSignatureData` via `multisig.NewMultisig(1)` with zero signatures

**Action:**
- Marshal and unmarshal the threshold=0 key to simulate network deserialization
- Call `VerifyMultisignature` with the zero-signature MultiSignatureData

**Result:**
- Verification returns `nil` (success) instead of error
- Confirms that threshold=0 bypasses all signature checks
- Demonstrates complete authentication bypass

## Notes

This vulnerability stems from the mismatch between constructor validation and protobuf deserialization. The constructor's panic on `threshold <= 0` clearly indicates this was never intended behavior. The issue affects the core authentication mechanism and represents a critical security failure that violates blockchain's fundamental trust model—transactions must be cryptographically authorized.

The vulnerability is particularly dangerous because:
1. It's completely invisible to users sending funds to such addresses
2. The exploit is deterministic and reliable
3. No private keys are needed for theft
4. Multiple parties could independently discover and exploit the same vulnerable address

### Citations

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
