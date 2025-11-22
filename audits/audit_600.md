## Audit Report

### Title
Address Parsing Bug in AllowancesByGranter Query Prevents Enumeration of Grants with Mixed-Length Addresses

### Summary
The `ParseAddressesFromFeeAllowanceKey` function contains an indexing bug that causes incorrect parsing of granter addresses when granter and grantee addresses have different lengths. This directly breaks the `AllowancesByGranter` query's ability to enumerate all grants, as the query relies on this parsing function to filter grants by granter address. [1](#0-0) 

### Impact
**Medium**

### Finding Description

**Location:** 
- Primary bug: `x/feegrant/key.go`, line 48 in `ParseAddressesFromFeeAllowanceKey` function
- Affected query: `x/feegrant/keeper/grpc_query.go`, lines 98-137 in `AllowancesByGranter` function [2](#0-1) [3](#0-2) 

**Intended Logic:**
The key format stores fee allowances as: `0x00<granteeLen><granteeBytes><granterLen><granterBytes>`. The parser should extract the granter address starting at position `3+granteeAddrLen` for `granterAddrLen` bytes. [4](#0-3) 

**Actual Logic:**
Line 48 uses `3+granterAddrLen` as the start index instead of `3+granteeAddrLen`:
```go
granter = sdk.AccAddress(key[3+granterAddrLen : 3+granteeAddrLen+byte(granterAddrLen)])
```

This extracts the wrong slice when addresses have different lengths. For example, with a 20-byte grantee and 32-byte granter:
- Correct extraction should be: `key[23:55]` (32 bytes)
- Actual extraction is: `key[35:55]` (20 bytes, wrong portion)

**Exploit Scenario:**
1. Cosmos SDK supports both 20-byte addresses (secp256k1) and 32-byte addresses (secp256r1/ADR-028) [5](#0-4) [6](#0-5) 

2. A user creates a fee grant from a 32-byte granter address to a 20-byte grantee address (or vice versa)

3. When `AllowancesByGranter` is called with the granter address, it iterates through all grants and calls `ParseAddressesFromFeeAllowanceKey` to extract and compare the granter

4. The parsing returns an incorrect granter address due to the indexing bug

5. The comparison fails at line 117, and the grant is excluded from results

6. The query fails to enumerate this grant, answering "No" to the security question

**Security Failure:**
Information integrity violation - the query returns incomplete results, failing to enumerate all grants for a specific address. This breaks the fundamental purpose of the query and can lead to:
- Users unable to see all their issued grants
- Applications making incorrect decisions based on incomplete data
- Grants effectively "hidden" from enumeration

### Impact Explanation

**Affected Components:**
- AllowancesByGranter query endpoint (public gRPC/REST API)
- Any application or user interface that relies on this query to display or manage fee grants
- Grant management workflows that depend on accurate enumeration

**Severity:**
When addresses with different lengths are used:
- Grants become invisible to the AllowancesByGranter query
- Users cannot audit all grants they've issued
- Applications may incorrectly conclude no grants exist
- While the grants remain functional and can still be used for fee payment, their invisibility to enumeration queries creates a security/UX issue

**System Impact:**
This qualifies as **Medium** severity under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" because:
- Query results are fundamentally incorrect
- Applications relying on this data will malfunction
- No direct loss of funds, but creates confusion and potential for errors in grant management
- Affects the integrity of protocol-level query interfaces

### Likelihood Explanation

**Trigger Conditions:**
- Requires fee grants between addresses of different lengths (20-byte vs 32-byte)
- Both address types are supported in Cosmos SDK [7](#0-6) 

**Likelihood:**
- **Medium to High** - As secp256r1 (32-byte addresses) becomes more widely adopted alongside legacy secp256k1 (20-byte addresses), mixed-length grants will occur naturally
- Can be triggered by any user creating grants between addresses of different types
- The bug is deterministic and will always cause enumeration failure for affected grants
- Current test coverage only tests equal-length addresses, missing this edge case [8](#0-7) 

### Recommendation

Fix the indexing in `ParseAddressesFromFeeAllowanceKey` at line 48 in `x/feegrant/key.go`:

**Change:**
```go
granter = sdk.AccAddress(key[3+granterAddrLen : 3+granteeAddrLen+byte(granterAddrLen)])
```

**To:**
```go
granter = sdk.AccAddress(key[3+granteeAddrLen : 3+granteeAddrLen+granterAddrLen])
```

This correctly positions the slice to extract the granter address starting after the grantee address and its length prefix.

**Additional Recommendations:**
1. Add test cases with mixed-length addresses to prevent regression
2. Validate the fix works with all supported address lengths (20 and 32 bytes)
3. Consider adding validation to ensure parsed addresses have expected lengths

### Proof of Concept

**File:** `x/feegrant/key_test.go`

**Test Function:** Add this test to demonstrate the bug:

```go
func TestMarshalAndUnmarshalFeegrantKeyWithDifferentLengths(t *testing.T) {
	// Create a 20-byte grantee address (typical secp256k1)
	grantee20 := sdk.AccAddress([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
	})
	
	// Create a 32-byte granter address (ADR-028 style)
	granter32 := sdk.AccAddress([]byte{
		100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
		110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
		120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
		130, 131,
	})
	
	// Create the key using the standard function
	key := feegrant.FeeAllowanceKey(granter32, grantee20)
	
	// Parse it back
	parsedGranter, parsedGrantee := feegrant.ParseAddressesFromFeeAllowanceKey(key)
	
	// Grantee should parse correctly (it comes first in the key)
	require.Equal(t, grantee20, parsedGrantee, "Grantee should parse correctly")
	
	// This will FAIL due to the bug - granter will not parse correctly
	require.Equal(t, granter32, parsedGranter, "Granter should parse correctly but FAILS due to indexing bug")
}
```

**Setup:**
1. Create two addresses with different lengths: 20 bytes (grantee) and 32 bytes (granter)
2. Use the standard `FeeAllowanceKey` function to create a properly formatted key

**Trigger:**
Call `ParseAddressesFromFeeAllowanceKey` to parse the key back into addresses

**Observation:**
- The grantee parses correctly (first 20 bytes)
- The granter parses incorrectly due to wrong slice indices
- The test assertion `require.Equal(t, granter32, parsedGranter)` will fail
- The parsed granter will be only 20 bytes instead of 32, and will contain the wrong data (last 20 bytes of the 32-byte granter instead of all 32 bytes)

This demonstrates that the `AllowancesByGranter` query cannot correctly identify grants when it calls this function at line 116, causing it to fail enumeration for mixed-length address grants.

### Citations

**File:** x/feegrant/key.go (L39-51)
```go
func ParseAddressesFromFeeAllowanceKey(key []byte) (granter, grantee sdk.AccAddress) {
	// key is of format:
	// 0x00<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes><msgType_Bytes>
	kv.AssertKeyAtLeastLength(key, 2)
	granteeAddrLen := key[1] // remove prefix key
	kv.AssertKeyAtLeastLength(key, int(2+granteeAddrLen))
	grantee = sdk.AccAddress(key[2 : 2+granteeAddrLen])
	granterAddrLen := int(key[2+granteeAddrLen])
	kv.AssertKeyAtLeastLength(key, 3+int(granteeAddrLen+byte(granterAddrLen)))
	granter = sdk.AccAddress(key[3+granterAddrLen : 3+granteeAddrLen+byte(granterAddrLen)])

	return granter, grantee
}
```

**File:** x/feegrant/keeper/grpc_query.go (L114-119)
```go
	pageRes, err := query.FilteredPaginate(prefixStore, req.Pagination, func(key []byte, value []byte, accumulate bool) (bool, error) {
		// ParseAddressesFromFeeAllowanceKey expects the full key including the prefix.
		granter, _ := feegrant.ParseAddressesFromFeeAllowanceKey(append(feegrant.FeeAllowanceKeyPrefix, key...))
		if !granter.Equals(granterAddr) {
			return false, nil
		}
```

**File:** crypto/keys/secp256k1/secp256k1.go (L149-159)
```go
// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("length of pubkey is incorrect")
	}

	sha := sha256.Sum256(pubKey.Key)
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha[:]) // does not error
	return crypto.Address(hasherRIPEMD160.Sum(nil))
}
```

**File:** types/address/hash.go (L13-14)
```go
// Len is the length of base addresses
const Len = sha256.Size
```

**File:** x/auth/types/params.go (L74-84)
```go
// SigVerifyCostSecp256r1 returns gas fee of secp256r1 signature verification.
// Set by benchmarking current implementation:
//
//	BenchmarkSig/secp256k1     4334   277167 ns/op   4128 B/op   79 allocs/op
//	BenchmarkSig/secp256r1    10000   108769 ns/op   1672 B/op   33 allocs/op
//
// Based on the results above secp256k1 is 2.7x is slwer. However we propose to discount it
// because we are we don't compare the cgo implementation of secp256k1, which is faster.
func (p Params) SigVerifyCostSecp256r1() uint64 {
	return p.SigVerifyCostSecp256k1 / 2
}
```

**File:** x/feegrant/key_test.go (L12-25)
```go
func TestMarshalAndUnmarshalFeegrantKey(t *testing.T) {
	grantee, err := sdk.AccAddressFromBech32("cosmos1qk93t4j0yyzgqgt6k5qf8deh8fq6smpn3ntu3x")
	require.NoError(t, err)
	granter, err := sdk.AccAddressFromBech32("cosmos1p9qh4ldfd6n0qehujsal4k7g0e37kel90rc4ts")
	require.NoError(t, err)

	key := feegrant.FeeAllowanceKey(granter, grantee)
	require.Len(t, key, len(grantee.Bytes())+len(granter.Bytes())+3)
	require.Equal(t, feegrant.FeeAllowancePrefixByGrantee(grantee), key[:len(grantee.Bytes())+2])

	g1, g2 := feegrant.ParseAddressesFromFeeAllowanceKey(key)
	require.Equal(t, granter, g1)
	require.Equal(t, grantee, g2)
}
```
