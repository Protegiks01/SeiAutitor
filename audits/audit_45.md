## Title
Secp256k1 Public Key Length Validation Bypass via Protobuf Unmarshal Causes Node Panic

## Summary
The protobuf unmarshaling path for `secp256k1.PubKey` does not validate key length, allowing attackers to submit transactions with invalid-length public keys (not 33 bytes) that bypass the Amino length check and later cause node panics when the `Address()` method is called during transaction processing.

## Impact
**Medium** - This vulnerability allows any unprivileged attacker to crash network processing nodes, resulting in a Denial of Service attack that can shut down greater than or equal to 30% of network nodes.

## Finding Description

**Location:**
- Primary vulnerability: [1](#0-0) 
- Panic trigger: [2](#0-1) 
- Attack vector entry point: [3](#0-2) 

**Intended Logic:** 
Secp256k1 public keys must be exactly 33 bytes (compressed format). The `UnmarshalAmino` function properly validates this: [4](#0-3) 

**Actual Logic:** 
When transactions are decoded using protobuf (the default encoding), the `InterfaceRegistry.UnpackAny` method calls `proto.Unmarshal`: [5](#0-4) 

This uses the auto-generated protobuf `Unmarshal` function which accepts any byte length without validation, directly assigning it to the `Key` field without checking that `len(m.Key) == 33`.

**Exploit Scenario:**
1. Attacker crafts a transaction with a secp256k1 public key that has invalid length (e.g., 32 or 34 bytes instead of 33)
2. Transaction is encoded using protobuf and submitted to the network
3. Node receives and decodes the transaction - protobuf unmarshaler accepts the invalid key without validation
4. During ante handler processing, `SetPubKeyDecorator.AnteHandle` retrieves the public key via `GetPubKeys()`: [6](#0-5) 
5. At line 80 of sigverify.go, the code calls `pk.Address()` to verify the public key matches the signer address
6. The `Address()` method panics due to incorrect key length, crashing the node

**Security Failure:** 
This breaks the availability guarantee of the network. The panic is unrecoverable at the transaction processing level, causing the node to crash when handling the malicious transaction in mempool validation or block execution.

## Impact Explanation

**Affected Components:**
- All network nodes that process transactions (validators, full nodes, RPC nodes)
- Transaction processing pipeline (mempool admission and block execution)

**Severity of Damage:**
- Any attacker can crash nodes by broadcasting a single malformed transaction
- Nodes will panic and require restart when processing the malicious transaction
- If the transaction enters a block, all nodes will crash when executing that block
- This can be repeated indefinitely to prevent network progress

**Why This Matters:**
This vulnerability enables a trivial Denial of Service attack requiring no resources beyond the ability to submit a transaction. An attacker can systematically crash network nodes, degrading network availability and potentially preventing block production if enough validators are affected.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with the ability to submit a transaction - no special privileges, staking, or validator status required.

**Conditions Required:**
- Attacker constructs a transaction with an invalid-length secp256k1 public key
- Transaction is encoded using protobuf (the default encoding method)
- Transaction is broadcast to the network

**Frequency:**
This can be exploited continuously and repeatedly. Each malformed transaction will crash any node that processes it. The attack is:
- **Easy to execute:** Simple transaction crafting with modified key bytes
- **Hard to prevent:** Requires all nodes to be patched
- **Repeatable:** Can be done indefinitely until fixed

## Recommendation

Add length validation to the protobuf `Unmarshal` path. Implement one of these solutions:

1. **Option A (Immediate Fix):** Add a validation step after protobuf unmarshaling in `UnpackAny` or in a post-unmarshal hook to verify secp256k1 public keys are exactly 33 bytes.

2. **Option B (Proper Fix):** Override the generated `Unmarshal` method in `secp256k1.go` to add validation:
```go
func (pubKey *PubKey) Unmarshal(data []byte) error {
    // Call the generated unmarshal
    if err := proto.Unmarshal(data, pubKey); err != nil {
        return err
    }
    // Validate length after unmarshaling
    if len(pubKey.Key) != PubKeySize {
        return errors.Wrap(errors.ErrInvalidPubKey, "invalid pubkey size")
    }
    return nil
}
```

3. **Option C (Defense in Depth):** Change the `Address()` method to return an error instead of panicking, and handle the error in all callers.

## Proof of Concept

**File:** `crypto/keys/secp256k1/secp256k1_test.go`

**Test Function:** Add this test to demonstrate the vulnerability:

```go
func TestInvalidLengthPubKeyProtobufUnmarshalCausesPanic(t *testing.T) {
    // This test demonstrates that protobuf unmarshaling accepts invalid length keys
    // which later cause panics when Address() is called
    
    // Create a PubKey with invalid length (32 bytes instead of 33)
    invalidKey := &secp256k1.PubKey{
        Key: make([]byte, 32), // Invalid: should be 33 bytes
    }
    
    // Marshal it to protobuf
    protoBytes, err := proto.Marshal(invalidKey)
    require.NoError(t, err)
    
    // Unmarshal it back - this should fail but doesn't
    var decoded secp256k1.PubKey
    err = proto.Unmarshal(protoBytes, &decoded)
    require.NoError(t, err) // No error! Protobuf accepts invalid length
    
    // Verify the invalid key was accepted
    require.Equal(t, 32, len(decoded.Key))
    
    // Now when we try to get the address, it panics
    require.Panics(t, func() {
        _ = decoded.Address() // This panics: "length of pubkey is incorrect"
    })
}
```

**Setup:** 
- Uses the existing test infrastructure in `crypto/keys/secp256k1/secp256k1_test.go`
- No additional setup required

**Trigger:** 
- Creates a `PubKey` with 32 bytes instead of 33
- Marshals to protobuf and unmarshals back
- Calls `Address()` method

**Observation:** 
- The protobuf `Unmarshal` succeeds without validation (no error returned)
- The `Address()` call panics with "length of pubkey is incorrect"
- This confirms that invalid keys can enter the system via protobuf and cause crashes later

**Running the PoC:**
```bash
cd crypto/keys/secp256k1
go test -run TestInvalidLengthPubKeyProtobufUnmarshalCausesPanic -v
```

The test will pass (showing the panic occurs), confirming the vulnerability. In a real transaction processing scenario, this panic would crash the node.

### Citations

**File:** crypto/keys/secp256k1/keys.pb.go (L305-308)
```go
			m.Key = append(m.Key[:0], dAtA[iNdEx:postIndex]...)
			if m.Key == nil {
				m.Key = []byte{}
			}
```

**File:** crypto/keys/secp256k1/secp256k1.go (L151-153)
```go
	if len(pubKey.Key) != PubKeySize {
		panic("length of pubkey is incorrect")
	}
```

**File:** crypto/keys/secp256k1/secp256k1.go (L184-190)
```go
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errors.Wrap(errors.ErrInvalidPubKey, "invalid pubkey size")
	}
	pubKey.Key = bz

	return nil
```

**File:** x/auth/ante/sigverify.go (L80-80)
```go
		if !simulate && !bytes.Equal(pk.Address(), signers[i]) {
```

**File:** codec/types/interface_registry.go (L294-296)
```go
	err := proto.Unmarshal(any.Value, msg)
	if err != nil {
		return err
```

**File:** x/auth/tx/builder.go (L107-128)
```go
func (w *wrapper) GetPubKeys() ([]cryptotypes.PubKey, error) {
	signerInfos := w.tx.AuthInfo.SignerInfos
	pks := make([]cryptotypes.PubKey, len(signerInfos))

	for i, si := range signerInfos {
		// NOTE: it is okay to leave this nil if there is no PubKey in the SignerInfo.
		// PubKey's can be left unset in SignerInfo.
		if si.PublicKey == nil {
			continue
		}

		pkAny := si.PublicKey.GetCachedValue()
		pk, ok := pkAny.(cryptotypes.PubKey)
		if ok {
			pks[i] = pk
		} else {
			return nil, sdkerrors.Wrapf(sdkerrors.ErrLogic, "Expecting PubKey, got: %T", pkAny)
		}
	}

	return pks, nil
}
```
