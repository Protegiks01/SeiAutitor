## Audit Report

### Title
Index Mismatch in SR25519 Batch Signature Verification Causes Authentication Bypass and DoS

### Summary
The SR25519 batch signature verifier in `x/auth/ante/batch_sigverify.go` contains a critical index mismatch bug that incorrectly maps batch verification results back to transaction indices. When batch verification fails due to invalid signatures, the error assignment logic uses the batch array index instead of the transaction index, causing valid transactions to be rejected (DoS) and potentially allowing invalid transactions to pass (authentication bypass). [1](#0-0) 

### Impact
**High**

This vulnerability breaks the fundamental security property of signature verification and can lead to:
- Denial of Service: Valid transactions from legitimate users are rejected
- Authentication Bypass: Transactions with invalid signatures may be accepted
- Network reliability degradation: Unpredictable transaction processing behavior

### Finding Description

**Location:** 
`x/auth/ante/batch_sigverify.go`, lines 177-186, in the `VerifyTxs` method of `SR25519BatchVerifier` [2](#0-1) 

**Intended Logic:**
The batch verifier should collect SR25519 signatures from multiple transactions, verify them in batch for efficiency, and correctly report which specific transactions have invalid signatures. The `sigTxIndices` array (line 95) is created to track the mapping from batch signature index to original transaction index, as some transactions may have pre-verification errors and skip batch verification.

**Actual Logic:**
When batch verification fails (`overall == false` at line 177), the code iterates through individual verification results. However, at line 180, it incorrectly uses the batch index `i` to set errors: `v.errors[i]`, when it should use `v.errors[sigTxIndices[i]]` to map back to the correct transaction index.

**Exploit Scenario:**
1. An attacker submits multiple transactions to the network, some with intentionally invalid SR25519 signatures
2. These transactions are batched with legitimate user transactions during block processing
3. Some transactions (e.g., transaction 0) may fail pre-verification checks (wrong sequence number, missing pubkey, etc.) and are not added to the batch verifier
4. Valid transactions (e.g., indices 1, 2, 3, 4) are added to the batch as batch indices 0, 1, 2, 3
5. The attacker's invalid signature at batch index 1 (transaction index 2) fails verification
6. Due to the bug, the error is assigned to `v.errors[1]` (transaction index 1) instead of `v.errors[2]`
7. Transaction 1 (valid) is rejected, transaction 2 (invalid) may pass through

**Security Failure:**
- **Authentication bypass**: Invalid signatures may not be properly rejected
- **Denial of Service**: Valid transactions are incorrectly rejected
- **Integrity violation**: The core security invariant of "only properly signed transactions are processed" is broken

### Impact Explanation

**Affected Assets and Processes:**
- Transaction processing integrity for all SR25519 signed transactions
- Network availability for legitimate users whose valid transactions get rejected
- Authentication security as the signature verification barrier is bypassed

**Severity of Damage:**
- **Medium to High DoS**: Legitimate transactions are randomly rejected based on batch composition, degrading network reliability
- **Authentication Bypass**: Transactions with invalid signatures can be accepted if the index mismatch causes their errors to be assigned elsewhere
- **Unpredictable Behavior**: The exact failure pattern depends on which transactions have pre-verification errors, making the system unreliable

**System Reliability:**
This fundamentally breaks the trust model of the blockchain. Users cannot rely on:
- Their valid transactions being processed
- Invalid transactions being properly rejected
- Deterministic transaction processing behavior

### Likelihood Explanation

**Who Can Trigger:**
Any network participant can trigger this vulnerability by submitting transactions with invalid SR25519 signatures. No special privileges are required.

**Conditions Required:**
- At least one transaction in a batch must have an invalid SR25519 signature
- At least one transaction must have pre-verification errors (common scenarios: wrong sequence number, nil transaction, type conversion failure, missing pubkey)
- The network must be using SR25519 signatures and batch verification (which is the intended optimization path)

**Frequency:**
This can occur during normal network operation and can be triggered frequently:
- Pre-verification errors are common (sequence number mismatches, new accounts without pubkeys set)
- Any user can submit invalid signatures intentionally or accidentally
- The bug manifests deterministically once the conditions are met

### Recommendation

**Fix:**
Modify the error assignment logic in `x/auth/ante/batch_sigverify.go` to use the correct transaction index mapping:

```go
if !overall {
    for i, individual := range individiauls {
        if !individual {
            v.errors[sigTxIndices[i]] = sdkerrors.Wrap(  // Use sigTxIndices[i] instead of i
                sdkerrors.ErrUnauthorized,
                "signature verification failed; please verify account number and chain-id",
            )
        }
    }
}
```

**Additional Safety Check:**
Add a bounds check to prevent potential panic if the arrays are misaligned:
```go
if !overall {
    for i, individual := range individiauls {
        if !individual && i < len(sigTxIndices) {
            v.errors[sigTxIndices[i]] = sdkerrors.Wrap(
                sdkerrors.ErrUnauthorized,
                "signature verification failed; please verify account number and chain-id",
            )
        }
    }
}
```

### Proof of Concept

**File:** `x/auth/ante/batch_sigverify_test.go` (new test file)

**Test Function:** `TestBatchVerifyIndexMismatch`

**Setup:**
1. Create a test context at block height 1 (to enable batch verification)
2. Create 5 transactions with SR25519 signatures:
   - Transaction 0: Invalid (nil transaction or pre-verification error)
   - Transaction 1: Valid signature
   - Transaction 2: Invalid signature (manipulated)
   - Transaction 3: Valid signature
   - Transaction 4: Valid signature
3. Initialize SR25519BatchVerifier with account keeper and sign mode handler

**Trigger:**
1. Call `verifier.VerifyTxs(ctx, txs)` with the batch of 5 transactions
2. Transaction 0 will fail pre-verification and not be added to batch
3. Transactions 1-4 will be added to batch as indices 0-3
4. Batch verification will return `overall=false` with `individiauls=[true, false, true, true]`

**Observation:**
```go
// Expected behavior:
// v.errors[0] should have error (pre-verification)
// v.errors[1] should be nil (valid)
// v.errors[2] should have error (invalid signature)
// v.errors[3] should be nil (valid)
// v.errors[4] should be nil (valid)

// Actual buggy behavior:
// v.errors[0] has error (pre-verification) ✓
// v.errors[1] has signature verification error ✗ (WRONG! tx 1 is valid)
// v.errors[2] is nil ✗ (WRONG! tx 2 has invalid signature)
// v.errors[3] is nil ✓
// v.errors[4] is nil ✓

assert.Nil(t, verifier.errors[1], "Transaction 1 should pass (valid signature)")
assert.NotNil(t, verifier.errors[2], "Transaction 2 should fail (invalid signature)")
// These assertions will fail on the vulnerable code, proving the bug
```

The test demonstrates that:
1. Transaction 1 with a valid signature is incorrectly rejected
2. Transaction 2 with an invalid signature is incorrectly accepted
3. The index mismatch causes errors to be assigned to wrong transactions

This PoC can be implemented using the existing test infrastructure from `x/auth/ante/sigverify_test.go` for creating test transactions and accounts with SR25519 keys using `sr25519.GenPrivKey()`.

### Citations

**File:** x/auth/ante/batch_sigverify.go (L95-163)
```go
	sigTxIndices := []int{}
	sequenceNumberCache := map[uint64]uint64{}
	for i := range txs {
		if v.errors[i] != nil {
			continue
		}
		for j := range sigsList[i] {
			acc, err := GetSignerAcc(ctx, v.ak, signerAddressesList[i][j])
			if err != nil {
				v.errors[i] = err
				continue
			}

			pubKey := acc.GetPubKey()
			if pubKey == nil {
				v.errors[i] = sdkerrors.Wrap(sdkerrors.ErrInvalidPubKey, "pubkey on account is not set")
				continue
			}
			typedPubKey, ok := pubKey.(*sr25519.PubKey)
			if !ok {
				v.errors[i] = sdkerrors.Wrapf(
					sdkerrors.ErrNotSupported,
					"only sr25519 supported at the moment",
				)
				continue
			}

			accNum := acc.GetAccountNumber()

			var seqNum uint64
			if cachedSeq, ok := sequenceNumberCache[accNum]; ok {
				seqNum = cachedSeq + 1
				sequenceNumberCache[accNum] = seqNum
			} else {
				sequenceNumberCache[accNum] = acc.GetSequence()
				seqNum = sequenceNumberCache[accNum]
			}

			sig := sigsList[i][j]
			if sig.Sequence != seqNum {
				params := v.ak.GetParams(ctx)
				if !params.GetDisableSeqnoCheck() {
					v.errors[i] = sdkerrors.Wrapf(
						sdkerrors.ErrWrongSequence,
						"account sequence mismatch, expected %d, got %d", acc.GetSequence(), sig.Sequence,
					)
					continue
				}
			}

			switch data := sig.Data.(type) {
			case *signing.SingleSignatureData:
				chainID := ctx.ChainID()
				signerData := authsigning.SignerData{
					ChainID:       chainID,
					AccountNumber: accNum,
					Sequence:      acc.GetSequence(),
				}
				signBytes, err := v.signModeHandler.GetSignBytes(data.SignMode, signerData, txs[i])
				if err != nil {
					v.errors[i] = err
					continue
				}
				err = v.verifier.Add(typedPubKey.Key, signBytes, data.Signature)
				if err != nil {
					v.errors[i] = err
					continue
				}
				sigTxIndices = append(sigTxIndices, i)
```

**File:** x/auth/ante/batch_sigverify.go (L177-186)
```go
	if !overall {
		for i, individual := range individiauls {
			if !individual {
				v.errors[i] = sdkerrors.Wrap(
					sdkerrors.ErrUnauthorized,
					"signature verification failed; please verify account number and chain-id",
				)
			}
		}
	}
```
