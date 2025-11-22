## Title
Batch Verifier Uses Incorrect Sequence Number for Multi-Transaction Signature Verification

## Summary
The SR25519 batch verifier in `x/auth/ante/batch_sigverify.go` incorrectly uses the original account sequence number instead of the cached incremented sequence number when verifying signatures for multiple transactions from the same signer. This causes legitimate transactions to fail signature verification, breaking batch processing for accounts submitting multiple transactions. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/auth/ante/batch_sigverify.go`, specifically lines 124-131 (sequence number caching logic) and line 151 (SignerData construction) [1](#0-0) [2](#0-1) 

**Intended Logic:** When multiple transactions in a batch are signed by the same account, the batch verifier should track incrementing sequence numbers using the `sequenceNumberCache`. Each subsequent transaction from the same signer should use an incremented sequence number (N, N+1, N+2, etc.). When verifying signatures, the verifier must compute sign bytes using the same sequence number that was used to create the signature.

**Actual Logic:** The code correctly tracks and validates sequence numbers in the cache (lines 124-131), but when constructing the `SignerData` for signature verification at line 151, it always uses `acc.GetSequence()` which returns the original sequence from account state, not the cached incremented value `seqNum`. This causes a mismatch between the sequence number used to create the signature and the sequence number used to verify it.

**Exploit Scenario:**
1. Account A has sequence number 5 in blockchain state
2. User creates two valid transactions in a batch:
   - Transaction 1: Signed by Account A with sequence 5
   - Transaction 2: Signed by Account A with sequence 6
3. Batch verifier processes Transaction 1:
   - Initializes cache: `sequenceNumberCache[AccNum] = 5`, `seqNum = 5`
   - Validates `sig.Sequence == 5` ✓
   - Creates SignerData with `Sequence: acc.GetSequence() = 5` ✓
   - Signature verification succeeds ✓
4. Batch verifier processes Transaction 2:
   - Reads from cache: `seqNum = cachedSeq + 1 = 6`
   - Validates `sig.Sequence == 6` ✓
   - Creates SignerData with `Sequence: acc.GetSequence() = 5` ✗ (should be 6)
   - Signature verification fails ✗ because sign bytes use sequence 5 instead of 6

**Security Failure:** This breaks transaction validation integrity. Legitimate, correctly-signed transactions are rejected during batch processing, causing a denial of service for users attempting to submit multiple transactions from the same account within a batch. This violates the invariant that validly-signed transactions should be accepted.

## Impact Explanation

**Affected Processes:** The batch signature verification system for SR25519 transactions is fundamentally broken when multiple transactions from the same account are included in a batch.

**Severity:** Any user attempting to send multiple transactions from the same account in a batch will have all transactions after the first one rejected with signature verification failures. This prevents legitimate use of the batch processing optimization and forces users to submit transactions sequentially, defeating the purpose of batch verification.

**System Impact:** This affects transaction processing reliability. The batch verifier is designed to optimize performance by verifying multiple signatures at once, but this bug makes it unusable for the common case where a user submits multiple transactions. This falls under "A bug in the layer 1 network code that results in unintended transaction behavior" as legitimate transactions are incorrectly rejected.

## Likelihood Explanation

**Who Can Trigger:** Any user sending multiple transactions from the same account within a block that uses batch verification can trigger this issue. No special privileges are required.

**Conditions Required:** This occurs during normal operation whenever:
1. The batch verifier is enabled (for SR25519 signatures)
2. A user submits multiple transactions from the same account in the same batch/block
3. The transactions are correctly signed with incrementing sequence numbers

**Frequency:** This will occur every time the above conditions are met, making it a deterministic bug rather than a race condition. Given that sending multiple transactions from the same account is a common pattern (e.g., for trading, batch operations), this could affect many users if batch verification is actively used.

## Recommendation

Modify line 151 in `batch_sigverify.go` to use the calculated `seqNum` from the cache instead of `acc.GetSequence()`:

Change:
```go
Sequence:      acc.GetSequence(),
```

To:
```go
Sequence:      seqNum,
```

This ensures that the signature verification uses the same sequence number that was validated and cached for each transaction, matching the sequence number used when the signature was originally created. [3](#0-2) 

## Proof of Concept

**Test File:** `x/auth/ante/batch_sigverify_test.go` (new file)

**Test Function:** `TestBatchVerifierMultipleTransactionsSameSigner`

**Setup:**
1. Create a test environment with account keeper and SR25519 batch verifier
2. Create an account with SR25519 keypair and sequence number 0
3. Create two test messages/transactions
4. Sign transaction 1 with sequence 0
5. Sign transaction 2 with sequence 1
6. Both transactions are from the same account

**Trigger:**
1. Call `verifier.VerifyTxs(ctx, []sdk.Tx{tx1, tx2})`
2. The batch verifier processes both transactions together

**Observation:**
The test should observe that `verifier.errors[1]` (the error for transaction 2) contains a signature verification failure error (`ErrUnauthorized`), even though transaction 2 was correctly signed with sequence 1. The error occurs because the verifier uses sequence 0 (from `acc.GetSequence()`) instead of sequence 1 (the cached value) when computing sign bytes for verification.

The test confirms the bug by demonstrating that a validly-signed second transaction fails verification solely due to the incorrect sequence number usage in SignerData construction.

**Expected Test Code Structure:**
```go
// Create SR25519 keys
priv := sr25519.GenPrivKey()
pub := priv.PubKey()
addr := sdk.AccAddress(pub.Address())

// Create account with sequence 0
acc := accountKeeper.NewAccountWithAddress(ctx, addr)
acc.SetSequence(0)
acc.SetPubKey(pub)
accountKeeper.SetAccount(ctx, acc)

// Create and sign two transactions with sequences 0 and 1
tx1 := createAndSignTx(priv, 0, msg1)
tx2 := createAndSignTx(priv, 1, msg2)

// Verify batch
verifier := NewSR25519BatchVerifier(accountKeeper, signModeHandler)
verifier.VerifyTxs(ctx, []sdk.Tx{tx1, tx2})

// Transaction 1 should pass
require.NoError(t, verifier.errors[0])

// Transaction 2 should FAIL due to the bug (but shouldn't in correct implementation)
require.Error(t, verifier.errors[1])
require.Contains(t, verifier.errors[1].Error(), "signature verification failed")
```

### Citations

**File:** x/auth/ante/batch_sigverify.go (L124-131)
```go
			var seqNum uint64
			if cachedSeq, ok := sequenceNumberCache[accNum]; ok {
				seqNum = cachedSeq + 1
				sequenceNumberCache[accNum] = seqNum
			} else {
				sequenceNumberCache[accNum] = acc.GetSequence()
				seqNum = sequenceNumberCache[accNum]
			}
```

**File:** x/auth/ante/batch_sigverify.go (L147-157)
```go
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
```
