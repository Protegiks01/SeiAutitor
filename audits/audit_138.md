# Audit Report

## Title
Index Mismatch Vulnerability Allows Invalid Signatures to Bypass Batch Verification

## Summary
The batch signature verifier in `x/auth/ante/batch_sigverify.go` contains a critical index mapping bug at lines 178-184. When mapping batch verification results back to transaction indices, the code incorrectly uses the loop index instead of the stored transaction indices, allowing transactions with invalid signatures to bypass verification and be executed.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The batch verifier should verify multiple SR25519 signatures in batch, then correctly map the verification results back to their original transaction indices. Each transaction's verification result should be stored in `v.errors[txIndex]` where `txIndex` is the original position of the transaction in the batch.

**Actual Logic:** 
The code builds up `sigTxIndices` to track which transaction index each signature in the batch corresponds to: [2](#0-1) [3](#0-2) 

However, when mapping verification results back at lines 178-184, the code uses the loop index `i` directly instead of `sigTxIndices[i]`. This means failed signature verifications are written to the wrong error indices.

**Exploit Scenario:**
1. An attacker constructs a block with transactions in this specific order:
   - Transaction 0: Contains an early validation error (e.g., mismatched number of signatures vs signers) that prevents it from being added to the batch. Error stored at `v.errors[0]`.
   - Transaction 1: Contains a cryptographically INVALID signature but passes early validation. Added to batch at position 0, with `sigTxIndices[0] = 1`.
   - Transaction 2+: Normal transactions with valid signatures, added to batch at positions 1+.

2. During batch verification:
   - `individiauls[0] = false` (Transaction 1's signature failed)
   - `individiauls[1+] = true` (other transactions passed)

3. Due to the bug, the loop sets `v.errors[0]` (should set `v.errors[1]`), overwriting Transaction 0's original error.

4. When the `BatchSigVerificationDecorator.AnteHandle` checks results: [4](#0-3) 
   
   Transaction 1 checks `v.errors[1]` which is `nil`, and proceeds despite having an invalid signature.

**Security Failure:** 
This breaks the fundamental authentication invariant that all transactions must have valid cryptographic signatures. Unauthorized transactions can execute, potentially transferring funds or performing state changes without proper authorization.

## Impact Explanation

This vulnerability compromises the core security property of signature verification in the blockchain. When exploited:

- **Unauthorized Transaction Execution:** Attackers can execute transactions without valid signatures, breaking the authentication model
- **Fund Theft:** Transactions with invalid signatures could transfer tokens or assets from accounts the attacker doesn't control
- **Smart Contract Exploitation:** Invalid transactions could call smart contracts with unauthorized parameters, potentially draining funds or corrupting state
- **Consensus Breakdown:** Different nodes might process blocks differently if some use batch verification and others don't, potentially causing chain splits

While the batch verifier is not currently used in the default ante handler configuration [5](#0-4) , the context shows it's designed for integration with transaction processing [6](#0-5) . If enabled, this vulnerability would have catastrophic security implications.

## Likelihood Explanation

**Triggering Conditions:**
- The batch verifier must be enabled and integrated into the ante handler chain
- An attacker needs to control transaction ordering in a block (achievable as a block proposer or through transaction submission timing)
- Requires crafting a transaction with early validation errors followed by a transaction with invalid signatures

**Exploitability:**
- **Who:** Any malicious block proposer or sophisticated attacker who can influence transaction ordering
- **When:** Can occur during normal block production once batch verification is enabled
- **Frequency:** Exploitable on every block where the attacker controls ordering

The vulnerability is deterministic and reliably exploitable once the preconditions are met. While the batch verifier appears unused currently, code paths for its integration exist, making this a latent critical vulnerability.

## Recommendation

Fix the index mapping by using `sigTxIndices` to map batch results back to transaction indices:

```go
overall, individiauls := v.verifier.Verify()
if !overall {
    for i, individual := range individiauls {
        if !individual {
            // Fix: Use sigTxIndices[i] instead of i
            v.errors[sigTxIndices[i]] = sdkerrors.Wrap(
                sdkerrors.ErrUnauthorized,
                "signature verification failed; please verify account number and chain-id",
            )
        }
    }
}
```

Additionally, add validation to ensure `len(individiauls) == len(sigTxIndices)` before the loop to catch any unexpected state.

## Proof of Concept

**File:** `x/auth/ante/batch_sigverify_test.go` (new test file)

**Test Function:** `TestBatchVerifierIndexMismatchVulnerability`

**Setup:**
1. Create a test environment with three accounts, each with SR25519 keys
2. Set up a batch verifier with `NewSR25519BatchVerifier`
3. Create three transactions:
   - Tx 0: Set an invalid number of signatures (mismatch between signers and signatures) to trigger early error
   - Tx 1: Create with a valid structure but tamper with the signature bytes to make it cryptographically invalid
   - Tx 2: Create a normal valid transaction

**Trigger:**
1. Call `verifier.VerifyTxs(ctx, []sdk.Tx{tx0, tx1, tx2})`
2. This processes all three transactions through the batch verifier

**Observation:**
1. Check `verifier.errors[0]` - should contain the early validation error from Tx 0
2. Check `verifier.errors[1]` - **BUG: will be nil instead of containing signature verification error**
3. Check `verifier.errors[2]` - should be nil (valid transaction)
4. When `BatchSigVerificationDecorator.AnteHandle` is called for Tx 1, it will check `verifier.errors[1]`, find nil, and allow the transaction with invalid signature to proceed

**Expected vs Actual:**
- Expected: `verifier.errors[1]` contains signature verification error, Tx 1 is rejected
- Actual: `verifier.errors[1]` is nil, Tx 1 with invalid signature is accepted

The test demonstrates that the index mismatch allows a transaction with a cryptographically invalid signature to bypass verification and be accepted for execution, which is a critical authentication bypass vulnerability.

### Citations

**File:** x/auth/ante/batch_sigverify.go (L95-95)
```go
	sigTxIndices := []int{}
```

**File:** x/auth/ante/batch_sigverify.go (L158-163)
```go
				err = v.verifier.Add(typedPubKey.Key, signBytes, data.Signature)
				if err != nil {
					v.errors[i] = err
					continue
				}
				sigTxIndices = append(sigTxIndices, i)
```

**File:** x/auth/ante/batch_sigverify.go (L176-186)
```go
	overall, individiauls := v.verifier.Verify()
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

**File:** x/auth/ante/batch_sigverify.go (L220-222)
```go
	if err := svd.verifier.errors[txIdx]; err != nil {
		return ctx, err
	}
```

**File:** x/auth/ante/ante.go (L44-45)
```go
	sequentialVerifyDecorator := NewSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler)
	sigVerifyDecorator = sequentialVerifyDecorator
```

**File:** simapp/app.go (L517-519)
```go
	txResults := []*abci.ExecTxResult{}
	for i, tx := range req.Txs {
		ctx = ctx.WithContext(context.WithValue(ctx.Context(), ante.ContextKeyTxIndexKey, i))
```
