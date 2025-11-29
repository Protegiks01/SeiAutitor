# Audit Report

## Title
Index Out of Bounds Panic in SetPubKeyDecorator Due to Missing Length Validation

## Summary
The `SetPubKeyDecorator` in the ante handler chain lacks validation to ensure the number of public keys from `AuthInfo.SignerInfos` matches the number of signers derived from transaction messages. This allows any user to craft transactions that pass `ValidateBasic()` but trigger index out of bounds panics during ante handler processing, causing validators to waste resources on malformed transactions.

## Impact
Low

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `SetPubKeyDecorator` should safely iterate over public keys and match them with corresponding signers to validate and store public key information. It should reject transactions where the number of public keys doesn't match the number of signers.

**Actual Logic:** 
The decorator retrieves `pubkeys` from `GetPubKeys()` which returns an array of length `len(AuthInfo.SignerInfos)` [2](#0-1) , and `signers` from `GetSigners()` which derives signers from transaction messages [3](#0-2) . These two arrays can have different lengths because they come from independent data sources.

The code loops over `pubkeys` and accesses `signers[i]` without validating that `i < len(signers)`, causing an index out of bounds panic when `len(pubkeys) > len(signers)`.

**Exploitation Path:**
1. Attacker creates a transaction with one message having one unique signer (N=1)
2. Sets `AuthInfo.SignerInfos` array to have 2 elements (M=2)
3. Sets `Signatures` array to have 1 element (matching N signers)
4. Transaction passes `ValidateBasic()` because it only checks `len(Signatures) == len(GetSigners())` (1 == 1) [4](#0-3) 
5. During ante handler execution in `SetPubKeyDecorator`, the code loops over 2 pubkeys
6. At iteration i=1, accessing `signers[1]` triggers an index out of bounds panic
7. The panic is caught by recovery middleware [5](#0-4)  and the transaction is rejected

**Security Guarantee Broken:**
The ante handler chain should efficiently reject invalid transactions during validation, not after processing through multiple expensive decorators. This vulnerability allows transactions to bypass early validation and consume validator resources unnecessarily.

## Impact Explanation

This vulnerability enables a denial-of-service attack vector where validators waste computational resources processing malformed transactions that should have been rejected during basic validation. Each malicious transaction forces validators to:

1. Decode the transaction
2. Execute multiple ante handler decorators (SetUpContext, RejectExtensionOptions, ValidateBasic, TxTimeoutHeight, ValidateMemo, ConsumeGasForTxSize, DeductFee) [6](#0-5) 
3. Panic in SetPubKeyDecorator
4. Process panic recovery and cleanup

Since these transactions are rejected during CheckTx (mempool admission), the attacker doesn't pay gas fees but still consumes validator resources. This fits the **Low severity** category: "Causing network processing nodes to process transactions from the mempool beyond set parameters."

The network continues to function and no funds are at risk, but validator efficiency is degraded when processing these malicious transactions.

## Likelihood Explanation

**Who can trigger it:**
Any network participant can exploit this vulnerability. No special permissions or resources are required beyond the ability to submit transactions, which is available to all users.

**Required conditions:**
- The default ante handler chain includes `SetPubKeyDecorator` (standard configuration)
- Attacker can craft and submit protobuf transactions (standard capability)

**Frequency:**
This can be exploited repeatedly. An attacker can pre-generate batches of malicious transactions and submit them continuously. Each transaction deterministically triggers the panic during CheckTx. The attack can be sustained as long as the attacker maintains network connectivity.

## Recommendation

Add a length validation check in `SetPubKeyDecorator.AnteHandle` before the iteration loop:

```go
func (spkd SetPubKeyDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
    sigTx, ok := tx.(authsigning.SigVerifiableTx)
    if !ok {
        return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid tx type")
    }

    pubkeys, err := sigTx.GetPubKeys()
    if err != nil {
        return ctx, err
    }
    signers := sigTx.GetSigners()
    
    // Add this validation check
    if len(pubkeys) != len(signers) {
        return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, 
            "invalid number of pubkeys; expected: %d, got %d", len(signers), len(pubkeys))
    }

    for i, pk := range pubkeys {
        // ... existing logic
    }
}
```

This validation pattern is already implemented in the batch signature verifier [7](#0-6) , confirming that this check is necessary and should be consistently applied.

Alternatively, add this check to `Tx.ValidateBasic()` to catch the issue earlier in the validation pipeline.

## Proof of Concept

While the provided PoC contains pseudo-code with incomplete sections, the vulnerability is evident from code analysis:

**Setup:**
- Create a transaction with one message (one signer)
- Manually construct `AuthInfo` with two `SignerInfo` elements  
- Set `Signatures` array to one element

**Action:**
- Call `ValidateBasic()` - passes because `len(Signatures) == len(GetSigners())` (1 == 1)
- Execute ante handler chain with `SetPubKeyDecorator`

**Result:**
- `GetPubKeys()` returns 2 elements (from `AuthInfo.SignerInfos`)
- `GetSigners()` returns 1 element (from message signers)
- Loop iterates twice, at i=1 accessing `signers[1]` causes panic
- Panic is caught and transaction rejected after wasting resources

The vulnerability can be verified by constructing a properly formatted protobuf transaction with mismatched `SignerInfos` and `Signatures` lengths that satisfy the existing `ValidateBasic()` check.

## Notes

The severity assessment differs from the report's claim:
- **Report claims**: Medium ("30% resource consumption increase")
- **Actual severity**: Low ("processing beyond set parameters")

The Medium severity claim requires proof of "at least 30% resource consumption increase," which is not substantiated with measurements or benchmarks. The actual impact matches the Low severity category where transactions are processed further into the ante handler chain than they should be, causing inefficiency but not meeting the 30% threshold required for Medium severity.

The vulnerability is valid and should be fixed, but the impact is resource inefficiency rather than a critical system failure.

### Citations

**File:** x/auth/ante/sigverify.go (L71-85)
```go
	for i, pk := range pubkeys {
		// PublicKey was omitted from slice since it has already been set in context
		if pk == nil {
			if !simulate {
				continue
			}
			pk = simSecp256k1Pubkey
		}
		// Only make check if simulate=false
		if !simulate && !bytes.Equal(pk.Address(), signers[i]) {
			return ctx, sdkerrors.Wrapf(sdkerrors.ErrInvalidPubKey,
				"pubKey does not match signer address %s with signer index: %d", signers[i], i)
		}

		acc, err := GetSignerAcc(ctx, spkd.ak, signers[i])
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

**File:** types/tx/types.go (L94-99)
```go
	if len(sigs) != len(t.GetSigners()) {
		return sdkerrors.Wrapf(
			sdkerrors.ErrUnauthorized,
			"wrong number of signers; expected %d, got %d", len(t.GetSigners()), len(sigs),
		)
	}
```

**File:** types/tx/types.go (L111-132)
```go
func (t *Tx) GetSigners() []sdk.AccAddress {
	var signers []sdk.AccAddress
	seen := map[string]bool{}

	for _, msg := range t.GetMsgs() {
		for _, addr := range msg.GetSigners() {
			if !seen[addr.String()] {
				signers = append(signers, addr)
				seen[addr.String()] = true
			}
		}
	}

	// ensure any specified fee payer is included in the required signers (at the end)
	feePayer := t.AuthInfo.Fee.Payer
	if feePayer != "" && !seen[feePayer] {
		payerAddr := sdk.MustAccAddressFromBech32(feePayer)
		signers = append(signers, payerAddr)
	}

	return signers
}
```

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
```

**File:** x/auth/ante/ante.go (L48-60)
```go
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

**File:** x/auth/ante/batch_sigverify.go (L66-68)
```go
		if len(pubkeys) != len(signerAddrs) {
			v.errors[i] = sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of pubkeys;  expected: %d, got %d", len(signerAddrs), len(pubkeys))
			continue
```
