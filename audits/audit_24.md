Based on my thorough technical analysis of the codebase, I have validated this security claim against all strict criteria.

# Audit Report

## Title
Index Out of Bounds Panic in SetPubKeyDecorator Due to Missing Length Validation

## Summary
The `SetPubKeyDecorator` in the ante handler chain lacks validation to ensure the number of public keys matches the number of signers. This allows any user to craft malformed transactions that pass `ValidateBasic()` but trigger panics during ante handler processing, causing validators to waste computational resources on transactions that should have been rejected earlier.

## Impact
Low

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The `SetPubKeyDecorator` should validate that the number of public keys matches the number of signers before iterating, ensuring safe array access and early rejection of malformed transactions.

**Actual Logic:**
The decorator retrieves `pubkeys` from `GetPubKeys()` which returns an array based on `AuthInfo.SignerInfos` length [2](#0-1) , and `signers` from `GetSigners()` which derives signers from transaction messages [3](#0-2) . These arrays can have different lengths because they come from independent data sources. The code loops over `pubkeys` and accesses `signers[i]` without bounds validation, causing an index out of bounds panic when `len(pubkeys) > len(signers)`.

**Exploitation Path:**
1. Attacker creates a transaction with one message containing one unique signer (N=1)
2. Sets `AuthInfo.SignerInfos` array to have 2 elements (M=2)  
3. Sets `Signatures` array to have 1 element (matching the 1 signer)
4. Transaction passes `ValidateBasic()` because it only validates `len(Signatures) == len(GetSigners())` (1 == 1) [4](#0-3) 
5. Transaction enters ante handler chain and proceeds through multiple decorators [5](#0-4) 
6. In `SetPubKeyDecorator`, the loop iterates twice (M=2), and at i=1, accessing `signers[1]` triggers an index out of bounds panic
7. Panic is caught by recovery middleware [6](#0-5)  and the transaction is rejected

**Security Guarantee Broken:**
The ante handler chain should efficiently reject invalid transactions during early validation stages. This vulnerability allows malformed transactions to bypass `ValidateBasic()` and consume validator resources through multiple expensive decorator executions before being rejected via panic recovery.

## Impact Explanation

This vulnerability enables resource exhaustion where validators waste computational resources processing malformed transactions. Each malicious transaction forces validators to:
1. Decode the transaction
2. Execute 7+ ante handler decorators (SetUpContext, RejectExtensionOptions, ValidateBasic decorator, TxTimeoutHeight, ValidateMemo, ConsumeGasForTxSize, DeductFee)
3. Panic in SetPubKeyDecorator  
4. Process panic recovery and cleanup

Since these transactions are rejected during CheckTx (mempool admission), attackers pay no gas fees while consuming validator resources. The network continues functioning and no funds are at risk, but validator efficiency is degraded. This matches the **Low severity** impact: "Causing network processing nodes to process transactions from the mempool beyond set parameters."

## Likelihood Explanation

**Who can trigger it:**
Any network participant can exploit this vulnerability without special permissions or resources beyond standard transaction submission capabilities.

**Required conditions:**
- The default ante handler chain includes `SetPubKeyDecorator` (standard configuration)
- Attacker can craft protobuf transactions (standard capability available to all users)

**Frequency:**
This can be exploited repeatedly and deterministically. An attacker can pre-generate batches of malformed transactions and submit them continuously. Each transaction reliably triggers the panic during CheckTx. The attack can be sustained as long as the attacker maintains network connectivity.

## Recommendation

Add length validation in `SetPubKeyDecorator.AnteHandle` before the iteration loop:

```go
if len(pubkeys) != len(signers) {
    return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, 
        "invalid number of pubkeys; expected: %d, got %d", len(signers), len(pubkeys))
}
```

This validation pattern is already correctly implemented in the batch signature verifier [7](#0-6) , confirming that this check is necessary and should be consistently applied across all signature verification paths.

Alternatively, add this validation to `Tx.ValidateBasic()` to catch the issue even earlier in the validation pipeline.

## Proof of Concept

The vulnerability can be demonstrated through code analysis:

**Setup:**
- Create a transaction with one message containing one unique signer
- Manually construct `AuthInfo` with two `SignerInfo` elements
- Set `Signatures` array to one element

**Action:**
- Call `ValidateBasic()` - passes because `len(Signatures) == len(GetSigners())` equals (1 == 1)
- Execute ante handler chain including `SetPubKeyDecorator`

**Result:**
- `GetPubKeys()` returns 2 elements (from `AuthInfo.SignerInfos`)
- `GetSigners()` returns 1 element (from message signers)
- Loop iterates twice; at i=1, accessing `signers[1]` causes index out of bounds panic
- Panic is caught by recovery middleware and transaction is rejected after wasting resources

The vulnerability is verifiable by constructing a protobuf transaction with `len(AuthInfo.SignerInfos) ≠ len(GetSigners())` that satisfies the existing `ValidateBasic()` check.

## Notes

This is a valid Low severity vulnerability that matches the explicitly listed impact category: "Causing network processing nodes to process transactions from the mempool beyond set parameters." The vulnerability allows transactions to bypass early validation (`ValidateBasic`) and proceed through multiple expensive decorators before being rejected via panic, wasting validator computational resources. The fix is straightforward and follows the pattern already established in the batch signature verifier.

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

**File:** x/auth/ante/batch_sigverify.go (L66-68)
```go
		if len(pubkeys) != len(signerAddrs) {
			v.errors[i] = sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of pubkeys;  expected: %d, got %d", len(signerAddrs), len(pubkeys))
			continue
```
