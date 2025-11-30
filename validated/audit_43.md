# Audit Report

## Title
Index Out of Bounds Panic in SetPubKeyDecorator Due to Missing Length Validation

## Summary
The `SetPubKeyDecorator` in the ante handler chain lacks validation to ensure the number of public keys matches the number of signers. This allows attackers to craft transactions with mismatched `AuthInfo.SignerInfos` and message signers that pass `ValidateBasic()` but trigger index out of bounds panics during ante handler processing, causing validators to waste computational resources.

## Impact
Low

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The `SetPubKeyDecorator` should validate that the number of public keys from `GetPubKeys()` matches the number of signers from `GetSigners()` before iterating, ensuring safe array access and early rejection of malformed transactions.

**Actual Logic:**
The decorator retrieves `pubkeys` from `GetPubKeys()` [2](#0-1)  which returns an array based on `AuthInfo.SignerInfos` length, and `signers` from `GetSigners()` [3](#0-2)  which derives signers from transaction messages. These arrays originate from independent data sources and can have different lengths. The code loops over `pubkeys` and accesses `signers[i]` at lines 80, 85, and 112 without bounds validation, causing an index out of bounds panic when `len(pubkeys) > len(signers)`.

**Exploitation Path:**
1. Attacker creates a transaction with one message containing one unique signer
2. Sets `AuthInfo.SignerInfos` array to have 2 elements  
3. Sets `Signatures` array to have 1 element
4. Transaction passes `ValidateBasic()` [4](#0-3)  because it only validates `len(Signatures) == len(GetSigners())` (1 == 1), not `len(SignerInfos) == len(GetSigners())`
5. Transaction enters ante handler chain [5](#0-4)  and proceeds through 7 decorators (SetUpContext, RejectExtensionOptions, ValidateBasic decorator, TxTimeoutHeight, ValidateMemo, ConsumeGasForTxSize, DeductFee)
6. In `SetPubKeyDecorator`, the loop iterates twice based on `len(pubkeys)=2`, and at i=1, accessing `signers[1]` triggers an index out of bounds panic
7. Panic is caught by recovery middleware [6](#0-5)  and the transaction is rejected

**Security Guarantee Broken:**
The ante handler chain should efficiently reject invalid transactions during early validation stages. This vulnerability allows malformed transactions to bypass `ValidateBasic()` and consume validator resources through multiple decorator executions before being rejected via panic recovery.

## Impact Explanation

This vulnerability enables resource exhaustion where validators waste computational resources processing malformed transactions. Each malicious transaction forces validators to decode the transaction and execute 7+ ante handler decorators before panicking in `SetPubKeyDecorator` and processing panic recovery. Since these transactions are rejected during CheckTx (mempool admission), attackers pay no gas fees while consuming validator resources. The attacker can repeatedly and deterministically submit batches of such transactions. The network continues functioning and no funds are at risk, but validator efficiency is degraded through unnecessary processing of transactions that should have been rejected at `ValidateBasic()`.

## Likelihood Explanation

**Who can trigger it:**
Any network participant can exploit this vulnerability without special permissions or resources beyond standard transaction submission capabilities.

**Required conditions:**
- The default ante handler chain includes `SetPubKeyDecorator` (standard configuration)
- Attacker can craft protobuf transactions with arbitrary `AuthInfo.SignerInfos` length (standard capability)

**Frequency:**
This can be exploited repeatedly and deterministically. An attacker can pre-generate batches of malformed transactions and submit them continuously to mempool. Each transaction reliably triggers the panic during CheckTx, wasting validator resources with no cost to the attacker.

## Recommendation

Add length validation in `SetPubKeyDecorator.AnteHandle` before the iteration loop:

```go
if len(pubkeys) != len(signers) {
    return ctx, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, 
        "invalid number of pubkeys; expected: %d, got %d", len(signers), len(pubkeys))
}
```

This validation pattern is already correctly implemented in the batch signature verifier [7](#0-6) , confirming that this check is necessary and should be consistently applied across all signature verification paths.

## Proof of Concept

The vulnerability can be demonstrated through the following execution flow:

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
- Loop in `SetPubKeyDecorator` iterates twice based on `len(pubkeys)=2`
- At i=1, accessing `signers[1]` causes index out of bounds panic
- Panic is caught by recovery middleware and transaction is rejected after wasting validator resources processing through 7+ ante handler decorators

## Notes

This is a valid Low severity vulnerability that matches the impact category: "Causing network processing nodes to process transactions from the mempool beyond set parameters." The vulnerability allows transactions to bypass early validation and proceed through multiple expensive decorators before being rejected via panic, wasting validator computational resources. The fix is straightforward and follows the pattern already established in the batch signature verifier, confirming this check is necessary for secure operation.

### Citations

**File:** x/auth/ante/sigverify.go (L59-128)
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
		if err != nil {
			return ctx, err
		}
		// account already has pubkey set,no need to reset
		if acc.GetPubKey() != nil {
			continue
		}
		err = acc.SetPubKey(pk)
		if err != nil {
			return ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidPubKey, err.Error())
		}
		spkd.ak.SetAccount(ctx, acc)
	}

	// Also emit the following events, so that txs can be indexed by these
	// indices:
	// - signature (via `tx.signature='<sig_as_base64>'`),
	// - concat(address,"/",sequence) (via `tx.acc_seq='cosmos1abc...def/42'`).
	sigs, err := sigTx.GetSignaturesV2()
	if err != nil {
		return ctx, err
	}

	var events sdk.Events
	for i, sig := range sigs {
		events = append(events, sdk.NewEvent(sdk.EventTypeTx,
			sdk.NewAttribute(sdk.AttributeKeyAccountSequence, fmt.Sprintf("%s/%d", signers[i], sig.Sequence)),
		))

		sigBzs, err := signatureDataToBz(sig.Data)
		if err != nil {
			return ctx, err
		}
		for _, sigBz := range sigBzs {
			events = append(events, sdk.NewEvent(sdk.EventTypeTx,
				sdk.NewAttribute(sdk.AttributeKeySignature, base64.StdEncoding.EncodeToString(sigBz)),
			))
		}
	}

	ctx.EventManager().EmitEvents(events)

	return next(ctx, tx, simulate)
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

**File:** x/auth/ante/ante.go (L47-60)
```go
	anteDecorators := []sdk.AnteFullDecorator{
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
