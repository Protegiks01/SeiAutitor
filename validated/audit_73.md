# Audit Report

## Title
MsgGrantAllowance Bypasses Bech32 Address Validation Enabling Fee-Free Resource Consumption

## Summary
The `MsgGrantAllowance.ValidateBasic()` method in the feegrant module fails to validate Bech32 address format, allowing transactions with malformed addresses to pass initial validation and consume node resources during ante handler execution without paying fees.

## Impact
Low

## Finding Description

**Location:**
- Module: `x/feegrant`
- File: `x/feegrant/msgs.go`
- Functions: `MsgGrantAllowance.ValidateBasic()` and `MsgGrantAllowance.GetSigners()`

**Intended Logic:**
The `ValidateBasic()` method should perform comprehensive stateless validation to reject invalid messages early in the transaction pipeline, before resource-intensive operations. This defense-in-depth mechanism prevents malformed transactions from consuming node resources without payment. [1](#0-0) 

**Actual Logic:**
The current implementation only validates that addresses are non-empty strings and different from each other. It does NOT validate Bech32 address format, unlike other modules such as bank and authz: [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. Attacker submits `MsgGrantAllowance` transaction with invalid Bech32 addresses (e.g., "invalid-granter" and "invalid-grantee")
2. Transaction enters CheckTx processing pipeline
3. `validateBasicTxMsgs()` calls `ValidateBasic()` which incorrectly passes [4](#0-3) 
4. Ante handler chain executes on a cached context [5](#0-4) 
5. Multiple decorators execute in order, including `DeductFeeDecorator` which deducts fees into the cache [6](#0-5) 
6. `SetPubKeyDecorator` executes and calls `sigTx.GetSigners()` [7](#0-6) 
7. This calls each message's `GetSigners()` which calls `sdk.AccAddressFromBech32()` and panics on invalid Bech32 [8](#0-7) [9](#0-8) 
8. Panic is recovered, ante handler returns error, but cached context is never committed [10](#0-9) 
9. No fees are charged (cache write is skipped) despite consuming resources through 6-7 ante decorators [11](#0-10) 

**Security Guarantee Broken:**
The defense-in-depth principle is violated. The system design expects `ValidateBasic()` to catch obviously invalid inputs before expensive processing. This vulnerability allows attackers to bypass this guard, consuming node resources without payment.

## Impact Explanation

This vulnerability enables attackers to submit transactions that consume node resources during CheckTx processing without paying fees. The attack causes network processing nodes to process transactions from the mempool beyond the designed validation parameters.

**Specific consequences:**
1. **Fee bypass**: Transactions consume CPU cycles through multiple ante decorators but pay zero fees due to cache rollback
2. **Resource asymmetry**: Processing cost to nodes exceeds normal invalid transactions that fail at ValidateBasic
3. **Mempool pollution**: Invalid transactions occupy CheckTx processing capacity that should handle valid transactions
4. **Difficult detection**: Transactions appear syntactically valid initially, potentially evading simple rate limiting

The impact qualifies as **Low severity** under the specified criteria: "Causing network processing nodes to process transactions from the mempool beyond set parameters" - transactions with invalid addresses should be rejected at ValidateBasic but instead are processed through the full ante handler chain.

## Likelihood Explanation

**Trigger Conditions:**
- Any unprivileged actor can trigger by submitting transactions via standard RPC endpoints
- No special permissions, tokens, or stake required
- No authentication needed beyond standard transaction submission
- Trivially exploitable with standard transaction construction tools

**Frequency:**
- Immediately exploitable in current codebase
- Can be repeated continuously
- Each malformed transaction consumes resources until rejected in ante handler
- Attack sustainability limited only by node rate limiting (which may be ineffective since transactions appear valid initially)

**Realistic Exploitation:**
This is highly likely to be exploited because:
1. Simple to execute - construct MsgGrantAllowance with arbitrary string addresses
2. Zero cost to attacker (no fees charged)
3. Difficult for nodes to distinguish from legitimate traffic without full validation
4. No blockchain state or special conditions required

## Recommendation

Add Bech32 address validation to `MsgGrantAllowance.ValidateBasic()` to align with the validation pattern used in bank and authz modules:

```go
func (msg MsgGrantAllowance) ValidateBasic() error {
    // Validate granter address format
    _, err := sdk.AccAddressFromBech32(msg.Granter)
    if err != nil {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid granter address (%s)", err)
    }
    
    // Validate grantee address format
    _, err = sdk.AccAddressFromBech32(msg.Grantee)
    if err != nil {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "invalid grantee address (%s)", err)
    }
    
    // Existing validation
    if msg.Grantee == msg.Granter {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "cannot self-grant fee authorization")
    }

    allowance, err := msg.GetFeeAllowanceI()
    if err != nil {
        return err
    }

    return allowance.ValidateBasic()
}
```

The same fix should be applied to `MsgRevokeAllowance.ValidateBasic()` [12](#0-11) 

## Proof of Concept

**Test demonstrating the vulnerability (add to x/feegrant/msgs_test.go):**

**Setup**: Create a MsgGrantAllowance with invalid Bech32 addresses (non-empty, different, but malformed strings like "invalid-granter-address" and "invalid-grantee-address")

**Action**: Call ValidateBasic() on the message with invalid addresses

**Result**: 
- ValidateBasic() incorrectly passes (demonstrates vulnerability)
- GetSigners() panics when called (would occur in ante handler)
- Contrast with bank module's MsgSend which properly rejects invalid addresses in ValidateBasic()

This demonstrates that the feegrant module has weaker validation than other modules, creating an exploitable gap where transactions bypass defense-in-depth checks and consume resources without paying fees.

## Notes

This vulnerability exists due to inconsistent validation patterns across cosmos-sdk modules. The feegrant module uses weaker validation than bank and authz modules, creating an exploitable gap in the defense-in-depth security model.

The fix is straightforward and follows established patterns from other modules. While the per-transaction overhead is relatively small, the zero-cost nature of the attack (no fees charged) makes it a viable vector for resource exhaustion attacks against network nodes. The vulnerability meets the Low severity criteria by allowing transactions to be processed beyond the set ValidateBasic() parameters that are designed to reject invalid transactions early.

### Citations

**File:** x/feegrant/msgs.go (L40-57)
```go
func (msg MsgGrantAllowance) ValidateBasic() error {
	if msg.Granter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing granter address")
	}
	if msg.Grantee == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing grantee address")
	}
	if msg.Grantee == msg.Granter {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "cannot self-grant fee authorization")
	}

	allowance, err := msg.GetFeeAllowanceI()
	if err != nil {
		return err
	}

	return allowance.ValidateBasic()
}
```

**File:** x/feegrant/msgs.go (L60-66)
```go
func (msg MsgGrantAllowance) GetSigners() []sdk.AccAddress {
	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{granter}
}
```

**File:** x/feegrant/msgs.go (L107-119)
```go
func (msg MsgRevokeAllowance) ValidateBasic() error {
	if msg.Granter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing granter address")
	}
	if msg.Grantee == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing grantee address")
	}
	if msg.Grantee == msg.Granter {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "addresses must be different")
	}

	return nil
}
```

**File:** x/bank/types/msgs.go (L29-38)
```go
func (msg MsgSend) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	_, err = sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid recipient address (%s)", err)
	}
```

**File:** x/authz/msgs.go (L54-68)
```go
func (msg MsgGrant) ValidateBasic() error {
	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}

	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
	}
	return msg.Grant.ValidateBasic()
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

**File:** baseapp/baseapp.go (L923-925)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```

**File:** baseapp/baseapp.go (L945-947)
```go
		anteCtx, msCache = app.cacheTxContext(ctx, checksum)
		anteCtx = anteCtx.WithEventManager(sdk.NewEventManager())
		newCtx, err := app.anteHandler(anteCtx, tx, mode == runTxModeSimulate)
```

**File:** baseapp/baseapp.go (L998-998)
```go
		msCache.Write()
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

**File:** x/auth/ante/sigverify.go (L59-69)
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
```

**File:** types/tx/types.go (L111-122)
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
```
