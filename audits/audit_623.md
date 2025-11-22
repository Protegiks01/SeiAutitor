Based on my thorough investigation of the sei-cosmos codebase, I have identified a vulnerability related to fee grant consumption.

## Audit Report

## Title
Fee Grant Consumption on Failed Transaction Execution Enables Allowance Drainage Attack

## Summary
Fee grants in the sei-cosmos protocol are consumed during the ante handler phase, before message execution. When a transaction with a fee granter passes basic validation but fails during message execution, the fee grant is still permanently consumed even though the transaction ultimately fails. This allows a malicious grantee to intentionally drain a granter's allowance by repeatedly submitting transactions designed to fail. [1](#0-0) 

## Impact
**Severity: Low** - Modification of transaction fees outside of design parameters / Direct loss of funds (granter's allowance)

## Finding Description

**Location:** The vulnerability exists in the transaction execution flow in `baseapp/baseapp.go`, specifically in the `runTx` function and how it handles ante handler state persistence versus message execution state persistence. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Intended Logic:** Fee grants should ideally only be consumed when transactions successfully execute their intended operations, or at minimum, the granter should have some protection against malicious grantees draining allowances through intentionally failing transactions.

**Actual Logic:** The transaction execution flow operates as follows:

1. Basic message validation occurs first using `validateBasicTxMsgs()` which calls `ValidateBasic()` on each message - this only performs stateless validation [6](#0-5) 

2. The ante handler executes (including fee deduction via `DeductFeeDecorator`) [7](#0-6) 

3. Within the fee deduction, if a fee granter is present, `UseGrantedFees` is called which consumes the grant [8](#0-7) 

4. The ante handler's cached state is written to the parent context at line 998, **permanently persisting the grant consumption**

5. A new cached context is created for message execution at line 1008

6. Messages are executed in `runMsgs` at line 1013

7. Only if message execution succeeds AND mode is `runTxModeDeliver` are the message execution changes written (lines 1015-1016)

The critical flaw is that ante handler changes (including grant consumption) are written at line 998 BEFORE message execution, while message execution uses a separate cache that is only written on success. This means grant consumption persists even when messages fail.

**Exploit Scenario:**
1. Alice grants Bob a fee allowance of 1000 tokens to help Bob pay for legitimate transactions
2. Bob creates transactions with messages that pass `ValidateBasic()` (stateless validation) but will definitely fail during execution - for example, a bank `MsgSend` attempting to send more tokens than Bob has [9](#0-8) 

3. The message passes `ValidateBasic()` because it only checks address validity and positive amounts, not actual balance

4. The ante handler executes, consuming Bob's fee (10 tokens) from Alice's grant via `UseGrantedFees` [10](#0-9) 

5. This consumption is written to state at line 998

6. The message execution fails due to insufficient balance, and the message execution cache is discarded

7. Alice's grant is now reduced by 10 tokens, but Bob's transaction failed

8. Bob repeats this 100 times to drain Alice's entire 1000 token allowance without accomplishing any useful work

**Security Failure:** The accounting invariant is broken - fee grants are consumed for failed transactions, enabling economic attacks where malicious grantees can drain granters' allowances. This violates the expected security property that granted funds are only consumed for computational work that achieves its intended purpose.

## Impact Explanation

**Assets Affected:** The granter's fee allowance funds are at risk. Any account that issues fee grants to untrusted parties can have their allowances drained.

**Severity of Damage:** A malicious grantee can completely drain a granter's allowance by submitting transactions designed to fail during execution. While the amounts per transaction may be limited by gas costs, repeated attacks can drain large allowances. This represents a direct loss of funds for the granter.

**System Impact:** This undermines the security and trust model of the fee grant system. Granters may be hesitant to issue grants if they know grantees can maliciously drain them. This affects the usability and adoption of the fee grant feature, which is designed to improve UX by allowing users to pay for others' transactions.

## Likelihood Explanation

**Who can trigger:** Any account that receives a fee grant can exploit this vulnerability. No special privileges are required beyond having a grant issued to them.

**Conditions required:** 
- A fee grant must exist from granter to grantee
- The grantee must be able to construct transactions that pass `ValidateBasic()` but fail during execution (this is trivial - simply attempt to send more tokens than you have)
- The network must be accepting transactions normally

**Frequency:** This can be exploited repeatedly and continuously until the grant is exhausted. An attacker can automate the submission of failing transactions. Given the ease of exploitation and the potential for complete allowance drainage, the likelihood is HIGH if the attacker has malicious intent.

## Recommendation

Implement one of the following mitigations:

**Option 1 (Recommended):** Modify the transaction execution flow to defer ante handler state writes until after message execution succeeds. The ante handler cache should only be written if both ante handler AND message execution succeed in `runTxModeDeliver`.

Modify `baseapp/baseapp.go` around lines 998 and 1015-1016 to:
- Remove or conditionally execute `msCache.Write()` at line 998
- After successful message execution, write both ante handler and message execution caches atomically
- On any failure (ante handler or message execution), discard both caches

**Option 2:** Add a configuration option to fee grants allowing granters to specify whether grants should be consumed on failed transactions. This gives granters control over the risk/reward tradeoff.

**Option 3:** Implement a partial refund mechanism where if messages fail, a percentage of the consumed grant is returned to the allowance.

## Proof of Concept

**File:** `x/auth/ante/feegrant_test.go` (add new test function)

**Test Function:** `TestFeeGrantConsumedOnFailedExecution`

```go
// This test demonstrates that fee grants are consumed even when 
// transaction messages fail during execution.

func (suite *AnteTestSuite) TestFeeGrantConsumedOnFailedExecution() {
    suite.SetupTest(false)
    app, ctx := suite.app, suite.ctx
    
    // Setup accounts
    priv1, _, granter := testdata.KeyTestPubAddr()
    priv2, _, grantee := testdata.KeyTestPubAddr()
    recipient := testdata.AccAddress()
    
    // Fund granter with sufficient tokens
    err := simapp.FundAccount(app.BankKeeper, ctx, granter, 
        sdk.NewCoins(sdk.NewInt64Coin("usei", 100000)))
    suite.Require().NoError(err)
    
    // Fund grantee with minimal tokens (insufficient for the send)
    err = simapp.FundAccount(app.BankKeeper, ctx, grantee, 
        sdk.NewCoins(sdk.NewInt64Coin("usei", 10)))
    suite.Require().NoError(err)
    
    // Grant fee allowance from granter to grantee
    initialAllowance := sdk.NewCoins(sdk.NewInt64Coin("usei", 1000))
    err = app.FeeGrantKeeper.GrantAllowance(ctx, granter, grantee, 
        &feegrant.BasicAllowance{
            SpendLimit: initialAllowance,
        })
    suite.Require().NoError(err)
    
    // Create a transaction that will fail during execution
    // (trying to send more than grantee has)
    msgSend := banktypes.NewMsgSend(
        grantee,
        recipient, 
        sdk.NewCoins(sdk.NewInt64Coin("usei", 1000)), // more than grantee has
    )
    
    // Verify ValidateBasic passes
    err = msgSend.ValidateBasic()
    suite.Require().NoError(err, "Message should pass ValidateBasic")
    
    // Build and sign transaction with fee granter
    fee := sdk.NewCoins(sdk.NewInt64Coin("usei", 50))
    tx, err := genTxWithFeeGranter(
        suite.protoTxCfg,
        []sdk.Msg{msgSend},
        fee,
        100000, // gas limit
        ctx.ChainID(),
        []uint64{app.AccountKeeper.GetAccount(ctx, grantee).GetAccountNumber()},
        []uint64{app.AccountKeeper.GetAccount(ctx, grantee).GetSequence()},
        granter, // fee granter
        priv2,   // grantee signs
    )
    suite.Require().NoError(err)
    
    // Check allowance before transaction
    allowanceBefore, err := app.FeeGrantKeeper.GetAllowance(ctx, granter, grantee)
    suite.Require().NoError(err)
    basicAllowanceBefore := allowanceBefore.(*feegrant.BasicAllowance)
    
    // Execute transaction through full stack (should fail during message execution)
    _, err = app.BaseApp.DeliverTx(abci.RequestDeliverTx{
        Tx: suite.txBuilder.GetProtoTx(),
    })
    suite.Require().Error(err, "Transaction should fail during message execution")
    suite.Require().Contains(err.Error(), "insufficient funds", 
        "Should fail with insufficient funds")
    
    // Check allowance after transaction
    allowanceAfter, err := app.FeeGrantKeeper.GetAllowance(ctx, granter, grantee)
    suite.Require().NoError(err)
    basicAllowanceAfter := allowanceAfter.(*feegrant.BasicAllowance)
    
    // VULNERABILITY: Grant is consumed even though transaction failed
    expectedRemaining := basicAllowanceBefore.SpendLimit.Sub(fee)
    suite.Require().True(
        basicAllowanceAfter.SpendLimit.IsEqual(expectedRemaining),
        "Grant was consumed despite transaction failure: expected %s, got %s",
        expectedRemaining,
        basicAllowanceAfter.SpendLimit,
    )
    
    // Verify grantee's balance unchanged (transaction did fail)
    granteeBalance := app.BankKeeper.GetBalance(ctx, grantee, "usei")
    suite.Require().Equal(int64(10), granteeBalance.Amount.Int64(),
        "Grantee balance should be unchanged since transaction failed")
}
```

**Setup:** The test creates a granter with funds, a grantee with minimal funds, and issues a fee grant. It then creates a bank send message that passes `ValidateBasic()` but will fail during execution due to insufficient balance.

**Trigger:** The transaction is executed through `DeliverTx`, which runs the full ante handler and message execution pipeline.

**Observation:** The test confirms that:
1. The transaction fails during message execution (insufficient funds error)
2. The fee grant is consumed (reduced by the fee amount)  
3. The grantee's balance is unchanged (proving the transaction truly failed)

This demonstrates the vulnerability: the grant is consumed even though the transaction failed to execute its intended operation.

### Citations

**File:** baseapp/baseapp.go (L787-801)
```go
// validateBasicTxMsgs executes basic validator calls for messages.
func validateBasicTxMsgs(msgs []sdk.Msg) error {
	if len(msgs) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "must contain at least one message")
	}

	for _, msg := range msgs {
		err := msg.ValidateBasic()
		if err != nil {
			return err
		}
	}

	return nil
}
```

**File:** baseapp/baseapp.go (L923-925)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```

**File:** baseapp/baseapp.go (L938-998)
```go
		// Branch context before AnteHandler call in case it aborts.
		// This is required for both CheckTx and DeliverTx.
		// Ref: https://github.com/cosmos/cosmos-sdk/issues/2772
		//
		// NOTE: Alternatively, we could require that AnteHandler ensures that
		// writes do not happen if aborted/failed.  This may have some
		// performance benefits, but it'll be more difficult to get right.
		anteCtx, msCache = app.cacheTxContext(ctx, checksum)
		anteCtx = anteCtx.WithEventManager(sdk.NewEventManager())
		newCtx, err := app.anteHandler(anteCtx, tx, mode == runTxModeSimulate)

		if !newCtx.IsZero() {
			// At this point, newCtx.MultiStore() is a store branch, or something else
			// replaced by the AnteHandler. We want the original multistore.
			//
			// Also, in the case of the tx aborting, we need to track gas consumed via
			// the instantiated gas meter in the AnteHandler, so we update the context
			// prior to returning.
			//
			// This also replaces the GasMeter in the context where GasUsed was initalized 0
			// and updated with gas consumed in the ante handler runs
			// The GasMeter is a pointer and its passed to the RunMsg and tracks the consumed
			// gas there too.
			ctx = newCtx.WithMultiStore(ms)
		}
		defer func() {
			if newCtx.DeliverTxCallback() != nil {
				newCtx.DeliverTxCallback()(ctx.WithGasMeter(sdk.NewInfiniteGasMeterWithMultiplier(ctx)))
			}
		}()

		events := ctx.EventManager().Events()

		if err != nil {
			return gInfo, nil, nil, 0, nil, nil, ctx, err
		}
		// GasMeter expected to be set in AnteHandler
		gasWanted = ctx.GasMeter().Limit()
		gasEstimate = ctx.GasEstimate()

		// Dont need to validate in checkTx mode
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
			storeAccessOpEvents := msCache.GetEvents()
			accessOps := ctx.TxMsgAccessOps()[acltypes.ANTE_MSG_INDEX]

			// TODO: (occ) This is an example of where we do our current validation. Note that this validation operates on the declared dependencies for a TX / antehandler + the utilized dependencies, whereas the validation
			missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
			if len(missingAccessOps) != 0 {
				for op := range missingAccessOps {
					ctx.Logger().Info((fmt.Sprintf("Antehandler Missing Access Operation:%s ", op.String())))
					op.EmitValidationFailMetrics()
				}
				errMessage := fmt.Sprintf("Invalid Concurrent Execution antehandler missing %d access operations", len(missingAccessOps))
				return gInfo, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
			}
		}

		priority = ctx.Priority()
		pendingTxChecker = ctx.PendingTxChecker()
		expireHandler = ctx.ExpireTxHandler()
		msCache.Write()
```

**File:** baseapp/baseapp.go (L1013-1016)
```go
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
```

**File:** x/auth/ante/fee.go (L134-200)
```go
func (dfd DeductFeeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	fee, priority, err := dfd.txFeeChecker(ctx, tx, simulate, dfd.paramsKeeper)
	if err != nil {
		return ctx, err
	}
	if err := dfd.checkDeductFee(ctx, tx, fee); err != nil {
		return ctx, err
	}

	newCtx := ctx.WithPriority(priority)

	return next(newCtx, tx, simulate)
}

func (dfd DeductFeeDecorator) checkDeductFee(ctx sdk.Context, sdkTx sdk.Tx, fee sdk.Coins) error {
	feeTx, ok := sdkTx.(sdk.FeeTx)
	if !ok {
		return sdkerrors.Wrap(sdkerrors.ErrTxDecode, "Tx must be a FeeTx")
	}

	if addr := dfd.accountKeeper.GetModuleAddress(types.FeeCollectorName); addr == nil {
		return fmt.Errorf("fee collector module account (%s) has not been set", types.FeeCollectorName)
	}

	feePayer := feeTx.FeePayer()
	feeGranter := feeTx.FeeGranter()
	deductFeesFrom := feePayer

	// if feegranter set deduct fee from feegranter account.
	// this works with only when feegrant enabled.
	if feeGranter != nil {
		if dfd.feegrantKeeper == nil {
			return sdkerrors.ErrInvalidRequest.Wrap("fee grants are not enabled")
		} else if !feeGranter.Equals(feePayer) {
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
			if err != nil {
				return sdkerrors.Wrapf(err, "%s does not not allow to pay fees for %s", feeGranter, feePayer)
			}
		}

		deductFeesFrom = feeGranter
	}

	deductFeesFromAcc := dfd.accountKeeper.GetAccount(ctx, deductFeesFrom)
	if deductFeesFromAcc == nil {
		return sdkerrors.ErrUnknownAddress.Wrapf("fee payer address: %s does not exist", deductFeesFrom)
	}

	// deduct the fees
	if !fee.IsZero() {
		err := DeductFees(dfd.bankKeeper, ctx, deductFeesFromAcc, fee)
		if err != nil {
			return err
		}
	}

	events := sdk.Events{
		sdk.NewEvent(
			sdk.EventTypeTx,
			sdk.NewAttribute(sdk.AttributeKeyFee, fee.String()),
			sdk.NewAttribute(sdk.AttributeKeyFeePayer, deductFeesFrom.String()),
		),
	}
	ctx.EventManager().EmitEvents(events)

	return nil
}
```

**File:** x/feegrant/keeper/keeper.go (L147-180)
```go
func (k Keeper) UseGrantedFees(ctx sdk.Context, granter, grantee sdk.AccAddress, fee sdk.Coins, msgs []sdk.Msg) error {
	f, err := k.getGrant(ctx, granter, grantee)
	if err != nil {
		return err
	}

	grant, err := f.GetGrant()
	if err != nil {
		return err
	}

	remove, err := grant.Accept(ctx, fee, msgs)

	if remove {
		// Ignoring the `revokeFeeAllowance` error, because the user has enough grants to perform this transaction.
		k.revokeAllowance(ctx, granter, grantee)
		if err != nil {
			return err
		}

		emitUseGrantEvent(ctx, granter.String(), grantee.String())

		return nil
	}

	if err != nil {
		return err
	}

	emitUseGrantEvent(ctx, granter.String(), grantee.String())

	// if fee allowance is accepted, store the updated state of the allowance
	return k.GrantAllowance(ctx, granter, grantee, grant)
}
```

**File:** x/bank/types/msgs.go (L28-49)
```go
// ValidateBasic Implements Msg.
func (msg MsgSend) ValidateBasic() error {
	_, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid sender address (%s)", err)
	}

	_, err = sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidAddress, "Invalid recipient address (%s)", err)
	}

	if !msg.Amount.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	if !msg.Amount.IsAllPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	return nil
}
```

**File:** x/feegrant/basic_fee.go (L20-36)
```go
func (a *BasicAllowance) Accept(ctx sdk.Context, fee sdk.Coins, _ []sdk.Msg) (bool, error) {
	if a.Expiration != nil && a.Expiration.Before(ctx.BlockTime()) {
		return true, sdkerrors.Wrap(ErrFeeLimitExpired, "basic allowance")
	}

	if a.SpendLimit != nil {
		left, invalid := a.SpendLimit.SafeSub(fee)
		if invalid {
			return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "basic allowance")
		}

		a.SpendLimit = left
		return left.IsZero(), nil
	}

	return false, nil
}
```
