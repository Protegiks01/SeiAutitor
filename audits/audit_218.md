## Audit Report

## Title
Fee Grant State Persists After Transaction Rollback Due to Premature Ante Handler Cache Write

## Summary
A critical atomicity violation exists in the transaction execution flow where fee grant modifications made during ante handler execution persist even when the transaction fails during message execution. This occurs because the ante handler cache is written unconditionally before message execution, while the message cache is only written on success.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Primary: `baseapp/baseapp.go`, function `runTx`, lines 945-1017
- Secondary: `x/feegrant/keeper/keeper.go`, function `UseGrantedFees`, lines 147-180
- Secondary: `x/auth/ante/fee.go`, function `checkDeductFee`, line 168 [1](#0-0) 

**Intended Logic:** 
Transactions should be atomic - either all state changes (including fee grant consumption) are committed, or none are. If a transaction fails at any point, all state modifications should be rolled back.

**Actual Logic:** 
The `runTx` function executes transactions in two phases with separate cache contexts:

1. **Ante Handler Phase** (lines 945-998): Creates a cache context, executes ante handlers (which consume fee grants), then **unconditionally writes** the cache at line 998 [2](#0-1) 

2. **Message Execution Phase** (lines 1008-1017): Creates a **new** cache context, executes messages, then **conditionally writes** the cache only if there's no error AND mode is DeliverTx [3](#0-2) 

When a transaction has a fee granter, `DeductFeeDecorator` calls `UseGrantedFees` during ante handling: [4](#0-3) 

This modifies the grant state by calling `Accept()` on the allowance and then persisting it: [5](#0-4) 

The `Accept` methods modify internal state (spend limits, period resets): [6](#0-5) [7](#0-6) 

**Exploit Scenario:**
1. Attacker has a fee grant from a granter with a spend limit (e.g., 1000 tokens)
2. Attacker crafts a transaction that will pass ante handler validation but fail during message execution (e.g., a message that triggers an error in its handler)
3. Transaction passes ante handler → fee grant is consumed and updated in storage via line 998 write
4. Message execution fails → message cache is NOT written (line 1016 skipped)
5. **Result:** Fee grant consumption persists despite transaction failure

**Security Failure:** 
Atomicity violation - partial state updates persist after transaction rollback, allowing attackers to drain fee grants without executing any operations.

## Impact Explanation

**Assets Affected:** Fee grant allowances, which represent delegated spending authority for transaction fees.

**Severity:** 
- Users who grant fee allowances lose funds without receiving the intended service
- Attackers can systematically drain all available fee grants by repeatedly submitting failing transactions
- Each failing transaction consumes the fee from the grant but performs no useful work
- The granter's funds are depleted without the grantee's transactions being executed

**System Impact:**
This violates a fundamental blockchain invariant: transaction atomicity. Users cannot trust that failed transactions will be fully reverted, undermining the reliability of the fee grant mechanism and potentially the broader transaction system.

## Likelihood Explanation

**Who can trigger:** Any user with access to a fee grant can exploit this vulnerability.

**Conditions required:** 
- A fee grant must exist between a granter and grantee
- Attacker must craft a transaction that passes ante handler but fails in message execution
- This is trivial to achieve (e.g., sending a message with invalid parameters, calling a non-existent contract, etc.)

**Frequency:** 
Can be exploited repeatedly in every block until the fee grant is fully consumed. An attacker could drain a large fee grant in minutes by submitting multiple failing transactions per block.

**Likelihood:** **Very High** - This is easily exploitable during normal network operation with no special conditions or timing requirements.

## Recommendation

Modify the transaction execution flow in `baseapp/baseapp.go` to ensure atomicity:

**Option 1 (Preferred):** Do not write the ante handler cache until after successful message execution. Accumulate both ante handler and message execution changes in nested caches, then write both atomically only on complete success.

**Option 2:** Move fee grant consumption to after message execution succeeds, but this changes the semantic of when fees are charged.

**Suggested Implementation for Option 1:**
```go
// In runTx function around lines 998-1017:
// Do NOT write msCache here - only after message execution succeeds
// Remove or comment out line 998: msCache.Write()

// After message execution, write both caches only on success:
if err == nil && mode == runTxModeDeliver {
    // Write message cache first
    msCache.Write()
}
// Note: The ante handler changes are in the parent context already due to line 961
// The issue is that msCache from ante handler is written before checking message success
```

The fundamental fix requires restructuring the cache hierarchy so both ante handler and message execution changes are committed atomically.

## Proof of Concept

**Test File:** `baseapp/feegrant_rollback_test.go` (new file)

**Test Setup:**
1. Create a SimApp instance with feegrant module enabled
2. Set up two accounts: granter (with funds) and grantee (fee payer)
3. Create a fee grant from granter to grantee with a specific spend limit (e.g., 1000 tokens)
4. Create a transaction that:
   - Uses the fee grant (passes ante handler)
   - Contains a message that will fail execution (e.g., invalid message parameters)

**Test Trigger:**
1. Record the initial fee grant state (spend limit remaining)
2. Submit the crafted transaction via `app.DeliverTx()`
3. Verify the transaction returns an error

**Test Observation:**
The test should verify that:
- Transaction execution returns an error (expected)
- Fee grant spend limit is REDUCED despite transaction failure (demonstrates the bug)
- Expected behavior: Fee grant should be UNCHANGED after failed transaction

**PoC Code Structure:**
```go
// File: baseapp/feegrant_rollback_test.go
func TestFeeGrantRollbackVulnerability(t *testing.T) {
    // 1. Setup app and accounts
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // 2. Create granter with funds
    granterAddr := /* create account */
    granteeAddr := /* create account */
    // Fund granter account
    
    // 3. Create fee grant with spend limit
    initialLimit := sdk.NewCoins(sdk.NewInt64Coin("usei", 1000))
    grant := &feegrant.BasicAllowance{SpendLimit: initialLimit}
    app.FeeGrantKeeper.GrantAllowance(ctx, granterAddr, granteeAddr, grant)
    
    // 4. Record initial state
    initialGrant, _ := app.FeeGrantKeeper.GetAllowance(ctx, granterAddr, granteeAddr)
    initialSpendLimit := initialGrant.(*feegrant.BasicAllowance).SpendLimit
    
    // 5. Create transaction with fee grant that will fail in message execution
    fee := sdk.NewCoins(sdk.NewInt64Coin("usei", 100))
    msg := /* create message that will fail - e.g., invalid bank send */
    tx := /* create tx with fee granter set to granterAddr */
    
    // 6. Deliver transaction - it should fail
    _, err := app.DeliverTx(/* encode tx */)
    require.Error(t, err) // Transaction should fail
    
    // 7. Check grant state - THIS REVEALS THE BUG
    finalGrant, _ := app.FeeGrantKeeper.GetAllowance(ctx, granterAddr, granteeAddr)
    finalSpendLimit := finalGrant.(*feegrant.BasicAllowance).SpendLimit
    
    // BUG: Spend limit is reduced even though transaction failed
    require.True(t, finalSpendLimit.IsLT(initialSpendLimit), 
        "BUG CONFIRMED: Fee grant consumed despite transaction failure")
    
    // Expected: Spend limit should be unchanged
    // require.Equal(t, initialSpendLimit, finalSpendLimit)
}
```

This test demonstrates that fee grants are consumed even when transactions fail, violating atomicity and allowing fund drainage.

### Citations

**File:** baseapp/baseapp.go (L945-1017)
```go
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
		anteEvents = events.ToABCIEvents()
		if app.TracingEnabled {
			anteSpan.End()
		}
	}

	// Create a new Context based off of the existing Context with a MultiStore branch
	// in case message processing fails. At this point, the MultiStore
	// is a branch of a branch.
	runMsgCtx, msCache := app.cacheTxContext(ctx, checksum)

	// Attempt to execute all messages and only update state if all messages pass
	// and we're in DeliverTx. Note, runMsgs will never return a reference to a
	// Result if any single message fails or does not have a registered Handler.
	result, err = app.runMsgs(runMsgCtx, msgs, mode)

	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
	}
```

**File:** x/auth/ante/fee.go (L168-168)
```go
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
```

**File:** x/feegrant/keeper/keeper.go (L158-179)
```go
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
```

**File:** x/feegrant/basic_fee.go (L31-31)
```go
		a.SpendLimit = left
```

**File:** x/feegrant/periodic_fee.go (L33-39)
```go
	a.PeriodCanSpend, isNeg = a.PeriodCanSpend.SafeSub(fee)
	if isNeg {
		return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "period limit")
	}

	if a.Basic.SpendLimit != nil {
		a.Basic.SpendLimit, isNeg = a.Basic.SpendLimit.SafeSub(fee)
```
