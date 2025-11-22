# Audit Report

## Title
Unlimited BasicAllowance Enables Complete Balance Drain Through Excessive Transaction Fees

## Summary
The BasicAllowance implementation in the feegrant module allows grantees to drain a granter's entire balance when SpendLimit is nil (unlimited). When an unlimited allowance is granted, the `Accept()` function performs no validation on fee amounts, and the transaction validation system only checks minimum gas prices without any maximum fee limit, enabling a malicious grantee to submit a transaction with arbitrarily high fees that completely drain the granter's account.

## Impact
High - Direct loss of funds

## Finding Description

**Location:** 
- Primary: `x/feegrant/basic_fee.go` lines 25-35 (Accept function) [1](#0-0) 

- Secondary: `x/auth/ante/fee.go` lines 148-200 (fee deduction logic) [2](#0-1) 

- Validation: `x/auth/ante/validator_tx_fee.go` lines 29-45 (minimum-only fee check) [3](#0-2) 

**Intended Logic:** 
The BasicAllowance with unlimited SpendLimit (nil) is designed to allow a grantee to pay transaction fees from the granter's account without a spending cap, as documented in ADR-029. [4](#0-3) 

The system should enable legitimate use cases where fee payment delegation is needed for many transactions over time.

**Actual Logic:** 
When `SpendLimit == nil`, the Accept() function immediately returns `(false, nil)` without any validation of the fee amount. The transaction validation system only enforces minimum gas prices through `CheckTxFeeWithValidatorMinGasPrices`, with no maximum fee check. This allows a grantee to specify arbitrarily large fee amounts in a transaction, which are then deducted from the granter's account via `DeductFees`. [5](#0-4) 

**Exploit Scenario:**
1. Granter creates an unlimited BasicAllowance for Grantee (SpendLimit = nil) [6](#0-5) 

2. Malicious Grantee constructs a transaction with:
   - Reasonable gas limit (e.g., 200,000)
   - Excessive fee amount (e.g., equal to Granter's entire balance: 1,000,000 tokens)
   
3. Transaction passes mempool validation (fee exceeds minimum gas price requirement)

4. In ante handler, `UseGrantedFees` is called, which invokes `Accept()` on the BasicAllowance [7](#0-6) 

5. Accept() returns `(false, nil)` without checking fee amount

6. Ante handler proceeds to deduct the full 1,000,000 tokens from Granter's account [8](#0-7) 

7. Granter's balance is completely drained in a single transaction

**Security Failure:** 
Authorization boundary violation and fund protection failure. While the granter authorized fee delegation, the system provides no safeguard against extreme abuse. The lack of any maximum fee validation or reasonableness check allows complete balance drainage, violating the reasonable expectation that "unlimited" means "for many reasonable transactions" rather than "drain everything in one transaction."

## Impact Explanation

**Assets Affected:** All tokens in the granter's account balance

**Severity of Damage:** 
- Complete loss of funds for the granter
- A single malicious transaction can drain the entire account
- No recovery mechanism exists once funds are sent to the fee collector module

**Why This Matters:**
- **Direct financial loss:** Granters who create unlimited allowances (e.g., organizations covering employee transaction fees, protocols subsidizing user transactions) can have their entire treasury drained
- **Violation of trust model:** Even if technically "unlimited," users reasonably expect some protection against single-transaction complete drainage
- **No safeguards:** Unlike traditional payment systems with fraud detection or spending alerts, there's zero protection
- **Irreversible:** Once fees are deducted and sent to the fee collector module, they cannot be recovered without governance intervention

## Likelihood Explanation

**Who Can Trigger:** Any grantee who has received an unlimited BasicAllowance from a granter

**Conditions Required:**
- Granter must create a BasicAllowance with `SpendLimit = nil`
- Granter must have sufficient balance to cover the excessive fee
- No other conditions or timing requirements needed

**Likelihood Assessment:**
- **Medium to High likelihood**: Unlimited allowances are a documented feature and may be commonly used in scenarios like:
  - Organizations providing unlimited fee coverage for employees
  - Protocols subsidizing user transactions without wanting to manage limits
  - Development/testing environments where limits seem unnecessary
  
- **Trivial to exploit**: Once an unlimited allowance exists, exploitation requires only submitting a single transaction with an excessive fee

- **Frequency**: Can be exploited immediately upon grant creation and repeated if the granter's balance is replenished

## Recommendation

Implement a maximum fee reasonableness check even for unlimited allowances:

1. **Add a configurable maximum fee multiplier**: Even with unlimited SpendLimit, validate that the fee doesn't exceed a reasonable multiple (e.g., 100x) of the minimum required fee based on gas limit and minimum gas price.

2. **Implement in Accept() function**: Modify `BasicAllowance.Accept()` to include:
   ```go
   // Even for unlimited allowances, check fee reasonableness
   if a.SpendLimit == nil {
       // Calculate reasonable maximum based on gas and minimum gas price
       maxReasonableFee := calculateMaxReasonableFee(ctx, fee, msgs)
       if fee.IsAnyGT(maxReasonableFee) {
           return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "fee exceeds reasonable limit")
       }
   }
   ```

3. **Add governance parameter**: Allow the network to configure the maximum fee multiplier via governance, providing flexibility while maintaining safety.

4. **Document clearly**: Update documentation to explicitly warn that unlimited allowances still have reasonableness checks to prevent abuse.

Alternative mitigation: Require explicit acknowledgment when creating unlimited allowances (e.g., a separate message type `MsgGrantUnlimitedAllowance` with clear warnings).

## Proof of Concept

**File:** `x/auth/ante/feegrant_test.go`

**Test Function:** Add the following test function to the existing test file:

```go
func (suite *AnteTestSuite) TestUnlimitedAllowanceDrainsBalance() {
    suite.SetupTest(false)
    app, ctx := suite.app, suite.ctx

    protoTxCfg := tx.NewTxConfig(codec.NewProtoCodec(app.InterfaceRegistry()), tx.DefaultSignModes)
    dfd := ante.NewDeductFeeDecorator(app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, suite.app.ParamsKeeper, nil)
    feeAnteHandler, _ := sdk.ChainAnteDecorators(sdk.DefaultWrappedAnteDecorator(dfd))

    // Setup: Create granter and grantee accounts
    priv1, _, addr1 := testdata.KeyTestPubAddr() // granter
    priv2, _, addr2 := testdata.KeyTestPubAddr() // malicious grantee

    // Fund granter with 100,000 tokens
    granterInitialBalance := sdk.NewInt(100000)
    err := simapp.FundAccount(suite.app.BankKeeper, suite.ctx, addr1, 
        []sdk.Coin{sdk.NewCoin("usei", granterInitialBalance)})
    suite.Require().NoError(err)

    // Verify initial balance
    granterBalance := app.BankKeeper.GetBalance(ctx, addr1, "usei")
    suite.Require().Equal(granterInitialBalance, granterBalance.Amount)

    // Grant UNLIMITED allowance (SpendLimit = nil)
    err = app.FeeGrantKeeper.GrantAllowance(ctx, addr1, addr2, &feegrant.BasicAllowance{
        SpendLimit: nil, // UNLIMITED
    })
    suite.Require().NoError(err)

    // Trigger: Malicious grantee submits transaction with excessive fee
    // Fee is set to 99,000 tokens (99% of granter's balance)
    excessiveFee := sdk.NewCoins(sdk.NewInt64Coin("usei", 99000))
    msgs := []sdk.Msg{testdata.NewTestMsg(addr2)}
    
    acc := app.AccountKeeper.GetAccount(ctx, addr2)
    privs, accNums, seqs := []cryptotypes.PrivKey{priv2}, []uint64{0}, []uint64{0}
    if acc != nil {
        accNums, seqs = []uint64{acc.GetAccountNumber()}, []uint64{acc.GetSequence()}
    }

    // Create transaction with excessive fee and granter as fee payer
    tx, err := genTxWithFeeGranter(protoTxCfg, msgs, excessiveFee, 
        helpers.DefaultGenTxGas, ctx.ChainID(), accNums, seqs, addr1, privs...)
    suite.Require().NoError(err)

    // Execute transaction
    _, err = feeAnteHandler(ctx, tx, false)
    suite.Require().NoError(err) // Transaction succeeds!

    // Observation: Verify granter's balance is drained
    granterBalanceAfter := app.BankKeeper.GetBalance(ctx, addr1, "usei")
    expectedRemaining := granterInitialBalance.Sub(sdk.NewInt(99000))
    suite.Require().Equal(expectedRemaining, granterBalanceAfter.Amount)
    
    // This demonstrates the vulnerability: A single transaction with excessive fee
    // drained 99% of the granter's balance with no safeguards or checks
    suite.T().Logf("Granter balance drained from %s to %s in a single transaction", 
        granterInitialBalance, granterBalanceAfter.Amount)
}
```

**Setup:** 
- Create granter account with 100,000 tokens
- Create grantee account (malicious actor)
- Grant unlimited BasicAllowance (SpendLimit = nil) from granter to grantee

**Trigger:** 
- Grantee submits a transaction with an excessive fee of 99,000 tokens (99% of granter's balance)
- Transaction specifies granter as fee payer via fee grant

**Observation:** 
- Transaction succeeds without any error
- Granter's balance is reduced by 99,000 tokens
- This confirms that unlimited allowances can be exploited to drain nearly the entire balance in a single transaction
- The test demonstrates the lack of any maximum fee validation or reasonableness check

This PoC can be added to the existing test suite and will demonstrate the vulnerability by showing that a malicious grantee can drain a granter's balance through excessive fees when an unlimited allowance is granted.

### Citations

**File:** x/feegrant/basic_fee.go (L25-35)
```go
	if a.SpendLimit != nil {
		left, invalid := a.SpendLimit.SafeSub(fee)
		if invalid {
			return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "basic allowance")
		}

		a.SpendLimit = left
		return left.IsZero(), nil
	}

	return false, nil
```

**File:** x/auth/ante/fee.go (L148-200)
```go
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

**File:** x/auth/ante/validator_tx_fee.go (L29-45)
```go
	if ctx.IsCheckTx() && !simulate {
		minGasPrices := GetMinimumGasPricesWantedSorted(feeParams.GetGlobalMinimumGasPrices(), ctx.MinGasPrices())
		if !minGasPrices.IsZero() {
			requiredFees := make(sdk.Coins, len(minGasPrices))

			// Determine the required fees by multiplying each required minimum gas
			// price by the gas limit, where fee = ceil(minGasPrice * gasLimit).
			glDec := sdk.NewDec(int64(gas))
			for i, gp := range minGasPrices {
				fee := gp.Amount.Mul(glDec)
				requiredFees[i] = sdk.NewCoin(gp.Denom, fee.Ceil().RoundInt())
			}

			if !feeCoins.IsAnyGTE(requiredFees) {
				return nil, 0, sdkerrors.Wrapf(sdkerrors.ErrInsufficientFee, "insufficient fees; got: %s required: %s", feeCoins, requiredFees)
			}
		}
```

**File:** docs/architecture/adr-029-fee-grant-module.md (L66-68)
```markdown
  // spend_limit specifies the maximum amount of tokens that can be spent
  // by this allowance and will be updated as tokens are spent. If it is
  // empty, there is no spend limit and any amount of coins can be spent.
```

**File:** x/feegrant/keeper/msg_server.go (L26-56)
```go
// GrantAllowance grants an allowance from the granter's funds to be used by the grantee.
func (k msgServer) GrantAllowance(goCtx context.Context, msg *feegrant.MsgGrantAllowance) (*feegrant.MsgGrantAllowanceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	// Checking for duplicate entry
	if f, _ := k.Keeper.GetAllowance(ctx, granter, grantee); f != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "fee allowance already exists")
	}

	allowance, err := msg.GetFeeAllowanceI()
	if err != nil {
		return nil, err
	}

	err = k.Keeper.GrantAllowance(ctx, granter, grantee, allowance)
	if err != nil {
		return nil, err
	}

	return &feegrant.MsgGrantAllowanceResponse{}, nil
}
```

**File:** x/feegrant/keeper/keeper.go (L146-180)
```go
// UseGrantedFees will try to pay the given fee from the granter's account as requested by the grantee
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
