# Audit Report

## Title
Zero-Fee Transactions with Fee Granter Trigger Unnecessary State Updates and Enable Resource Exhaustion

## Summary
The ante handler's `DeductFeeDecorator` improperly handles zero-fee transactions when a fee granter is set. It invokes the fee grant validation and state update logic (`UseGrantedFees`) even when no fees are being charged, causing unnecessary storage operations, event emissions, and allowance state modifications. This enables unprivileged attackers to consume validator resources without paying transaction fees.

## Impact
**Medium**

## Finding Description

**Location:** 
- `x/auth/ante/fee.go`, function `checkDeductFee`, lines 164-188
- `x/feegrant/keeper/keeper.go`, function `UseGrantedFees`, lines 147-180

**Intended Logic:**
The ante handler should validate fee grants and deduct fees from the granter's account when a transaction specifies a fee granter. Zero-fee transactions should either be rejected when a fee granter is set, or should skip the fee grant logic entirely since no fees need to be paid.

**Actual Logic:**
When a transaction has `fee = 0` and a `feeGranter` is set:
1. [1](#0-0) 
   The code calls `UseGrantedFees` whenever the fee granter differs from the fee payer, **regardless of whether the fee is zero**.

2. [2](#0-1) 
   `UseGrantedFees` calls the allowance's `Accept` method, emits events, and saves the updated allowance state back to storage.

3. [3](#0-2) 
   The actual fee deduction only occurs if `!fee.IsZero()`, meaning zero-fee transactions skip the deduction step.

This creates a logical inconsistency: the fee grant validation and state update logic executes even though no fees are actually being charged or deducted.

**Exploit Scenario:**
1. Attacker obtains a fee grant from a victim (either through social engineering or by receiving a legitimate grant)
2. Attacker crafts transactions with `fee = 0` and `feeGranter` set to the victim's address
3. If the network allows zero-fee transactions (minimum gas price = 0) or a validator includes these transactions directly in blocks during DeliverTx (where minimum fee checks don't apply per [4](#0-3) ), the transactions are accepted
4. Each zero-fee transaction triggers:
   - Storage read of the fee grant allowance
   - Execution of the allowance's `Accept` method (which may update state, especially for `PeriodicAllowance` via [5](#0-4) )
   - Storage write of the allowance back to state
   - Event emission via [6](#0-5) 
5. No fees are deducted from either the fee payer or granter
6. Attacker can spam these transactions to consume validator resources (storage I/O, event processing) without paying any transaction fees

**Security Failure:**
This violates the fee mechanism's resource protection invariant. Transaction fees exist to prevent spam and ensure resource consumers pay for network usage. By allowing zero-fee transactions with a fee granter to trigger expensive state operations without charging fees, the system enables resource exhaustion attacks that bypass the fee mechanism entirely.

## Impact Explanation

**Affected Resources:**
- Validator storage I/O (reading and writing fee grant allowances)
- Event emission system (events are emitted for each zero-fee transaction)
- Network bandwidth (spam transactions can fill blocks)
- Fee grant state (allowances are modified without fees being charged)

**Severity:**
An attacker with a fee grant can:
1. Spam zero-fee transactions to increase validator resource consumption (storage operations, event processing) by triggering fee grant state updates without paying
2. For `PeriodicAllowance`, manipulate period reset timing by spamming zero-fee transactions when periods expire
3. Cause state bloat through unnecessary allowance updates
4. Bypass the fee mechanism's spam protection

This qualifies as **Medium** severity under the impact criteria:
- "Increasing network processing node resource consumption by at least 30% without brute force actions" - achievable through sustained spam of zero-fee transactions with fee granter set
- "Modification of transaction fees outside of design parameters" - fee grant allowances are modified without any fees being charged

## Likelihood Explanation

**Trigger Conditions:**
- Any user with a fee grant can exploit this
- Requires network to accept zero-fee transactions (minimum gas price = 0) OR validator to include transactions directly in blocks during DeliverTx phase
- No special privileges required beyond having a fee grant

**Frequency:**
- While many production networks set minimum gas prices > 0 (preventing entry via CheckTx/mempool), validators can always include zero-fee transactions during DeliverTx since [7](#0-6)  shows minimum fee validation only occurs during CheckTx
- Testnets and development networks often run with zero minimum gas prices, making them immediately vulnerable
- A malicious or compromised validator can include these transactions in any network

**Likelihood:** Medium to High in networks that allow zero-fee transactions; Medium in networks with minimum gas prices due to validator-level inclusion possibility.

## Recommendation

Add a check to reject zero-fee transactions when a fee granter is set, OR skip the `UseGrantedFees` call entirely when `fee.IsZero()`. The logic should be reordered:

```
In checkDeductFee function (x/auth/ante/fee.go):

if !fee.IsZero() {
    // Only process fee grant logic if fees are actually being charged
    if feeGranter != nil && dfd.feegrantKeeper != nil && !feeGranter.Equals(feePayer) {
        err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
        if err != nil {
            return sdkerrors.Wrapf(err, "%s does not allow to pay fees for %s", feeGranter, feePayer)
        }
        deductFeesFrom = feeGranter
    }
    
    deductFeesFromAcc := dfd.accountKeeper.GetAccount(ctx, deductFeesFrom)
    if deductFeesFromAcc == nil {
        return sdkerrors.ErrUnknownAddress.Wrapf("fee payer address: %s does not exist", deductFeesFrom)
    }
    
    err := DeductFees(dfd.bankKeeper, ctx, deductFeesFromAcc, fee)
    if err != nil {
        return err
    }
} else if feeGranter != nil && !feeGranter.Equals(feePayer) {
    // Reject zero-fee transactions with fee granter set
    return sdkerrors.ErrInvalidRequest.Wrap("zero fee transactions cannot use fee granter")
}
```

This ensures fee grant logic only executes when fees are actually being charged, preventing the resource exhaustion vulnerability.

## Proof of Concept

**File:** `x/auth/ante/feegrant_test.go`

**Test Function:** Add new test case `TestZeroFeeWithFeeGranter` to the existing test suite

**Setup:**
1. Initialize test context with `SetupTest(false)`
2. Create two accounts: `addr1` (grantee) and `addr2` (granter)
3. Fund `addr2` with sufficient balance (e.g., 99999 tokens)
4. Create a `BasicAllowance` fee grant from `addr2` to `addr1` with SpendLimit of 500 tokens
5. Set global and validator minimum gas prices to zero to allow zero-fee transactions

**Trigger:**
1. Create a transaction from `addr1` with:
   - `fee = 0` (zero coins)
   - `feeGranter = addr2`
   - A simple test message
2. Execute the transaction through the ante handler chain

**Observation:**
1. The transaction should succeed (no error returned)
2. Check that `UseGrantedFees` was called by observing the `EventTypeUseFeeGrant` event was emitted
3. Verify the fee grant allowance was read from and written back to storage (check storage access operations)
4. Confirm that `addr2`'s balance was NOT reduced (no fees actually deducted)
5. Confirm that the fee grant's SpendLimit was NOT reduced (should still be 500 tokens)

This demonstrates that zero-fee transactions with a fee granter trigger the entire fee grant validation and state update logic without actually charging any fees, enabling the resource exhaustion vulnerability.

**Expected Behavior:** The test should demonstrate that the transaction succeeds and triggers state updates without fee deduction, confirming the vulnerability. The test passing (showing this behavior) proves the vulnerability exists.

### Citations

**File:** x/auth/ante/fee.go (L167-172)
```go
		} else if !feeGranter.Equals(feePayer) {
			err := dfd.feegrantKeeper.UseGrantedFees(ctx, feeGranter, feePayer, fee, sdkTx.GetMsgs())
			if err != nil {
				return sdkerrors.Wrapf(err, "%s does not not allow to pay fees for %s", feeGranter, feePayer)
			}
		}
```

**File:** x/auth/ante/fee.go (L183-188)
```go
	if !fee.IsZero() {
		err := DeductFees(dfd.bankKeeper, ctx, deductFeesFromAcc, fee)
		if err != nil {
			return err
		}
	}
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

**File:** x/auth/ante/validator_tx_fee.go (L29-46)
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
	}
```

**File:** x/feegrant/periodic_fee.go (L29-29)
```go
	a.tryResetPeriod(blockTime)
```
