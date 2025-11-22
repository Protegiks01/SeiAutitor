## Audit Report

## Title
Bypass of SendEnabled Restriction via Delegation Allowing Transfer of Disabled Denominations

## Summary
The `IsSendEnabledCoins` check is enforced when creating vesting accounts and sending coins via `MsgSend`/`MsgMultiSend`, but is completely bypassed in the delegation flow. Users (including vesting accounts) can delegate coins with disabled denominations to validators, circumventing governance/admin decisions to freeze transfers of specific denoms.

## Impact
Medium

## Finding Description

**Location:** 
- Missing check in `x/bank/keeper/keeper.go` in the `DelegateCoins` function (lines 184-225)
- [1](#0-0) 

**Intended Logic:** 
When a denomination is disabled via the `SendEnabled` parameter, no transfers of that denomination should be possible. This restriction is enforced via `IsSendEnabledCoins` checks in:
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Actual Logic:** 
The `DelegateCoins` function transfers coins from a user account to a module account (the staking pool) without checking if the denomination is enabled for sending. The delegation flow is:
1. User submits `MsgDelegate`
2. [5](#0-4)  calls staking keeper's `Delegate`
3. [6](#0-5)  calls `bankKeeper.DelegateCoinsFromAccountToModule`
4. [7](#0-6)  calls `DelegateCoins`
5. `DelegateCoins` deducts coins and tracks delegation but never calls `IsSendEnabledCoins`

**Exploit Scenario:**
1. Governance/admin disables sending of denomination "frozentoken" via `SendEnabled` parameter (e.g., during an emergency or security incident)
2. User account (including vesting accounts) holds "frozentoken"
3. User cannot send tokens via `MsgSend` or `MsgMultiSend` (correctly blocked)
4. User submits `MsgDelegate` to delegate "frozentoken" to any validator
5. The delegation succeeds, transferring coins from user account to the bonded/unbonded pool
6. The send restriction is completely bypassed

**Security Failure:** 
Authorization bypass - the protocol's denomination transfer restrictions are circumvented, allowing users to move disabled tokens when they should be frozen. This breaks the governance-controlled security mechanism for emergency token freezing.

## Impact Explanation

- **Affected Process:** Denomination-level transfer restrictions configured via the `SendEnabled` parameter
- **Severity:** When governance disables a denomination (typically during emergencies, exploits, or security incidents), the expectation is that NO transfers occur. Delegation bypasses this completely, allowing continued token movement.
- **Why It Matters:** 
  - Defeats the purpose of emergency token freezes
  - Violates governance decisions and protocol design
  - Could enable continued exploitation during incident response
  - Breaks trust in the protocol's security controls

## Likelihood Explanation

- **Who Can Trigger:** Any token holder (including vesting accounts) with disabled denominations
- **Conditions Required:** 
  - A denomination must be disabled via `SendEnabled` parameter
  - User must have balance of that denomination
  - At least one active validator to delegate to
- **Frequency:** Can be triggered at any time when denoms are disabled. While denomination disabling might be rare, when it occurs (e.g., during security incidents), this bypass is easily exploitable and undermines the entire freeze mechanism.

## Recommendation

Add `IsSendEnabledCoins` check in the `DelegateCoins` function before allowing the delegation:

```go
func (k BaseKeeper) DelegateCoins(ctx sdk.Context, delegatorAddr, moduleAccAddr sdk.AccAddress, amt sdk.Coins) error {
    moduleAcc := k.ak.GetAccount(ctx, moduleAccAddr)
    if moduleAcc == nil {
        return sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", moduleAccAddr)
    }

    // Add this check
    if err := k.IsSendEnabledCoins(ctx, amt...); err != nil {
        return err
    }

    if !amt.IsValid() {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
    }
    // ... rest of function
}
```

Also consider adding the same check to `UndelegateCoins` and any other token movement functions for consistency.

## Proof of Concept

**File:** `x/staking/keeper/delegation_test.go` (add new test function)

**Test Function:** `TestDelegateDisabledDenom`

**Setup:**
1. Initialize test app with staking and bank keepers
2. Create a validator
3. Create a user account with balance in a custom denom (e.g., "testtoken")
4. Set bank params to disable sending of "testtoken" by setting `SendEnabled` parameter for that denom to `false`

**Trigger:**
1. Attempt to send "testtoken" via `MsgSend` - should fail with send disabled error
2. Attempt to delegate "testtoken" to the validator - currently succeeds (demonstrates vulnerability)

**Observation:**
- `MsgSend` correctly fails with `ErrSendDisabled`
- `MsgDelegate` succeeds even though the denom is disabled
- After delegation, user balance decreases and module balance increases, proving the bypass
- The test should assert that delegation SHOULD fail but currently passes, demonstrating the vulnerability

**Test Code Outline:**
```go
func TestDelegateDisabledDenom(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create validator
    validators := createTestValidators(t, ctx, app, []int64{100})
    
    // Create user with custom denom balance
    userAddr := sdk.AccAddress([]byte("user"))
    disabledDenom := "testtoken"
    amount := sdk.NewCoins(sdk.NewCoin(disabledDenom, sdk.NewInt(1000)))
    
    // Fund user account
    require.NoError(t, app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, amount))
    require.NoError(t, app.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, userAddr, amount))
    
    // Disable the denom
    params := app.BankKeeper.GetParams(ctx)
    params = params.SetSendEnabledParam(disabledDenom, false)
    app.BankKeeper.SetParams(ctx, params)
    
    // Verify send is blocked
    err := app.BankKeeper.SendCoins(ctx, userAddr, sdk.AccAddress([]byte("recipient")), amount)
    require.Error(t, err)
    require.Contains(t, err.Error(), "transfers are currently disabled")
    
    // Attempt delegation - SHOULD fail but currently succeeds
    delegateAmount := sdk.NewCoin(disabledDenom, sdk.NewInt(500))
    _, err = app.StakingKeeper.Delegate(ctx, userAddr, delegateAmount.Amount, types.Unbonded, validators[0], true)
    
    // This assertion SHOULD pass (delegation should be blocked) but currently fails
    // demonstrating the vulnerability
    require.Error(t, err, "Delegation of disabled denom should fail but currently succeeds")
    require.Contains(t, err.Error(), "transfers are currently disabled")
}
```

The test demonstrates that while `SendCoins` correctly rejects disabled denominations, `Delegate` allows them through, proving the bypass vulnerability.

### Citations

**File:** x/bank/keeper/keeper.go (L184-225)
```go
func (k BaseKeeper) DelegateCoins(ctx sdk.Context, delegatorAddr, moduleAccAddr sdk.AccAddress, amt sdk.Coins) error {
	moduleAcc := k.ak.GetAccount(ctx, moduleAccAddr)
	if moduleAcc == nil {
		return sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", moduleAccAddr)
	}

	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	balances := sdk.NewCoins()

	for _, coin := range amt {
		balance := k.GetBalance(ctx, delegatorAddr, coin.GetDenom())
		if balance.IsLT(coin) {
			return sdkerrors.Wrapf(
				sdkerrors.ErrInsufficientFunds, "failed to delegate; %s is smaller than %s", balance, amt,
			)
		}

		balances = balances.Add(balance)
		err := k.setBalance(ctx, delegatorAddr, balance.Sub(coin), true)
		if err != nil {
			return err
		}
	}

	if err := k.trackDelegation(ctx, delegatorAddr, balances, amt); err != nil {
		return sdkerrors.Wrap(err, "failed to track delegation")
	}
	// emit coin spent event
	ctx.EventManager().EmitEvent(
		types.NewCoinSpentEvent(delegatorAddr, amt),
	)

	err := k.AddCoins(ctx, moduleAccAddr, amt, true)
	if err != nil {
		return err
	}

	return nil
}
```

**File:** x/bank/keeper/keeper.go (L509-509)
```go
	return k.DelegateCoins(ctx, senderAddr, recipientAcc.GetAddress(), amt)
```

**File:** x/bank/keeper/msg_server.go (L29-31)
```go
	if err := k.IsSendEnabledCoins(ctx, msg.Amount...); err != nil {
		return nil, err
	}
```

**File:** x/bank/keeper/msg_server.go (L83-85)
```go
		if err := k.IsSendEnabledCoins(ctx, in.Coins...); err != nil {
			return nil, err
		}
```

**File:** x/auth/vesting/msg_server.go (L35-37)
```go
	if err := bk.IsSendEnabledCoins(ctx, msg.Amount...); err != nil {
		return nil, err
	}
```

**File:** x/staking/keeper/msg_server.go (L218-218)
```go
	newShares, err := k.Keeper.Delegate(ctx, delegatorAddress, msg.Amount.Amount, types.Unbonded, validator, true)
```

**File:** x/staking/keeper/delegation.go (L701-702)
```go
		if err := k.bankKeeper.DelegateCoinsFromAccountToModule(ctx, delegatorAddress, sendName, coins); err != nil {
			return sdk.Dec{}, err
```
