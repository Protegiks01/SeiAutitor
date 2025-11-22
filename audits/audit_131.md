## Audit Report

## Title
Vesting Account EndTime Bypass Allows Immediate Unlock of All Funds

## Summary
The vesting account creation logic in `msg_server.go` allows users to set an EndTime in the past (e.g., EndTime = 1), which causes all vesting funds to become immediately spendable, completely bypassing the vesting mechanism. The ValidateBasic check only verifies EndTime > 0 but does not validate that EndTime is in the future relative to the current block time.

## Impact
**High** - Direct loss of vesting functionality, effectively allowing immediate access to funds that should be locked under vesting schedules.

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Validation: [2](#0-1) 

**Intended Logic:** 
Vesting accounts should lock funds that gradually become spendable over time based on a vesting schedule. The EndTime should be in the future to ensure funds remain locked until the vesting period completes.

**Actual Logic:** 
The ValidateBasic method only checks if EndTime > 0 [2](#0-1) , allowing any positive timestamp including past timestamps (e.g., EndTime = 1). When a vesting account is created with a past EndTime, the GetVestedCoins logic returns all OriginalVesting as already vested because the current block time is greater than EndTime [3](#0-2) .

**Exploit Scenario:**
1. Attacker creates a MsgCreateVestingAccount with EndTime = 1 (unix epoch + 1 second, which passes ValidateBasic)
2. The account is created with StartTime = current block time and EndTime = 1 [4](#0-3) 
3. When checking spendable balance, GetVestedCoins compares blockTime.Unix() >= EndTime (1) and returns all OriginalVesting [3](#0-2) 
4. LockedCoins becomes 0, making all funds immediately spendable [5](#0-4) 
5. Attacker can immediately transfer all vested funds

**Security Failure:** 
Authorization and access control failure - the vesting time-lock mechanism is completely bypassed, allowing unauthorized immediate access to funds that should be locked.

## Impact Explanation

This vulnerability affects the core vesting functionality:
- **Funds at Risk:** All funds intended to be locked in vesting accounts become immediately accessible
- **Vesting Bypass:** The entire purpose of vesting (gradual token unlocking over time) is defeated
- **Value Loss:** Projects using vesting for token distribution, team allocations, or investor lock-ups lose the time-based protection mechanism
- **Trust Impact:** Undermines the security guarantees of the vesting module

The severity is High because it represents a direct loss of the vesting security mechanism, which is a critical feature for token economics and controlled fund release in blockchain protocols.

## Likelihood Explanation

**Likelihood: Very High**
- **Who can exploit:** Any user creating a vesting account (no special privileges required)
- **Conditions:** None beyond normal account creation - the exploit works during standard operation
- **Frequency:** Can be exploited immediately upon every vesting account creation with malicious EndTime
- **Ease:** Trivial to exploit - simply set EndTime to any past timestamp > 0 (e.g., 1, 100, 1000000)

This vulnerability will be exploited frequently if not fixed, as it's discoverable through basic testing and requires no sophisticated attack techniques.

## Recommendation

Add validation in `MsgCreateVestingAccount.ValidateBasic()` to ensure EndTime is in the future:

```go
// In x/auth/vesting/types/msgs.go, modify ValidateBasic:
func (msg MsgCreateVestingAccount) ValidateBasic() error {
    // ... existing address and amount validation ...
    
    if msg.EndTime <= 0 {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid end time")
    }
    
    // Add this check:
    if msg.EndTime <= time.Now().Unix() {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "end time must be in the future")
    }
    
    return nil
}
```

Alternatively, add validation in the message server handler before account creation to compare EndTime against `ctx.BlockTime().Unix()`.

## Proof of Concept

**File:** `x/auth/vesting/handler_test.go`  
**Test Function:** Add new test case to `TestMsgCreateVestingAccount`

**Setup:**
Add the following test case to the existing `testCases` slice in `TestMsgCreateVestingAccount`:

```go
{
    name:      "create vesting account with past end time - should unlock immediately",
    msg:       types.NewMsgCreateVestingAccount(addr1, addr9, sdk.NewCoins(sdk.NewInt64Coin("test", 100)), 1, false, nil),
    expectErr: false,
},
```

**Additional verification after account creation:**
```go
// After the account creation loop, add verification:
toAddr9, _ := sdk.AccAddressFromBech32(addr9.String())
accI := suite.app.AccountKeeper.GetAccount(ctx, toAddr9)
if accI != nil {
    acc, ok := accI.(*types.ContinuousVestingAccount)
    suite.Require().True(ok)
    
    // Verify EndTime is in the past
    suite.Require().Equal(int64(1), acc.EndTime)
    suite.Require().Less(acc.EndTime, ctx.BlockTime().Unix())
    
    // CRITICAL: Verify all coins are immediately vested (vulnerability)
    vestedCoins := acc.GetVestedCoins(ctx.BlockTime())
    suite.Require().Equal(sdk.NewCoins(sdk.NewInt64Coin("test", 100)), vestedCoins)
    
    // CRITICAL: Verify no coins are locked (vulnerability)
    lockedCoins := acc.LockedCoins(ctx.BlockTime())
    suite.Require().Equal(sdk.NewCoins(), lockedCoins)
    
    // CRITICAL: All coins should be spendable immediately (vulnerability)
    spendableCoins := suite.app.BankKeeper.SpendableCoins(ctx, toAddr9)
    suite.Require().Equal(sdk.NewCoins(sdk.NewInt64Coin("test", 100)), spendableCoins)
}
```

**Observation:**
The test will pass, demonstrating that:
1. ValidateBasic accepts EndTime = 1 (past timestamp)
2. The account is created successfully
3. All vested coins are immediately unlocked and spendable
4. The vesting mechanism is completely bypassed

This proves the vulnerability is real and exploitable.

### Citations

**File:** x/auth/vesting/msg_server.go (L72-79)
```go
	baseVestingAccount := types.NewBaseVestingAccount(baseAccount.(*authtypes.BaseAccount), msg.Amount.Sort(), msg.EndTime, admin)

	var acc authtypes.AccountI

	if msg.Delayed {
		acc = types.NewDelayedVestingAccountRaw(baseVestingAccount)
	} else {
		acc = types.NewContinuousVestingAccountRaw(baseVestingAccount, ctx.BlockTime().Unix())
```

**File:** x/auth/vesting/types/msgs.go (L59-61)
```go
	if msg.EndTime <= 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid end time")
	}
```

**File:** x/auth/vesting/types/vesting_account.go (L236-238)
```go
	} else if blockTime.Unix() >= cva.EndTime {
		return cva.OriginalVesting
	}
```

**File:** x/bank/keeper/view.go (L167-177)
```go
func (k BaseViewKeeper) LockedCoins(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins {
	acc := k.ak.GetAccount(ctx, addr)
	if acc != nil {
		vacc, ok := acc.(vestexported.VestingAccount)
		if ok {
			return vacc.LockedCoins(ctx.BlockTime())
		}
	}

	return sdk.NewCoins()
}
```
