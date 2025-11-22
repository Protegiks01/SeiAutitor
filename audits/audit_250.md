## Title
Module Account Delegation Rewards Permanently Locked Due to Inconsistent Withdraw Address Validation

## Summary
When a module account delegates tokens without setting a custom withdraw address, the default behavior of `GetDelegatorWithdrawAddr` returns the module account's own address. However, the bank keeper's `SendCoinsFromModuleToAccount` explicitly blocks transfers to module accounts via the `blockedAddrs` check, causing reward withdrawals to fail permanently. This creates an irrecoverable fund-locking scenario.

## Impact
**Critical** - Permanent freezing of funds (fix requires hard fork)

## Finding Description

**Location:** 
- `x/distribution/keeper/store.go` lines 12-19 (GetDelegatorWithdrawAddr)
- `x/bank/keeper/keeper.go` lines 360-362 (SendCoinsFromModuleToAccount blockedAddrs check)
- `x/distribution/keeper/delegation.go` lines 169-173 (withdrawDelegationRewards)
- `simapp/app.go` lines 607-614 (ModuleAccountAddrs creating blockedAddrs map)

**Intended Logic:** 
The distribution module should prevent any scenario where rewards cannot be withdrawn. The `SetWithdrawAddr` function explicitly blocks module accounts from being set as withdraw addresses to prevent funds from being locked in accounts without proper withdrawal mechanisms. [1](#0-0) 

**Actual Logic:** 
`GetDelegatorWithdrawAddr` returns the delegator's address as default when no custom address is set, without checking if that address is a module account. [2](#0-1)  When `withdrawDelegationRewards` attempts to send rewards to this address using `SendCoinsFromModuleToAccount`, the bank keeper's blocked address check rejects the transfer because all module accounts are added to `blockedAddrs`. [3](#0-2) [4](#0-3) 

**Exploit Scenario:**
1. A module account (e.g., governance module) delegates tokens through a governance proposal or programmatic keeper call to `Delegate`. [5](#0-4) 
2. No custom withdraw address is set (module accounts cannot sign `MsgSetWithdrawAddress` messages as they lack private keys)
3. Staking rewards accumulate to the delegation over time
4. When attempting to withdraw rewards via `WithdrawDelegationRewards`:
   - `GetDelegatorWithdrawAddr` returns the module account address (the delegator itself)
   - `withdrawDelegationRewards` calls `k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, finalRewards)` [6](#0-5) 
   - `SendCoinsFromModuleToAccount` checks `k.BlockedAddr(recipientAddr)` which returns true for module accounts
   - The transaction fails with error "is not allowed to receive funds"
5. Rewards remain permanently locked with no on-chain mechanism to recover them

**Security Failure:** 
This breaks the accounting invariant that all earned rewards must be withdrawable. The inconsistency between validation in `SetWithdrawAddr` (which blocks module accounts) and the lack of validation in `GetDelegatorWithdrawAddr` creates a fund-locking vulnerability.

## Impact Explanation

**Affected Assets:** All staking rewards accumulated by module account delegations become permanently frozen.

**Severity:** This vulnerability causes direct and permanent loss of access to funds (rewards) with no recovery mechanism possible through normal protocol operations. The only fix would require a hard fork with state migration to either:
- Manually set proper withdraw addresses for affected module accounts
- Transfer locked rewards to a recoverable account
- Modify the blocked addresses list

**System Impact:** Module accounts defined in `maccPerms` include critical protocol modules like the governance module, distribution module, and staking pools. [7](#0-6)  If any of these delegate tokens (e.g., through governance proposals or programmatic operations), their rewards become irrecoverable, representing a critical protocol vulnerability.

## Likelihood Explanation

**Who Can Trigger:** Any actor who can cause a module account to delegate tokens, including:
- Governance participants submitting proposals that delegate from the gov module account
- Protocol upgrades or custom modules that programmatically delegate from module accounts

**Conditions Required:**
- A module account performs delegation without first setting a custom withdraw address
- Rewards accumulate over time
- An attempt is made to withdraw these rewards

**Frequency:** While not common in typical operations, this can occur whenever governance or custom modules manage delegations. The severity is high because once triggered, the funds are permanently locked. Given that module accounts cannot sign messages to set withdraw addresses, any delegation by a module account without programmatic withdraw address setup will result in this vulnerability.

## Recommendation

Add a validation check in `GetDelegatorWithdrawAddr` to detect when the default address (delegator address) is a blocked module account and either:

1. **Immediate fix:** Reject the query with a clear error indicating the withdraw address must be explicitly set
2. **Better fix:** Add a validation in the staking module's `Delegate` function to require module accounts to have a non-module-account withdraw address set before allowing delegation

```go
// In GetDelegatorWithdrawAddr
func (k Keeper) GetDelegatorWithdrawAddr(ctx sdk.Context, delAddr sdk.AccAddress) sdk.AccAddress {
    store := ctx.KVStore(k.storeKey)
    b := store.Get(types.GetDelegatorWithdrawAddrKey(delAddr))
    if b == nil {
        // Check if delegator is a blocked address (module account)
        if k.blockedAddrs[delAddr.String()] {
            // Return error or panic - module accounts must set explicit withdraw address
            panic(fmt.Sprintf("module account %s must set explicit withdraw address before delegating", delAddr))
        }
        return delAddr
    }
    return sdk.AccAddress(b)
}
```

Alternatively, add a check in the `Delegate` function to ensure module accounts have set a valid withdraw address before delegating.

## Proof of Concept

**File:** `x/distribution/keeper/delegation_test.go` (add new test function)

**Test Function Name:** `TestModuleAccountDelegationRewardLocking`

**Setup:**
1. Initialize test app with module accounts in blockedAddrs
2. Fund a module account (e.g., gov module account)
3. Create a validator
4. Have the module account delegate to the validator (programmatically via keeper)
5. Allocate rewards to the validator
6. Attempt to withdraw delegation rewards

**Trigger:**
Call `WithdrawDelegationRewards` with the module account as delegator

**Observation:**
The test should demonstrate that:
1. The delegation succeeds
2. Rewards are allocated
3. `GetDelegatorWithdrawAddr` returns the module account address
4. `WithdrawDelegationRewards` fails with "is not allowed to receive funds" error
5. Rewards remain locked in the distribution module with no way to withdraw

**Expected Result:** The withdrawal should fail, proving that rewards become permanently locked when module accounts delegate without setting custom withdraw addresses.

The test would follow this pattern (pseudocode):
```go
func TestModuleAccountDelegationRewardLocking(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Get gov module account (a blocked address)
    govModuleAddr := app.AccountKeeper.GetModuleAddress(govtypes.ModuleName)
    
    // Fund the module account
    // Create and bond validator
    // Module account delegates to validator (via keeper)
    // Allocate rewards
    
    // Verify GetDelegatorWithdrawAddr returns module account itself
    withdrawAddr := app.DistrKeeper.GetDelegatorWithdrawAddr(ctx, govModuleAddr)
    require.Equal(t, govModuleAddr, withdrawAddr)
    
    // Verify module account is in blocked addresses
    require.True(t, app.BankKeeper.BlockedAddr(govModuleAddr))
    
    // Attempt to withdraw - should fail
    _, err := app.DistrKeeper.WithdrawDelegationRewards(ctx, govModuleAddr, valAddr)
    require.Error(t, err)
    require.Contains(t, err.Error(), "is not allowed to receive funds")
    
    // Rewards are now permanently locked
}
```

This test proves the vulnerability by showing that module account delegations create an unrecoverable fund-locking scenario.

### Citations

**File:** x/distribution/keeper/keeper.go (L64-82)
```go
func (k Keeper) SetWithdrawAddr(ctx sdk.Context, delegatorAddr sdk.AccAddress, withdrawAddr sdk.AccAddress) error {
	if k.blockedAddrs[withdrawAddr.String()] {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", withdrawAddr)
	}

	if !k.GetWithdrawAddrEnabled(ctx) {
		return types.ErrSetWithdrawAddrDisabled
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSetWithdrawAddress,
			sdk.NewAttribute(types.AttributeKeyWithdrawAddress, withdrawAddr.String()),
		),
	)

	k.SetDelegatorWithdrawAddr(ctx, delegatorAddr, withdrawAddr)
	return nil
}
```

**File:** x/distribution/keeper/store.go (L12-19)
```go
func (k Keeper) GetDelegatorWithdrawAddr(ctx sdk.Context, delAddr sdk.AccAddress) sdk.AccAddress {
	store := ctx.KVStore(k.storeKey)
	b := store.Get(types.GetDelegatorWithdrawAddrKey(delAddr))
	if b == nil {
		return delAddr
	}
	return sdk.AccAddress(b)
}
```

**File:** x/bank/keeper/keeper.go (L360-362)
```go
	if k.BlockedAddr(recipientAddr) {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", recipientAddr)
	}
```

**File:** simapp/app.go (L134-143)
```go
	// module account permissions
	maccPerms = map[string][]string{
		authtypes.FeeCollectorName:     nil,
		distrtypes.ModuleName:          nil,
		minttypes.ModuleName:           {authtypes.Minter},
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
		govtypes.ModuleName:            {authtypes.Burner},
	}
)
```

**File:** simapp/app.go (L607-614)
```go
func (app *SimApp) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
}
```

**File:** x/staking/keeper/delegation.go (L631-703)
```go
func (k Keeper) Delegate(
	ctx sdk.Context, delAddr sdk.AccAddress, bondAmt sdk.Int, tokenSrc types.BondStatus,
	validator types.Validator, subtractAccount bool,
) (newShares sdk.Dec, err error) {
	// In some situations, the exchange rate becomes invalid, e.g. if
	// Validator loses all tokens due to slashing. In this case,
	// make all future delegations invalid.
	if validator.InvalidExRate() {
		return sdk.ZeroDec(), types.ErrDelegatorShareExRateInvalid
	}

	// check if the validator voting power exceeds the upper bound after the delegation
	// validator.Tokens
	lastTotalPower := k.GetLastTotalPower(ctx)
	maxVotingPowerEnforcementThreshold := k.MaxVotingPowerEnforcementThreshold(ctx)

	// 1 power = Bond Amount / Power Reduction
	validatorAddtionalPower := bondAmt.Quo(k.PowerReduction(ctx))
	newTotalPower := lastTotalPower.Add(validatorAddtionalPower)

	// If it's beyond genesis then enforce power ratio per validator if there's more than maxVotingPowerEnforcementThreshold
	if newTotalPower.GTE(maxVotingPowerEnforcementThreshold) && ctx.BlockHeight() > 0 {
		// Convert bond amount to power first
		validatorNewTotalPower := validator.Tokens.Add(bondAmt).Quo(k.PowerReduction(ctx))
		// Validator's new total power cannot exceed the max power ratio that's allowed
		newVotingPowerRatio := validatorNewTotalPower.ToDec().Quo(newTotalPower.ToDec())
		maxVotingPowerRatio := k.MaxVotingPowerRatio(ctx)
		if newVotingPowerRatio.GT(maxVotingPowerRatio) {
			k.Logger(ctx).Error(
				fmt.Sprintf("validator's voting power ratio exceeds the max allowed ratio: %s > %s\n", newVotingPowerRatio.String(), maxVotingPowerRatio.String()),
			)
			return sdk.ZeroDec(), types.ErrExceedMaxVotingPowerRatio
		}
	}

	// Get or create the delegation object
	delegation, found := k.GetDelegation(ctx, delAddr, validator.GetOperator())
	if !found {
		delegation = types.NewDelegation(delAddr, validator.GetOperator(), sdk.ZeroDec())
	}

	// call the appropriate hook if present
	if found {
		k.BeforeDelegationSharesModified(ctx, delAddr, validator.GetOperator())
	} else {
		k.BeforeDelegationCreated(ctx, delAddr, validator.GetOperator())
	}

	delegatorAddress := sdk.MustAccAddressFromBech32(delegation.DelegatorAddress)

	// if subtractAccount is true then we are
	// performing a delegation and not a redelegation, thus the source tokens are
	// all non bonded
	if subtractAccount {
		if tokenSrc == types.Bonded {
			panic("delegation token source cannot be bonded")
		}

		var sendName string

		switch {
		case validator.IsBonded():
			sendName = types.BondedPoolName
		case validator.IsUnbonding(), validator.IsUnbonded():
			sendName = types.NotBondedPoolName
		default:
			panic("invalid validator status")
		}

		coins := sdk.NewCoins(sdk.NewCoin(k.BondDenom(ctx), bondAmt))
		if err := k.bankKeeper.DelegateCoinsFromAccountToModule(ctx, delegatorAddress, sendName, coins); err != nil {
			return sdk.Dec{}, err
		}
```

**File:** x/distribution/keeper/delegation.go (L168-173)
```go
	if !finalRewards.IsZero() {
		withdrawAddr := k.GetDelegatorWithdrawAddr(ctx, del.GetDelegatorAddr())
		err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, finalRewards)
		if err != nil {
			return nil, err
		}
```
