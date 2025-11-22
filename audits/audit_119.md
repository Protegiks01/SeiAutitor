## Title
Chain-Halting Panic via Fee Grant to Module Account Address

## Summary
A non-privileged user can trigger a network-wide panic by granting a fee allowance to a module account address, causing all validators to crash when subsequently accessing that module account.

## Impact
High

## Finding Description

**Location:** 
- Vulnerable handler: [1](#0-0) 
- Account creation without validation: [2](#0-1) 
- Panic location: [3](#0-2) 

**Intended Logic:** 
Module addresses should only contain ModuleAccount types, never regular BaseAccounts. The banking module enforces this by blocking transfers to module addresses via the `BlockedAddr` check [4](#0-3) , and module addresses are populated in the blocked list [5](#0-4) .

**Actual Logic:** 
The `MsgGrantAllowance` handler does not validate whether the grantee address is a module account address before creating an account. When granting an allowance to a non-existent address, the system creates a BaseAccount at that address without checking if it's in the blocked addresses list.

**Exploit Scenario:**
1. Attacker calculates a module address (e.g., fee_collector, distribution, mint) using the deterministic derivation [6](#0-5) 
2. Attacker submits `MsgGrantAllowance` with grantee set to the module address
3. The handler creates a BaseAccount at the module address
4. Any subsequent operation requiring that module account (e.g., fee collection, reward distribution, token minting) calls `GetModuleAccount` [7](#0-6) 
5. The type assertion fails because a BaseAccount exists instead of ModuleAccount, triggering a panic
6. All validators crash, halting the network

**Security Failure:** 
This breaks the invariant that module addresses must only contain ModuleAccount types, leading to a denial-of-service that causes total network shutdown.

## Impact Explanation

- **Affected processes:** All core blockchain operations that interact with module accounts (fee collection, staking rewards, token minting/burning, governance)
- **Severity of damage:** Complete network halt. All validators panic and cannot process blocks. The chain becomes permanently frozen until a coordinated hard fork removes the malicious account.
- **System importance:** This is a critical failure - the blockchain cannot function without access to module accounts. Operations like `SendCoinsFromAccountToModule` [8](#0-7)  immediately panic when they try to retrieve the corrupted module account.

## Likelihood Explanation

- **Who can trigger:** Any user with sufficient funds to pay transaction fees
- **Conditions required:** None beyond normal chain operation. The attacker only needs to know module names (which are public in the codebase)
- **Frequency:** Can be executed immediately with a single transaction. Once triggered, the chain is permanently halted until a hard fork

## Recommendation

Add a `BlockedAddr` check in the `MsgGrantAllowance` handler before creating the grantee account:

```go
if bk.BlockedAddr(grantee) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive fee grants", msg.Grantee)
}
```

This check should be added immediately after parsing the grantee address and before checking if the account exists, similar to the validation in `CreateVestingAccount` [9](#0-8) .

## Proof of Concept

**File:** `x/feegrant/keeper/msg_server_test.go`

**Test Function:** Add this test to the existing `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestGrantAllowanceToModuleAccountPanic() {
    // Get a module account address (fee_collector)
    moduleAddr := authtypes.NewModuleAddress(authtypes.FeeCollectorName)
    
    // Create a basic allowance
    any, err := codectypes.NewAnyWithValue(&feegrant.BasicAllowance{
        SpendLimit: suite.atom,
    })
    suite.Require().NoError(err)
    
    // Grant allowance to module address (should be blocked but isn't)
    msg := &feegrant.MsgGrantAllowance{
        Granter:   suite.addrs[0].String(),
        Grantee:   moduleAddr.String(),
        Allowance: any,
    }
    
    _, err = suite.msgSrvr.GrantAllowance(suite.ctx, msg)
    suite.Require().NoError(err) // This succeeds when it should fail
    
    // Verify a BaseAccount was created at the module address
    acc := suite.app.AccountKeeper.GetAccount(suite.sdkCtx, moduleAddr)
    suite.Require().NotNil(acc)
    _, isModuleAccount := acc.(authtypes.ModuleAccountI)
    suite.Require().False(isModuleAccount) // It's a BaseAccount, not ModuleAccount
    
    // Now any call to GetModuleAccount will panic
    suite.Require().Panics(func() {
        suite.app.AccountKeeper.GetModuleAccount(suite.sdkCtx, authtypes.FeeCollectorName)
    })
}
```

**Setup:** Uses the existing test suite infrastructure with simapp.

**Trigger:** Calls `MsgGrantAllowance` with a module address as the grantee, which creates a BaseAccount at that address.

**Observation:** The test confirms that:
1. The grant succeeds (no BlockedAddr check)
2. A BaseAccount is created at the module address
3. Calling `GetModuleAccount` for that module panics with "account is not a module account"

This demonstrates the complete attack: a single user transaction can corrupt a module account address and cause all subsequent module operations to panic, halting the entire network.

### Citations

**File:** x/feegrant/keeper/msg_server.go (L27-55)
```go
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
```

**File:** x/feegrant/keeper/keeper.go (L40-47)
```go
func (k Keeper) GrantAllowance(ctx sdk.Context, granter, grantee sdk.AccAddress, feeAllowance feegrant.FeeAllowanceI) error {

	// create the account if it is not in account state
	granteeAcc := k.authKeeper.GetAccount(ctx, grantee)
	if granteeAcc == nil {
		granteeAcc = k.authKeeper.NewAccountWithAddress(ctx, grantee)
		k.authKeeper.SetAccount(ctx, granteeAcc)
	}
```

**File:** x/auth/keeper/keeper.go (L187-193)
```go
	acc := ak.GetAccount(ctx, addr)
	if acc != nil {
		macc, ok := acc.(types.ModuleAccountI)
		if !ok {
			panic("account is not a module account")
		}
		return macc, perms
```

**File:** x/auth/keeper/keeper.go (L206-209)
```go
func (ak AccountKeeper) GetModuleAccount(ctx sdk.Context, moduleName string) types.ModuleAccountI {
	acc, _ := ak.GetModuleAccountAndPermissions(ctx, moduleName)
	return acc
}
```

**File:** x/bank/keeper/msg_server.go (L47-49)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
	}
```

**File:** simapp/app.go (L607-613)
```go
func (app *SimApp) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
```

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** x/bank/keeper/keeper.go (L393-402)
```go
func (k BaseKeeper) SendCoinsFromAccountToModule(
	ctx sdk.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins,
) error {
	recipientAcc := k.ak.GetModuleAccount(ctx, recipientModule)
	if recipientAcc == nil {
		panic(sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", recipientModule))
	}

	return k.SendCoins(ctx, senderAddr, recipientAcc.GetAddress(), amt)
}
```

**File:** x/auth/vesting/msg_server.go (L48-50)
```go
	if bk.BlockedAddr(to) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
	}
```
