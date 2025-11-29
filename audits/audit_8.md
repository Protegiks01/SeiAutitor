# Audit Report

## Title
Chain-Halting Panic via Fee Grant to Module Account Address

## Summary
The feegrant module's `MsgGrantAllowance` handler allows any user to create a BaseAccount at a module account address, breaking the critical invariant that module addresses must only contain ModuleAccounts. This causes all validators to panic when subsequently accessing the corrupted module account, resulting in complete network shutdown.

## Impact
High

## Finding Description

- **location**: The vulnerability spans multiple files:
  - Entry point: [1](#0-0) 
  - Account creation without validation: [2](#0-1) 
  - Panic trigger: [3](#0-2) 

- **intended logic**: Module addresses should exclusively contain ModuleAccount types to maintain system integrity. The banking module correctly enforces this by blocking transfers to module addresses [4](#0-3) , and the vesting module similarly validates recipients [5](#0-4) . Module addresses are populated in the blocked list [6](#0-5)  and passed to the bank keeper during initialization.

- **actual logic**: The `MsgGrantAllowance` handler accepts any valid address as a grantee without checking if it's a blocked/module address. When the grantee account doesn't exist, `GrantAllowance` unconditionally creates a BaseAccount at that address, even if it's a module address. The feegrant keeper only has access to the authKeeper [7](#0-6) , so it cannot perform a `BlockedAddr` check. Additionally, `ValidateBasic()` for `MsgGrantAllowance` [8](#0-7)  only validates that addresses are non-empty and different, but doesn't check for blocked addresses.

- **exploitation path**:
  1. Attacker calculates a module address deterministically using public module names [9](#0-8)  (e.g., "fee_collector", "distribution", "mint")
  2. Attacker submits a `MsgGrantAllowance` transaction with the module address as the grantee
  3. The handler creates a BaseAccount at the module address without any validation
  4. In the next block, when the distribution module's `AllocateTokens` function [10](#0-9)  attempts to retrieve the fee collector module account during BeginBlock processing
  5. `GetModuleAccount` [11](#0-10)  is called, which internally uses `GetModuleAccountAndPermissions`
  6. The type assertion fails because a BaseAccount exists instead of a ModuleAccount, triggering a panic
  7. All validators crash simultaneously, halting the entire network

- **security guarantee broken**: The critical invariant that "module addresses exclusively contain ModuleAccount types" is violated. This invariant is essential for the blockchain's operation, as module accounts are central to fee collection, token minting, staking rewards, and other core protocol functions.

## Impact Explanation

This vulnerability causes **complete network shutdown**. The impact includes:

- **Total validator failure**: All validators will panic when any operation attempts to access the corrupted module account through `GetModuleAccount` or related functions like `SendCoinsFromAccountToModule` [12](#0-11) 
- **Immediate halt**: Since fee collection happens in BeginBlock for every block, the network halts immediately after the malicious transaction is included
- **Permanent freeze**: The chain cannot recover without a coordinated hard fork to remove the corrupted account from state
- **Critical system operations affected**: Fee collection, token minting, staking reward distribution, governance operations, and all other module account interactions become impossible

The vulnerability matches the impact criteria: **"Network not being able to confirm new transactions (total network shutdown)"** which is classified as **High** severity.

## Likelihood Explanation

- **Who can trigger**: Any user with sufficient funds to pay transaction fees (~$0.01 equivalent)
- **Conditions required**: 
  - No special permissions or privileges needed
  - Only requires knowledge of module names, which are public in the codebase [13](#0-12) 
  - No rate limiting or additional barriers
- **Frequency**: Can be executed immediately with a single transaction. The attack is deterministic and guaranteed to succeed. Once triggered, the network remains halted until a hard fork is coordinated.

## Recommendation

Add a `BlockedAddr` check in the `MsgGrantAllowance` handler before account creation. The feegrant keeper needs to be modified to include a reference to the bank keeper:

1. Update the Keeper struct to include a bank keeper interface that exposes `BlockedAddr`
2. Add validation in the `GrantAllowance` function immediately after address parsing:

```go
if bk.BlockedAddr(grantee) {
    return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive fee grants", grantee.String())
}
```

This mirrors the protection pattern already implemented in the vesting module and bank module, ensuring consistent security across all account-creating operations.

## Proof of Concept

**File**: `x/feegrant/keeper/msg_server_test.go`

**Test Function**: Add to the existing `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestGrantAllowanceToModuleAccountPanic() {
    // Setup: Calculate the fee_collector module address
    moduleAddr := authtypes.NewModuleAddress(authtypes.FeeCollectorName)
    
    any, err := codectypes.NewAnyWithValue(&feegrant.BasicAllowance{
        SpendLimit: suite.atom,
    })
    suite.Require().NoError(err)
    
    // Action: Grant allowance to module address
    msg := &feegrant.MsgGrantAllowance{
        Granter:   suite.addrs[0].String(),
        Grantee:   moduleAddr.String(),
        Allowance: any,
    }
    
    _, err = suite.msgSrvr.GrantAllowance(suite.ctx, msg)
    suite.Require().NoError(err) // Succeeds - no BlockedAddr check
    
    // Result: BaseAccount created at module address
    acc := suite.app.AccountKeeper.GetAccount(suite.sdkCtx, moduleAddr)
    suite.Require().NotNil(acc)
    _, isModuleAccount := acc.(authtypes.ModuleAccountI)
    suite.Require().False(isModuleAccount) // It's a BaseAccount, not ModuleAccount
    
    // Accessing the module account now causes panic
    suite.Require().Panics(func() {
        suite.app.AccountKeeper.GetModuleAccount(suite.sdkCtx, authtypes.FeeCollectorName)
    })
}
```

**Expected behavior**: The test demonstrates that:
1. The grant operation succeeds without any blocked address validation
2. A BaseAccount is improperly created at the module account address
3. Subsequent calls to `GetModuleAccount` panic with "account is not a module account"
4. This panic would crash all validators in a production environment when triggered during normal block processing

### Citations

**File:** x/feegrant/keeper/msg_server.go (L27-56)
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
}
```

**File:** x/feegrant/keeper/keeper.go (L17-21)
```go
type Keeper struct {
	cdc        codec.BinaryCodec
	storeKey   sdk.StoreKey
	authKeeper feegrant.AccountKeeper
}
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

**File:** x/auth/vesting/msg_server.go (L48-50)
```go
	if bk.BlockedAddr(to) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
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

**File:** simapp/app.go (L606-614)
```go
// ModuleAccountAddrs returns all the app's module account addresses.
func (app *SimApp) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
}
```

**File:** x/feegrant/msgs.go (L39-57)
```go
// ValidateBasic implements the sdk.Msg interface.
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

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** x/distribution/keeper/allocation.go (L15-27)
```go
func (k Keeper) AllocateTokens(
	ctx sdk.Context, sumPreviousPrecommitPower, totalPreviousPower int64,
	previousProposer sdk.ConsAddress, bondedVotes []abci.VoteInfo,
) {

	logger := k.Logger(ctx)

	// fetch and clear the collected fees for distribution, since this is
	// called in BeginBlock, collected fees will be from the previous block
	// (and distributed to the previous proposer)
	feeCollector := k.authKeeper.GetModuleAccount(ctx, k.feeCollectorName)
	feesCollectedInt := k.bankKeeper.GetAllBalances(ctx, feeCollector.GetAddress())
	feesCollected := sdk.NewDecCoinsFromCoins(feesCollectedInt...)
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
