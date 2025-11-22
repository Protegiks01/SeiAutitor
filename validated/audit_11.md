# Audit Report

## Title
Front-Running Module Account Creation Causes Network-Wide Panic During Chain Upgrades

## Summary
An attacker can front-run module account creation during chain upgrades by pre-creating a `BaseAccount` at the deterministic module address before the upgrade executes. When the new module's `InitGenesis` calls `GetModuleAccount`, it encounters the `BaseAccount` instead of a `ModuleAccountI`, triggering an unconditional panic that halts all validators simultaneously.

## Impact
**High**

## Finding Description

**Location:**
- Panic location: [1](#0-0) 
- Account creation vector: [2](#0-1) 
- Blocked address check: [3](#0-2) 
- Module address initialization: [4](#0-3) 

**Intended Logic:**
Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses. The `blockedAddrs` mechanism should prevent regular users from creating accounts at module addresses. When a chain upgrade adds a new module, `GetModuleAccount` should safely create the module account during `InitGenesis`.

**Actual Logic:**
The `blockedAddrs` map is populated only from existing modules in `maccPerms` at app initialization. [4](#0-3)  Future modules that will be added via upgrade are not in this map. When an attacker sends coins to a future module address, the `BlockedAddr` check passes because the address isn't blocked yet. [5](#0-4)  This creates a `BaseAccount` at the module address. [6](#0-5)  During the upgrade, when `GetModuleAccountAndPermissions` retrieves this account and finds it's not a `ModuleAccountI`, it executes an unconditional panic. [7](#0-6) 

**Exploitation Path:**
1. Attacker observes upgrade proposal announcing new module "newmodule" at height 100000
2. Attacker calculates deterministic module address: `crypto.AddressHash([]byte("newmodule"))` [8](#0-7) 
3. At block 99990, attacker submits `MsgSend` with 1 token to the calculated address
4. `Send` handler checks `BlockedAddr(to)` - returns false (address not in blockedAddrs yet)
5. `SendCoins` creates `BaseAccount` at module address via `NewAccountWithAddress` [9](#0-8) 
6. At block 100000, upgrade executes `RunMigrations` [10](#0-9) 
7. New module's `InitGenesis` calls `GetModuleAccount` (as seen in multiple modules like mint, gov, auth)
8. `GetModuleAccountAndPermissions` finds `BaseAccount`, executes `panic("account is not a module account")`
9. All validators panic at the same height during consensus
10. Network completely halts

**Security Guarantee Broken:**
Network availability and upgrade safety are violated. The deterministic module address derivation combined with the static blockedAddrs map creates a race condition where attackers can claim future module addresses before they're protected.

## Impact Explanation

This vulnerability causes complete network shutdown affecting all validators simultaneously. When all validators panic at the same block height during upgrade execution:

- No new transactions can be confirmed after the upgrade height
- The upgrade plan is already consumed but module initialization failed, leaving state inconsistent
- Chain cannot progress without manual intervention
- Recovery requires coordinated hard fork with state export/import or emergency patch
- Existing upgrade cannot be rolled back cleanly

This matches the HIGH impact criterion: "Network not being able to confirm new transactions (total network shutdown)."

## Likelihood Explanation

**Trigger Conditions:**
- **Who:** Any network participant with minimal funds (transaction fees + 1 token)
- **When:** Between upgrade proposal passing and upgrade execution (typically days/weeks window)
- **Requirements:** Knowledge of new module name (publicly available in governance proposal)

**Frequency:**
- Can occur with every chain upgrade introducing new modules
- Multiple chain upgrades per year in active Cosmos chains
- High likelihood given low cost, public information, and large time window

**Detection Difficulty:**
- Attack transaction appears as normal coin transfer
- Indistinguishable from legitimate transfers
- Only becomes apparent when all validators crash during upgrade

The combination of public information, minimal cost, large time window, and inability to detect makes exploitation highly likely.

## Recommendation

**Primary Fix:**
Add graceful handling in `GetModuleAccountAndPermissions` to convert pre-existing `BaseAccount` to `ModuleAccount`:

```go
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Handle case where BaseAccount was created before module
        if baseAcc, isBase := acc.(*types.BaseAccount); isBase && 
           baseAcc.GetPubKey() == nil && baseAcc.GetSequence() == 0 {
            // Convert to module account preserving account number
            newMacc := types.NewModuleAccount(baseAcc, moduleName, perms...)
            ak.SetModuleAccount(ctx, newMacc)
            return newMacc, perms
        }
        panic("account is not a module account")
    }
    return macc, perms
}
```

**Alternative Prevention:**
Implement proactive blocking of future module addresses by maintaining a registry of planned module names from pending upgrade proposals and adding their addresses to `blockedAddrs` dynamically.

## Proof of Concept

**Test File:** `x/auth/keeper/keeper_test.go`

**Setup:**
1. Create test app and context using `createTestApp(true)`
2. Calculate deterministic module address for "newmodule" using `types.NewModuleAddress(moduleName)`
3. Create and fund attacker account with tokens

**Action:**
1. Attacker sends 1 token to calculated module address via `BankKeeper.SendCoins`
2. Verify `BaseAccount` created at module address (type assertion confirms it's not `ModuleAccount`)
3. Call `GetModuleAccount` for the module name

**Result:**
- `GetModuleAccount` panics with message "account is not a module account"
- Demonstrates that validators would crash during actual upgrade
- Confirms network shutdown scenario

The test validates that the attack path is feasible and would cause the claimed network-wide panic during consensus execution.

## Notes

The vulnerability stems from a fundamental design assumption that module addresses are "reserved" through the `blockedAddrs` mechanism, but this mechanism is static and only protects addresses of modules that exist at initialization time. The deterministic address derivation [8](#0-7)  allows attackers to precompute future module addresses, and the account creation logic [6](#0-5)  permits account creation at any non-blocked address. Combined with the unconditional panic [7](#0-6)  and the upgrade flow that calls `InitGenesis` for new modules [11](#0-10) , this creates a critical vulnerability in the upgrade process.

### Citations

**File:** x/auth/keeper/keeper.go (L181-202)
```go
func (ak AccountKeeper) GetModuleAccountAndPermissions(ctx sdk.Context, moduleName string) (types.ModuleAccountI, []string) {
	addr, perms := ak.GetModuleAddressAndPermissions(moduleName)
	if addr == nil {
		return nil, []string{}
	}

	acc := ak.GetAccount(ctx, addr)
	if acc != nil {
		macc, ok := acc.(types.ModuleAccountI)
		if !ok {
			panic("account is not a module account")
		}
		return macc, perms
	}

	// create a new module account
	macc := types.NewEmptyModuleAccount(moduleName, perms...)
	maccI := (ak.NewAccount(ctx, macc)).(types.ModuleAccountI) // set the account number
	ak.SetModuleAccount(ctx, maccI)

	return maccI, perms
}
```

**File:** x/bank/keeper/send.go (L155-173)
```go
// SendCoins transfers amt coins from a sending account to a receiving account.
// An error is returned upon failure.
func (k BaseSendKeeper) SendCoins(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
	if err := k.SendCoinsWithoutAccCreation(ctx, fromAddr, toAddr, amt); err != nil {
		return err
	}

	// Create account if recipient does not exist.
	//
	// NOTE: This should ultimately be removed in favor a more flexible approach
	// such as delegated fee messages.
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
	}

	return nil
}
```

**File:** x/bank/keeper/msg_server.go (L26-76)
```go
func (k msgServer) Send(goCtx context.Context, msg *types.MsgSend) (*types.MsgSendResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := k.IsSendEnabledCoins(ctx, msg.Amount...); err != nil {
		return nil, err
	}

	from, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return nil, err
	}
	to, err := sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return nil, err
	}

	allowListCache := make(map[string]AllowedAddresses)
	if !k.IsInDenomAllowList(ctx, from, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to send funds", msg.FromAddress)
	}

	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
	}

	err = k.SendCoins(ctx, from, to, msg.Amount)
	if err != nil {
		return nil, err
	}

	defer func() {
		for _, a := range msg.Amount {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "send"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
		),
	)

	return &types.MsgSendResponse{}, nil
}
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

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** x/auth/keeper/account.go (L9-17)
```go
func (ak AccountKeeper) NewAccountWithAddress(ctx sdk.Context, addr sdk.AccAddress) types.AccountI {
	acc := ak.proto()
	err := acc.SetAddress(addr)
	if err != nil {
		panic(err)
	}

	return ak.NewAccount(ctx, acc)
}
```

**File:** types/module/module.go (L545-596)
```go
// Please also refer to docs/core/upgrade.md for more information.
func (m Manager) RunMigrations(ctx sdk.Context, cfg Configurator, fromVM VersionMap) (VersionMap, error) {
	c, ok := cfg.(configurator)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
	}
	var modules = m.OrderMigrations
	if modules == nil {
		modules = DefaultMigrationsOrder(m.ModuleNames())
	}

	updatedVM := VersionMap{}
	for _, moduleName := range modules {
		module := m.Modules[moduleName]
		fromVersion, exists := fromVM[moduleName]
		toVersion := module.ConsensusVersion()

		// Only run migrations when the module exists in the fromVM.
		// Run InitGenesis otherwise.
		//
		// the module won't exist in the fromVM in two cases:
		// 1. A new module is added. In this case we run InitGenesis with an
		// empty genesis state.
		// 2. An existing chain is upgrading to v043 for the first time. In this case,
		// all modules have yet to be added to x/upgrade's VersionMap store.
		if exists {
			err := c.runModuleMigrations(ctx, moduleName, fromVersion, toVersion)
			if err != nil {
				return nil, err
			}
		} else {
			cfgtor, ok := cfg.(configurator)
			if !ok {
				// Currently, the only implementator of Configurator (the interface)
				// is configurator (the struct).
				return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
			}

			moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))
			ctx.Logger().Info(fmt.Sprintf("adding a new module: %s", moduleName))
			// The module manager assumes only one module will update the
			// validator set, and that it will not be by a new module.
			if len(moduleValUpdates) > 0 {
				return nil, sdkerrors.Wrapf(sdkerrors.ErrLogic, "validator InitGenesis updates already set by a previous module")
			}
		}

		updatedVM[moduleName] = toVersion
	}

	return updatedVM, nil
}
```
