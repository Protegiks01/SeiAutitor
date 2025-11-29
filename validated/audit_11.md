# Audit Report

## Title
Front-Running Module Account Creation Causes Network-Wide Panic During Chain Upgrades

## Summary
An attacker can exploit the static nature of the `blockedAddrs` mechanism to pre-create a `BaseAccount` at a future module's deterministic address before a chain upgrade. During the upgrade, when `InitGenesis` calls `GetModuleAccount`, the system encounters the `BaseAccount` instead of the expected `ModuleAccountI`, triggering an unconditional panic that simultaneously halts all validators.

## Impact
High

## Finding Description

**Location:**
- Panic location: [1](#0-0) 
- Account creation: [2](#0-1) 
- Blocked address check: [3](#0-2) 
- Module address calculation: [4](#0-3) 
- Blocked addresses initialization: [5](#0-4) 

**Intended Logic:**
Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses. The `blockedAddrs` mechanism should prevent regular users from creating accounts at module addresses. When a chain upgrade adds a new module, `GetModuleAccount` should safely create the module account during `InitGenesis`.

**Actual Logic:**
The `blockedAddrs` map is populated only from existing modules in `maccPerms` at app initialization [6](#0-5) . Future modules added via upgrade are not in this map. When an attacker sends coins to a future module address, the `BlockedAddr` check passes because the address isn't blocked yet [7](#0-6) . This creates a `BaseAccount` at the module address using the default account prototype [8](#0-7)  which is configured as `ProtoBaseAccount` [9](#0-8) . During the upgrade, when `GetModuleAccountAndPermissions` retrieves this account and finds it's not a `ModuleAccountI`, it executes an unconditional panic.

**Exploitation Path:**
1. Attacker observes upgrade proposal announcing new module "newmodule" with upgrade height 100000
2. Attacker calculates deterministic module address using `crypto.AddressHash([]byte("newmodule"))` 
3. Before upgrade (e.g., block 99990), attacker submits `MsgSend` with 1 token to the calculated address
4. `Send` handler checks `BlockedAddr(to)` - returns false because address is not in `blockedAddrs` yet
5. `SendCoins` creates `BaseAccount` at module address via `NewAccountWithAddress`
6. At block 100000, upgrade executes and `RunMigrations` is called [10](#0-9) 
7. New module's `InitGenesis` is called for modules not in fromVM [11](#0-10) 
8. `InitGenesis` calls `GetModuleAccount` which calls `GetModuleAccountAndPermissions`
9. `GetModuleAccountAndPermissions` finds `BaseAccount` at module address, type assertion fails, panic occurs
10. All validators panic at the same height during consensus execution
11. Network completely halts

**Security Guarantee Broken:**
Network availability and upgrade safety are violated. The deterministic module address derivation combined with the static `blockedAddrs` map creates a race condition where attackers can claim future module addresses before they're protected.

## Impact Explanation

This vulnerability causes complete network shutdown affecting all validators simultaneously. When all validators panic at the same block height during upgrade execution:

- No new transactions can be confirmed after the upgrade height
- The upgrade plan is consumed but module initialization failed, leaving state inconsistent
- Chain cannot progress without manual intervention
- Recovery requires coordinated hard fork with state export/import or emergency patch
- Existing upgrade cannot be rolled back cleanly

This matches the specified impact criterion: "Network not being able to confirm new transactions (total network shutdown)."

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

The combination of public information, minimal cost, large attack window, and inability to detect makes exploitation highly likely.

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

**Test Setup:**
1. Create test app and context
2. Calculate deterministic module address for "testmodule" using `types.NewModuleAddress("testmodule")`
3. Fund an attacker account with tokens

**Action:**
1. Before the module is added to `maccPerms`, send 1 token to the calculated module address via `BankKeeper.SendCoins`
2. Verify a `BaseAccount` is created at the module address (type assertion confirms it's not a `ModuleAccount`)
3. Update the app's `maccPerms` to include "testmodule" and reinitialize the AccountKeeper with the new permissions
4. Call `GetModuleAccount(ctx, "testmodule")`

**Expected Result:**
- `GetModuleAccount` panics with message "account is not a module account"
- Demonstrates that validators would crash during actual upgrade when `InitGenesis` is called
- Confirms the network shutdown scenario

## Notes

The vulnerability stems from a fundamental design assumption that module addresses are "reserved" through the `blockedAddrs` mechanism, but this mechanism is static and only protects addresses of modules that exist at initialization time. The deterministic address derivation allows attackers to precompute future module addresses, and the account creation logic permits account creation at any non-blocked address. Combined with the unconditional panic and the upgrade flow that calls `InitGenesis` for new modules, this creates a critical vulnerability in the upgrade process.

### Citations

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

**File:** x/bank/keeper/send.go (L166-170)
```go
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
	}
```

**File:** x/bank/keeper/send.go (L348-355)
```go
func (k BaseSendKeeper) BlockedAddr(addr sdk.AccAddress) bool {
	if len(addr) == len(CoinbaseAddressPrefix)+8 {
		if bytes.Equal(CoinbaseAddressPrefix, addr[:len(CoinbaseAddressPrefix)]) {
			return true
		}
	}
	return k.blockedAddrs[addr.String()]
}
```

**File:** x/bank/keeper/msg_server.go (L47-47)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
```

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** simapp/app.go (L135-142)
```go
	maccPerms = map[string][]string{
		authtypes.FeeCollectorName:     nil,
		distrtypes.ModuleName:          nil,
		minttypes.ModuleName:           {authtypes.Minter},
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
		govtypes.ModuleName:            {authtypes.Burner},
	}
```

**File:** simapp/app.go (L261-263)
```go
	app.AccountKeeper = authkeeper.NewAccountKeeper(
		appCodec, keys[authtypes.StoreKey], app.GetSubspace(authtypes.ModuleName), authtypes.ProtoBaseAccount, maccPerms,
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

**File:** types/module/module.go (L575-589)
```go
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
```

**File:** x/mint/genesis.go (L13-13)
```go
	ak.GetModuleAccount(ctx, types.ModuleName)
```
