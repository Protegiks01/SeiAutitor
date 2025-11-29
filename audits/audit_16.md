# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain during upgrades that introduce new modules by sending coins to the predicted module account address before the upgrade executes. This creates a BaseAccount at that address, which causes the upgrade to panic when the new module's InitGenesis attempts to retrieve or create a ModuleAccount, finding an incompatible account type instead.

## Impact
High

## Finding Description

**Location:**
- Module address derivation: [1](#0-0) 
- Panic on type mismatch: [2](#0-1) 
- Auto-account creation: [3](#0-2) 
- Upgrade calls InitGenesis for new modules: [4](#0-3) 
- InitGenesis calls GetModuleAccount: [5](#0-4) 
- Upgrade handler propagates panic: [6](#0-5) 

**Intended Logic:**
When a chain upgrade adds a new module, the upgrade handler should call `RunMigrations`, which invokes `InitGenesis` for the new module. `InitGenesis` calls `GetModuleAccount`, which should either find an existing ModuleAccount or create a new one if the address is unused.

**Actual Logic:**
Module account addresses are deterministically derived using `crypto.AddressHash([]byte(moduleName))`. An attacker can predict the address of a future module by examining the upgrade binary. Before the upgrade height, the attacker sends any amount of coins to this predicted address. The `SendCoins` function automatically creates a `BaseAccount` at any recipient address that doesn't exist. When the upgrade executes, `RunMigrations` calls the new module's `InitGenesis`, which calls `GetModuleAccount`. This function retrieves the existing account and attempts to cast it to `ModuleAccountI`. Since a `BaseAccount` exists instead, the type assertion fails and the code panics with "account is not a module account".

**Exploitation Path:**
1. Attacker monitors on-chain governance for upgrade proposals that add new modules
2. Attacker downloads or inspects the upgrade binary to identify new module names from the `maccPerms` map [7](#0-6) 
3. Attacker computes the module account address: `crypto.AddressHash([]byte(newModuleName))`
4. Before the upgrade height, attacker submits a standard `MsgSend` transaction transferring any amount (even dust) to the predicted address
5. The bank keeper's `SendCoins` creates a `BaseAccount` at the target address
6. At the upgrade height, the upgrade handler executes via `BeginBlocker` [8](#0-7) 
7. The handler calls `RunMigrations`, which detects the new module and calls its `InitGenesis`
8. `InitGenesis` calls `GetModuleAccount`, which finds the `BaseAccount` and panics
9. The panic propagates through `ApplyUpgrade`, causing the upgrade transaction to fail
10. All validator nodes halt at the same height with the same panic, preventing the chain from producing new blocks

**Security Guarantee Broken:**
The system assumes governance-approved upgrades will execute successfully. This vulnerability allows any unprivileged user to prevent upgrade execution, breaking the chain's liveness and governance security model.

## Impact Explanation

This vulnerability causes a **total network shutdown**. When the upgrade handler panics, the chain cannot progress past the upgrade height. All validators experience the same panic deterministically, resulting in:

- Complete halt of block production at the upgrade height
- No new transactions can be confirmed or processed
- All validator nodes stuck in the same failed state
- Economic activity ceases until emergency intervention
- Requires coordinated rollback or emergency hotfix binary deployment
- Breaks the fundamental guarantee that governance-approved upgrades will succeed

The attack cost is minimal (only gas fees plus a dust amount for the transfer), while the impact is catastrophic. The chain remains halted until validators coordinate an emergency response, which may take hours or days depending on governance and coordination overhead.

## Likelihood Explanation

**High Likelihood:**

- **Who can trigger:** Any network participant with minimal funds to submit one transaction
- **Required conditions:**
  - Pending upgrade proposal visible in on-chain governance (public information)
  - New module name visible in upgrade binary (publicly released before upgrade height)
  - Ability to submit transaction before upgrade (normal network operation)
  
- **Attack feasibility:** 
  - Extremely low barrier to entry (no special privileges or significant capital required)
  - Module names and addresses are trivially predictable
  - Upgrades are publicly announced with advance notice
  - Once discovered, this attack can be systematically applied to all future upgrades adding modules
  
- **Detection difficulty:** The attacker's transaction appears as a normal coin transfer, making pre-emptive detection and prevention challenging

The combination of high impact and high likelihood makes this a critical vulnerability that threatens the network's ability to upgrade safely.

## Recommendation

**Primary Fix:** Modify `GetModuleAccountAndPermissions` to handle the case where a regular account exists at a module address gracefully rather than panicking:

```go
acc := ak.GetAccount(ctx, addr)
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Check if account is empty and can be safely converted
        if acc.GetSequence() == 0 && acc.GetPubKey() == nil {
            // Convert empty BaseAccount to ModuleAccount
            macc = types.NewModuleAccount(acc.(*types.BaseAccount), moduleName, perms...)
            ak.SetAccount(ctx, macc)
            return macc, perms
        }
        // Return error instead of panic for non-empty accounts
        return nil, []string{}
    }
    return macc, perms
}
```

**Additional Mitigations:**

1. **Pre-upgrade validation:** Add a check in the upgrade handler that validates new module addresses are either unused or already proper ModuleAccounts before executing migrations

2. **Address derivation enhancement:** Consider adding a chain-specific salt or version parameter to module address derivation to make addresses unpredictable until upgrade execution

3. **Blocked addresses proactive update:** Add a mechanism to block predicted new module addresses once an upgrade proposal passes governance

## Proof of Concept

**File:** `x/auth/keeper/keeper_test.go`

**Test Function:** `TestModuleAccountFrontRunningAttack`

**Setup:**
1. Create test app using `createTestApp(true)` [9](#0-8) 
2. Define a new module name that doesn't exist in current maccPerms: `newModuleName := "futuremodule"`
3. Predict the module address: `predictedAddr := types.NewModuleAddress(newModuleName)`
4. Create a BaseAccount at predicted address: `baseAcc := app.AccountKeeper.NewAccountWithAddress(ctx, predictedAddr)`
5. Save the account: `app.AccountKeeper.SetAccount(ctx, baseAcc)`

**Action:**
1. Simulate upgrade by creating new AccountKeeper with updated maccPerms including the new module
2. Call `newKeeper.GetModuleAccount(ctx, newModuleName)`

**Result:**
The call to `GetModuleAccount` panics with "account is not a module account" because it finds a BaseAccount at the module address instead of a ModuleAccountI. This demonstrates that an attacker-created BaseAccount prevents proper module account initialization, which would cause the upgrade to fail and halt the chain.

The test can be verified by:
```go
require.Panics(t, func() {
    newKeeper.GetModuleAccount(ctx, newModuleName)
}, "Expected panic when BaseAccount exists at module address")
```

## Notes

This vulnerability exists at the intersection of three design choices:
1. Deterministic and predictable module account address derivation
2. Automatic BaseAccount creation when transferring coins to any address
3. Strict type checking with panic rather than error handling

The vulnerability specifically affects upgrades that introduce new modules because existing module addresses are already in the `blockedAddrs` map [10](#0-9) , preventing coin transfers to them. However, new module addresses are not blocked until after the upgrade completes, creating a window of vulnerability between proposal passage and upgrade execution.

### Citations

**File:** x/auth/types/account.go (L163-165)
```go
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** x/auth/keeper/keeper.go (L187-192)
```go
	acc := ak.GetAccount(ctx, addr)
	if acc != nil {
		macc, ok := acc.(types.ModuleAccountI)
		if !ok {
			panic("account is not a module account")
		}
```

**File:** x/bank/keeper/send.go (L166-170)
```go
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
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

**File:** x/upgrade/keeper/keeper.go (L371-374)
```go
	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
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

**File:** x/upgrade/abci.go (L71-71)
```go
		applyUpgrade(k, ctx, plan)
```

**File:** x/auth/keeper/integration_test.go (L11-18)
```go
// returns context and app with params set on account keeper
func createTestApp(isCheckTx bool) (*simapp.SimApp, sdk.Context) {
	app := simapp.Setup(isCheckTx)
	ctx := app.BaseApp.NewContext(isCheckTx, tmproto.Header{})
	app.AccountKeeper.SetParams(ctx, authtypes.DefaultParams())

	return app, ctx
}
```
