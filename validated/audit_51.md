# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain during upgrades that introduce new modules by sending coins to the deterministically predictable module account address before the upgrade executes, creating a BaseAccount that causes the upgrade to panic during module initialization.

## Impact
Medium

## Finding Description

**Location:**
- Module address derivation: [1](#0-0) 
- Panic on type mismatch: [2](#0-1) 
- Auto-account creation on coin transfer: [3](#0-2) 
- BlockedAddr check in MsgSend: [4](#0-3) 
- BlockedAddr implementation: [5](#0-4) 
- Module account address mapping from maccPerms: [6](#0-5) 
- RunMigrations calls InitGenesis for new modules: [7](#0-6) 
- InitGenesis calls GetModuleAccount: [8](#0-7) 
- Upgrade handler error propagation: [9](#0-8) 
- BeginBlocker calls applyUpgrade: [10](#0-9) 

**Intended logic:**
When a chain upgrade adds a new module, the upgrade handler should successfully initialize the new module by either finding an existing ModuleAccount or creating one if the address is unused. Module account addresses should be protected from receiving direct transfers through the blockedAddrs mechanism, which blocks transfers to all module account addresses.

**Actual logic:**
Module account addresses are deterministically derived using `crypto.AddressHash([]byte(moduleName))`. Before an upgrade, the new module is not in the old binary's `maccPerms` map, so its address is not included in the `blockedAddrs` map that prevents coin transfers. This allows an attacker to send coins to the predicted module address, which automatically creates a BaseAccount at that address. When the upgrade executes with the new binary, `GetModuleAccount` retrieves the existing BaseAccount and attempts to cast it to `ModuleAccountI`. The type assertion fails, causing a panic with the message "account is not a module account".

**Exploitation path:**
1. Attacker monitors on-chain governance for upgrade proposals adding new modules
2. Attacker analyzes the publicly released upgrade binary to identify new module names
3. Attacker computes the future module address: `crypto.AddressHash([]byte(moduleName))`
4. Before the upgrade height, attacker submits a `MsgSend` transaction to the predicted address
5. The `BlockedAddr` check returns false (address not in old binary's blockedAddrs)
6. `SendCoins` succeeds and creates a BaseAccount at the target address
7. At upgrade height, `BeginBlocker` calls `applyUpgrade`
8. The upgrade handler invokes `RunMigrations`
9. `RunMigrations` detects the new module and calls its `InitGenesis`
10. `InitGenesis` calls `GetModuleAccount`, which retrieves the BaseAccount
11. Type assertion `macc, ok := acc.(types.ModuleAccountI)` fails (ok = false)
12. Code panics with "account is not a module account"
13. Panic propagates through upgrade handler, crashing all validators deterministically
14. Network halts - no blocks produced, no transactions confirmed

**Security guarantee broken:**
The system assumes governance-approved upgrades will execute successfully. This vulnerability allows any unprivileged user to prevent upgrade execution, breaking the chain's liveness guarantee and enabling denial-of-service through governance process manipulation. The blockedAddrs protection mechanism fails because it only protects addresses known to the current binary, not future module addresses.

## Impact Explanation

This vulnerability causes total network shutdown at the upgrade height. When the upgrade handler panics in `BeginBlocker`, the chain cannot progress. All validators experience the same deterministic panic at the identical block height, resulting in:

- Complete halt of block production at the upgrade height
- No new transactions can be confirmed or processed
- All validator nodes stuck in identical failed state  
- Economic activity ceases until emergency intervention
- Requires coordinated rollback or emergency hotfix deployment to recover

The attack cost is minimal (only transaction gas fees plus a dust amount for the transfer), while the impact is catastrophic. The deterministic nature ensures all validators fail simultaneously, preventing any possibility of normal consensus recovery.

## Likelihood Explanation

**High Likelihood**

**Who can trigger:** Any network participant with minimal funds to submit a single transaction (no special privileges or permissions required)

**Required conditions:**
- Pending upgrade proposal visible in on-chain governance (public information)
- New module name visible in upgrade binary (publicly released before upgrade height per standard practice)
- Ability to submit transaction before upgrade executes (normal network operation)

**Attack feasibility:**
- Extremely low barrier to entry - no special privileges or complex setup required
- Module names and addresses are trivially predictable from publicly available upgrade binaries
- Upgrades are announced days or weeks in advance through governance
- The attacker's transaction appears as a normal coin transfer, making pre-emptive detection difficult
- No rate limiting or special validation prevents this attack vector

The combination of public information availability, deterministic address computation, long advance notice periods, and minimal attack cost makes this highly likely to be exploited.

## Recommendation

**Primary Fix:** Modify `GetModuleAccountAndPermissions` to handle the case where a regular account exists at a module address gracefully rather than panicking:

1. Check if the existing account is a BaseAccount with zero sequence and no public key (indicating an unused account)
2. If so, convert it to a ModuleAccount by wrapping the BaseAccount using the existing `NewModuleAccount` function
3. If the account has been used (non-zero sequence or has pubkey), return an error that can be handled by the upgrade handler with clear diagnostics

**Additional Mitigations:**

1. **Pre-upgrade validation:** Add a validation step in the upgrade handler that checks new module addresses are either unused or already proper ModuleAccounts before executing migrations, allowing graceful failure with actionable error messages

2. **Blocked addresses proactive update:** Add a mechanism to dynamically block predicted new module addresses once an upgrade proposal passes governance, preventing coins from being sent during the pre-upgrade window

3. **Upgrade pre-flight check:** Implement validation that scans for BaseAccounts at predicted new module addresses and either converts them or fails gracefully before the critical upgrade logic executes

## Proof of Concept

**Setup:**
1. Create test app with AccountKeeper initialized with existing modules in maccPerms
2. Initialize BankKeeper with blockedAddrs derived from current maccPerms  
3. Define new module name not in current maccPerms: `newModuleName := "futuremodule"`
4. Compute predicted address: `predictedAddr := authtypes.NewModuleAddress(newModuleName)`
5. Create sender account with sufficient balance

**Action:**
1. Verify address is NOT blocked: `require.False(t, app.BankKeeper.BlockedAddr(predictedAddr))`
2. Send coins to predicted address: `app.BankKeeper.SendCoins(ctx, fromAddr, predictedAddr, coins)`
3. Verify BaseAccount created: `acc := app.AccountKeeper.GetAccount(ctx, predictedAddr)`
4. Confirm it's not a ModuleAccount: `_, ok := acc.(authtypes.ModuleAccountI); require.False(t, ok)`
5. Simulate upgrade by adding module to permAddrs: `app.AccountKeeper.permAddrs[newModuleName] = ...`
6. Call GetModuleAccount as would happen in InitGenesis: `app.AccountKeeper.GetModuleAccount(ctx, newModuleName)`

**Result:**
The `GetModuleAccount` call panics with "account is not a module account" because it finds a BaseAccount at the module address instead of a ModuleAccountI. This demonstrates that an attacker-created BaseAccount prevents proper module account initialization during upgrades, causing deterministic validator crashes and total network shutdown.

## Notes

The vulnerability exists at the intersection of three design choices: (1) deterministic and predictable module address derivation, (2) automatic BaseAccount creation when transferring coins to non-existent addresses, and (3) panic-based error handling in `GetModuleAccount` that doesn't gracefully handle type mismatches. The timing window between governance approval and upgrade execution creates an exploitable race condition where any user can poison module addresses before the blockedAddrs protection activates in the new binary.

This vulnerability matches the impact criterion "Network not being able to confirm new transactions (total network shutdown)" which is classified as Medium severity in the assessment framework.

### Citations

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
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

**File:** types/module/module.go (L562-584)
```go
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

**File:** x/upgrade/abci.go (L71-71)
```go
		applyUpgrade(k, ctx, plan)
```
