# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain during upgrades that introduce new modules by sending coins to the deterministically predictable module account address before the upgrade executes. This creates a BaseAccount at that address, causing the upgrade to panic when InitGenesis attempts to retrieve or create a ModuleAccount, resulting in total network shutdown.

## Impact
High

## Finding Description

**Location:**
- Module address derivation: [1](#0-0) 
- Panic on type mismatch: [2](#0-1) 
- Auto-account creation: [3](#0-2) 
- RunMigrations calls InitGenesis: [4](#0-3) 
- InitGenesis calls GetModuleAccount: [5](#0-4) 
- Upgrade handler propagates panic: [6](#0-5) 
- BlockedAddr check in MsgSend: [7](#0-6) 
- Module account address mapping: [8](#0-7) 

**Intended logic:**
When a chain upgrade adds a new module, the upgrade handler calls RunMigrations, which invokes InitGenesis for the new module. InitGenesis calls GetModuleAccount, which should either find an existing ModuleAccount or create a new one if the address is unused. Module account addresses should be protected from receiving direct transfers through the blockedAddrs mechanism.

**Actual logic:**
Module account addresses are deterministically derived from the module name using a hash function. Before the upgrade, the new module is not in the old binary's maccPerms map, so its address is not in the blockedAddrs map during pre-upgrade operation. This allows an attacker to send coins to the predicted address, which automatically creates a BaseAccount. When the upgrade executes with the new binary (which includes the module in maccPerms), GetModuleAccount retrieves the existing account and attempts to cast it to ModuleAccountI. Since a BaseAccount exists instead of a ModuleAccount, the type assertion fails and the code panics with "account is not a module account".

**Exploitation path:**
1. Attacker monitors on-chain governance for upgrade proposals that add new modules
2. Attacker analyzes the publicly released upgrade binary to extract new module names
3. Attacker computes the future module address using crypto.AddressHash([]byte(moduleName))
4. Before the upgrade height, attacker submits a MsgSend transaction transferring a minimal amount to the predicted address
5. The MsgSend handler checks BlockedAddr which returns false (address not yet in blockedAddrs map from old binary)
6. SendCoins creates a BaseAccount at the target address
7. At upgrade height, BeginBlocker calls applyUpgrade [9](#0-8) 
8. ApplyUpgrade calls the upgrade handler which invokes RunMigrations
9. RunMigrations detects the new module (not in fromVM) and calls InitGenesis
10. InitGenesis calls GetModuleAccount, which retrieves the BaseAccount and panics during type assertion
11. Panic propagates through ApplyUpgrade, causing all validators to halt at the same height deterministically

**Security guarantee broken:**
The system assumes governance-approved upgrades will execute successfully. This vulnerability allows any unprivileged user to prevent upgrade execution, breaking the chain's liveness guarantee and governance security model. The protection mechanism (blockedAddrs) fails because it only protects addresses known to the current binary, not future module addresses.

## Impact Explanation

This vulnerability causes **total network shutdown** at the upgrade height, matching the "Network not being able to confirm new transactions (total network shutdown)" impact criterion. When the upgrade handler panics in BeginBlocker, the chain cannot progress. All validators experience the same deterministic panic, resulting in:

- Complete halt of block production at the upgrade height
- No new transactions can be confirmed or processed
- All validator nodes stuck in identical failed state
- Economic activity ceases until emergency intervention
- Requires coordinated rollback or emergency hotfix deployment

The attack cost is minimal (only gas fees plus dust amount for transfer), while the impact is catastrophic. The deterministic nature ensures all validators fail simultaneously, preventing any possibility of consensus recovery.

## Likelihood Explanation

**High Likelihood:**

**Who can trigger:** Any network participant with minimal funds to submit one transaction (no special privileges or permissions required)

**Required conditions:**
- Pending upgrade proposal visible in on-chain governance (public information available to all)
- New module name visible in upgrade binary (publicly released before upgrade height per standard practice)
- Ability to submit transaction before upgrade executes (normal network operation)

**Attack feasibility:**
- Extremely low barrier to entry (no special privileges, no complex setup)
- Module names and addresses are trivially predictable from public upgrade binaries
- Upgrades are publicly announced with days or weeks of advance notice via governance
- The attacker's transaction appears as a normal coin transfer, making pre-emptive detection challenging
- No rate limiting or special checks prevent this attack vector

The combination of public information, deterministic address computation, and minimal cost makes this highly likely to be exploited by adversaries or even accidentally triggered.

## Recommendation

**Primary Fix:** Modify GetModuleAccountAndPermissions to handle the case where a regular account exists at a module address gracefully rather than panicking. Implement logic to:
1. Check if the existing account is a BaseAccount with zero sequence and no pubkey (unused account)
2. If so, convert it to a ModuleAccount by wrapping the BaseAccount
3. If the account has been used (non-zero sequence or has pubkey), return an error that can be handled by the upgrade handler

**Additional Mitigations:**

1. **Pre-upgrade validation:** Add a validation step in the upgrade handler that checks new module addresses are either unused or already proper ModuleAccounts before executing migrations. This allows the upgrade to abort gracefully with a clear error message rather than panicking.

2. **Address derivation enhancement:** Consider adding a chain-specific salt or version parameter to module address derivation to make addresses unpredictable until upgrade execution, or use a different address derivation mechanism for new modules.

3. **Blocked addresses proactive update:** Add a mechanism to dynamically block predicted new module addresses once an upgrade proposal passes governance, preventing coins from being sent to these addresses during the pre-upgrade window.

4. **Upgrade pre-flight check:** Implement a pre-flight validation in the upgrade handler that scans for any BaseAccounts at predicted new module addresses and either converts them or fails gracefully with actionable error messages.

## Proof of Concept

**Setup:**
1. Create test app with AccountKeeper initialized with existing modules in maccPerms map
2. Initialize bank keeper with blockedAddrs derived from current maccPerms
3. Define a new module name not in current maccPerms: `newModuleName := "futuremodule"`
4. Compute predicted address: `predictedAddr := types.NewModuleAddress(newModuleName)`
5. Simulate attacker's front-running by sending coins to predicted address via SendCoins
6. Verify BaseAccount is created at the predicted address

**Action:**
1. Simulate upgrade by adding the new module to AccountKeeper's permAddrs map (simulating new binary)
2. Call `GetModuleAccount(ctx, newModuleName)` as would happen during InitGenesis execution
3. Observe the panic behavior

**Result:**
The GetModuleAccount call panics with "account is not a module account" because it finds a BaseAccount at the module address instead of a ModuleAccountI. This demonstrates that an attacker-created BaseAccount prevents proper module account initialization during upgrades, causing the chain to halt.

**Test pseudocode:**
```go
// 1. Setup with old binary configuration
app := setupTestApp()
ctx := app.NewContext(false, tmproto.Header{})
newModuleName := "futuremodule"
predictedAddr := authtypes.NewModuleAddress(newModuleName)

// 2. Attacker action (before upgrade)
// BlockedAddr returns false because futuremodule not in old maccPerms
require.False(t, app.BankKeeper.BlockedAddr(predictedAddr))
// Send coins creates BaseAccount
err := app.BankKeeper.SendCoins(ctx, fromAddr, predictedAddr, coins)
require.NoError(t, err)
// Verify BaseAccount exists
acc := app.AccountKeeper.GetAccount(ctx, predictedAddr)
_, ok := acc.(authtypes.ModuleAccountI)
require.False(t, ok) // It's a BaseAccount, not ModuleAccount

// 3. Simulate upgrade with new binary (add module to permAddrs)
app.AccountKeeper.permAddrs[newModuleName] = authtypes.NewPermissionsForAddress(newModuleName, []string{})

// 4. This would panic in real upgrade
require.Panics(t, func() {
    app.AccountKeeper.GetModuleAccount(ctx, newModuleName)
})
```

## Notes

The vulnerability exists at the intersection of three design choices: (1) deterministic and predictable module address derivation, (2) automatic BaseAccount creation when transferring coins to non-existent addresses, and (3) panic-based error handling in GetModuleAccount that doesn't gracefully handle type mismatches. The timing window between governance approval and upgrade execution creates an exploitable race condition where any user can poison the module address before the blockedAddrs protection activates in the new binary.

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

**File:** types/module/module.go (L583-584)
```go
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

**File:** x/upgrade/abci.go (L71-71)
```go
		applyUpgrade(k, ctx, plan)
```
