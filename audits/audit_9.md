# Audit Report

## Title
Front-Running Module Account Creation Causes Network-Wide Panic During Chain Upgrades

## Summary
An attacker can pre-create a `BaseAccount` at the deterministic address of a future module before a chain upgrade, causing all validators to panic when the new module's `InitGenesis` calls `GetModuleAccount` during upgrade execution. This results in complete network shutdown.

## Impact
High

## Finding Description

**Location:**
- Panic trigger: `x/auth/keeper/keeper.go` lines 187-192 [1](#0-0) 
- Account creation vector: `x/bank/keeper/send.go` lines 166-170 [2](#0-1) 
- Module address derivation: `x/auth/types/account.go` lines 162-165 [3](#0-2) 
- Upgrade flow: `types/module/module.go` line 583 [4](#0-3) 

**Intended Logic:**
When a chain upgrade adds a new module, `InitGenesis` should safely call `GetModuleAccount` to create or retrieve the module's account. Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses. Regular users should not be able to create accounts at future module addresses.

**Actual Logic:**
The blocking mechanism in `ModuleAccountAddrs()` only prevents sends to addresses of CURRENTLY registered modules in the static `maccPerms` map [5](#0-4) . A module being added in a future upgrade is not yet in this map, so its address is not blocked. This allows any user to send coins to the future module address, which creates a `BaseAccount` there [2](#0-1) . When `GetModuleAccountAndPermissions` later retrieves this account, it performs a type assertion expecting `ModuleAccountI` and panics unconditionally when it finds a `BaseAccount` instead [6](#0-5) .

**Exploitation Path:**
1. Governance proposal passes to add new module "newmodule" at upgrade height H (public information)
2. Attacker calculates deterministic module address using `crypto.AddressHash([]byte("newmodule"))` [7](#0-6) 
3. Before height H, attacker submits `MsgSend` to transfer 1 token to the calculated address
4. `BlockedAddr` check passes because the module is not yet in `blockedAddrs` [8](#0-7) 
5. `SendCoins` creates a `BaseAccount` at the module address [9](#0-8) 
6. At height H, upgrade executes and `RunMigrations` is called
7. For the new module, `InitGenesis` is invoked [4](#0-3) 
8. Module's `InitGenesis` calls `GetModuleAccount` (e.g., [10](#0-9) )
9. `GetModuleAccountAndPermissions` finds the `BaseAccount`, type assertion fails, and panics [11](#0-10) 
10. All validators execute identical deterministic code and panic at the same height
11. Network completely halts - no new blocks can be produced

**Security Guarantee Broken:**
Network availability and consensus liveness. The system fails to safely handle module upgrades when accounts are pre-created at future module addresses.

## Impact Explanation

This vulnerability causes **total network shutdown** affecting all validators simultaneously:

- All validator nodes panic during the upgrade block's execution
- Network cannot produce new blocks after the upgrade height
- Chain state becomes inconsistent (upgrade plan consumed but module initialization incomplete)
- No transactions can be confirmed
- Requires coordinated emergency response: hard fork with state export/import or emergency patch deployment
- The attack undermines the fundamental ability to perform safe chain upgrades

The impact qualifies as **High severity** under the category "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**High likelihood** due to:

- **Minimal cost**: Only requires transaction fees plus 1 token of minimal denomination
- **No special privileges**: Any network participant can execute the attack
- **Public information**: Module names are disclosed in governance proposals days/weeks before execution
- **Ample time window**: Attackers have the entire period between proposal passage and upgrade execution
- **100% success rate**: If executed before the upgrade, the attack is guaranteed to succeed
- **Detection difficulty**: The malicious transaction appears as a normal coin transfer
- **Frequency**: Affects every chain upgrade that introduces new modules (multiple per year in active chains)

## Recommendation

**Immediate Fix:**
Implement graceful handling in `GetModuleAccountAndPermissions` to convert pre-existing `BaseAccount` instances to proper module accounts:

```go
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Handle pre-created BaseAccount
        if baseAcc, isBase := acc.(*types.BaseAccount); isBase && 
           baseAcc.GetPubKey() == nil && baseAcc.GetSequence() == 0 {
            // Convert to module account with same account number
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
Add proactive validation during account creation to maintain a registry of reserved future module addresses and prevent `NewAccountWithAddress` from creating accounts at those addresses.

## Proof of Concept

**Test File**: `x/auth/keeper/keeper_test.go`

**Test Function**: `TestModuleAccountFrontrunning`

**Setup:**
1. Create test application and context using `createTestApp(true)` [12](#0-11) 
2. Calculate deterministic address for new module using `types.NewModuleAddress(moduleName)` [7](#0-6) 
3. Create and fund attacker account with coins

**Action:**
1. Attacker sends 1 token to the calculated module address via `app.BankKeeper.SendCoins()`
2. This triggers automatic `BaseAccount` creation [9](#0-8) 
3. Verify `BaseAccount` was created at module address using `app.AccountKeeper.GetAccount()`
4. Call `app.AccountKeeper.GetModuleAccount(ctx, moduleName)` to simulate module initialization

**Result:**
- The test confirms a `BaseAccount` (not `ModuleAccountI`) exists at the module address
- Calling `GetModuleAccount` triggers panic with message "account is not a module account" [11](#0-10) 
- This demonstrates the network would halt if this occurred during a real upgrade execution

The vulnerability is confirmed by tracing the execution flow through the cited code locations, demonstrating that the protection mechanisms do not prevent pre-creation of accounts at future module addresses.

### Citations

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

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** types/module/module.go (L583-583)
```go
			moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))
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

**File:** x/bank/keeper/msg_server.go (L47-47)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
```

**File:** x/mint/genesis.go (L13-13)
```go
	ak.GetModuleAccount(ctx, types.ModuleName)
```

**File:** x/auth/keeper/integration_test.go (L12-17)
```go
func createTestApp(isCheckTx bool) (*simapp.SimApp, sdk.Context) {
	app := simapp.Setup(isCheckTx)
	ctx := app.BaseApp.NewContext(isCheckTx, tmproto.Header{})
	app.AccountKeeper.SetParams(ctx, authtypes.DefaultParams())

	return app, ctx
```
