# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain during upgrades that introduce new modules by sending coins to the predicted module account address before the upgrade executes. This creates a BaseAccount at that address, causing the upgrade to panic when the new module's InitGenesis attempts to retrieve or create a ModuleAccount, resulting in total network shutdown.

## Impact
High

## Finding Description

**Location:**
- Module address derivation: [1](#0-0) 
- Panic on type mismatch: [2](#0-1) 
- Auto-account creation: [3](#0-2) 
- Upgrade calls InitGenesis: [4](#0-3) 
- InitGenesis calls GetModuleAccount: [5](#0-4) 
- Upgrade handler propagates panic: [6](#0-5) 
- Blocked addresses mechanism: [7](#0-6) 

**Intended logic:**
When a chain upgrade adds a new module, the upgrade handler should call RunMigrations, which invokes InitGenesis for the new module. InitGenesis calls GetModuleAccount, which should either find an existing ModuleAccount or create a new one if the address is unused.

**Actual logic:**
Module account addresses are deterministically derived using crypto.AddressHash([]byte(moduleName)) [8](#0-7) . Before the upgrade, the new module is not in the old binary's maccPerms map [9](#0-8) , so its address is not in the blockedAddrs map. This allows an attacker to send coins to the predicted address, which automatically creates a BaseAccount [3](#0-2) . When the upgrade executes with the new binary (which includes the module in maccPerms), GetModuleAccount retrieves the existing account and attempts to cast it to ModuleAccountI. Since a BaseAccount exists instead, the type assertion fails and the code panics [10](#0-9) .

**Exploitation path:**
1. Attacker monitors governance for upgrade proposals adding new modules
2. Attacker extracts new module names from the publicly released upgrade binary
3. Attacker computes module address using crypto.AddressHash([]byte(moduleName))
4. Before upgrade height, attacker submits MsgSend transferring dust amount to predicted address
5. MsgSend handler checks BlockedAddr [11](#0-10)  which returns false (address not in blockedAddrs yet)
6. SendCoins creates BaseAccount at target address
7. At upgrade height, BeginBlocker calls applyUpgrade [12](#0-11) 
8. RunMigrations detects new module and calls its InitGenesis [4](#0-3) 
9. InitGenesis calls GetModuleAccount, which finds BaseAccount and panics
10. Panic propagates through ApplyUpgrade, halting all validators at the same height deterministically

**Security guarantee broken:**
The system assumes governance-approved upgrades will execute successfully. This vulnerability allows any unprivileged user to prevent upgrade execution, breaking the chain's liveness guarantee and governance security model.

## Impact Explanation

This vulnerability causes **total network shutdown** at the upgrade height. When the upgrade handler panics in BeginBlocker, the chain cannot progress. All validators experience the same deterministic panic, resulting in:

- Complete halt of block production at upgrade height
- No new transactions can be confirmed or processed
- All validator nodes stuck in identical failed state
- Economic activity ceases until emergency intervention
- Requires coordinated rollback or emergency hotfix deployment

The attack cost is minimal (only gas fees plus dust amount for transfer), while the impact is catastrophic. This matches the "Network not being able to confirm new transactions (total network shutdown)" impact criterion at High severity.

## Likelihood Explanation

**High Likelihood:**

**Who can trigger:** Any network participant with minimal funds to submit one transaction

**Required conditions:**
- Pending upgrade proposal visible in on-chain governance (public information)
- New module name visible in upgrade binary (publicly released before upgrade height)
- Ability to submit transaction before upgrade (normal network operation)

**Attack feasibility:**
- Extremely low barrier to entry (no special privileges required)
- Module names are trivially predictable from public upgrade binaries
- Upgrades are publicly announced with advance notice via governance
- The attacker's transaction appears as a normal coin transfer, making pre-emptive detection challenging

## Recommendation

**Primary Fix:** Modify GetModuleAccountAndPermissions to handle the case where a regular account exists at a module address gracefully rather than panicking. Check if the account is an empty BaseAccount and can be safely converted to a ModuleAccount. If the account has been used (non-zero sequence or has pubkey), return an error instead of panicking.

**Additional Mitigations:**

1. **Pre-upgrade validation:** Add a check in the upgrade handler that validates new module addresses are either unused or already proper ModuleAccounts before executing migrations

2. **Address derivation enhancement:** Consider adding a chain-specific salt or version parameter to module address derivation to make addresses unpredictable until upgrade execution

3. **Blocked addresses proactive update:** Add a mechanism to dynamically block predicted new module addresses once an upgrade proposal passes governance, or implement a grace period check

## Proof of Concept

**Setup:**
1. Create test app with AccountKeeper initialized with existing modules in maccPerms
2. Define a new module name not in current maccPerms: `newModuleName := "futuremodule"`
3. Compute predicted address: `predictedAddr := types.NewModuleAddress(newModuleName)`
4. Simulate attacker's front-running by creating BaseAccount at predicted address
5. Save the account to state

**Action:**
1. Simulate new binary by adding the new module to AccountKeeper's permAddrs map
2. Call `GetModuleAccount(ctx, newModuleName)` (as would happen during upgrade InitGenesis)

**Result:**
The call panics with "account is not a module account" because it finds a BaseAccount at the module address instead of a ModuleAccountI. This demonstrates that an attacker-created BaseAccount prevents proper module account initialization during upgrades, causing the chain to halt.

**Notes:**
The vulnerability exists at the intersection of: (1) deterministic module address derivation, (2) automatic BaseAccount creation when transferring coins, and (3) panic-based error handling in GetModuleAccount. The timing window between proposal passage and upgrade execution creates an exploitable race condition where any user can poison the module address before the upgrade protections activate.

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

**File:** x/bank/keeper/msg_server.go (L47-47)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
```

**File:** x/upgrade/abci.go (L71-71)
```go
		applyUpgrade(k, ctx, plan)
```
