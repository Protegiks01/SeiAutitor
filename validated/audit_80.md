# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain by sending coins to a predicted future module account address before a chain upgrade executes. This causes automatic creation of a `BaseAccount` at the module address, which triggers a panic during upgrade initialization when `GetModuleAccount` expects a `ModuleAccountI`, halting all validator nodes.

## Impact
Medium

## Finding Description

**Location:**
- Module address derivation: [1](#0-0) 
- Panic condition: [2](#0-1) 
- Account auto-creation: [3](#0-2) 
- BlockedAddr check: [4](#0-3) 
- Blocklist population: [5](#0-4) 
- Module permissions map: [6](#0-5) 
- New module InitGenesis trigger: [7](#0-6) 
- InitGenesis calling GetModuleAccount: [8](#0-7) 
- Upgrade execution flow: [9](#0-8) 
- Panic propagation: [10](#0-9) 

**Intended Logic:**
When a chain upgrade introduces a new module, `GetModuleAccount` should create a `ModuleAccountI` at the deterministic module address during `InitGenesis`. If no account exists at that address, it creates a new module account. If a module account already exists, it returns it.

**Actual Logic:**
The `GetModuleAccount` function performs a type assertion and panics if it finds a `BaseAccount` instead of a `ModuleAccountI` at the module address. [11](#0-10)  The `BlockedAddr` mechanism only prevents sending coins to existing module accounts listed in the `blockedAddrs` map, which is populated from the current `maccPerms` at application initialization. [5](#0-4)  Future module addresses from pending upgrades are not included in this blocklist, allowing attackers to send coins to these predictable addresses, which triggers automatic `BaseAccount` creation. [3](#0-2) 

**Exploitation Path:**
1. Attacker monitors governance proposals for scheduled upgrades and downloads the upgrade binary
2. Identifies new module names added to `maccPerms` by inspecting the binary or source code
3. Computes the future module address using the deterministic formula in [1](#0-0) 
4. Submits a `MsgSend` transaction transferring coins to the predicted address
5. The `BlockedAddr` check passes because the future module address is not in the current `blockedAddrs` map [4](#0-3) 
6. A `BaseAccount` is automatically created at the module address when coins are received [3](#0-2) 
7. At upgrade height, `BeginBlocker` executes the upgrade handler [9](#0-8) 
8. The handler calls `RunMigrations`, which detects the new module (not in `fromVM`) and calls `InitGenesis` [12](#0-11) 
9. `InitGenesis` calls `GetModuleAccount` [8](#0-7) 
10. `GetModuleAccount` finds a `BaseAccount`, fails the type assertion, and panics [11](#0-10) 
11. The panic propagates uncaught through `ApplyUpgrade` [10](#0-9)  halting all validator nodes

**Security Guarantee Broken:**
The system assumes governance-approved upgrades will execute successfully at the designated height. This vulnerability allows any unprivileged user to prevent approved upgrades from completing by exploiting the predictable module address generation and lack of forward-looking address blocking.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes halt execution at the upgrade height and cannot produce or commit new blocks
- **No transaction processing**: The network becomes unable to confirm any new transactions, freezing all blockchain activity  
- **Emergency intervention required**: Recovery requires coordinated action such as rollback, hotfix binary release, or out-of-band coordination among validators
- **Economic disruption**: All blockchain services cease operation until resolution
- **Governance undermined**: Legitimate governance-approved upgrades become attack vectors

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category, classified as **Medium severity**.

## Likelihood Explanation

**Trigger Conditions:**
- **Public information**: Upgrade proposals and binaries are publicly available on-chain and in repositories
- **Low cost**: Attack requires only standard transaction fees plus minimal coin amount (dust quantities work)
- **No privileges required**: Any user capable of submitting transactions can execute this attack
- **High frequency**: Every upgrade introducing new modules with module accounts is vulnerable
- **Trivial timing**: Attacker only needs to submit the transaction before upgrade height (potentially weeks in advance)

**Attacker Profile:**
- Requires basic blockchain interaction skills (ability to submit transactions)
- Needs ability to inspect binaries/source to identify new module names
- Must understand module address derivation algorithm (publicly documented)
- No special access, permissions, or resources required beyond a funded account

**Probability:**
High likelihood of exploitation. The attack is straightforward, low-cost, and can systematically target every future upgrade that adds modules. The deterministic nature of module addresses makes the attack highly reliable.

## Recommendation

**Immediate Fix:**
Modify `GetModuleAccountAndPermissions` to handle `BaseAccount` gracefully:
1. Check if the account has non-zero sequence number or balance
2. If the BaseAccount is empty, safely remove it using [13](#0-12) 
3. If the BaseAccount has been used, return an error instead of panicking
4. Create the proper ModuleAccount after removal

**Additional Protections:**
1. **Pre-upgrade validation**: Add validation that checks for account conflicts at future module addresses before executing the upgrade handler
2. **Extended blocking**: When an upgrade proposal is submitted, dynamically add predicted future module addresses to the `BlockedAddr` list
3. **Upgrade plan validation**: Add governance proposal validation that checks for conflicts at future module addresses when upgrades are proposed

## Proof of Concept

**Test Setup:**
1. Initialize test application with current modules using simapp
2. Identify future module name (e.g., "newmodule") to be added in upgrade
3. Compute predicted module address: `futureAddr := authtypes.NewModuleAddress("newmodule")`
4. Create and fund attacker account
5. Execute `bankKeeper.SendCoins(ctx, attackerAddr, futureAddr, coins)`
6. Verify `BaseAccount` exists at `futureAddr` using `accountKeeper.GetAccount(ctx, futureAddr)`

**Action:**
1. Add "newmodule" to `maccPerms` map to simulate upgrade
2. Call `accountKeeper.GetModuleAccount(ctx, "newmodule")`

**Result:**
The call panics with "account is not a module account", demonstrating that the `BaseAccount` at the predicted address causes the panic that would halt the chain during a real upgrade. This confirms all validators would experience identical behavior at the upgrade height, causing consensus failure and total network shutdown.

## Notes

This vulnerability demonstrates a critical gap in upgrade safety mechanisms where deterministic address generation for module accounts creates a predictable attack surface. The issue is exacerbated by the separation between blocklist population (at app initialization with current modules) and module addition (during upgrades). The lack of error handling for unexpected account types at module addresses transforms what should be a recoverable error into a consensus-halting panic.

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

**File:** x/bank/keeper/msg_server.go (L47-48)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
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

**File:** x/upgrade/abci.go (L115-117)
```go
func applyUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	ctx.Logger().Info(fmt.Sprintf("applying upgrade \"%s\" at %s", plan.Name, plan.DueAt()))
	k.ApplyUpgrade(ctx, plan)
```

**File:** x/upgrade/keeper/keeper.go (L371-373)
```go
	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
```

**File:** x/auth/keeper/account.go (L68-74)
```go
// RemoveAccount removes an account for the account mapper store.
// NOTE: this will cause supply invariant violation if called
func (ak AccountKeeper) RemoveAccount(ctx sdk.Context, acc types.AccountI) {
	addr := acc.GetAddress()
	store := ctx.KVStore(ak.key)
	store.Delete(types.AddressStoreKey(addr))
}
```
