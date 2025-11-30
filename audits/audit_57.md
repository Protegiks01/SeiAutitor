# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain by sending coins to a predicted future module account address before a chain upgrade executes. The deterministic module address derivation allows predicting addresses, automatic account creation enables creating a `BaseAccount` at the target address, and `GetModuleAccount` panics when it encounters a `BaseAccount` instead of a `ModuleAccountI` during upgrade initialization, halting all validator nodes.

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
When a chain upgrade introduces a new module, `GetModuleAccount` should create a `ModuleAccountI` at the deterministic module address during `InitGenesis`. If no account exists at that address, it creates a new module account. If a module account already exists, it returns it for use by the module.

**Actual Logic:**
The `GetModuleAccount` function performs a type assertion and panics if it finds a `BaseAccount` instead of a `ModuleAccountI` at the module address. While `BlockedAddr` prevents sending coins to existing module accounts, the blocklist is populated only from the current `maccPerms` map at application initialization. Future module addresses from pending upgrades are not included in this blocklist, allowing attackers to send coins to these predictable addresses, which triggers automatic `BaseAccount` creation.

**Exploitation Path:**
1. Attacker monitors on-chain governance proposals for scheduled upgrades
2. Downloads the upgrade binary and inspects the source or binary to identify new module names added to `maccPerms`
3. Computes the future module address using the deterministic formula: `crypto.AddressHash([]byte(newModuleName))`
4. Submits a `MsgSend` transaction transferring coins (even dust amounts) to the predicted address
5. The `BlockedAddr` check passes because the future module address is not in the current `blockedAddrs` map
6. A `BaseAccount` is automatically created at the module address when coins are received
7. At the upgrade height, `BeginBlocker` executes the upgrade handler
8. The upgrade handler calls `RunMigrations`, which detects the new module (not in `fromVM`) and calls `InitGenesis` with default genesis state
9. `InitGenesis` calls `GetModuleAccount` to ensure the module account exists
10. `GetModuleAccount` retrieves the account at the module address, finds a `BaseAccount`, fails the type assertion, and panics with "account is not a module account"
11. The panic propagates uncaught through the call stack: `InitGenesis` → `RunMigrations` → upgrade handler → `ApplyUpgrade` → `BeginBlocker`
12. All validator nodes halt at the upgrade height, unable to progress beyond this block

**Security Guarantee Broken:**
The system assumes that governance-approved upgrades will execute successfully at the designated height. This vulnerability allows any unprivileged user to prevent approved upgrades from completing, achieving denial-of-service by exploiting the predictable module address generation and lack of forward-looking address blocking.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes halt execution at the upgrade height and cannot produce or commit new blocks
- **No transaction processing**: The network becomes unable to confirm any new transactions, freezing all blockchain activity
- **Emergency intervention required**: Recovery requires coordinated action such as a rollback to pre-upgrade height, release of a hotfix binary with handling for the malicious account, or out-of-band coordination among validators
- **Economic disruption**: All blockchain services cease operation until resolution, potentially causing significant economic damage
- **Governance undermined**: Legitimate governance-approved upgrades become attack vectors that malicious actors can weaponize

**Affected Systems:**
- Consensus layer: Upgrade execution fails during block processing
- All validator nodes: Every validator hits the same panic at the same height
- Governance process: Approved upgrades can be sabotaged by any participant

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category, classified as **Medium severity** according to the provided impact taxonomy.

## Likelihood Explanation

**Trigger Conditions:**
- **Public information**: Upgrade proposals and their associated binaries are publicly available on-chain and in repositories
- **Low cost**: The attack requires only standard transaction fees plus a minimal coin amount (even dust quantities work)
- **No privileges required**: Any user capable of submitting transactions can execute this attack
- **High frequency**: Every upgrade that introduces new modules with module accounts is vulnerable
- **Trivial timing**: Attacker only needs to submit the transaction before the upgrade height, which could be days or weeks in advance

**Attacker Profile:**
- Requires basic blockchain interaction skills (ability to submit transactions)
- Needs ability to inspect binaries or source code to identify new module names
- Must understand the module address derivation algorithm (publicly documented)
- No special access, permissions, or resources required beyond a funded account

**Probability:**
High likelihood of exploitation. The attack is straightforward, low-cost, and can systematically target every future upgrade that adds modules. Once this vulnerability becomes known, rational adversaries or griefers could exploit it to disrupt the network. The deterministic nature of module addresses makes the attack highly reliable.

## Recommendation

**Immediate Fix:**
Modify `GetModuleAccountAndPermissions` in `x/auth/keeper/keeper.go` to handle `BaseAccount` gracefully instead of panicking:

```go
acc := ak.GetAccount(ctx, addr)
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Check if account is uninitialized and safe to migrate
        if acc.GetSequence() != 0 {
            return nil, []string{}, fmt.Errorf("cannot create module account: active account exists at %s with non-zero sequence", addr)
        }
        // Check if account has received funds
        balance := ak.bankKeeper.GetAllBalances(ctx, addr)
        if !balance.IsZero() {
            return nil, []string{}, fmt.Errorf("cannot create module account: account at %s has non-zero balance", addr)
        }
        // Safe to convert empty BaseAccount to ModuleAccount
        // Delete the BaseAccount and create a proper ModuleAccount
        ak.RemoveAccount(ctx, acc)
    } else {
        return macc, perms
    }
}
// Create new module account (existing logic)
macc := types.NewEmptyModuleAccount(moduleName, perms...)
// ... rest of creation logic
```

**Additional Protections:**
1. **Pre-upgrade validation**: Add validation in upgrade `BeginBlocker` that checks for account conflicts at future module addresses before executing the upgrade handler, failing fast with a clear error message
2. **Extended blocking**: When an upgrade proposal is submitted, dynamically add predicted future module addresses to the `BlockedAddr` list to prevent front-running
3. **Non-deterministic derivation**: Consider adding entropy (e.g., block hash at upgrade height) to module address derivation to make addresses unpredictable until upgrade execution, though this would require careful design to maintain determinism across validators
4. **Upgrade plan validation**: Add a governance proposal validation step that checks for conflicts at future module addresses when upgrades are proposed

## Proof of Concept

**Test File:** Create `x/auth/keeper/keeper_test.go` or add to existing test file

**Setup:**
1. Initialize a test application using `simapp` with the current set of modules
2. Identify a future module name (e.g., "newmodule") that will be added in an upgrade
3. Compute the predicted module address: `futureAddr := authtypes.NewModuleAddress("newmodule")`
4. Create and fund an attacker account with sufficient coins for the test
5. Execute `bankKeeper.SendCoins(ctx, attackerAddr, futureAddr, coins)` to send coins to the predicted address
6. Verify that a `BaseAccount` now exists at `futureAddr` using `accountKeeper.GetAccount(ctx, futureAddr)`

**Action:**
1. Simulate the upgrade scenario by adding "newmodule" to the `maccPerms` map
2. Create a new `AccountKeeper` instance or modify the existing one to include "newmodule" in its module permissions
3. Call `accountKeeper.GetModuleAccount(ctx, "newmodule")` to simulate what would happen during `InitGenesis` execution

**Result:**
The call to `GetModuleAccount` panics with the error message "account is not a module account". This demonstrates that:
- The `BaseAccount` was successfully created at the predicted address before the upgrade
- The panic occurs during module account retrieval as claimed
- In production, this panic would propagate uncaught through the upgrade execution path, halting the chain at the upgrade height

**Validation Points:**
- Confirm `BaseAccount` exists at the predicted address with non-zero balance
- Confirm panic occurs with the expected error message
- Trace that no defer/recover mechanisms exist in the upgrade path to catch this panic
- Verify all validators would experience identical behavior, causing consensus failure

## Notes

This vulnerability demonstrates a critical gap in the upgrade safety mechanisms where deterministic address generation for module accounts creates a predictable attack surface. The issue is exacerbated by the separation between the blocklist population (which happens at app initialization with current modules) and the module addition process (which happens during upgrades). The lack of error handling for unexpected account types at module addresses transforms what should be a recoverable error into a consensus-halting panic.

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

**File:** simapp/app.go (L607-613)
```go
func (app *SimApp) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
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
