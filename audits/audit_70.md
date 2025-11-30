# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain by sending coins to a deterministically computed future module account address before a chain upgrade executes. This creates a `BaseAccount` at the module address, which triggers an unrecoverable panic during upgrade initialization when `GetModuleAccount` expects a `ModuleAccountI`, causing all validator nodes to crash at the upgrade height.

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
When a chain upgrade introduces a new module, `GetModuleAccount` should create a `ModuleAccountI` at the deterministic module address during `InitGenesis`. If no account exists at that address, it should create a new module account. The `BlockedAddr` mechanism is intended to prevent sending funds to module accounts to protect them from external interference.

**Actual Logic:**
The `GetModuleAccount` function performs a type assertion that panics if it finds a `BaseAccount` instead of a `ModuleAccountI` at the module address. [2](#0-1)  The `BlockedAddr` mechanism only prevents sending coins to addresses listed in the `blockedAddrs` map, which is populated from the current `maccPerms` at application initialization. [5](#0-4)  Future module addresses from pending upgrades are not included in this blocklist, allowing anyone to send coins to these predictable addresses. When coins are sent to a non-existent address, the banking module automatically creates a `BaseAccount`. [3](#0-2) 

**Exploitation Path:**
1. Attacker monitors governance proposals for scheduled upgrades and examines the upgrade binary to identify new modules
2. Computes the future module address using the deterministic derivation formula (hashing the module name)
3. Submits a `MsgSend` transaction transferring minimal coins to the predicted module address
4. The `BlockedAddr` check passes because the future module address is not in the current `blockedAddrs` map [4](#0-3) 
5. A `BaseAccount` is automatically created at the module address when coins are received [3](#0-2) 
6. At the upgrade height, `BeginBlocker` executes the upgrade handler [9](#0-8) 
7. The handler calls `RunMigrations`, which detects the new module (not in `fromVM`) and calls `InitGenesis` with default genesis [7](#0-6) 
8. The module's `InitGenesis` calls `GetModuleAccount` to ensure the module account exists [8](#0-7) 
9. `GetModuleAccount` finds the pre-existing `BaseAccount`, the type assertion fails, and it panics with "account is not a module account" [2](#0-1) 
10. The panic propagates uncaught through `ApplyUpgrade` [10](#0-9) , crashing the validator node
11. Since all validators execute identical deterministic code, they all panic at the same block height, causing total consensus failure

**Security Guarantee Broken:**
The system assumes that governance-approved upgrades will execute successfully at the designated height. This vulnerability allows any unprivileged user to prevent approved upgrades from completing by exploiting the deterministic nature of module address generation and the temporal gap between blocklist initialization and module addition.

## Impact Explanation

The consequences of this vulnerability are severe:

- **Total network shutdown**: All validator nodes halt execution at the upgrade height and cannot produce or commit new blocks
- **No transaction processing**: The network becomes unable to confirm any new transactions, freezing all on-chain activity
- **Emergency intervention required**: Recovery requires coordinated emergency action among validators, such as coordinated rollback, hotfix binary release with modified upgrade logic, or manual state cleanup
- **Economic disruption**: All blockchain services and applications cease operation until resolution
- **Governance undermined**: Legitimate governance-approved upgrades become exploitable attack vectors, undermining the upgrade mechanism

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category, classified as **Medium severity** according to the provided impact classification.

## Likelihood Explanation

The likelihood of exploitation is high due to:

**Trigger Conditions:**
- **Public information**: Upgrade proposals and binaries are publicly available on-chain and in code repositories
- **Low cost**: Attack requires only standard transaction fees plus minimal coin amount (dust quantities sufficient)
- **No privileges required**: Any user capable of submitting transactions can execute this attack
- **High frequency vulnerability**: Every upgrade introducing new modules with module accounts is vulnerable
- **Trivial timing**: Attacker only needs to submit the transaction anytime before upgrade height (potentially weeks in advance)

**Attacker Profile:**
- Requires basic blockchain interaction skills (ability to submit transactions)
- Needs ability to inspect binaries/source code to identify new module names
- Must understand the deterministic module address derivation algorithm (publicly documented)
- No special access, permissions, or significant resources required beyond a funded account

**Probability:**
The attack is straightforward, low-cost, and can systematically target every future upgrade that adds modules. The deterministic nature of module addresses makes the attack highly reliable and reproducible.

## Recommendation

**Immediate Fix:**
Modify `GetModuleAccountAndPermissions` in the auth keeper to handle unexpected account types gracefully instead of panicking:

1. When an account exists at the module address but is not a `ModuleAccountI`, check if it's a `BaseAccount`
2. If the BaseAccount has zero balance and zero sequence number (unused), safely remove it using `RemoveAccount` [11](#0-10) 
3. If the BaseAccount has been used (non-zero balance or sequence), return an error instead of panicking
4. After removal or on error, log the incident for forensic analysis
5. Create the proper ModuleAccount at the address

**Additional Protections:**

1. **Pre-upgrade validation**: Add validation checks in the upgrade handler that verify no account conflicts exist at future module addresses before executing migrations
2. **Extended blocking**: Implement a mechanism to dynamically add predicted future module addresses to the `BlockedAddr` list when an upgrade proposal containing new modules is submitted or approved
3. **Upgrade plan validation**: Add governance proposal validation that checks for existing accounts at future module addresses when upgrades are proposed, rejecting proposals that would conflict
4. **Defensive InitGenesis**: Update module `InitGenesis` functions to explicitly check for and handle account type mismatches rather than assuming `GetModuleAccount` will always succeed

## Proof of Concept

**Test Setup:**
1. Initialize a test application with current modules using simapp
2. Identify a future module name (e.g., "newmodule") that will be added in an upgrade
3. Compute the predicted module address: `futureAddr := authtypes.NewModuleAddress("newmodule")`
4. Create and fund an attacker account with minimal coins
5. Execute `bankKeeper.SendCoins(ctx, attackerAddr, futureAddr, minimalCoins)` to send funds to the future module address
6. Verify a `BaseAccount` exists at `futureAddr` using `accountKeeper.GetAccount(ctx, futureAddr)` and confirm it's not a `ModuleAccountI`

**Action:**
1. Simulate an upgrade by adding "newmodule" to the `maccPerms` map in the application configuration
2. Call `accountKeeper.GetModuleAccount(ctx, "newmodule")` to simulate what would happen during `InitGenesis`

**Result:**
The call panics with "account is not a module account", demonstrating that the pre-existing `BaseAccount` at the predicted address causes the panic that would halt all validator nodes during a real upgrade. Since all validators execute the same deterministic code at the upgrade height, they would all panic simultaneously, causing consensus failure and total network shutdown requiring emergency intervention to recover.

## Notes

This vulnerability demonstrates a critical gap in upgrade safety mechanisms where the deterministic address generation for module accounts creates a predictable and exploitable attack surface. The issue is exacerbated by the temporal separation between blocklist population (at application initialization using current modules) and module addition (during upgrades). The lack of defensive error handling for unexpected account types at module addresses transforms what could be a recoverable error into a consensus-halting panic, making this a viable denial-of-service vector against chain upgrades.

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
