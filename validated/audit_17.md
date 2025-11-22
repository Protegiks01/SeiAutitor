# Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
An attacker can halt the entire blockchain by sending coins to a predicted future module account address before a chain upgrade executes. The deterministic module address derivation combined with automatic account creation allows creating a `BaseAccount` at the future module's address, which causes `GetModuleAccount` to panic during upgrade initialization, halting the chain.

## Impact
High

## Finding Description

**Location:**
- Address derivation: [1](#0-0) 
- Panic point: [2](#0-1) 
- Account auto-creation: [3](#0-2) 
- Module initialization: [4](#0-3) 
- Upgrade execution: [5](#0-4) 

**Intended Logic:**
When a chain upgrade introduces a new module, `GetModuleAccount` should create a `ModuleAccountI` at the deterministic module address during `InitGenesis`. If no account exists, it creates one; if a module account exists, it returns it.

**Actual Logic:**
The `GetModuleAccount` function panics if it finds a `BaseAccount` instead of a `ModuleAccountI` at the module address. While `BlockedAddr` prevents sending coins to existing module accounts [6](#0-5) , the blocklist is populated only with current modules [7](#0-6)  from the static `maccPerms` map [8](#0-7) . Future module addresses from pending upgrades are not blocked.

**Exploitation Path:**
1. Attacker monitors on-chain governance for upgrade proposals
2. Downloads the upgrade binary and identifies new module names in `maccPerms`
3. Computes the future module address: `crypto.AddressHash([]byte(newModuleName))`
4. Submits `MsgSend` transaction to transfer coins to the predicted address
5. `BlockedAddr` check passes because the future module isn't in the current `blockedAddrs` map
6. A `BaseAccount` is auto-created at the module address
7. At upgrade height, `BeginBlocker` calls the upgrade handler
8. Upgrade handler calls `RunMigrations` which detects the new module and calls `InitGenesis` [9](#0-8) 
9. `InitGenesis` calls `GetModuleAccount` [10](#0-9) 
10. Type assertion fails and panics [11](#0-10) 
11. Panic propagates uncaught, halting all validator nodes at the upgrade height

**Security Guarantee Broken:**
The system assumes governance-approved upgrades will execute successfully. This vulnerability allows any unprivileged user to prevent upgrades from completing, achieving denial-of-service through consensus failure.

## Impact Explanation

**Consequences:**
- **Total network shutdown**: All validator nodes halt at the upgrade height and cannot progress
- **No transaction processing**: The network cannot confirm any new transactions
- **Emergency intervention required**: Requires coordinated rollback or hotfix binary release
- **Economic disruption**: All blockchain activity ceases until resolution

**Affected Systems:**
- Consensus layer (upgrade execution fails)
- All network nodes (halt at same height)
- Governance process (approved upgrades become attack vectors)

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category classified as **High severity**.

## Likelihood Explanation

**Trigger Conditions:**
- **Public information**: Upgrade proposals and binaries are publicly available
- **Low cost**: Attack requires only transaction fees plus minimal coin amount (dust)
- **No privileges**: Any user with transaction submission capability can execute
- **High frequency**: Every upgrade introducing new modules is vulnerable

**Attacker Profile:**
- Requires basic blockchain interaction skills
- Needs ability to inspect binary or source code
- Must submit transaction before upgrade height (trivial timing requirement)

**Probability:**
High likelihood - the attack is straightforward, low-cost, and can target every future upgrade that adds modules. Once the vulnerability becomes known, it can be systematically exploited.

## Recommendation

**Immediate Fix:**
Modify `GetModuleAccountAndPermissions` to handle `BaseAccount` gracefully:
```
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Check if account is empty and safe to migrate
        if acc.GetSequence() != 0 || !k.GetBalance(ctx, addr).IsZero() {
            return nil, []string{}, fmt.Errorf("cannot create module account: regular account exists at %s", addr)
        }
        // Safe to convert empty BaseAccount to ModuleAccount
        // ... conversion logic ...
    }
    return macc, perms
}
```

**Additional Protections:**
1. Add pre-upgrade validation in `BeginBlocker` to check for account conflicts before executing upgrade handler
2. Extend `BlockedAddr` mechanism to include predicted future module addresses from pending upgrade proposals
3. Consider adding entropy/nonce to module address derivation to make addresses unpredictable until upgrade execution

## Proof of Concept

**Test File:** `x/auth/keeper/keeper_test.go`

**Setup:**
1. Initialize test application with current modules
2. Predict address of future module using `NewModuleAddress("newmodule")`
3. Create attacker account and fund it
4. Send coins to predicted module address via `SendCoins`
5. Verify `BaseAccount` created at target address

**Action:**
1. Simulate upgrade by creating new `AccountKeeper` with "newmodule" in `maccPerms`
2. Call `GetModuleAccount(ctx, "newmodule")` to simulate `InitGenesis` execution

**Result:**
The call panics with "account is not a module account", demonstrating that the upgrade would fail and halt the chain. The panic occurs at the type assertion check in `GetModuleAccountAndPermissions`, which is uncaught during upgrade execution.

**Validation:**
- Confirmed `BaseAccount` exists at predicted address before upgrade simulation
- Confirmed panic occurs when attempting module account creation
- Confirmed panic is not caught in upgrade execution path
- In production, this panic would propagate through `RunMigrations` → upgrade handler → `ApplyUpgrade` → `BeginBlocker`, halting the chain

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

**File:** types/module/module.go (L575-590)
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
		}
```

**File:** x/upgrade/abci.go (L115-117)
```go
func applyUpgrade(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	ctx.Logger().Info(fmt.Sprintf("applying upgrade \"%s\" at %s", plan.Name, plan.DueAt()))
	k.ApplyUpgrade(ctx, plan)
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

**File:** x/mint/genesis.go (L13-13)
```go
	ak.GetModuleAccount(ctx, types.ModuleName)
```
