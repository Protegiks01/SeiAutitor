# Audit Report

## Title
Front-Running Module Account Creation Causes Network-Wide Panic During Chain Upgrades

## Summary
An attacker can front-run module account creation during chain upgrades by pre-creating a `BaseAccount` at the deterministic module address before the upgrade executes. When the new module's `InitGenesis` calls `GetModuleAccount`, it encounters the `BaseAccount` instead of a `ModuleAccountI`, triggering an unconditional panic that halts all validators simultaneously, causing complete network shutdown.

## Impact
**Medium** (High if considering hard fork recovery requirement)

## Finding Description

**Location:**
- Panic trigger: [1](#0-0) 
- Account creation vector: [2](#0-1) 
- Blocked address check: [3](#0-2) 
- Module address population: [4](#0-3) 

**Intended Logic:**
Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses. The `blockedAddrs` mechanism should prevent regular users from creating accounts at module addresses. When a chain upgrade adds a new module, `GetModuleAccount` should safely create the module account during `InitGenesis`.

**Actual Logic:**
The `blockedAddrs` map is populated only from existing modules in `maccPerms` at app initialization [5](#0-4) . Future modules that will be added via upgrade are not in this map. The `BlockedAddr` check [6](#0-5)  is a simple map lookup that returns false for future module addresses. When an attacker sends coins to a future module address, `SendCoins` creates a `BaseAccount` at that address [7](#0-6) . During the upgrade, when `GetModuleAccountAndPermissions` retrieves this account and finds it's not a `ModuleAccountI`, it executes an unconditional panic at line 191.

**Exploitation Path:**
1. Attacker observes upgrade proposal announcing new module "newmodule" at height 100000 (module name is public in governance proposal)
2. Attacker calculates deterministic module address using [8](#0-7) 
3. At block 99990, attacker submits `MsgSend` with 1 token to the calculated address
4. `Send` handler checks `BlockedAddr(to)` - returns false (address not in blockedAddrs yet)
5. `SendCoins` creates `BaseAccount` at module address via `NewAccountWithAddress`
6. At block 100000, upgrade executes via [9](#0-8)  (BeginBlocker)
7. Upgrade calls [10](#0-9)  which invokes `InitGenesis` for new modules (line 583)
8. New module's `InitGenesis` calls `GetModuleAccount` (confirmed in [11](#0-10) , [12](#0-11) , [13](#0-12) )
9. `GetModuleAccountAndPermissions` finds `BaseAccount`, executes panic("account is not a module account")
10. All validators panic at the same height during consensus execution
11. Network completely halts

**Security Guarantee Broken:**
Network availability and upgrade safety are violated. The deterministic module address derivation combined with the static `blockedAddrs` map creates a race condition where attackers can claim future module addresses before they're protected.

## Impact Explanation

This vulnerability causes complete network shutdown affecting all validators simultaneously. When all validators panic at the same block height during upgrade execution in [14](#0-13) :

- No new transactions can be confirmed after the upgrade height
- The upgrade plan is already consumed but module initialization failed, leaving state inconsistent
- Chain cannot progress without manual intervention
- Recovery requires coordinated hard fork with state export/import or emergency patch
- Existing upgrade cannot be rolled back cleanly

This matches the impact criterion: "Network not being able to confirm new transactions (total network shutdown)" - classified as **Medium** in the provided criteria, though the hard fork recovery requirement could elevate this to **High**.

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
- Indistinguishable from legitimate transfers until upgrade executes
- Only becomes apparent when all validators crash during upgrade

The combination of public information, minimal cost, large time window, and inability to detect makes exploitation highly likely.

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
Implement proactive blocking of future module addresses by maintaining a registry of planned module names from pending upgrade proposals and adding their addresses to `blockedAddrs` dynamically, or implement a check in the bank keeper to prevent account creation at addresses matching the module address derivation pattern.

## Proof of Concept

**Test File:** `x/auth/keeper/keeper_test.go`

**Setup:**
1. Create test app and context using standard test initialization
2. Calculate deterministic module address for "newmodule" using `types.NewModuleAddress("newmodule")`
3. Create and fund attacker account with tokens via bank keeper

**Action:**
1. Attacker sends 1 token to calculated module address via `BankKeeper.SendCoins`
2. Verify `BaseAccount` created at module address (type assertion confirms it's not `ModuleAccount`)
3. Call `GetModuleAccount(ctx, "newmodule")`

**Result:**
- `GetModuleAccount` panics with message "account is not a module account"
- Demonstrates that validators would crash during actual upgrade when `InitGenesis` is called
- Confirms network shutdown scenario

The test validates that the attack path is feasible and would cause the claimed network-wide panic during consensus execution in the upgrade BeginBlocker.

## Notes

The vulnerability stems from a fundamental design assumption that module addresses are "reserved" through the `blockedAddrs` mechanism, but this mechanism is static and only protects addresses of modules that exist at initialization time. The deterministic address derivation allows attackers to precompute future module addresses, and the account creation logic permits account creation at any non-blocked address. Combined with the unconditional panic and the upgrade flow that calls `InitGenesis` for new modules, this creates a critical vulnerability in the upgrade process.

### Citations

**File:** x/auth/keeper/keeper.go (L181-202)
```go
func (ak AccountKeeper) GetModuleAccountAndPermissions(ctx sdk.Context, moduleName string) (types.ModuleAccountI, []string) {
	addr, perms := ak.GetModuleAddressAndPermissions(moduleName)
	if addr == nil {
		return nil, []string{}
	}

	acc := ak.GetAccount(ctx, addr)
	if acc != nil {
		macc, ok := acc.(types.ModuleAccountI)
		if !ok {
			panic("account is not a module account")
		}
		return macc, perms
	}

	// create a new module account
	macc := types.NewEmptyModuleAccount(moduleName, perms...)
	maccI := (ak.NewAccount(ctx, macc)).(types.ModuleAccountI) // set the account number
	ak.SetModuleAccount(ctx, maccI)

	return maccI, perms
}
```

**File:** x/bank/keeper/send.go (L155-173)
```go
// SendCoins transfers amt coins from a sending account to a receiving account.
// An error is returned upon failure.
func (k BaseSendKeeper) SendCoins(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
	if err := k.SendCoinsWithoutAccCreation(ctx, fromAddr, toAddr, amt); err != nil {
		return err
	}

	// Create account if recipient does not exist.
	//
	// NOTE: This should ultimately be removed in favor a more flexible approach
	// such as delegated fee messages.
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
	}

	return nil
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

**File:** x/bank/keeper/msg_server.go (L26-76)
```go
func (k msgServer) Send(goCtx context.Context, msg *types.MsgSend) (*types.MsgSendResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := k.IsSendEnabledCoins(ctx, msg.Amount...); err != nil {
		return nil, err
	}

	from, err := sdk.AccAddressFromBech32(msg.FromAddress)
	if err != nil {
		return nil, err
	}
	to, err := sdk.AccAddressFromBech32(msg.ToAddress)
	if err != nil {
		return nil, err
	}

	allowListCache := make(map[string]AllowedAddresses)
	if !k.IsInDenomAllowList(ctx, from, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to send funds", msg.FromAddress)
	}

	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
	}

	err = k.SendCoins(ctx, from, to, msg.Amount)
	if err != nil {
		return nil, err
	}

	defer func() {
		for _, a := range msg.Amount {
			if a.Amount.IsInt64() {
				telemetry.SetGaugeWithLabels(
					[]string{"tx", "msg", "send"},
					float32(a.Amount.Int64()),
					[]metrics.Label{telemetry.NewLabel("denom", a.Denom)},
				)
			}
		}
	}()

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.AttributeValueCategory),
		),
	)

	return &types.MsgSendResponse{}, nil
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

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** x/upgrade/abci.go (L23-98)
```go
func BeginBlocker(k keeper.Keeper, ctx sdk.Context, _ abci.RequestBeginBlock) {
	if ctx.IsTracing() {
		return
	}
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	plan, planFound := k.GetUpgradePlan(ctx)

	if !k.DowngradeVerified() {
		k.SetDowngradeVerified(true)
		lastAppliedPlan, _ := k.GetLastCompletedUpgrade(ctx)
		// This check will make sure that we are using a valid binary.
		// It'll panic in these cases if there is no upgrade handler registered for the last applied upgrade.
		// 1. If there is no scheduled upgrade.
		// 2. If the plan is not ready.
		// 3. If the plan is ready and skip upgrade height is set for current height.
		if !planFound || !plan.ShouldExecute(ctx) || (plan.ShouldExecute(ctx) && k.IsSkipHeight(ctx.BlockHeight())) {
			if lastAppliedPlan != "" && !k.HasHandler(lastAppliedPlan) {
				panic(fmt.Sprintf("Wrong app version %d, upgrade handler is missing for %s upgrade plan", ctx.ConsensusParams().Version.AppVersion, lastAppliedPlan))
			}
		}
	}

	if !planFound {
		return
	}

	telemetry.SetGaugeWithLabels(
		[]string{"cosmos", "upgrade", "plan", "height"},
		float32(plan.Height),
		[]metrics.Label{
			{Name: "name", Value: plan.Name},
			{Name: "info", Value: plan.Info},
		},
	)

	// If the plan's block height has passed, then it must be the executed version
	// All major and minor releases are REQUIRED to execute on the scheduled block height
	if plan.ShouldExecute(ctx) {
		// If skip upgrade has been set for current height, we clear the upgrade plan
		if k.IsSkipHeight(ctx.BlockHeight()) {
			skipUpgrade(k, ctx, plan)
			return
		}
		// If we don't have an upgrade handler for this upgrade name, then we need to shutdown
		if !k.HasHandler(plan.Name) {
			panicUpgradeNeeded(k, ctx, plan)
		}
		applyUpgrade(k, ctx, plan)
		return
	}

	details, err := plan.UpgradeDetails()
	if err != nil {
		ctx.Logger().Error("failed to parse upgrade details", "err", err)
	}

	// If running a pending minor release, apply the upgrade if handler is present
	// Minor releases are allowed to run before the scheduled upgrade height, but not required to.
	if details.IsMinorRelease() {
		// if not yet present, then emit a scheduled log (every 100 blocks, to reduce logs)
		if !k.HasHandler(plan.Name) && !k.IsSkipHeight(plan.Height) {
			if ctx.BlockHeight()%100 == 0 {
				ctx.Logger().Info(BuildUpgradeScheduledMsg(plan))
			}
		}
		return
	}

	// if we have a handler for a non-minor upgrade, that means it updated too early and must stop
	if k.HasHandler(plan.Name) {
		downgradeMsg := fmt.Sprintf("BINARY UPDATED BEFORE TRIGGER! UPGRADE \"%s\" - in binary but not executed on chain", plan.Name)
		ctx.Logger().Error(downgradeMsg)
		panic(downgradeMsg)
	}
}
```

**File:** types/module/module.go (L545-596)
```go
// Please also refer to docs/core/upgrade.md for more information.
func (m Manager) RunMigrations(ctx sdk.Context, cfg Configurator, fromVM VersionMap) (VersionMap, error) {
	c, ok := cfg.(configurator)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", configurator{}, cfg)
	}
	var modules = m.OrderMigrations
	if modules == nil {
		modules = DefaultMigrationsOrder(m.ModuleNames())
	}

	updatedVM := VersionMap{}
	for _, moduleName := range modules {
		module := m.Modules[moduleName]
		fromVersion, exists := fromVM[moduleName]
		toVersion := module.ConsensusVersion()

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
			// The module manager assumes only one module will update the
			// validator set, and that it will not be by a new module.
			if len(moduleValUpdates) > 0 {
				return nil, sdkerrors.Wrapf(sdkerrors.ErrLogic, "validator InitGenesis updates already set by a previous module")
			}
		}

		updatedVM[moduleName] = toVersion
	}

	return updatedVM, nil
}
```

**File:** x/mint/genesis.go (L9-14)
```go
// InitGenesis new mint genesis
func InitGenesis(ctx sdk.Context, keeper keeper.Keeper, ak types.AccountKeeper, data *types.GenesisState) {
	keeper.SetMinter(ctx, data.Minter)
	keeper.SetParams(ctx, data.Params)
	ak.GetModuleAccount(ctx, types.ModuleName)
}
```

**File:** x/gov/genesis.go (L11-54)
```go
// InitGenesis - store genesis parameters
func InitGenesis(ctx sdk.Context, ak types.AccountKeeper, bk types.BankKeeper, k keeper.Keeper, data *types.GenesisState) {
	k.SetProposalID(ctx, data.StartingProposalId)
	k.SetDepositParams(ctx, data.DepositParams)
	k.SetVotingParams(ctx, data.VotingParams)
	k.SetTallyParams(ctx, data.TallyParams)

	// check if the deposits pool account exists
	moduleAcc := k.GetGovernanceAccount(ctx)
	if moduleAcc == nil {
		panic(fmt.Sprintf("%s module account has not been set", types.ModuleName))
	}

	var totalDeposits sdk.Coins
	for _, deposit := range data.Deposits {
		k.SetDeposit(ctx, deposit)
		totalDeposits = totalDeposits.Add(deposit.Amount...)
	}

	for _, vote := range data.Votes {
		k.SetVote(ctx, vote)
	}

	for _, proposal := range data.Proposals {
		switch proposal.Status {
		case types.StatusDepositPeriod:
			k.InsertInactiveProposalQueue(ctx, proposal.ProposalId, proposal.DepositEndTime)
		case types.StatusVotingPeriod:
			k.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
		}
		k.SetProposal(ctx, proposal)
	}

	// if account has zero balance it probably means it's not set, so we set it
	balance := bk.GetAllBalances(ctx, moduleAcc.GetAddress())
	if balance.IsZero() {
		ak.SetModuleAccount(ctx, moduleAcc)
	}

	// check if total deposits equals balance, if it doesn't panic because there were export/import errors
	if !balance.IsEqual(totalDeposits) {
		panic(fmt.Sprintf("expected module account was %s but we got %s", balance.String(), totalDeposits.String()))
	}
}
```

**File:** x/auth/genesis.go (L12-28)
```go
// a genesis port script to the new fee collector account
func InitGenesis(ctx sdk.Context, ak keeper.AccountKeeper, data types.GenesisState) {
	ak.SetParams(ctx, data.Params)

	accounts, err := types.UnpackAccounts(data.Accounts)
	if err != nil {
		panic(err)
	}
	accounts = types.SanitizeGenesisAccounts(accounts)

	for _, a := range accounts {
		acc := ak.NewAccount(ctx, a)
		ak.SetAccount(ctx, acc)
	}

	ak.GetModuleAccount(ctx, types.FeeCollectorName)
}
```

**File:** x/upgrade/keeper/keeper.go (L364-391)
```go
// ApplyUpgrade will execute the handler associated with the Plan and mark the plan as done.
func (k Keeper) ApplyUpgrade(ctx sdk.Context, plan types.Plan) {
	handler := k.upgradeHandlers[plan.Name]
	if handler == nil {
		panic("ApplyUpgrade should never be called without first checking HasHandler")
	}

	updatedVM, err := handler(ctx, plan, k.GetModuleVersionMap(ctx))
	if err != nil {
		panic(err)
	}

	k.SetModuleVersionMap(ctx, updatedVM)

	// incremement the protocol version and set it in state and baseapp
	nextProtocolVersion := k.getProtocolVersion(ctx) + 1
	k.setProtocolVersion(ctx, nextProtocolVersion)
	if k.versionSetter != nil {
		// set protocol version on BaseApp
		k.versionSetter.SetProtocolVersion(nextProtocolVersion)
	}

	// Must clear IBC state after upgrade is applied as it is stored separately from the upgrade plan.
	// This will prevent resubmission of upgrade msg after upgrade is already completed.
	k.ClearIBCState(ctx, plan.Height)
	k.ClearUpgradePlan(ctx)
	k.SetDone(ctx, plan.Name)
}
```
