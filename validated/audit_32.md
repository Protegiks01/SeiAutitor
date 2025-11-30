# Audit Report

## Title
Pre-Creation of BaseAccount at Future Module Address Causes Network Halt During Chain Upgrades

## Summary
An attacker can send coins to the deterministic address of a future module before a chain upgrade, creating a `BaseAccount` at that address. When the new module's `InitGenesis` calls `GetModuleAccount` during upgrade execution, the type assertion fails and triggers a panic, causing all validators to halt simultaneously and preventing the network from producing new blocks.

## Impact
Medium

## Finding Description

**Location:**
- Panic trigger: [1](#0-0) 
- Account creation: [2](#0-1) 
- Blocked address check: [3](#0-2) 
- Module address calculation: [4](#0-3) 
- Module account registry: [5](#0-4) 
- Static module permissions: [6](#0-5) 

**Intended Logic:**
When a chain upgrade adds a new module, the upgrade handler should safely call `InitGenesis`, which retrieves or creates the module account via `GetModuleAccount`. Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses, and regular users should not be able to create accounts at future module addresses before they are registered.

**Actual Logic:**
The blocked address mechanism only includes addresses of currently registered modules from the static `maccPerms` map. [5](#0-4)  A future module's address is not in this map, so the `BlockedAddr` check passes [7](#0-6) , allowing any user to send coins to that address. This triggers automatic `BaseAccount` creation. [2](#0-1)  During upgrade, when `InitGenesis` calls `GetModuleAccount` [8](#0-7) , the `GetModuleAccountAndPermissions` function performs a type assertion and unconditionally panics when finding a `BaseAccount` instead of `ModuleAccountI`. [1](#0-0) 

**Exploitation Path:**
1. Governance proposal passes to add new module at upgrade height H (module name is public information)
2. Attacker calculates deterministic module address using `NewModuleAddress(moduleName)` [4](#0-3) 
3. Before height H, attacker submits `MsgSend` transferring 1 token to the calculated address
4. `BlockedAddr` check passes because the module is not yet registered [5](#0-4) 
5. `SendCoins` creates a `BaseAccount` at the module address [2](#0-1) 
6. At height H, upgrade executes and `InitGenesis` is called for the new module [9](#0-8) 
7. Module's `InitGenesis` calls `GetModuleAccount` [8](#0-7) 
8. `GetModuleAccountAndPermissions` finds the `BaseAccount`, type assertion fails, and panics [1](#0-0) 
9. All validators execute identical deterministic code and panic at the same height
10. Network completely halts - no new blocks can be produced

**Security Guarantee Broken:**
Network availability and consensus liveness. The system fails to safely handle module upgrades when accounts are pre-created at future module addresses.

## Impact Explanation

This vulnerability causes total network shutdown affecting all validators simultaneously. All validator nodes panic during the upgrade block's execution, preventing the network from producing new blocks after the upgrade height. The chain state becomes inconsistent with the upgrade plan consumed but module initialization incomplete. No transactions can be confirmed, and recovery requires coordinated emergency response with either a hard fork or emergency patch deployment to all validators.

## Likelihood Explanation

**High likelihood** due to:
- **Minimal cost**: Only requires standard transaction fees plus 1 token of minimal denomination
- **No special privileges**: Any network participant can execute the attack
- **Public information**: Module names are disclosed in governance proposals days or weeks before execution
- **Ample time window**: Attackers have the entire period between proposal passage and upgrade execution to perform the attack
- **100% success rate**: If executed before the upgrade, the attack succeeds due to deterministic execution across all validators
- **Detection difficulty**: The malicious transaction appears as a normal coin transfer
- **High frequency**: Affects every chain upgrade that introduces new modules (multiple per year in active chains)

## Recommendation

Implement graceful handling in `GetModuleAccountAndPermissions` to detect and convert pre-existing unused `BaseAccount` instances to proper module accounts. Check if the account is a `BaseAccount` that has never been used (verified by `GetPubKey() == nil && GetSequence() == 0`), and if so, safely convert it to a module account rather than panicking.

**Alternative mitigation**: Extend the blocked address mechanism to include a registry of reserved future module addresses based on planned upgrade proposals, preventing account creation at these addresses before the upgrade executes.

## Proof of Concept

**Setup:**
- Create test application and context using simapp test framework [10](#0-9) 
- Calculate deterministic address for module "futuremodule" using [4](#0-3) 
- Fund attacker account with coins

**Action:**
- Attacker sends 1 token to calculated module address via `app.BankKeeper.SendCoins()`
- Automatic `BaseAccount` creation occurs [2](#0-1) 
- Verify `BaseAccount` exists at module address using `app.AccountKeeper.GetAccount()`
- Simulate upgrade by calling `app.AccountKeeper.GetModuleAccount(ctx, "futuremodule")`

**Result:**
- Test confirms `BaseAccount` (not `ModuleAccountI`) exists at the calculated module address
- Calling `GetModuleAccount` triggers panic with message "account is not a module account" [11](#0-10) 
- Demonstrates network would halt if this occurred during actual upgrade execution

## Notes

The vulnerability exploits the time gap between governance proposal announcement and upgrade execution, where future module addresses are not yet protected by the blocked address mechanism. [5](#0-4)  This allows pre-creation of incompatible account types at reserved addresses, violating the invariant that module addresses should only contain module accounts. The AccountKeeper's proto function is set to create `BaseAccount` instances by default, [12](#0-11)  which when combined with the lack of protection for future module addresses, creates this attack vector.

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

**File:** x/auth/types/account.go (L162-165)
```go
// NewModuleAddress creates an AccAddress from the hash of the module's name
func NewModuleAddress(name string) sdk.AccAddress {
	return sdk.AccAddress(crypto.AddressHash([]byte(name)))
}
```

**File:** simapp/app.go (L134-142)
```go
	// module account permissions
	maccPerms = map[string][]string{
		authtypes.FeeCollectorName:     nil,
		distrtypes.ModuleName:          nil,
		minttypes.ModuleName:           {authtypes.Minter},
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
		govtypes.ModuleName:            {authtypes.Burner},
	}
```

**File:** simapp/app.go (L262-262)
```go
		appCodec, keys[authtypes.StoreKey], app.GetSubspace(authtypes.ModuleName), authtypes.ProtoBaseAccount, maccPerms,
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

**File:** x/bank/keeper/msg_server.go (L47-49)
```go
	if k.BlockedAddr(to) || !k.IsInDenomAllowList(ctx, to, msg.Amount, allowListCache) {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", msg.ToAddress)
	}
```

**File:** x/mint/genesis.go (L13-13)
```go
	ak.GetModuleAccount(ctx, types.ModuleName)
```

**File:** types/module/module.go (L583-583)
```go
			moduleValUpdates := module.InitGenesis(ctx, cfgtor.cdc, module.DefaultGenesis(cfgtor.cdc))
```

**File:** x/auth/keeper/integration_test.go (L12-17)
```go
func createTestApp(isCheckTx bool) (*simapp.SimApp, sdk.Context) {
	app := simapp.Setup(isCheckTx)
	ctx := app.BaseApp.NewContext(isCheckTx, tmproto.Header{})
	app.AccountKeeper.SetParams(ctx, authtypes.DefaultParams())

	return app, ctx
```
