# Audit Report

## Title
Pre-Creation of BaseAccount at Future Module Address Causes Network Halt During Chain Upgrades

## Summary
An attacker can send coins to the deterministic address of a future module before it is registered, creating a `BaseAccount` at that address. When the module's `InitGenesis` calls `GetModuleAccount` during upgrade execution, the type assertion fails and triggers an unconditional panic, causing all validators to halt simultaneously and preventing the network from producing new blocks.

## Impact
High

## Finding Description

**Location:**
- Panic trigger: `x/auth/keeper/keeper.go` lines 187-192 [1](#0-0) 
- Account creation: `x/bank/keeper/send.go` lines 166-170 [2](#0-1) 
- Blocked address mechanism: `x/bank/keeper/send.go` lines 348-355 [3](#0-2) 
- Module address calculation: `x/auth/types/account.go` lines 162-165 [4](#0-3) 

**Intended Logic:**
Module accounts should only exist as `ModuleAccountI` types at their deterministic addresses. The blocked address mechanism should prevent regular users from sending coins to module addresses, ensuring that module accounts are created properly through `GetModuleAccount`. During chain upgrades, new modules should have their accounts safely created during `InitGenesis`.

**Actual Logic:**
The blocked address list is populated only from currently registered modules in the static `maccPerms` map [5](#0-4) . Future module addresses are not in this map, so `BlockedAddr` checks pass [6](#0-5) , allowing any user to send coins to those addresses. This triggers automatic `BaseAccount` creation [2](#0-1)  via the default `ProtoBaseAccount` constructor [7](#0-6) . During upgrade, when the module's `InitGenesis` calls `GetModuleAccount` [8](#0-7) , the function retrieves the existing account and performs a type assertion to `ModuleAccountI`. When it finds a `BaseAccount` instead, the assertion fails and the code unconditionally panics [1](#0-0) .

**Exploitation Path:**
1. Governance proposal announces new module addition at upgrade height H (module name is public information)
2. Attacker calculates the deterministic module address using `NewModuleAddress(moduleName)` [4](#0-3) 
3. Before height H, attacker submits a standard `MsgSend` transferring 1 token to the calculated address
4. The `BlockedAddr` check passes because the future module is not yet in the `maccPerms` map [9](#0-8) 
5. `SendCoins` automatically creates a `BaseAccount` at the module address [2](#0-1) 
6. At upgrade height H, the upgrade executes and `InitGenesis` is called for the new module
7. The module's `InitGenesis` calls `GetModuleAccount` [8](#0-7) 
8. `GetModuleAccountAndPermissions` retrieves the `BaseAccount`, attempts type assertion to `ModuleAccountI`, and panics [10](#0-9) 
9. All validators execute identical deterministic code and panic at the same height
10. Network completely halts - no new blocks can be produced

**Security Guarantee Broken:**
Network availability and consensus liveness. The system fails to protect future module addresses from premature account creation, violating the invariant that module addresses should only contain `ModuleAccountI` instances.

## Impact Explanation

This vulnerability causes complete network shutdown affecting all validators simultaneously. When the upgrade block is executed, all validator nodes panic during `InitGenesis` execution, preventing the network from producing any new blocks after the upgrade height. The chain state becomes inconsistent with the upgrade plan consumed but module initialization incomplete. No transactions can be confirmed, and the network remains halted until a coordinated emergency response with either a hard fork or emergency patch deployment to all validators.

## Likelihood Explanation

**Very high likelihood** due to:
- **Minimal cost**: Only requires standard transaction fees plus 1 token of minimal denomination
- **No special privileges**: Any network participant can execute the attack  
- **Public information**: Module names are disclosed in governance proposals days or weeks before execution
- **Large time window**: Attackers have the entire period between proposal passage and upgrade execution (typically days to weeks)
- **100% success rate**: If executed before the upgrade, the attack succeeds with certainty due to deterministic execution across all validators
- **Low detection difficulty**: The malicious transaction appears as a normal coin transfer and is indistinguishable from legitimate activity
- **High frequency**: Affects every chain upgrade that introduces new modules (multiple times per year in active chains)

## Recommendation

Implement graceful handling in `GetModuleAccountAndPermissions` to detect and convert pre-existing unused `BaseAccount` instances to proper module accounts:

```go
acc := ak.GetAccount(ctx, addr)
if acc != nil {
    macc, ok := acc.(types.ModuleAccountI)
    if !ok {
        // Check if it's an unused BaseAccount that can be safely converted
        if baseAcc, isBase := acc.(*types.BaseAccount); isBase {
            if baseAcc.GetPubKey() == nil && baseAcc.GetSequence() == 0 {
                // Convert unused BaseAccount to ModuleAccount
                macc := types.NewEmptyModuleAccount(moduleName, perms...)
                macc.AccountNumber = baseAcc.GetAccountNumber()
                maccI := macc.(types.ModuleAccountI)
                ak.SetModuleAccount(ctx, maccI)
                return maccI, perms
            }
        }
        panic("account is not a module account")
    }
    return macc, perms
}
```

**Alternative mitigation**: Extend the blocked address mechanism to include a registry of reserved future module addresses based on planned upgrade proposals, preventing account creation at these addresses before the upgrade executes.

## Proof of Concept

**Setup:**
- Create test application and context using `simapp.Setup()` [11](#0-10) 
- Calculate deterministic address for a future module "futuremodule" using `authtypes.NewModuleAddress("futuremodule")` [4](#0-3) 
- Fund an attacker account with sufficient coins

**Action:**
- Attacker sends 1 token to the calculated module address via `app.BankKeeper.SendCoins()`
- Automatic `BaseAccount` creation occurs [2](#0-1) 
- Verify `BaseAccount` exists using `app.AccountKeeper.GetAccount(ctx, moduleAddr)`
- Verify it's not a `ModuleAccountI` through type assertion
- Simulate upgrade by calling `app.AccountKeeper.GetModuleAccount(ctx, "futuremodule")`

**Result:**
- Test confirms a `BaseAccount` (not `ModuleAccountI`) exists at the calculated module address
- Calling `GetModuleAccount` triggers panic with message "account is not a module account" [12](#0-11) 
- Demonstrates that if this occurred during actual upgrade execution, all validators would panic and the network would halt

## Notes

The vulnerability exploits the temporal gap between governance proposal announcement and upgrade execution, during which future module addresses are not protected by the blocked address mechanism [5](#0-4) . This allows pre-creation of incompatible account types at reserved addresses, violating the critical invariant that module addresses should only contain module accounts. The `AccountKeeper` is configured with `ProtoBaseAccount` as its account constructor [13](#0-12) , which creates `BaseAccount` instances by default [7](#0-6) . Combined with the lack of protection for future module addresses, this creates a severe attack vector that can halt the entire network.

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

**File:** x/auth/types/account.go (L45-47)
```go
// ProtoBaseAccount - a prototype function for BaseAccount
func ProtoBaseAccount() AccountI {
	return &BaseAccount{}
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

**File:** x/auth/keeper/integration_test.go (L12-17)
```go
func createTestApp(isCheckTx bool) (*simapp.SimApp, sdk.Context) {
	app := simapp.Setup(isCheckTx)
	ctx := app.BaseApp.NewContext(isCheckTx, tmproto.Header{})
	app.AccountKeeper.SetParams(ctx, authtypes.DefaultParams())

	return app, ctx
```
