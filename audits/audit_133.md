## Audit Report

## Title
Denial-of-Service via Front-Running Module Account Creation During Chain Upgrades

## Summary
Module account addresses are deterministically derived using a simple hash of the module name, making them predictable. An attacker can front-run chain upgrades by sending coins to a predicted module account address before the upgrade executes, causing the upgrade to panic and halt the chain when the new module attempts initialization. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Address derivation: [1](#0-0) 
- Vulnerable panic point: [2](#0-1) 
- Auto-account creation: [3](#0-2) 
- Module initialization: [4](#0-3) 

**Intended Logic:** 
When a chain upgrade adds a new module, the module's account should be created as a `ModuleAccountI` during the upgrade's `InitGenesis` execution. The `GetModuleAccount` function should either find an existing module account or auto-create one.

**Actual Logic:** 
The `GetModuleAccount` function panics if it finds a regular `BaseAccount` at the module account address instead of a `ModuleAccountI`. This occurs because:
1. Module account addresses are predictably derived
2. Sending coins to any address auto-creates a `BaseAccount`
3. The type-check in `GetModuleAccountAndPermissions` panics on type mismatch

**Exploit Scenario:**
1. Attacker monitors governance for upgrade proposals that add new modules (e.g., via [5](#0-4) )
2. From the new binary, attacker identifies the new module name in `maccPerms`
3. Attacker predicts the module account address: `crypto.AddressHash([]byte(newModuleName))`
4. Before the upgrade height, attacker submits a transaction sending any amount of coins to the predicted address
5. The `SendCoins` function auto-creates a `BaseAccount` at that address
6. At upgrade height, the upgrade handler calls `RunMigrations`, which calls the new module's `InitGenesis`
7. Module's `InitGenesis` calls `GetModuleAccount` (e.g., [6](#0-5) )
8. `GetModuleAccount` finds the attacker-created `BaseAccount`, attempts to cast it to `ModuleAccountI`, and panics
9. The upgrade transaction fails, halting the entire chain at the upgrade height

**Security Failure:** 
Denial-of-service through consensus failure. The upgrade cannot complete, causing all validator nodes to halt at the upgrade height, requiring emergency coordination to recover.

## Impact Explanation

**Affected Assets and Processes:**
- Network availability: The entire chain halts at upgrade height
- Network operations: No new transactions can be processed
- Chain governance: Upgrade process is compromised

**Severity:**
- **Critical**: Total network shutdown requiring emergency intervention
- Validators cannot progress past the upgrade height
- Requires either a coordinated rollback or a hotfix binary release
- All pending transactions are blocked
- Economic activity ceases until resolution

**System Security:**
This breaks the fundamental assumption that governance-approved upgrades will execute successfully. It allows any unprivileged attacker with minimal funds (just gas costs + dust amount for the coin transfer) to halt the network indefinitely.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant with sufficient funds to submit a transaction (extremely low barrier).

**Required Conditions:**
1. A pending upgrade proposal that adds a new module (publicly visible in governance)
2. Knowledge of the new module's name (available in the upgrade binary)
3. Ability to submit a transaction before the upgrade height (normal network participation)

**Frequency:**
- **High likelihood**: This attack can be executed on every upgrade that introduces a new module
- Upgrade proposals are public and occur regularly in active chains
- The attack requires minimal sophistication and resources
- Once discovered, attackers can systematically target all future upgrades

## Recommendation

Modify `GetModuleAccountAndPermissions` to safely handle the case where a regular account exists at a module account address:

1. When an account exists at the module address but is not a `ModuleAccountI`, instead of panicking:
   - Return an error to the caller
   - OR, validate the account has zero balance and no transactions, then safely convert it to a module account
   - OR, check during validation phase (before upgrade execution) that no conflicting accounts exist

2. Add pre-upgrade validation that checks predicted module account addresses for conflicts:
   - Before upgrade execution, verify that addresses of new modules either don't exist or are already proper `ModuleAccountI`
   - Fail early with a clear error if conflicts are detected

3. Consider adding a nonce or version parameter to the module address derivation to make addresses unpredictable until upgrade execution.

## Proof of Concept

**File:** `x/auth/keeper/keeper_test.go`

**Test Function:** `TestModuleAccountFrontRunningAttack`

```go
// Add this test to x/auth/keeper/keeper_test.go

func TestModuleAccountFrontRunningAttack(t *testing.T) {
    // Setup: Create initial app (simulating pre-upgrade state)
    app, ctx := createTestApp(true)
    
    // Attacker predicts the address of a future module "newmodule"
    newModuleName := "newmodule"
    predictedModuleAddr := types.NewModuleAddress(newModuleName)
    
    // Attacker sends coins to the predicted address, creating a BaseAccount
    attackerAddr := sdk.AccAddress([]byte("attacker-address"))
    app.AccountKeeper.SetAccount(ctx, app.AccountKeeper.NewAccountWithAddress(ctx, attackerAddr))
    
    // Simulate sending coins which creates a BaseAccount at the module address
    baseAcc := app.AccountKeeper.NewAccountWithAddress(ctx, predictedModuleAddr)
    app.AccountKeeper.SetAccount(ctx, baseAcc)
    
    // Verify a BaseAccount was created
    existingAcc := app.AccountKeeper.GetAccount(ctx, predictedModuleAddr)
    require.NotNil(t, existingAcc)
    _, isModuleAccount := existingAcc.(types.ModuleAccountI)
    require.False(t, isModuleAccount, "Should be a BaseAccount, not a ModuleAccount")
    
    // Simulate upgrade: Create new keeper with "newmodule" in permissions
    maccPerms := simapp.GetMaccPerms()
    maccPerms[newModuleName] = []string{types.Minter}
    
    cdc := simapp.MakeTestEncodingConfig().Marshaler
    newKeeper := keeper.NewAccountKeeper(
        cdc, app.GetKey(types.StoreKey), app.GetSubspace(types.ModuleName),
        types.ProtoBaseAccount, maccPerms,
    )
    
    // Trigger: Try to get the module account (simulating InitGenesis)
    // This should panic because a BaseAccount exists at the module address
    require.Panics(t, func() {
        newKeeper.GetModuleAccount(ctx, newModuleName)
    }, "GetModuleAccount should panic when it finds a BaseAccount at module address")
}
```

**Setup:**
1. Initialize test app with standard configuration
2. Predict a future module's account address using `NewModuleAddress`
3. Create a regular `BaseAccount` at that address (simulating attacker's coin transfer)

**Trigger:**
1. Create a new `AccountKeeper` with the new module in `maccPerms` (simulating post-upgrade state)
2. Call `GetModuleAccount` for the new module name

**Observation:**
The test expects a panic when `GetModuleAccount` is called, demonstrating that an attacker-created `BaseAccount` at a module address prevents the module account from being properly initialized. The panic occurs in the type assertion check, which would cause the upgrade transaction to fail and halt the chain.

## Notes

The vulnerability arises from the intersection of three design choices:
1. Deterministic, predictable module account addresses
2. Automatic account creation when sending coins to any address
3. Strict type checking that panics rather than gracefully handling mismatches

While each design choice is reasonable in isolation, their combination creates an attack vector that allows unprivileged actors to DoS chain upgrades.

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

**File:** types/module/module.go (L515-517)
```go
//   - if the module does not exist in the `fromVM` (which means that it's a new module,
//     because it was not in the previous x/upgrade's store), then run
//     `InitGenesis` on that module.
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

**File:** x/mint/genesis.go (L13-13)
```go
	ak.GetModuleAccount(ctx, types.ModuleName)
```
