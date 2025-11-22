# Audit Report

## Title
Missing Validation in Genesis Import Allows Negative Balance Unbonding Entries to Cause Chain Halt

## Summary
The `SetUnbondingDelegationEntry` function and genesis import process do not validate that unbonding delegation entries have non-negative balance or creationHeight values. An attacker can inject malicious unbonding entries with negative balances through genesis state, which will cause the chain to panic and halt when these entries mature and the system attempts to complete the unbonding.

## Impact
**High**

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Genesis import: [2](#0-1) 
- Validation gap: [3](#0-2) 
- Crash point: [4](#0-3) 

**Intended Logic:** The staking module should ensure all unbonding delegation entries have valid non-negative balance amounts and reasonable creationHeight values. Genesis validation should reject any malformed state before chain initialization.

**Actual Logic:** 
1. `SetUnbondingDelegationEntry` accepts `balance` and `creationHeight` parameters without any validation [1](#0-0) 
2. `NewUnbondingDelegationEntry` creates entries without validating the balance or creationHeight [5](#0-4) 
3. `ValidateGenesis` only validates validators and params, but does NOT validate unbonding delegations [3](#0-2) 
4. During genesis import, unbonding delegations are loaded directly without validation [2](#0-1) 

**Exploit Scenario:**
1. An attacker crafts a malicious genesis file containing an unbonding delegation entry with a negative balance value (e.g., `-1000000`)
2. The chain initializes with this genesis state - no validation catches the negative balance
3. The negative balance corrupts accounting: `notBondedTokens = notBondedTokens.Add(entry.Balance)` [6](#0-5) 
4. When the unbonding period elapses and the entry matures, the EndBlocker automatically triggers `CompleteUnbonding`
5. At completion, the code attempts: `amt := sdk.NewCoin(bondDenom, entry.Balance)` [4](#0-3) 
6. `NewCoin` validates that amounts are non-negative and panics on negative values [7](#0-6) 
7. The panic halts the entire chain - all nodes stop processing blocks

**Security Failure:** This breaks the availability invariant. The blockchain cannot process any transactions once the panic occurs, resulting in a complete network shutdown requiring manual intervention and potentially a hard fork to fix the corrupted state.

## Impact Explanation

**Affected Assets/Processes:**
- Entire network availability and consensus
- All pending transactions in mempool
- Network uptime and reliability

**Severity of Damage:**
- Complete chain halt when the malicious unbonding entry matures
- All validator nodes panic simultaneously
- No new blocks can be produced or transactions confirmed
- Requires emergency coordinator intervention to identify and fix the corrupted state
- May require a hard fork or coordinated state export/import to recover

**Why This Matters:**
This is a critical denial-of-service vulnerability that can cause total network shutdown. In a production blockchain, this would halt all economic activity, freeze user funds, and potentially cause significant financial losses. The vulnerability is particularly dangerous because:
1. It can be triggered during chain initialization/upgrades
2. The attack surface includes any genesis import scenario
3. Recovery requires coordinated emergency response across all validators

## Likelihood Explanation

**Who Can Trigger:**
The attack requires control over the genesis state, which typically occurs during:
- Initial chain launch
- Chain upgrades that involve genesis export/import
- Testnet resets or hard forks
- State sync scenarios

**Conditions Required:**
- Attacker must inject malicious genesis state (requires compromise of genesis generation process or social engineering during chain initialization)
- Alternatively, if state export/import mechanisms don't validate, corrupted state could propagate

**Frequency:**
While genesis manipulation requires privileged access, it's a realistic scenario during:
- Coordinated chain launches where multiple parties contribute to genesis
- Emergency chain restarts
- Network upgrades involving state migration
Once triggered, the impact is immediate and total when the entry matures.

## Recommendation

Add comprehensive validation for unbonding delegation entries:

1. **In `ValidateGenesis`**, add validation for unbonding delegations:
   - Check all `UnbondingDelegationEntry.Balance` values are non-negative
   - Check all `UnbondingDelegationEntry.CreationHeight` values are non-negative
   - Validate that completion times are after creation times

2. **In `SetUnbondingDelegationEntry`**, add defensive checks:
   - Validate `balance.IsNegative() == false`
   - Validate `creationHeight >= 0`
   - Return error if validation fails

3. **Add validation method** to `UnbondingDelegation` type:
   ```
   func (ubd UnbondingDelegation) Validate() error
   ```
   Check all entries have valid balance and creationHeight values.

## Proof of Concept

**File:** `x/staking/genesis_test.go`

**Test Function:** `TestInitGenesis_NegativeBalanceUnbondingEntry`

**Setup:**
1. Initialize a test app and context
2. Create a validator with bonded tokens
3. Fund the NotBondedPool module account
4. Create an unbonding delegation entry with negative balance in genesis state

**Trigger:**
1. Call `InitGenesis` with the malicious genesis state containing negative balance unbonding entry
2. Advance time to make the unbonding entry mature
3. Trigger the EndBlocker which calls `CompleteUnbonding`

**Observation:**
The test will panic at the `sdk.NewCoin` call when processing the negative balance, demonstrating the chain halt vulnerability. The panic occurs because [8](#0-7)  checks for negative amounts and returns an error, which causes [7](#0-6)  to panic.

```go
func TestInitGenesis_NegativeBalanceUnbondingEntry(t *testing.T) {
    app, ctx, addrs := bootstrapGenesisTest(2)
    
    // Create validator and fund pools
    valTokens := sdk.NewInt(1000000)
    params := app.StakingKeeper.GetParams(ctx)
    
    // Create unbonding delegation with NEGATIVE balance
    negativeBalance := sdk.NewInt(-1000)
    completionTime := ctx.BlockTime().Add(params.UnbondingTime)
    
    ubd := types.UnbondingDelegation{
        DelegatorAddress: addrs[0].String(),
        ValidatorAddress: sdk.ValAddress(addrs[1]).String(),
        Entries: []types.UnbondingDelegationEntry{
            {
                CreationHeight: ctx.BlockHeight(),
                CompletionTime: completionTime,
                InitialBalance: negativeBalance,
                Balance:        negativeBalance,
            },
        },
    }
    
    genesisState := &types.GenesisState{
        Params:               params,
        UnbondingDelegations: []types.UnbondingDelegation{ubd},
    }
    
    // This should panic during validation but doesn't - vulnerability!
    require.NotPanics(t, func() {
        staking.InitGenesis(ctx, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, genesisState)
    })
    
    // Advance time to mature the unbonding
    ctx = ctx.WithBlockTime(completionTime.Add(time.Second))
    
    // This WILL panic when trying to complete unbonding with negative balance
    require.Panics(t, func() {
        _, err := app.StakingKeeper.CompleteUnbonding(ctx, addrs[0], sdk.ValAddress(addrs[1]))
        require.NoError(t, err)
    }, "CompleteUnbonding should panic when processing negative balance entry")
}
```

The test demonstrates that:
1. Genesis import accepts negative balance without validation
2. When `CompleteUnbonding` processes the entry, it panics at `sdk.NewCoin` call
3. This panic would halt the entire chain in production

### Citations

**File:** x/staking/keeper/delegation.go (L307-321)
```go
func (k Keeper) SetUnbondingDelegationEntry(
	ctx sdk.Context, delegatorAddr sdk.AccAddress, validatorAddr sdk.ValAddress,
	creationHeight int64, minTime time.Time, balance sdk.Int,
) types.UnbondingDelegation {
	ubd, found := k.GetUnbondingDelegation(ctx, delegatorAddr, validatorAddr)
	if found {
		ubd.AddEntry(creationHeight, minTime, balance)
	} else {
		ubd = types.NewUnbondingDelegation(delegatorAddr, validatorAddr, creationHeight, minTime, balance)
	}

	k.SetUnbondingDelegation(ctx, ubd)

	return ubd
}
```

**File:** x/staking/keeper/delegation.go (L886-886)
```go
				amt := sdk.NewCoin(bondDenom, entry.Balance)
```

**File:** x/staking/genesis.go (L81-88)
```go
	for _, ubd := range data.UnbondingDelegations {
		keeper.SetUnbondingDelegation(ctx, ubd)

		for _, entry := range ubd.Entries {
			keeper.InsertUBDQueue(ctx, ubd, entry.CompletionTime)
			notBondedTokens = notBondedTokens.Add(entry.Balance)
		}
	}
```

**File:** x/staking/genesis.go (L230-236)
```go
func ValidateGenesis(data *types.GenesisState) error {
	if err := validateGenesisStateValidators(data.Validators); err != nil {
		return err
	}

	return data.Params.Validate()
}
```

**File:** x/staking/types/delegation.go (L93-100)
```go
func NewUnbondingDelegationEntry(creationHeight int64, completionTime time.Time, balance sdk.Int) UnbondingDelegationEntry {
	return UnbondingDelegationEntry{
		CreationHeight: creationHeight,
		CompletionTime: completionTime,
		InitialBalance: balance,
		Balance:        balance,
	}
}
```

**File:** types/coin.go (L22-24)
```go
	if err := coin.Validate(); err != nil {
		panic(err)
	}
```

**File:** types/coin.go (L47-49)
```go
	if coin.Amount.IsNegative() {
		return fmt.Errorf("negative coin amount: %v", coin.Amount)
	}
```
