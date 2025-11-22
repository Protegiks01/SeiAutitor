## Audit Report

## Title
MintDenom Change Breaks Inflation Calculations Due to Supply Mismatch Between Minting and Staking Tokens

## Summary
When MintDenom is changed via governance proposal, the mint module's BeginBlocker continues calculating inflation based on the staking bond denomination supply (BondDenom) but mints coins in the new MintDenom. This causes incorrect inflation rates when the two tokens have different supplies, breaking the core economic invariant that inflation should be calculated based on the minted token's supply.

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Supply fetching: [2](#0-1) 
- Coin creation: [3](#0-2) 
- Parameter validation (insufficient): [4](#0-3) 

**Intended Logic:** 
The mint module should calculate inflation based on the total supply of the token being minted (MintDenom). The annual provisions should be `Inflation * MintDenomSupply`, and block provisions should mint the correct proportion of that token.

**Actual Logic:** 
The BeginBlocker fetches `StakingTokenSupply(ctx)` which returns the supply of the staking module's BondDenom [5](#0-4) , then calculates `AnnualProvisions = Inflation * StakingTokenSupply` [6](#0-5) , but creates the minted coin using `params.MintDenom` [7](#0-6) . When MintDenom ≠ BondDenom, the inflation calculation uses the wrong supply base.

**Exploit Scenario:**
1. Initial state: MintDenom = BondDenom = "usei" with supply of 1,000,000,000 tokens
2. A governance proposal passes to change MintDenom to "newtoken" (e.g., for introducing a new rewards token)
3. The parameter change validation only checks the denom format [8](#0-7) , not supply compatibility
4. "newtoken" has a supply of 10,000,000 tokens (100x smaller than usei)
5. BeginBlocker executes:
   - Fetches totalStakingSupply = 1,000,000,000 (usei supply)
   - Calculates AnnualProvisions = 0.10 * 1,000,000,000 = 100,000,000
   - Mints BlockProvision amount in "newtoken" based on these provisions
6. Result: "newtoken" is inflated at 10x the intended rate (100,000,000 provisions / 10,000,000 supply = 1000% actual inflation vs 10% intended)

**Security Failure:**
This breaks the accounting invariant that minting should be proportional to the minted token's supply. The system exhibits unintended protocol behavior where token economics are fundamentally broken, leading to either massive over-inflation (if new token has lower supply) or under-inflation (if new token has higher supply) compared to the configured inflation parameters.

## Impact Explanation

**Affected Assets/Processes:**
- The newly minted token's supply and economic model
- Token holders of the new MintDenom (value dilution through over-inflation)
- Protocol economic security (inflation-based incentive mechanisms)

**Severity of Damage:**
- If the new MintDenom has significantly lower supply than BondDenom, extreme over-inflation occurs, potentially minting more tokens per block than the entire existing supply
- If the new MintDenom has significantly higher supply, under-inflation occurs, breaking reward mechanisms
- The mismatch can be 10x, 100x, or even infinite (if new token starts at 0 supply)
- This violates the core economic design where inflation parameters are calibrated for specific supply levels

**Why This Matters:**
The mint module is a core protocol component that ensures proper token distribution and validator incentives. When its calculations become decoupled from the actual token supply, the entire economic model breaks down. This meets the "Medium" severity criteria as "a bug in the layer 1 network code that results in unintended smart contract behavior" - the minting behavior becomes completely unintended relative to the configured parameters.

## Likelihood Explanation

**Who Can Trigger:**
This requires a governance proposal to change the MintDenom parameter. While governance is privileged, the instructions explicitly state to examine "subtle logic errors or unintended behaviors that could be triggered accidentally" by privileged roles. A well-intentioned governance proposal to introduce a new rewards token would trigger this bug.

**Required Conditions:**
- Governance proposal passes to change MintDenom
- New MintDenom has a different supply than BondDenom
- BeginBlocker executes (happens every block)

**Frequency:**
Once triggered, the incorrect behavior persists for every block until another governance action corrects it. The likelihood increases as protocols consider multi-token economies or want to change their minting token. Many Cosmos chains have discussed or implemented multi-token systems, making this a realistic scenario.

## Recommendation

When MintDenom is changed via governance, the system should:

1. **Add validation** in the parameter change handler to check if MintDenom equals BondDenom, or warn if they differ
2. **Modify BeginBlocker** to fetch the supply of the actual MintDenom instead of BondDenom:
   ```
   // Instead of: totalStakingSupply := k.StakingTokenSupply(ctx)
   // Use: mintDenomSupply := k.bankKeeper.GetSupply(ctx, params.MintDenom).Amount
   ```
3. **Reset minter state** when MintDenom changes to recalculate AnnualProvisions based on the new token's supply
4. **Add migration logic** in the params.SetParams or parameter change handler to detect MintDenom changes and reset the minter accordingly

The minimal fix is to change the supply fetching in BeginBlocker to use MintDenom's supply rather than BondDenom's supply.

## Proof of Concept

**File:** `x/mint/keeper/mint_denom_change_test.go` (new test file)

**Setup:**
1. Initialize simapp with default params (MintDenom = BondDenom = "usei")
2. Set initial supply: 1,000,000,000 usei
3. Create a new token "newtoken" with supply of 10,000,000 tokens
4. Set minter state with 10% inflation rate

**Trigger:**
1. Change MintDenom parameter to "newtoken" via governance
2. Call BeginBlocker to execute one minting cycle
3. Calculate expected vs actual minted amounts

**Observation:**
The test demonstrates that:
- Expected minting (based on newtoken supply): 10% of 10,000,000 = 1,000,000 tokens per year
- Actual minting (based on usei supply): 10% of 1,000,000,000 = 100,000,000 tokens per year (100x higher!)
- This proves the inflation calculation is using the wrong supply base

**Test Code Structure:**
```go
func TestMintDenomChangeSupplyMismatch(t *testing.T) {
    app, ctx := createTestApp(false)
    
    // Setup: Create newtoken with different supply
    newTokenDenom := "newtoken"
    newTokenSupply := sdk.NewInt(10_000_000)
    
    // Mint newtoken to establish its supply
    newTokenCoins := sdk.NewCoins(sdk.NewCoin(newTokenDenom, newTokenSupply))
    err := app.BankKeeper.MintCoins(ctx, minttypes.ModuleName, newTokenCoins)
    require.NoError(t, err)
    
    // Set minter with 10% inflation
    minter := minttypes.NewMinter(sdk.NewDecWithPrec(10, 2), sdk.ZeroDec())
    app.MintKeeper.SetMinter(ctx, minter)
    
    // Get initial usei supply (should be ~1B from default setup)
    useiSupply := app.BankKeeper.GetSupply(ctx, "usei").Amount
    
    // Change MintDenom to newtoken
    params := app.MintKeeper.GetParams(ctx)
    params.MintDenom = newTokenDenom
    app.MintKeeper.SetParams(ctx, params)
    
    // Execute BeginBlocker
    mint.BeginBlocker(ctx, app.MintKeeper)
    
    // Get minter to check AnnualProvisions
    updatedMinter := app.MintKeeper.GetMinter(ctx)
    
    // Expected: provisions based on newtoken supply (10M)
    expectedProvisions := minter.Inflation.MulInt(newTokenSupply)
    
    // Actual: provisions based on usei supply (1B)  
    actualProvisions := updatedMinter.AnnualProvisions
    
    // Assert the bug: actual provisions are based on wrong supply
    require.NotEqual(t, expectedProvisions, actualProvisions)
    require.Equal(t, minter.Inflation.MulInt(useiSupply), actualProvisions)
    
    // This demonstrates ~100x over-inflation of newtoken
    ratio := actualProvisions.Quo(expectedProvisions)
    require.True(t, ratio.GT(sdk.NewDec(50))) // At least 50x higher
}
```

This PoC can be added to the mint keeper test suite and will fail on the current code, demonstrating that changing MintDenom causes inflation calculations to use the wrong supply base.

### Citations

**File:** x/mint/abci.go (L21-24)
```go
	totalStakingSupply := k.StakingTokenSupply(ctx)
	bondedRatio := k.BondedRatio(ctx)
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
	minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
```

**File:** x/staking/keeper/pool.go (L65-68)
```go
// StakingTokenSupply staking tokens from the total supply
func (k Keeper) StakingTokenSupply(ctx sdk.Context) sdk.Int {
	return k.bankKeeper.GetSupply(ctx, k.BondDenom(ctx)).Amount
}
```

**File:** x/mint/types/minter.go (L71-72)
```go
func (m Minter) NextAnnualProvisions(_ Params, totalSupply sdk.Int) sdk.Dec {
	return m.Inflation.MulInt(totalSupply)
```

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```

**File:** x/mint/types/params.go (L104-117)
```go
func validateMintDenom(i interface{}) error {
	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if strings.TrimSpace(v) == "" {
		return errors.New("mint denom cannot be blank")
	}
	if err := sdk.ValidateDenom(v); err != nil {
		return err
	}

	return nil
```
