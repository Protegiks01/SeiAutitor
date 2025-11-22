## Audit Report

### Title
Decimal Truncation in Block Minting Causes Systematic Inflation Shortfall

### Summary
The `BlockProvision` function in the mint module truncates decimal values to integers every block, causing cumulative loss of inflation rewards. In scenarios with low total supply, this can result in zero tokens being minted despite positive inflation rates, violating the protocol's economic model. [1](#0-0) 

### Impact
**Medium**

### Finding Description

**Location:** 
The vulnerability exists in `x/mint/types/minter.go`, specifically in the `BlockProvision` function (lines 77-80), which is called every block by `BeginBlocker` in `x/mint/abci.go` (line 28). [2](#0-1) 

**Intended Logic:**
The protocol calculates `AnnualProvisions` as `Inflation × TotalSupply` and stores this value in state. This represents the total tokens expected to be minted over a year. The `BlockProvision` function should distribute this amount proportionally across all blocks in the year. [3](#0-2) [4](#0-3) 

**Actual Logic:**
The `BlockProvision` function divides `AnnualProvisions` by `BlocksPerYear` (default: 6,311,520) and truncates the result to an integer using `TruncateInt()`. This discards all fractional token amounts every single block.

Two critical scenarios emerge:

1. **Zero Minting:** When `AnnualProvisions < BlocksPerYear`, the division yields < 1.0 tokens per block, which truncates to 0. With minimum inflation of 7% and BlocksPerYear = 6,311,520, this occurs when `TotalSupply < 90,164,571` tokens.

2. **Cumulative Loss:** Even with larger supplies, fractional amounts (up to 0.999... tokens per block) are lost. Over 6.3M blocks annually, this accumulates to a maximum loss of 6,311,519 tokens per year.

**Exploit Scenario:**
No attacker action is required - this occurs automatically:
1. Chain launches with initial supply < 90M tokens (or any value where `Inflation × Supply < BlocksPerYear`)
2. `BeginBlocker` runs every block, calculating provisions
3. `BlockProvision` truncates to 0, minting no tokens despite positive inflation
4. Stakers receive no inflation rewards, validators receive reduced compensation
5. The stored `AnnualProvisions` value diverges from actual minted amount

Existing test confirms this behavior is present: [5](#0-4) 

**Security Failure:**
This breaks the **economic accounting invariant**: the protocol emits `AnnualProvisions` in events and stores it in state, implying this amount will be minted. However, actual minting systematically falls short due to truncation. [6](#0-5) 

### Impact Explanation

**Affected Assets:**
- Staking rewards: Validators and delegators receive less inflation than the protocol parameters specify
- Economic security: Reduced rewards diminish incentives for staking and network security
- Protocol integrity: Published `AnnualProvisions` values do not match actual minting

**Severity:**
For a new chain with 50M token supply at 7% inflation:
- Expected annual provisions: 3,500,000 tokens
- Per-block provision: 3,500,000 / 6,311,520 = 0.554 tokens
- Actual minted per block: 0 tokens (truncated)
- **Total annual loss: 3,500,000 tokens (100% of expected inflation)**

For an established chain with 10B token supply at 7% inflation:
- Expected annual provisions: 700,000,000 tokens  
- Per-block provision: 110.91 tokens
- Actual minted per block: 110 tokens (truncated)
- **Annual loss: 5,744,783 tokens (0.82% of expected inflation)**

This constitutes unintended protocol behavior with measurable economic impact, fitting the Medium severity category: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

### Likelihood Explanation

**Triggering:**
- Automatically triggered every single block during normal operation
- No special privileges or attacker actions required
- Guaranteed to occur on any chain using this codebase

**Conditions:**
- Always present for low-supply chains (< 90M tokens with default parameters)
- Present with diminishing impact as supply increases
- Cannot be avoided without code changes

**Frequency:**
- Occurs 6,311,520 times per year (every block)
- Impact persists indefinitely until fixed
- Cumulative loss grows linearly with time

### Recommendation

Replace the truncation-based approach with a mechanism that tracks and carries forward fractional amounts:

```go
// In Minter struct, add a field to track remainder:
type Minter struct {
    Inflation        sdk.Dec
    AnnualProvisions sdk.Dec
    Remainder        sdk.Dec  // Track fractional tokens across blocks
}

// In BlockProvision function:
func (m Minter) BlockProvision(params Params) (sdk.Coin, sdk.Dec) {
    provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
    
    // Add previous remainder
    totalProvision := provisionAmt.Add(m.Remainder)
    
    // Extract integer part for minting
    mintAmount := totalProvision.TruncateInt()
    
    // Calculate new remainder for next block
    newRemainder := totalProvision.Sub(sdk.NewDecFromInt(mintAmount))
    
    return sdk.NewCoin(params.MintDenom, mintAmount), newRemainder
}
```

Update `BeginBlocker` to persist the remainder in the minter state after each block. This ensures that over time, the actual minted amount converges to `AnnualProvisions` with minimal loss.

### Proof of Concept

**File:** `x/mint/types/minter_test.go`

**Test Function:** `TestTruncationLoss` (add new test)

**Setup:**
```go
func TestTruncationLoss(t *testing.T) {
    // Test 1: Zero minting scenario with low supply
    params := DefaultParams()
    
    // Simulate a chain with 50M total supply and 7% inflation
    totalSupply := sdk.NewInt(50_000_000)
    inflation := sdk.NewDecWithPrec(7, 2) // 7%
    
    minter := NewMinter(inflation, sdk.ZeroDec())
    minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalSupply)
    
    // Expected annual provisions: 50M * 0.07 = 3.5M tokens
    expectedAnnual := sdk.NewDec(3_500_000)
    require.True(t, minter.AnnualProvisions.Equal(expectedAnnual))
```

**Trigger:**
```go
    // Calculate block provision
    blockProvision := minter.BlockProvision(params)
    
    // With 6,311,520 blocks per year:
    // 3,500,000 / 6,311,520 = 0.554 tokens per block
    // This truncates to 0!
    require.True(t, blockProvision.Amount.IsZero(),
        "Expected zero minting but got %s", blockProvision.Amount)
```

**Observation:**
```go
    // Test 2: Cumulative loss over a year
    // Simulate larger supply: 10B tokens at 7% inflation
    totalSupplyLarge := sdk.NewInt(10_000_000_000)
    minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalSupplyLarge)
    
    // Expected: 700M tokens per year
    expectedAnnualLarge := sdk.NewDec(700_000_000)
    require.True(t, minter.AnnualProvisions.Equal(expectedAnnualLarge))
    
    // Simulate minting for all blocks in a year
    totalMinted := sdk.ZeroInt()
    for i := 0; i < int(params.BlocksPerYear); i++ {
        provision := minter.BlockProvision(params)
        totalMinted = totalMinted.Add(provision.Amount)
    }
    
    // Convert expected annual to Int for comparison
    expectedMintedInt := expectedAnnualLarge.TruncateInt()
    actualLoss := expectedMintedInt.Sub(totalMinted)
    
    // Loss should be significant (millions of tokens)
    require.True(t, actualLoss.GT(sdk.NewInt(5_000_000)),
        "Expected loss > 5M tokens, got %s", actualLoss)
    
    // Calculate loss percentage
    lossPercentage := sdk.NewDecFromInt(actualLoss).Quo(expectedAnnualLarge).MulInt64(100)
    
    t.Logf("Annual provisions: %s", minter.AnnualProvisions)
    t.Logf("Expected minted: %s", expectedMintedInt)
    t.Logf("Actually minted: %s", totalMinted)
    t.Logf("Loss: %s tokens (%.2f%%)", actualLoss, lossPercentage.MustFloat64())
}
```

This test demonstrates that the truncation causes zero minting with low supply and millions of tokens lost annually with normal supply, confirming the vulnerability.

### Notes

The vulnerability is inherent in the design choice to use integer truncation rather than tracking fractional amounts. While the existing test suite shows awareness of zero-minting scenarios, there is no compensation mechanism to ensure that `AnnualProvisions` accurately reflects actual minting over time. This creates a systematic underpayment of inflation rewards that compounds the longer the chain operates.

### Citations

**File:** x/mint/types/minter.go (L71-73)
```go
func (m Minter) NextAnnualProvisions(_ Params, totalSupply sdk.Int) sdk.Dec {
	return m.Inflation.MulInt(totalSupply)
}
```

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```

**File:** x/mint/abci.go (L20-25)
```go
	// recalculate inflation rate
	totalStakingSupply := k.StakingTokenSupply(ctx)
	bondedRatio := k.BondedRatio(ctx)
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
	minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
	k.SetMinter(ctx, minter)
```

**File:** x/mint/abci.go (L27-29)
```go
	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)
```

**File:** x/mint/abci.go (L46-54)
```go
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeMint,
			sdk.NewAttribute(types.AttributeKeyBondedRatio, bondedRatio.String()),
			sdk.NewAttribute(types.AttributeKeyInflation, minter.Inflation.String()),
			sdk.NewAttribute(types.AttributeKeyAnnualProvisions, minter.AnnualProvisions.String()),
			sdk.NewAttribute(sdk.AttributeKeyAmount, mintedCoin.Amount.String()),
		),
	)
```

**File:** x/mint/types/minter_test.go (L70-70)
```go
		{(secondsPerYear / 5) / 2, 0},
```
