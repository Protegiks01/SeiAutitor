## Title
Insufficient Lower Bound Validation on BlocksPerYear Allows Hyperinflation Attack

## Summary
The `validateBlocksPerYear` function in the mint module only validates that BlocksPerYear is non-zero, but does not enforce any reasonable lower bound. This allows governance proposals to set BlocksPerYear to extremely small values (e.g., 1), which causes each block to mint provisions intended for an entire year, leading to catastrophic hyperinflation and economic collapse.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The BlocksPerYear parameter represents the expected number of blocks per year and is used to distribute annual token minting provisions evenly across blocks. The validation should ensure this parameter is set to a reasonable value that corresponds to the actual expected blocks per year (typically millions of blocks).

**Actual Logic:** 
The validation only checks if BlocksPerYear equals zero, allowing any positive value including 1, 2, or other extremely small values. When BlocksPerYear is set to a very small value, the minting calculations in `BlockProvision` become catastrophically incorrect. [2](#0-1) 

The BlockProvision calculation divides AnnualProvisions by BlocksPerYear. If BlocksPerYear=1, the entire year's provisions are minted in a single block instead of being distributed across ~6 million blocks.

**Exploit Scenario:**
1. An attacker (or a well-meaning participant making an error) submits a governance proposal to change BlocksPerYear to 1 or another very small value
2. The proposal passes validation since 1 > 0
3. If the proposal is approved by governance (through voter apathy, misunderstanding, or malicious coordination), the parameter is updated
4. Every subsequent block mints provisions equal to (or a large fraction of) the entire annual provisions
5. Within minutes, the total token supply inflates by orders of magnitude, destroying the token's economic value

**Security Failure:**
This breaks the economic security invariant that inflation should be controlled and predictable. The accounting logic fails catastrophically, allowing unintended massive token creation that devalues all existing holdings.

## Impact Explanation

**Assets Affected:** All token holders' assets are severely devalued through hyperinflation.

**Severity:** 
- If BlocksPerYear=1 with 10% annual inflation and 1 billion total supply:
  - AnnualProvisions = 100 million tokens
  - BlockProvision = 100 million tokens per block
  - At 5-second blocks: 1.2 billion new tokens per minute
  - Within one hour: 72 billion new tokens (72x the original supply)
  
This constitutes a **direct loss of funds** through severe devaluation of existing token holdings. The economic model of the chain would collapse, potentially rendering the chain unusable and requiring a hard fork to recover.

## Likelihood Explanation

**Trigger Conditions:**
- Any address with sufficient tokens for the governance deposit can submit a proposal
- Requires majority governance approval to pass
- Could occur through:
  - Malicious governance attack by coordinated bad actors
  - Human error in proposal creation (typo, misunderstanding of parameter)
  - Social engineering of governance voters
  - Voter apathy allowing malicious proposal to pass

**Frequency:** 
While requiring governance approval is a significant barrier, the lack of validation means the system has no technical safeguard against this catastrophic configuration. Governance mistakes or attacks are realistic scenarios in blockchain systems.

## Recommendation

Add a reasonable lower bound validation to `validateBlocksPerYear`. The lower bound should represent a minimum reasonable expectation, such as blocks produced in at least 30 days:

```go
func validateBlocksPerYear(i interface{}) error {
    v, ok := i.(uint64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v == 0 {
        return fmt.Errorf("blocks per year must be positive: %d", v)
    }
    
    // Minimum of ~30 days worth of blocks (assuming 5s blocks)
    // 30 days * 24 hours * 60 min * 60 sec / 5 sec = 518,400 blocks
    minBlocksPerYear := uint64(518400)
    if v < minBlocksPerYear {
        return fmt.Errorf("blocks per year too low, must be at least %d: got %d", minBlocksPerYear, v)
    }

    return nil
}
```

## Proof of Concept

**File:** `x/mint/keeper/integration_test.go`

**Test Function:** `TestBlocksPerYearHyperinflationVulnerability`

```go
func TestBlocksPerYearHyperinflationVulnerability(t *testing.T) {
    app, ctx := createTestApp(false)
    
    // Setup: Get initial state
    initialMinter := app.MintKeeper.GetMinter(ctx)
    initialParams := app.MintKeeper.GetParams(ctx)
    
    // Set a realistic total supply (1 billion tokens)
    totalSupply := sdk.NewInt(1_000_000_000_000_000) // 1B with 6 decimals
    
    // Calculate annual provisions with 10% inflation
    inflation := sdk.NewDecWithPrec(10, 2) // 10%
    initialMinter.Inflation = inflation
    annualProvisions := inflation.MulInt(totalSupply)
    initialMinter.AnnualProvisions = annualProvisions
    app.MintKeeper.SetMinter(ctx, initialMinter)
    
    // Normal case: Calculate expected block provision with default BlocksPerYear
    normalBlockProvision := initialMinter.BlockProvision(initialParams)
    
    // Trigger: Set BlocksPerYear to 1 (which passes validation!)
    maliciousParams := initialParams
    maliciousParams.BlocksPerYear = 1
    
    // This should fail validation but currently doesn't
    err := maliciousParams.Validate()
    require.NoError(t, err) // Demonstrates the validation bug
    
    app.MintKeeper.SetParams(ctx, maliciousParams)
    
    // Observation: Calculate block provision with malicious params
    maliciousMinter := app.MintKeeper.GetMinter(ctx)
    maliciousBlockProvision := maliciousMinter.BlockProvision(maliciousParams)
    
    // With BlocksPerYear=1, each block mints the ENTIRE annual provisions
    require.Equal(t, annualProvisions.TruncateInt(), maliciousBlockProvision.Amount,
        "BlockProvision should equal full AnnualProvisions when BlocksPerYear=1")
    
    // Show the massive difference
    ratio := maliciousBlockProvision.Amount.Quo(normalBlockProvision.Amount)
    require.True(t, ratio.GT(sdk.NewInt(1_000_000)), 
        "Malicious provision is over 1 million times higher than normal")
    
    // Simulate minting for just 10 blocks
    totalMinted := sdk.ZeroInt()
    for i := 0; i < 10; i++ {
        provision := maliciousMinter.BlockProvision(maliciousParams)
        totalMinted = totalMinted.Add(provision.Amount)
    }
    
    // After just 10 blocks, we've minted 10x the annual provisions!
    expectedAnnual := annualProvisions.TruncateInt()
    require.True(t, totalMinted.GT(expectedAnnual.MulRaw(9)),
        "After 10 blocks, minted amount should exceed 9x annual provisions")
    
    t.Logf("Normal block provision: %s", normalBlockProvision.Amount)
    t.Logf("Malicious block provision: %s", maliciousBlockProvision.Amount)
    t.Logf("Multiplier: %s", ratio)
    t.Logf("After 10 blocks: %s (%.2fx annual)", totalMinted, 
        sdk.NewDec(10).Quo(sdk.NewDec(1)))
}
```

**Setup:** Creates a test app with realistic total supply and inflation parameters.

**Trigger:** Sets BlocksPerYear to 1, which incorrectly passes validation.

**Observation:** Demonstrates that:
1. The validation accepts BlocksPerYear=1
2. Each block mints the entire annual provisions instead of 1/6,000,000th of them
3. After just 10 blocks, the supply would increase by 10x the intended annual amount
4. This proves the catastrophic hyperinflation vulnerability

### Citations

**File:** x/mint/types/params.go (L184-194)
```go
func validateBlocksPerYear(i interface{}) error {
	v, ok := i.(uint64)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v == 0 {
		return fmt.Errorf("blocks per year must be positive: %d", v)
	}

	return nil
```

**File:** x/mint/types/minter.go (L75-80)
```go
// BlockProvision returns the provisions for a block based on the annual
// provisions rate.
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```
