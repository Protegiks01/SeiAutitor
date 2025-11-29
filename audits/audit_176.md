Audit Report

## Title
Insufficient Lower Bound Validation on BlocksPerYear Enables Catastrophic Hyperinflation Through Governance Misconfiguration

## Summary
The `validateBlocksPerYear` function in the mint module lacks reasonable lower bound validation, only checking for zero values. This allows governance proposals to set BlocksPerYear to extremely small values (e.g., 1), causing catastrophic hyperinflation where each block mints provisions intended for an entire year, leading to severe devaluation of all existing token holdings and potential chain collapse requiring a hard fork.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended logic:** The BlocksPerYear parameter should represent the expected number of blocks per year (~6.3 million for 5-second blocks) and is used to distribute annual token minting provisions evenly across all blocks in a year. Validation should enforce reasonable bounds that correspond to actual blockchain operation parameters.

**Actual logic:** The validation function only checks if the value equals zero, accepting any positive value including 1, 2, or other unreasonably small values. The BlockProvision calculation then divides AnnualProvisions by this parameter. With BlocksPerYear=1, the entire year's inflation provisions are minted in every single block instead of being distributed across millions of blocks.

**Exploitation path:** 
1. A governance proposer submits a parameter change proposal setting BlocksPerYear to an extremely small value (potentially through typo or miscalculation)
2. The proposal passes the insufficient validation check since any value > 0 is accepted
3. If approved by governance (through voter apathy, misunderstanding of the parameter's impact, or insufficient review), the parameter is updated
4. The `BeginBlocker` function executes on every block, calling `BlockProvision(params)` which divides AnnualProvisions by the misconfigured BlocksPerYear value
5. Each subsequent block mints provisions equal to (or a large fraction of) the entire annual inflation target
6. Within minutes to hours, the token supply inflates by orders of magnitude (10x, 100x, or more), causing severe devaluation

**Security guarantee broken:** The economic security invariant that inflation should be controlled, predictable, and distributed evenly over time is catastrophically violated. The system allows a configuration that destroys the token economic model through uncontrolled massive token creation, even though this is clearly beyond the intended scope of governance parameter adjustments.

## Impact Explanation

This vulnerability causes **direct loss of funds** through severe devaluation of all existing token holdings via hyperinflation. With BlocksPerYear=1 and realistic parameters (10% annual inflation, 1 billion token supply):
- Each block would mint 100 million tokens (the full annual provision)
- At 5-second blocks: 1.2 billion new tokens per minute
- After 1 hour: 72 billion new tokens (72x the original supply)

All existing token holders would see their holdings devalued by 98%+ within hours. The chain's economic model would collapse, likely rendering it unusable and requiring a **hard fork** to recover, which qualifies as **permanent freezing of funds** until the hard fork is executed.

## Likelihood Explanation

While this requires a governance proposal to pass, the scenario is realistic through:

1. **Human error:** A proposer could accidentally type "1" instead of "6307200" or make a calculation error
2. **Insufficient review:** Governance voters might not carefully verify numeric parameter values
3. **Voter apathy:** Low participation could allow a poorly constructed proposal to pass

Although malicious exploitation would require majority collusion (out of scope), the **inadvertent triggering** by a trusted governance participant through honest mistake falls under the exception for "trusted role inadvertently triggering an unrecoverable security failure beyond their intended authority." Governance is intended to tune economic parameters, not to enable chain destruction.

The lack of technical safeguards (reasonable bounds checking) means the system has no defense against this catastrophic misconfiguration.

## Recommendation

Add reasonable lower and upper bound validation to `validateBlocksPerYear`:

```go
func validateBlocksPerYear(i interface{}) error {
    v, ok := i.(uint64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v == 0 {
        return fmt.Errorf("blocks per year must be positive: %d", v)
    }
    
    // Minimum: ~30 days of blocks (5s blocks = 518,400 blocks)
    // Maximum: ~3 years of blocks (19M blocks) for safety margin
    minBlocksPerYear := uint64(518400)
    maxBlocksPerYear := uint64(19000000)
    
    if v < minBlocksPerYear {
        return fmt.Errorf("blocks per year too low, must be at least %d: got %d", minBlocksPerYear, v)
    }
    
    if v > maxBlocksPerYear {
        return fmt.Errorf("blocks per year too high, must be at most %d: got %d", maxBlocksPerYear, v)
    }

    return nil
}
```

## Proof of Concept

The vulnerability can be demonstrated through the following test scenario:

**Setup:** Initialize a test chain with realistic parameters:
- Total supply: 1 billion tokens
- Annual inflation: 10%
- Default BlocksPerYear: 6,307,200 (5-second blocks)

**Action:** 
1. Create a governance proposal to set BlocksPerYear = 1
2. Verify the proposal passes validation (demonstrating the bug)
3. Apply the parameter change

**Result:**
1. The `Validate()` function accepts BlocksPerYear = 1 (should reject)
2. `BlockProvision` calculation: AnnualProvisions / 1 = 100 million tokens per block
3. After 10 blocks: 1 billion new tokens minted (10x the annual target)
4. The provision per block is over 1 million times higher than the normal rate

This demonstrates that the insufficient validation allows a catastrophic misconfiguration where a single typo or calculation error in a governance proposal could destroy the chain's economic model within minutes, requiring emergency intervention and a hard fork to recover.

**Notes:**

This finding qualifies as a High severity vulnerability because:
- It matches the impact category "Permanent freezing of funds (fix requires hard fork)" 
- It also constitutes "Direct loss of funds" through severe devaluation
- While it requires governance approval (privileged), it falls under the explicit exception for cases where "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority"
- The realistic trigger is human error (typo/miscalculation), not requiring malicious majority collusion
- Defense-in-depth principles dictate that critical parameters should have reasonable bounds checking regardless of who can modify them

### Citations

**File:** x/mint/types/params.go (L184-195)
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
}
```

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```
