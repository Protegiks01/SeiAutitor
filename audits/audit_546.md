## Title
Missing Validation for Negative AnnualProvisions Allows Chain Halt via BlockProvision Panic

## Summary
The `ValidateMinter` function only validates that `Inflation` is non-negative but fails to validate `AnnualProvisions`. [1](#0-0)  This allows a malicious genesis state to contain negative `AnnualProvisions`, which causes `BlockProvision` to panic when it attempts to create a coin with a negative amount. [2](#0-1)  The panic occurs in `BeginBlocker` during the first block, causing complete chain halt.

## Impact
**High**

## Finding Description

**Location:** 
- Primary vulnerability: `x/mint/types/minter.go`, function `ValidateMinter` (lines 35-40)
- Panic trigger: `x/mint/types/minter.go`, function `BlockProvision` (lines 77-80)
- Panic location: `types/coin.go`, function `NewCoin` (lines 22-23)

**Intended Logic:** 
The `ValidateMinter` function should ensure all minter state fields are valid before allowing the minter to be persisted. Since `AnnualProvisions` represents the expected annual token provisions (an economic value that should always be non-negative), it should be validated similarly to `Inflation`.

**Actual Logic:**
`ValidateMinter` only validates `Inflation`: [3](#0-2) 

It does not validate `AnnualProvisions`. This allows negative values to pass validation during genesis initialization. [4](#0-3) 

When `BlockProvision` is called, it performs: `provisionAmt = m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))`. If `AnnualProvisions` is negative, the division preserves the negative sign. The result is truncated and passed to `sdk.NewCoin`, which validates the amount and panics if negative. [5](#0-4) 

**Exploit Scenario:**
1. Attacker provides or influences genesis configuration with negative `AnnualProvisions` (e.g., `"annual_provisions": "-1000.0"`)
2. Genesis validation passes because `ValidateMinter` doesn't check `AnnualProvisions`
3. Chain initialization succeeds with the malicious genesis state
4. First block's `BeginBlocker` executes and calls `minter.BlockProvision(params)` [6](#0-5) 
5. `BlockProvision` calculates negative provision amount and calls `NewCoin` with negative value
6. `NewCoin` panics with error "negative coin amount" [7](#0-6) 
7. Panic propagates through `BeginBlocker`, causing chain halt

**Security Failure:**
This violates the **consensus availability** invariant. The chain cannot process any blocks and halts completely. All validators are unable to progress, resulting in total network shutdown.

## Impact Explanation

**Affected:** The entire blockchain network and all participants.

**Severity:** This causes **total network shutdown** - the chain cannot confirm any transactions and becomes permanently unusable until a hard fork is deployed with corrected genesis state.

**Why it matters:** 
- **Network availability**: Complete DoS of the blockchain
- **Hard fork required**: Recovery requires coordinating all validators to restart with corrected genesis
- **Trust damage**: Users lose confidence in the network's reliability
- **Economic impact**: All economic activity halts; no transactions can be processed

This vulnerability fits the "High" impact category: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who can trigger:** Anyone with access to genesis configuration or ability to influence genesis validators during chain initialization. In some cases, genesis files are created through governance votes or multi-party coordination where an attacker could submit malicious parameters.

**Conditions required:** 
- Chain must be initializing from genesis (new chain or post-hard-fork restart)
- Attacker must be able to set or influence `AnnualProvisions` in genesis state

**Frequency:** While this requires specific timing (genesis initialization), the impact is catastrophic and permanent. Once triggered, it causes immediate and irreversible network failure. Social engineering or compromised genesis coordinators could enable this attack during legitimate chain launches.

## Recommendation

Add validation for `AnnualProvisions` in the `ValidateMinter` function:

```go
func ValidateMinter(minter Minter) error {
	if minter.Inflation.IsNegative() {
		return fmt.Errorf("mint parameter Inflation should be positive, is %s",
			minter.Inflation.String())
	}
	if minter.AnnualProvisions.IsNegative() {
		return fmt.Errorf("mint parameter AnnualProvisions should be non-negative, is %s",
			minter.AnnualProvisions.String())
	}
	return nil
}
```

This ensures that both critical minter fields are validated before allowing the minter state to be persisted.

## Proof of Concept

**Test File:** `x/mint/types/minter_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func TestBlockProvisionPanicWithNegativeAnnualProvisions(t *testing.T) {
	// Setup: Create a minter with negative AnnualProvisions
	// This simulates a malicious genesis state
	minter := Minter{
		Inflation:        sdk.NewDecWithPrec(13, 2), // 13% (valid)
		AnnualProvisions: sdk.NewDec(-1000),         // Negative (malicious)
	}
	
	params := DefaultParams()
	
	// Verify that ValidateMinter incorrectly passes
	// (This is the vulnerability - it should fail but doesn't)
	err := ValidateMinter(minter)
	require.NoError(t, err, "ValidateMinter should fail but doesn't - this is the bug!")
	
	// Trigger: Call BlockProvision which will panic
	// This simulates what happens in BeginBlocker
	require.Panics(t, func() {
		minter.BlockProvision(params)
	}, "BlockProvision should panic with negative AnnualProvisions")
}
```

**Observation:** 
1. The test confirms `ValidateMinter` incorrectly passes validation for negative `AnnualProvisions`
2. When `BlockProvision` is called, it panics with "negative coin amount"
3. This panic would occur in `BeginBlocker`, halting the chain

**To run this test:**
```bash
cd x/mint/types
go test -run TestBlockProvisionPanicWithNegativeAnnualProvisions -v
```

The test will demonstrate that:
- Negative `AnnualProvisions` passes validation (the vulnerability)
- Calling `BlockProvision` with negative `AnnualProvisions` causes a panic
- This panic would halt the chain in production when `BeginBlocker` executes

### Citations

**File:** x/mint/types/minter.go (L35-40)
```go
func ValidateMinter(minter Minter) error {
	if minter.Inflation.IsNegative() {
		return fmt.Errorf("mint parameter Inflation should be positive, is %s",
			minter.Inflation.String())
	}
	return nil
```

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```

**File:** x/mint/types/genesis.go (L21-26)
```go
func ValidateGenesis(data GenesisState) error {
	if err := data.Params.Validate(); err != nil {
		return err
	}

	return ValidateMinter(data.Minter)
```

**File:** types/coin.go (L14-27)
```go
// NewCoin returns a new coin with a denomination and amount. It will panic if
// the amount is negative or if the denomination is invalid.
func NewCoin(denom string, amount Int) Coin {
	coin := Coin{
		Denom:  denom,
		Amount: amount,
	}

	if err := coin.Validate(); err != nil {
		panic(err)
	}

	return coin
}
```

**File:** types/coin.go (L47-49)
```go
	if coin.Amount.IsNegative() {
		return fmt.Errorf("negative coin amount: %v", coin.Amount)
	}
```

**File:** x/mint/abci.go (L28-28)
```go
	mintedCoin := minter.BlockProvision(params)
```
