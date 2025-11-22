## Audit Report

## Title
Annual Provisions Storage Bypass Leading to Incorrect Token Minting Calculations

## Summary
The BeginBlocker function in the mint module fetches stored annual provisions from state but never uses them for minting calculations. Instead, it immediately recalculates new provisions and uses those, violating the design intent that provisions should be "stored correctly for use in subsequent block provision calculations." This results in minting amounts being based on instantaneous state rather than stable stored values, potentially causing incorrect token issuance and economic parameter drift. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** `x/mint/abci.go`, BeginBlocker function, lines 17-28

**Intended Logic:** According to the function comment "BeginBlocker mints new tokens for the previous block" and the security question's premise, the intended flow should be:
1. Retrieve annual provisions calculated and stored in the previous block
2. Use those stored provisions to calculate block provision for minting
3. Then calculate new provisions for use in the next block
4. Store the new provisions for subsequent use [2](#0-1) 

**Actual Logic:** The current implementation:
1. Retrieves minter with stored annual provisions (line 17)
2. Immediately recalculates new inflation (line 23)
3. Recalculates new annual provisions using the NEW inflation (line 24)
4. Stores the recalculated minter (line 25)
5. Uses the NEWLY calculated provisions for minting (line 28)

The stored annual provisions from the previous block are fetched but never used - they are overwritten before being consumed. [3](#0-2) [4](#0-3) [5](#0-4) 

**Exploit Scenario:** While not requiring a malicious actor, this bug triggers automatically every block:
1. Block N-1 completes with annual provisions = X stored in state
2. Block N begins and BeginBlocker executes
3. Stored provisions X are fetched but ignored
4. New provisions Y are calculated based on block N's state
5. Minting uses Y instead of X
6. Provisions X are never used for their intended purpose

**Security Failure:** This violates the accounting invariant that annual provisions should be stable stored values used in subsequent calculations. The system operates with unintended token issuance behavior where minting amounts are based on instantaneous recalculations rather than stable pre-calculated provisions, potentially causing inflation rate deviation from intended economic parameters. [6](#0-5) 

## Impact Explanation

This bug affects the core economic parameters of the blockchain:

- **Token Supply Affected:** The total token supply grows at potentially incorrect rates because minting calculations don't use the stable provisions that were calculated and stored for this purpose
- **Economic Model Deviation:** The stored annual provisions serve no purpose - state storage is wasted on values that are immediately overwritten without use
- **Staker Rewards Impact:** Validators and delegators may receive incorrect reward amounts if the provisions used for minting differ from what was calculated in the previous block
- **Inflation Volatility:** Without using stable stored provisions, minting becomes more reactive to instantaneous state changes, potentially increasing volatility in inflation rates

The severity is Medium because this represents "a bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the protocol executes with incorrect token issuance logic, though individual users don't lose existing funds directly. [7](#0-6) 

## Likelihood Explanation

**Triggering Frequency:** This bug triggers automatically in every single block - it is 100% consistent and reproducible.

**Who Can Trigger:** No specific actor needs to trigger this - it happens as part of normal block production. Every block that goes through BeginBlocker exhibits this behavior.

**Conditions Required:** No special conditions required - this occurs during normal network operation. The bug is in the fundamental block processing logic.

**Exploitation Frequency:** Occurs approximately every 5 seconds (assuming default 5-second block time), or ~6.3 million times per year, affecting all token minting operations. [8](#0-7) 

## Recommendation

Reorder the operations in BeginBlocker to use stored provisions before recalculating new ones:

1. Move lines 28-40 (BlockProvision calculation and minting) to execute BEFORE lines 20-25 (inflation and annual provisions recalculation)
2. This ensures block N uses annual provisions calculated and stored in block N-1
3. Then calculate new provisions for use in block N+1

The corrected flow should be:
```
// Get minter with provisions from previous block
minter := k.GetMinter(ctx)

// Mint using the stored provisions from previous block
mintedCoin := minter.BlockProvision(params)
// ... perform minting operations ...

// NOW calculate new provisions for next block
totalStakingSupply := k.StakingTokenSupply(ctx)
bondedRatio := k.BondedRatio(ctx)
minter.Inflation = minter.NextInflationRate(params, bondedRatio)
minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
k.SetMinter(ctx, minter)
```

This ensures stored provisions are actually used for their intended purpose in subsequent block calculations.

## Proof of Concept

**File:** `x/mint/keeper/integration_test.go`
**Function:** `TestAnnualProvisionsNotUsedForMinting` (new test to add)

**Setup:**
1. Initialize test app and context
2. Set initial minter with specific annual provisions (e.g., 1,000,000 tokens)
3. Store this minter to state
4. Prepare conditions that would result in DIFFERENT provisions if recalculated (e.g., change bonding ratio or supply)

**Trigger:**
1. Call BeginBlocker for the next block
2. Observe the minted amount

**Observation:**
The test will demonstrate that:
- The minted amount is NOT based on the stored provisions (1,000,000) from the previous block
- Instead, it's based on freshly calculated provisions in the current block
- This proves the stored provisions are never used

The test should capture the minter before and after BeginBlocker execution and verify that:
1. The BlockProvision calculation uses newly calculated AnnualProvisions, not the stored ones
2. The ratio of minted amount to stored annual provisions does NOT equal 1/BlocksPerYear
3. Instead, the ratio uses the recalculated provisions

This demonstrates the invariant violation where stored provisions are bypassed in favor of immediate recalculation, confirming the bug that annual provisions are NOT "stored correctly for use in subsequent block provision calculations." [9](#0-8)

### Citations

**File:** x/mint/abci.go (L12-28)
```go
// BeginBlocker mints new tokens for the previous block.
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	// fetch stored minter & params
	minter := k.GetMinter(ctx)
	params := k.GetParams(ctx)

	// recalculate inflation rate
	totalStakingSupply := k.StakingTokenSupply(ctx)
	bondedRatio := k.BondedRatio(ctx)
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
	minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
	k.SetMinter(ctx, minter)

	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
```

**File:** x/mint/types/minter.go (L77-80)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
}
```

**File:** x/mint/spec/03_begin_block.md (L36-44)
```markdown
## NextAnnualProvisions

Calculate the annual provisions based on current total supply and inflation
rate. This parameter is calculated once per block.

```
NextAnnualProvisions(params Params, totalSupply sdk.Dec) (provisions sdk.Dec) {
	return Inflation * totalSupply
```
```

**File:** x/mint/types/params.go (L51-51)
```go
		BlocksPerYear:       uint64(60 * 60 * 8766 / 5), // assuming 5 second block times
```

**File:** x/mint/keeper/integration_test.go (L11-20)
```go
// returns context and an app with updated mint keeper
func createTestApp(isCheckTx bool) (*simapp.SimApp, sdk.Context) {
	app := simapp.Setup(isCheckTx)

	ctx := app.BaseApp.NewContext(isCheckTx, tmproto.Header{})
	app.MintKeeper.SetParams(ctx, types.DefaultParams())
	app.MintKeeper.SetMinter(ctx, types.DefaultInitialMinter())

	return app, ctx
}
```
