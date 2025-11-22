# Audit Report

## Title
Missing Cross-Module Validation Between MintDenom and BondDenom Leading to Incorrect Token Minting

## Summary
The mint module calculates inflation based on the total supply of the staking bond denomination (`BondDenom`) but mints new tokens using a potentially different denomination (`MintDenom`). There is no cross-module validation to ensure these parameters remain consistent, allowing the system to mint incorrect tokens with inflation rates calculated from unrelated token supplies. This logic error can be triggered through governance parameter changes. [1](#0-0) 

## Impact
**Severity: Medium**

## Finding Description

**Location:** 
- Primary issue: [2](#0-1) 
- Inflation calculation dependency: [3](#0-2) 
- Minting logic: [4](#0-3) 
- Missing validation: [5](#0-4) 

**Intended Logic:** 
The mint module should calculate inflation based on the total supply of the staking token and mint new tokens of the same denomination to maintain consistent token economics. The inflation mechanism is designed to reward stakers proportionally to the bonded ratio of the staking token.

**Actual Logic:**
The code has a hidden cross-module dependency that is never validated:

1. `BeginBlocker` calls `k.StakingTokenSupply(ctx)` which retrieves the supply of the staking module's `BondDenom` parameter [3](#0-2) 

2. This supply is used to calculate `minter.AnnualProvisions` which determines how many tokens should be minted per year [6](#0-5) 

3. However, `minter.BlockProvision(params)` creates coins using `params.MintDenom` which is a completely independent parameter from the mint module [4](#0-3) 

4. Both parameters can be changed independently via governance proposals [7](#0-6) 

5. The parameter validation only checks that each denomination is a valid format, not that they match [8](#0-7)  and [9](#0-8) 

**Exploit Scenario:**
1. Chain initializes with both `MintDenom` and `BondDenom` set to default "usei" [10](#0-9) 

2. A governance proposal is submitted to change `MintDenom` to a different denomination (e.g., "wrongtoken") for any reason - perhaps mistakenly thinking it should match a new token standard, or due to misunderstanding the parameter's purpose

3. The proposal passes validation because `validateMintDenom` only checks that "wrongtoken" is a valid denomination format [8](#0-7) 

4. After the proposal executes, every block the mint module will:
   - Query the total supply of "usei" (the `BondDenom`) - e.g., 1,000,000,000 tokens
   - Calculate inflation rate based on the bonded ratio of "usei"  
   - Calculate how many tokens to mint based on "usei" supply
   - **But actually mint "wrongtoken" instead of "usei"** [4](#0-3) 

5. The newly minted "wrongtoken" tokens are sent to the fee collector and distributed as rewards [11](#0-10) 

**Security Failure:**
This breaks the fundamental token economics invariant that inflation rewards are paid in the staking token. The accounting logic becomes inconsistent - inflation calculations are based on one token's supply but applied to a different token's minting schedule.

## Impact Explanation

**Affected Assets/Processes:**
- Token supply integrity: Wrong denomination tokens are minted instead of staking tokens
- Economic security: Stakers expecting rewards in the staking token receive rewards in a different token
- Inflation mechanism: The inflation rate calculated for the staking token is applied to an unrelated token

**Severity of Damage:**
- Token economics breakdown: The core assumption that "inflation mints the staking token" is violated
- Validator/delegator rewards: Participants receive the wrong token denomination as rewards
- Supply accounting: The intended token is not minted while an unrelated token is inflated
- Protocol integrity: The fundamental mechanism linking staking, inflation, and rewards is broken

**Why This Matters:**
This is a critical design flaw where the protocol assumes an invariant (MintDenom == BondDenom) but never enforces it. While both parameters default to the same value, the lack of validation allows them to diverge through governance proposals, breaking the token economics model. This qualifies as "unintended protocol behavior" under the Medium severity scope.

## Likelihood Explanation

**Who Can Trigger:**
Requires a governance proposal with sufficient votes, which is a privileged action. However, this is a **subtle logic error** - proposers may not realize MintDenom must match BondDenom because there's no documentation, validation, or enforcement of this requirement.

**Conditions Required:**
- A governance parameter change proposal for MintDenom
- The proposal must pass voting (requires governance participation, not malicious intent)
- After execution, the issue manifests automatically in every subsequent block

**Frequency:**
- Could occur accidentally through well-intentioned governance proposals attempting to "update" token parameters
- The absence of any validation or warning makes this error easy to introduce
- Once triggered, the incorrect behavior persists in every block until another governance proposal fixes it

The vulnerability exists in the current codebase as a missing invariant check. While it requires governance action to manifest, the lack of any safeguard against this misconfiguration constitutes a design flaw in the protocol logic itself.

## Recommendation

Add cross-module validation to enforce the invariant that `MintDenom` must equal `BondDenom`:

1. **Immediate Fix:** Add validation in the parameter change handler to reject proposals that would cause MintDenom != BondDenom:

```go
// In x/params/proposal_handler.go or a custom handler
func validateMintStakingConsistency(ctx sdk.Context, k keeper.Keeper, changes []ParamChange) error {
    // Track if either MintDenom or BondDenom is being changed
    // After all changes applied, verify they remain equal
    // Reject proposal if they would diverge
}
```

2. **Genesis Validation:** Add a check in the application's genesis validation (not just individual module validation) to ensure MintDenom == BondDenom [5](#0-4) 

3. **Runtime Assertion:** Add a defensive check in BeginBlocker to panic if MintDenom != BondDenom, ensuring this invariant is enforced at runtime [2](#0-1) 

4. **Documentation:** Add clear documentation that MintDenom must always equal the staking BondDenom and explain why this invariant is critical for token economics.

## Proof of Concept

**Test File:** `x/mint/keeper/mint_denom_inconsistency_test.go` (new file)

**Setup:**
1. Initialize a SimApp with default genesis state where both MintDenom and BondDenom are "usei"
2. Mint initial supply of "usei" tokens and set up staking with bonded tokens
3. Record the initial supply of "usei" 

**Trigger:**
1. Use governance parameter change to set MintDenom to "wrongtoken" (different from BondDenom "usei")
2. Advance the blockchain by one block to trigger BeginBlocker
3. The mint module will calculate inflation based on "usei" supply but mint "wrongtoken"

**Observation:**
1. Verify that "wrongtoken" tokens were minted and added to supply
2. Verify that "usei" token supply did NOT increase despite inflation calculation being based on it
3. Verify that fee collector received "wrongtoken" instead of "usei"
4. This confirms the vulnerability: inflation calculated from wrong token supply

**Test Code Structure:**
```go
func TestMintDenomInconsistencyVulnerability(t *testing.T) {
    app, ctx := createTestApp(false)
    
    // Set initial state with usei as both MintDenom and BondDenom
    // Mint some usei and bond some for staking
    initialUseiSupply := app.BankKeeper.GetSupply(ctx, "usei")
    
    // Change MintDenom via params (simulating governance proposal)
    mintParams := app.MintKeeper.GetParams(ctx)
    mintParams.MintDenom = "wrongtoken"  
    app.MintKeeper.SetParams(ctx, mintParams)
    
    // Verify BondDenom is still "usei"
    stakingParams := app.StakingKeeper.GetParams(ctx)
    require.Equal(t, "usei", stakingParams.BondDenom)
    
    // Trigger BeginBlocker (which uses StakingTokenSupply with BondDenom)
    mint.BeginBlocker(ctx, app.MintKeeper)
    
    // OBSERVE VULNERABILITY:
    // 1. "wrongtoken" was minted (supply increased from 0)
    wrongtokenSupply := app.BankKeeper.GetSupply(ctx, "wrongtoken")
    require.True(t, wrongtokenSupply.Amount.GT(sdk.ZeroInt()), 
        "wrongtoken should have been minted")
    
    // 2. "usei" supply did NOT increase despite inflation calculation
    newUseiSupply := app.BankKeeper.GetSupply(ctx, "usei")
    require.Equal(t, initialUseiSupply.Amount, newUseiSupply.Amount,
        "usei supply should not have changed but inflation was calculated from it")
    
    // This proves the vulnerability: wrong token minted
}
```

This PoC demonstrates that when MintDenom != BondDenom, the system mints the wrong token while calculating inflation from a different token's supply, breaking the token economics invariant.

### Citations

**File:** x/mint/abci.go (L13-55)
```go
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
	mintedCoins := sdk.NewCoins(mintedCoin)

	err := k.MintCoins(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	// send the minted coins to the fee collector account
	err = k.AddCollectedFees(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	if mintedCoin.Amount.IsInt64() {
		defer telemetry.ModuleSetGauge(types.ModuleName, float32(mintedCoin.Amount.Int64()), "minted_tokens")
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeMint,
			sdk.NewAttribute(types.AttributeKeyBondedRatio, bondedRatio.String()),
			sdk.NewAttribute(types.AttributeKeyInflation, minter.Inflation.String()),
			sdk.NewAttribute(types.AttributeKeyAnnualProvisions, minter.AnnualProvisions.String()),
			sdk.NewAttribute(sdk.AttributeKeyAmount, mintedCoin.Amount.String()),
		),
	)
}
```

**File:** x/staking/keeper/pool.go (L66-68)
```go
func (k Keeper) StakingTokenSupply(ctx sdk.Context) sdk.Int {
	return k.bankKeeper.GetSupply(ctx, k.BondDenom(ctx)).Amount
}
```

**File:** x/mint/types/minter.go (L77-79)
```go
func (m Minter) BlockProvision(params Params) sdk.Coin {
	provisionAmt := m.AnnualProvisions.QuoInt(sdk.NewInt(int64(params.BlocksPerYear)))
	return sdk.NewCoin(params.MintDenom, provisionAmt.TruncateInt())
```

**File:** x/mint/types/genesis.go (L19-27)
```go
// ValidateGenesis validates the provided genesis state to ensure the
// expected invariants holds.
func ValidateGenesis(data GenesisState) error {
	if err := data.Params.Validate(); err != nil {
		return err
	}

	return ValidateMinter(data.Minter)
}
```

**File:** x/params/proposal_handler.go (L26-42)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
```

**File:** x/mint/types/params.go (L44-52)
```go
func DefaultParams() Params {
	return Params{
		MintDenom:           sdk.DefaultBondDenom,
		InflationRateChange: sdk.NewDecWithPrec(13, 2),
		InflationMax:        sdk.NewDecWithPrec(20, 2),
		InflationMin:        sdk.NewDecWithPrec(7, 2),
		GoalBonded:          sdk.NewDecWithPrec(67, 2),
		BlocksPerYear:       uint64(60 * 60 * 8766 / 5), // assuming 5 second block times
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

**File:** x/staking/types/params.go (L251-265)
```go
func validateBondDenom(i interface{}) error {
	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if strings.TrimSpace(v) == "" {
		return errors.New("bond denom cannot be blank")
	}

	if err := sdk.ValidateDenom(v); err != nil {
		return err
	}

	return nil
```
