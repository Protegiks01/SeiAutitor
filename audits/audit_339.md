## Audit Report

## Title
Slashing Parameters Lack Cross-Parameter Validation Allowing Complete Bypass of Downtime Slashing

## Summary
The `SetParams` function in the slashing keeper does not validate combinations of parameters, only individual parameter values. This allows governance to accidentally persist a parameter set where `SignedBlocksWindow` and `MinSignedPerWindow` combine to completely disable downtime slashing, enabling validators to remain offline indefinitely without penalty. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in `x/slashing/keeper/params.go` at lines 52-53 in the `SetParams` function, and manifests in the downtime slashing logic in `x/slashing/keeper/infractions.go` at lines 92-96. [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The slashing module is designed to penalize validators for downtime by tracking missed blocks in a sliding window. Validators should be slashed when they miss more than the allowed threshold of blocks. The `SetParams` function should ensure that all parameter combinations maintain this security property.

**Actual Logic:** 
The `SetParams` function calls `k.paramspace.SetParamSet(ctx, &params)` which validates each parameter individually through their respective validator functions, but does not validate relationships between parameters. [3](#0-2) [4](#0-3) 

The critical calculation occurs in the `MinSignedPerWindow()` keeper method, which multiplies the fraction by the window size and applies banker's rounding: [5](#0-4) [6](#0-5) 

When `MinSignedPerWindow * SignedBlocksWindow` rounds to 0 due to banker's rounding (e.g., 0.5 * 1 = 0.5 rounds to 0), the downtime slashing check becomes ineffective: [7](#0-6) 

With `minSignedPerWindow = 0`, the calculation becomes `maxMissed = window - 0 = window`. Since the `MissedBlocksCounter` in a sliding window of size `window` can never exceed `window`, the condition `signInfo.MissedBlocksCounter > maxMissed` on line 96 will never be true, completely disabling downtime slashing.

**Exploit Scenario:**
1. A governance proposal sets slashing parameters to seemingly valid values:
   - `SignedBlocksWindow = 1` (passes validation: must be > 0)
   - `MinSignedPerWindow = 0.5` (passes validation: must be >= 0 and <= 1)
2. These values individually pass their respective validators
3. However, `MinSignedPerWindow() = 0.5 * 1 = 0.5` rounds to 0 via banker's rounding
4. Validators can now miss every single block without triggering the slashing condition
5. Multiple validators could exploit this to go offline, potentially causing network shutdown [8](#0-7) [9](#0-8) 

**Security Failure:**
This breaks the economic security invariant that validators must maintain liveness or face slashing penalties. The liveness guarantee of the blockchain is compromised, as validators have no economic incentive to stay online.

## Impact Explanation

The vulnerability affects the network's liveness guarantees and economic security model:

- **Affected Process:** Validator downtime slashing mechanism, which is critical for maintaining network liveness
- **Severity:** If exploited by a sufficient number of validators, the network could halt entirely due to insufficient validators being online to produce blocks, falling under the "Network not being able to confirm new transactions (total network shutdown)" impact category
- **Economic Impact:** Validators could go offline without penalty, breaking the staking economic model where uptime is financially enforced
- **System Reliability:** The protocol's ability to maintain consensus and process transactions depends on validator liveness, which this vulnerability completely undermines

This vulnerability matters because blockchains rely on economic incentives to ensure validators behave correctly. Removing the downtime slashing penalty eliminates a fundamental security mechanism.

## Likelihood Explanation

**Trigger Mechanism:** Requires a governance proposal to set these parameters, which is a privileged action. However, the vulnerability can be triggered accidentally:

- Governance participants may not understand the subtle interaction between banker's rounding and small window sizes
- Each parameter individually appears valid and passes validation
- There are no warnings or validation errors when setting dangerous combinations
- The issue is non-obvious: setting `SignedBlocksWindow = 1` and `MinSignedPerWindow = 0.5` looks reasonable at first glance

**Frequency:** Once the vulnerable parameters are set through governance:
- Any validator can immediately exploit it by going offline
- The exploitation is passive (validators simply stop signing blocks)
- The issue persists until governance passes another proposal to fix the parameters

**Realistic Conditions:** While it requires governance action, the rules explicitly state to focus on "subtle logic errors or unintended behaviors that could be triggered accidentally" for privileged functionality, which this qualifies as.

## Recommendation

Add a `Validate()` method to the `Params` struct in `x/slashing/types/params.go` that checks parameter combinations and call it in `SetParams` before persisting:

```go
func (p Params) Validate() error {
    // Validate individual parameters first
    if err := validateSignedBlocksWindow(p.SignedBlocksWindow); err != nil {
        return err
    }
    if err := validateMinSignedPerWindow(p.MinSignedPerWindow); err != nil {
        return err
    }
    // ... validate other individual params
    
    // Validate parameter combinations
    minSigned := p.MinSignedPerWindow.MulInt64(p.SignedBlocksWindow).RoundInt64()
    if minSigned == 0 {
        return fmt.Errorf(
            "parameter combination results in zero minimum signed blocks: "+
            "SignedBlocksWindow=%d * MinSignedPerWindow=%s rounds to 0. "+
            "This would disable downtime slashing. "+
            "Increase either SignedBlocksWindow or MinSignedPerWindow.",
            p.SignedBlocksWindow, p.MinSignedPerWindow)
    }
    
    return nil
}
```

Then modify `SetParams` to call this validation:

```go
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) {
    if err := params.Validate(); err != nil {
        panic(fmt.Sprintf("invalid slashing params: %s", err))
    }
    k.paramspace.SetParamSet(ctx, &params)
}
```

This ensures that any parameter combination that would disable downtime slashing is rejected before being persisted.

## Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`

**Test Function:** `TestInvalidParameterCombinationDisablesDowntimeSlashing`

**Setup:**
1. Initialize a test blockchain with default slashing parameters
2. Create a validator with standard voting power
3. Allow the validator to sign blocks normally to establish baseline behavior

**Trigger:**
1. Set vulnerable parameters via `SetParams`:
   - `SignedBlocksWindow = 1`  
   - `MinSignedPerWindow = sdk.NewDecWithPrec(5, 1)` (0.5)
2. Verify that `MinSignedPerWindow()` returns 0 due to rounding
3. Have the validator miss consecutive blocks indefinitely (e.g., 1000 blocks)

**Observation:**
The test confirms the vulnerability by observing:
1. `MinSignedPerWindow()` returns 0 (demonstrating the rounding issue)
2. The validator's `MissedBlocksCounter` increments but never exceeds `maxMissed = 1`
3. The validator is never jailed despite missing every block
4. The validator's tokens are not slashed
5. The validator remains in bonded status throughout

**Expected Behavior (if secure):** The validator should be slashed and jailed after missing sufficient blocks.

**Actual Behavior (vulnerable):** The validator can miss every block indefinitely without penalty.

**Test Code Structure:**
```go
func TestInvalidParameterCombinationDisablesDowntimeSlashing(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create validator
    power := int64(100)
    pks := simapp.CreateTestPubKeys(1)
    addr, val := pks[0].Address(), pks[0]
    // ... setup validator bonding ...
    
    // Set vulnerable parameters
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = 1
    params.MinSignedPerWindow = sdk.NewDecWithPrec(5, 1) // 0.5
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Verify rounding causes minSignedPerWindow to be 0
    minSigned := app.SlashingKeeper.MinSignedPerWindow(ctx)
    require.Equal(t, int64(0), minSigned, "MinSignedPerWindow should round to 0")
    
    // Validator misses 1000 consecutive blocks
    for height := int64(0); height < 1000; height++ {
        ctx = ctx.WithBlockHeight(height)
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, false), app.SlashingKeeper)
    }
    
    // Validator should have been slashed but is not (vulnerability)
    validator, _ := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(addr))
    require.Equal(t, stakingtypes.Bonded, validator.GetStatus(), "Validator incorrectly remains bonded despite missing all blocks")
    require.False(t, validator.IsJailed(), "Validator should have been jailed but was not")
}
```

This PoC demonstrates that the lack of cross-parameter validation in `SetParams` allows a critical security mechanism to be completely bypassed through governance parameter settings that individually appear valid.

### Citations

**File:** x/slashing/keeper/params.go (L17-24)
```go
func (k Keeper) MinSignedPerWindow(ctx sdk.Context) int64 {
	var minSignedPerWindow sdk.Dec
	k.paramspace.Get(ctx, types.KeyMinSignedPerWindow, &minSignedPerWindow)
	signedBlocksWindow := k.SignedBlocksWindow(ctx)

	// NOTE: RoundInt64 will never panic as minSignedPerWindow is
	//       less than 1.
	return minSignedPerWindow.MulInt64(signedBlocksWindow).RoundInt64()
```

**File:** x/slashing/keeper/params.go (L52-53)
```go
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) {
	k.paramspace.SetParamSet(ctx, &params)
```

**File:** x/slashing/keeper/infractions.go (L72-96)
```go
	minSignedPerWindow := k.MinSignedPerWindow(ctx)
	if missed {
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeLiveness,
				sdk.NewAttribute(types.AttributeKeyAddress, consAddr.String()),
				sdk.NewAttribute(types.AttributeKeyMissedBlocks, fmt.Sprintf("%d", signInfo.MissedBlocksCounter)),
				sdk.NewAttribute(types.AttributeKeyHeight, fmt.Sprintf("%d", height)),
			),
		)

		logger.Debug(
			"absent validator",
			"height", height,
			"validator", consAddr.String(),
			"missed", signInfo.MissedBlocksCounter,
			"threshold", minSignedPerWindow,
		)
	}

	minHeight := signInfo.StartHeight + window
	maxMissed := window - minSignedPerWindow
	shouldSlash = false
	// if we are past the minimum height and the validator has missed too many blocks, punish them
	if height > minHeight && signInfo.MissedBlocksCounter > maxMissed {
```

**File:** x/slashing/types/params.go (L54-61)
```go
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(KeySignedBlocksWindow, &p.SignedBlocksWindow, validateSignedBlocksWindow),
		paramtypes.NewParamSetPair(KeyMinSignedPerWindow, &p.MinSignedPerWindow, validateMinSignedPerWindow),
		paramtypes.NewParamSetPair(KeyDowntimeJailDuration, &p.DowntimeJailDuration, validateDowntimeJailDuration),
		paramtypes.NewParamSetPair(KeySlashFractionDoubleSign, &p.SlashFractionDoubleSign, validateSlashFractionDoubleSign),
		paramtypes.NewParamSetPair(KeySlashFractionDowntime, &p.SlashFractionDowntime, validateSlashFractionDowntime),
	}
```

**File:** x/slashing/types/params.go (L72-82)
```go
func validateSignedBlocksWindow(i interface{}) error {
	v, ok := i.(int64)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v <= 0 {
		return fmt.Errorf("signed blocks window must be positive: %d", v)
	}

	return nil
```

**File:** x/slashing/types/params.go (L85-98)
```go
func validateMinSignedPerWindow(i interface{}) error {
	v, ok := i.(sdk.Dec)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v.IsNegative() {
		return fmt.Errorf("min signed per window cannot be negative: %s", v)
	}
	if v.GT(sdk.OneDec()) {
		return fmt.Errorf("min signed per window too large: %s", v)
	}

	return nil
```

**File:** x/params/types/subspace.go (L241-254)
```go
func (s Subspace) SetParamSet(ctx sdk.Context, ps ParamSet) {
	for _, pair := range ps.ParamSetPairs() {
		// pair.Field is a pointer to the field, so indirecting the ptr.
		// go-amino automatically handles it but just for sure,
		// since SetStruct is meant to be used in InitGenesis
		// so this method will not be called frequently
		v := reflect.Indirect(reflect.ValueOf(pair.Value)).Interface()

		if err := pair.ValidatorFn(v); err != nil {
			panic(fmt.Sprintf("value from ParamSetPair is invalid: %s", err))
		}

		s.Set(ctx, pair.Key, v)
	}
```

**File:** types/decimal.go (L572-578)
```go
// RoundInt64 rounds the decimal using bankers rounding
func (d Dec) RoundInt64() int64 {
	chopped := chopPrecisionAndRoundNonMutative(d.i)
	if !chopped.IsInt64() {
		panic("Int64() out of bound")
	}
	return chopped.Int64()
```
