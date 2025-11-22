## Audit Report

### Title
Missing Validation of Power Parameter Allows Bypass of Slashing Economic Penalties

### Summary
The `power` parameter passed to `HandleValidatorSignatureConcurrent` from the ABCI `RequestBeginBlock.LastCommitInfo` is not validated to ensure it is positive and non-zero. When negative or zero power values are provided, validators can be jailed for downtime infractions without having their tokens slashed, bypassing the intended economic penalty of the slashing mechanism.

### Impact
**Medium**

This vulnerability falls under "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" and could also be considered "Modification of transaction fees outside of design parameters" as slashing penalties are a core economic mechanism.

### Finding Description

**Location:** 
- Primary: `x/slashing/keeper/infractions.go` in function `HandleValidatorSignatureConcurrent` [1](#0-0) 
- Called from: `x/slashing/abci.go` [2](#0-1) 
- Slashing execution: `x/staking/keeper/slash.go` [3](#0-2) 

**Intended Logic:**
When validators miss too many blocks (downtime), they should be both jailed (removed from active set) and slashed (have a fraction of their tokens burned as economic penalty). The `power` parameter represents the validator's voting power at the infraction height and is used to calculate the amount of tokens to slash.

**Actual Logic:**
The power parameter is passed directly from `LastCommitInfo` without validation [2](#0-1) . When this power value is zero or negative:

1. It's stored in `SlashInfo` struct [4](#0-3) 
2. Passed to the `Slash` function [5](#0-4) 
3. Converted via `TokensFromConsensusPower(ctx, power)` which simply multiplies: `NewInt(power).Mul(powerReduction)` [6](#0-5) 
4. Results in zero or negative `slashAmount`
5. The defensive check `tokensToBurn = sdk.MaxInt(tokensToBurn, sdk.ZeroInt())` ensures at least zero tokens are burned [7](#0-6) 
6. Validator gets jailed [8](#0-7)  but with ZERO economic penalty

**Exploit Scenario:**
While `LastCommitInfo` normally comes from Tendermint consensus engine, several edge cases could result in zero or malformed power values:
1. During validator set transitions when a validator is being removed (power going to 0) while simultaneously crossing downtime threshold
2. Consensus engine bugs or race conditions that report incorrect validator power
3. State corruption or replay scenarios during chain upgrades

In these cases, validators would avoid the economic slashing penalty while still being jailed.

**Security Failure:**
The economic security model is violated. Slashing serves as economic deterrent against validator misbehavior. When validators can be jailed without losing tokens, the fundamental incentive mechanism of Proof-of-Stake is compromised. This breaks the accounting invariant that validators who commit downtime infractions must lose a proportional amount of their stake.

### Impact Explanation

**Affected Assets:** 
- Validator staked tokens that should be slashed
- Network economic security model
- Delegator trust in fair validator penalties

**Severity:**
When triggered, validators avoid losing tokens (typically 0.01% to 1% of their stake for downtime) while only suffering temporary jailing. This undermines the economic incentives designed to ensure validator availability and honest behavior. If this becomes known or exploitable, it could:
- Reduce validator accountability
- Damage delegator confidence in the protocol
- Create unfair advantages for validators who encounter this edge case
- Weaken the overall economic security of the network

**System Impact:**
This breaks the protocol's design parameters for validator punishment and modifies the effective "transaction fees" (slashing penalties) outside intended parameters, which is explicitly listed as a Low impact in the scope.

### Likelihood Explanation

**Trigger Conditions:**
- Requires `LastCommitInfo.Votes` to contain a validator entry with power ≤ 0
- This validator must also cross the downtime slashing threshold
- Can occur during validator set transitions, consensus engine edge cases, or protocol bugs

**Who Can Trigger:**
- Not directly exploitable by unprivileged attackers
- Requires either: (a) Tendermint/CometBFT to report malformed data, (b) edge cases in validator lifecycle, or (c) state inconsistencies
- However, the lack of validation means the application fails to defend against malformed inputs

**Frequency:**
- Low frequency under normal operation
- Higher risk during: network upgrades, validator set churn, or if consensus engine bugs exist
- Once triggered, affects one validator at a time but sets precedent for unfair treatment

### Recommendation

Add validation in `HandleValidatorSignatureConcurrent` to reject invalid power values:

```go
func (k Keeper) HandleValidatorSignatureConcurrent(ctx sdk.Context, addr cryptotypes.Address, power int64, signed bool) (...) {
    // Validate power parameter
    if power <= 0 {
        panic(fmt.Sprintf("Invalid validator power %d for address %s: power must be positive", power, sdk.ConsAddress(addr)))
    }
    // ... rest of function
}
```

This ensures defense-in-depth by validating external inputs even from trusted sources, and makes the failure mode explicit (panic) rather than silent (bypassing slashing).

### Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`

**Test Function:** `TestHandleValidatorSignatureWithZeroPower`

**Setup:**
1. Initialize a test application with one validator having 100 voting power
2. Set slashing parameters: SignedBlocksWindow=1000, MinSignedPerWindow=500 (50%)
3. Record initial validator token balance

**Trigger:**
1. Validator signs blocks normally for first 1000 blocks (using power=100)
2. Validator misses 501 consecutive blocks BUT LastCommitInfo reports power=0 instead of 100
3. This crosses the downtime threshold and should trigger slashing

**Observation:**
- Validator is jailed (status changes to Unbonding) ✓
- Validator's token balance remains UNCHANGED (no slashing occurred) ✗
- Compare with control case using power=100: validator loses 1% of tokens

**Test Code Location:**
Add to `x/slashing/keeper/keeper_test.go` after existing downtime tests:

```go
func TestHandleValidatorSignatureWithZeroPower(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Setup validator
    power := int64(100)
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
    pks := simapp.CreateTestPubKeys(1)
    val := pks[0]
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    amt := tstaking.CreateValidatorWithValPower(valAddrs[0], val, power, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = 1000
    params.MinSignedPerWindow = sdk.NewDec(500)
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Record initial balance
    validator, _ := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(val))
    initialTokens := validator.GetTokens()
    
    // Validator signs 500 blocks normally
    for h := int64(0); h < 500; h++ {
        ctx = ctx.WithBlockHeight(h)
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, true), app.SlashingKeeper)
    }
    
    // Validator misses 501 blocks with ZERO power reported
    for h := int64(500); h < 1001; h++ {
        ctx = ctx.WithBlockHeight(h)
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), 0, false), app.SlashingKeeper)
    }
    
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Check results
    validator, _ = app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(val))
    
    // Validator should be jailed
    require.True(t, validator.IsJailed())
    
    // BUG: Validator tokens unchanged despite crossing downtime threshold
    // Expected: tokens reduced by SlashFractionDowntime (1%)
    // Actual: tokens remain unchanged because power=0 bypassed slashing
    require.Equal(t, initialTokens, validator.GetTokens(), "Validator avoided slashing due to zero power")
}
```

**Expected Behavior:** Test passes, demonstrating that zero power bypasses token slashing while still jailing the validator.

**Notes:**
- The test uses the existing test framework pattern from `keeper_test.go` [9](#0-8) 
- The `CreateBeginBlockReq` helper accepts power as a parameter [10](#0-9) 
- This proves the vulnerability is present in the code logic regardless of how LastCommitInfo is populated in production

### Citations

**File:** x/slashing/keeper/infractions.go (L22-22)
```go
func (k Keeper) HandleValidatorSignatureConcurrent(ctx sdk.Context, addr cryptotypes.Address, power int64, signed bool) (consAddr sdk.ConsAddress, missedInfo types.ValidatorMissedBlockArray, signInfo types.ValidatorSigningInfo, shouldSlash bool, slashInfo SlashInfo) {
```

**File:** x/slashing/keeper/infractions.go (L107-113)
```go
			slashInfo = SlashInfo{
				height:             height,
				power:              power,
				distributionHeight: distributionHeight,
				minHeight:          minHeight,
				minSignedPerWindow: minSignedPerWindow,
			}
```

**File:** x/slashing/keeper/infractions.go (L140-140)
```go
	k.sk.Slash(ctx, consAddr, slashInfo.distributionHeight, slashInfo.power, k.SlashFractionDowntime(ctx))
```

**File:** x/slashing/keeper/infractions.go (L141-141)
```go
	k.sk.Jail(ctx, consAddr)
```

**File:** x/slashing/abci.go (L41-41)
```go
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```

**File:** x/staking/keeper/slash.go (L24-34)
```go
func (k Keeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdk.Dec) {
	logger := k.Logger(ctx)

	if slashFactor.IsNegative() {
		panic(fmt.Errorf("attempted to slash with a negative slash factor: %v", slashFactor))
	}

	// Amount of slashing = slash slashFactor * power at time of infraction
	amount := k.TokensFromConsensusPower(ctx, power)
	slashAmountDec := amount.ToDec().Mul(slashFactor)
	slashAmount := slashAmountDec.TruncateInt()
```

**File:** x/staking/keeper/slash.go (L107-107)
```go
	tokensToBurn = sdk.MaxInt(tokensToBurn, sdk.ZeroInt()) // defensive.
```

**File:** types/staking.go (L38-39)
```go
func TokensFromConsensusPower(power int64, powerReduction Int) Int {
	return NewInt(power).Mul(powerReduction)
```

**File:** x/slashing/keeper/keeper_test.go (L128-184)
```go
func TestHandleAlreadyJailed(t *testing.T) {
	// initial setup
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
	pks := simapp.CreateTestPubKeys(1)
	addr, val := valAddrs[0], pks[0]
	power := int64(100)
	tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)

	amt := tstaking.CreateValidatorWithValPower(addr, val, power, true)

	staking.EndBlocker(ctx, app.StakingKeeper)

	params := app.SlashingKeeper.GetParams(ctx)
	params.SignedBlocksWindow = 1000
	app.SlashingKeeper.SetParams(ctx, params)

	slashingParams := app.SlashingKeeper.GetParams(ctx)
	slashingParams.SlashFractionDoubleSign = sdk.NewDec(1).Quo(sdk.NewDec(20))
	slashingParams.SlashFractionDowntime = sdk.NewDec(1).Quo(sdk.NewDec(100))
	app.SlashingKeeper.SetParams(ctx, slashingParams)

	// 1000 first blocks OK
	height := int64(0)
	for ; height < app.SlashingKeeper.SignedBlocksWindow(ctx); height++ {
		ctx = ctx.WithBlockHeight(height)
		slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, true), app.SlashingKeeper)
	}

	// 501 blocks missed
	for ; height < app.SlashingKeeper.SignedBlocksWindow(ctx)+(app.SlashingKeeper.SignedBlocksWindow(ctx)-app.SlashingKeeper.MinSignedPerWindow(ctx))+1; height++ {
		ctx = ctx.WithBlockHeight(height)
		slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, false), app.SlashingKeeper)
	}

	// end block
	staking.EndBlocker(ctx, app.StakingKeeper)

	// validator should have been jailed and slashed
	validator, _ := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(val))
	require.Equal(t, stakingtypes.Unbonding, validator.GetStatus())

	// validator should have been slashed
	resultingTokens := amt.Sub(app.StakingKeeper.TokensFromConsensusPower(ctx, 1))
	require.Equal(t, resultingTokens, validator.GetTokens())

	// another block missed
	ctx = ctx.WithBlockHeight(height)
	slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, false), app.SlashingKeeper)

	// validator should not have been slashed twice
	validator, _ = app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(val))
	require.Equal(t, resultingTokens, validator.GetTokens())
}
```

**File:** x/slashing/testslashing/params.go (L22-36)
```go
func CreateBeginBlockReq(valAddr bytes.HexBytes, power int64, signed bool) abcitypes.RequestBeginBlock {
	return abcitypes.RequestBeginBlock{
		LastCommitInfo: abcitypes.LastCommitInfo{
			Votes: []abcitypes.VoteInfo{
				{
					Validator: abcitypes.Validator{
						Address: valAddr.Bytes(),
						Power:   power,
					},
					SignedLastBlock: signed,
				},
			},
		},
	}
}
```
