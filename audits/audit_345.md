# Audit Report

## Title
Integer Overflow in SignedBlocksWindow Parameter Causes Network-Wide Node Crash

## Summary
The validation for the `SignedBlocksWindow` parameter in the slashing module only checks for non-positive values but fails to validate against extremely large positive values. When set to a value near `math.MaxInt64` via governance proposal, the parameter causes integer overflow during array length calculation in `HandleValidatorSignatureConcurrent`, resulting in a runtime panic that crashes all nodes processing blocks. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Validation: [2](#0-1) 
- Vulnerable calculation: [3](#0-2) 
- Array creation: [4](#0-3) 

**Intended Logic:** 
The `validateSignedBlocksWindow` function is supposed to ensure that the `SignedBlocksWindow` parameter is valid for use in slashing calculations. The window size is used to track validator liveness by creating a bit array to store missed blocks. [2](#0-1) 

**Actual Logic:** 
The validation only checks `if v <= 0`, preventing negative and zero values, but does not validate against extremely large positive values that could cause integer overflow in subsequent calculations. [1](#0-0) 

When `SignedBlocksWindow` is set to a value near `math.MaxInt64` (9,223,372,036,854,775,807), the calculation at line 45 of infractions.go performs: `arrLen := (window + UINT_64_NUM_BITS - 1) / UINT_64_NUM_BITS` where `UINT_64_NUM_BITS = 64`. [3](#0-2) [5](#0-4) 

With `window = 9,223,372,036,854,775,807`:
- `window + 63 = 9,223,372,036,854,775,870`
- This exceeds `MaxInt64`, causing integer overflow
- The result wraps to `-9,223,372,036,854,775,746`
- `arrLen = -9,223,372,036,854,775,746 / 64 = -144,115,188,075,855,903` (negative)

The negative `arrLen` is then used to create an array: `missedInfo.MissedBlocks = make([]uint64, arrLen)`, which triggers a runtime panic: "makeslice: len out of range". [6](#0-5) 

**Exploit Scenario:**
1. An attacker (or even accidental misconfiguration) submits a governance proposal to change the `SignedBlocksWindow` parameter to `9,223,372,036,854,775,807` (or any value >= `9,223,372,036,854,775,745`)
2. The proposal passes validation since the value is positive [7](#0-6) 
3. The proposal is executed through the parameter change handler [8](#0-7) 
4. When any validator signs or misses a block, `HandleValidatorSignatureConcurrent` is called [9](#0-8) 
5. The integer overflow occurs during array length calculation, resulting in a negative value
6. The `make()` call panics, crashing the node
7. All nodes in the network crash when processing blocks, causing total network shutdown

**Security Failure:** 
This is a denial-of-service vulnerability that violates network availability. The system crashes due to improper input validation allowing arithmetic overflow, which breaks memory safety assumptions in Go's array allocation.

## Impact Explanation

**Affected Components:**
- All validator nodes processing blocks
- Network consensus and block production
- Transaction finality

**Severity of Damage:**
- **Total network shutdown:** All nodes crash when attempting to process validator signatures during block production
- **Consensus breakdown:** No new blocks can be finalized as all nodes panic before completing block processing
- **Requires hard fork:** Recovery would require a coordinated hard fork to fix the parameter value, as the network cannot process blocks to execute a corrective governance proposal

**System Reliability Impact:**
This vulnerability completely halts the blockchain network. Unlike partial outages, this affects 100% of nodes simultaneously when they attempt to process the first block after the parameter change. The network cannot self-recover without manual intervention and a hard fork.

## Likelihood Explanation

**Who can trigger it:**
Any network participant with sufficient voting power to pass a governance proposal. This does not require privileged access beyond normal governance participation. Even well-intentioned proposals with calculation errors could trigger this vulnerability.

**Conditions required:**
1. A governance proposal must be submitted and pass with the malicious/incorrect parameter value
2. The parameter change must be applied on-chain
3. Any validator signature processing must occur (which happens on every block)

**Frequency:**
- The vulnerability is triggered immediately on the first block processed after the parameter change
- Once triggered, it affects all nodes simultaneously and persistently
- The network remains down until a hard fork is deployed

The likelihood is **MODERATE to HIGH** because:
- Governance proposals are a standard network operation
- The validation appears secure (checks for positive values) but has a subtle flaw
- Human error in proposal creation could easily result in an extremely large value
- The consequences are catastrophic and immediate

## Recommendation

Add an upper bound check to the `validateSignedBlocksWindow` function to prevent integer overflow:

```go
func validateSignedBlocksWindow(i interface{}) error {
    v, ok := i.(int64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v <= 0 {
        return fmt.Errorf("signed blocks window must be positive: %d", v)
    }
    
    // Add maximum bound check to prevent integer overflow
    // Max safe value calculated as: (math.MaxInt64 - 63) to prevent overflow in (window + 63)
    const maxSafeWindow = 9223372036854775744 // math.MaxInt64 - 63
    if v > maxSafeWindow {
        return fmt.Errorf("signed blocks window exceeds maximum safe value: %d (max: %d)", v, maxSafeWindow)
    }

    return nil
}
```

Alternatively, use a more conservative practical limit (e.g., 1 billion blocks, which represents years of operation at typical block times) to prevent both overflow and excessively large memory allocations.

## Proof of Concept

**File:** `x/slashing/keeper/infractions_test.go`

**Test Function:** `TestSignedBlocksWindowOverflow`

**Setup:**
1. Initialize a test application using `simapp.Setup(false)`
2. Create a test context
3. Set up a validator with test keys and addresses

**Trigger:**
1. Set the `SignedBlocksWindow` parameter to a value that causes overflow: `9223372036854775807` (math.MaxInt64)
2. Call `HandleValidatorSignatureConcurrent` with a validator address and signature status
3. The function attempts to calculate `arrLen := (window + 63) / 64`, which overflows
4. The subsequent `make([]uint64, arrLen)` with negative length causes a panic

**Observation:**
The test should catch the panic using `require.Panics()` or similar assertion, demonstrating that the node crashes when processing validator signatures with an overflowed window parameter.

**Test Code Structure:**
```go
func TestSignedBlocksWindowOverflow(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
    pks := simapp.CreateTestPubKeys(1)
    addr, val := valAddrs[0], pks[0]
    
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    tstaking.CreateValidatorWithValPower(addr, val, 100, true)
    
    // Set SignedBlocksWindow to math.MaxInt64 to trigger overflow
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = 9223372036854775807 // math.MaxInt64
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Create signing info for the validator
    signInfo := types.NewValidatorSigningInfo(
        sdk.ConsAddress(val.Address()),
        ctx.BlockHeight(),
        0,
        time.Unix(0, 0),
        false,
        0,
    )
    app.SlashingKeeper.SetValidatorSigningInfo(ctx, sdk.ConsAddress(val.Address()), signInfo)
    
    // This should panic due to integer overflow in arrLen calculation
    require.Panics(t, func() {
        app.SlashingKeeper.HandleValidatorSignatureConcurrent(
            ctx,
            val.Address(),
            100,
            true,
        )
    }, "Expected panic due to negative array length from integer overflow")
}
```

This test demonstrates that setting `SignedBlocksWindow` to `math.MaxInt64` causes a panic when processing validator signatures, confirming the vulnerability.

### Citations

**File:** x/slashing/types/params.go (L72-83)
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
}
```

**File:** x/slashing/keeper/infractions.go (L22-22)
```go
func (k Keeper) HandleValidatorSignatureConcurrent(ctx sdk.Context, addr cryptotypes.Address, power int64, signed bool) (consAddr sdk.ConsAddress, missedInfo types.ValidatorMissedBlockArray, signInfo types.ValidatorSigningInfo, shouldSlash bool, slashInfo SlashInfo) {
```

**File:** x/slashing/keeper/infractions.go (L45-45)
```go
		arrLen := (window + UINT_64_NUM_BITS - 1) / UINT_64_NUM_BITS
```

**File:** x/slashing/keeper/infractions.go (L46-50)
```go
		missedInfo = types.ValidatorMissedBlockArray{
			Address:      consAddr.String(),
			WindowSize:   window,
			MissedBlocks: make([]uint64, arrLen),
		}
```

**File:** x/slashing/keeper/signing_info.go (L10-10)
```go
const UINT_64_NUM_BITS = 64
```

**File:** x/params/types/subspace.go (L213-215)
```go
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
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
