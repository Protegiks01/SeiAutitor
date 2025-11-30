# Audit Report

## Title
Unbounded Memory Allocation via SignedBlocksWindow Governance Parameter Enabling Total Network Shutdown

## Summary
The `SignedBlocksWindow` parameter validation in the slashing module lacks an upper bound check, allowing governance to set arbitrarily large values that trigger massive concurrent memory allocations during BeginBlocker execution. This causes all nodes to crash with out-of-memory errors, resulting in total network shutdown that requires a hard fork to recover.

## Impact
Medium

## Finding Description

**Location:**
- Validation: `x/slashing/types/params.go`, function `validateSignedBlocksWindow` [1](#0-0) 

- Memory allocation: `x/slashing/keeper/signing_info.go`, function `ParseBitGroupsToBoolArray` [2](#0-1) 

- Vulnerable resize logic: `x/slashing/keeper/infractions.go`, function `ResizeMissedBlockArray` [3](#0-2) 

- Automatic trigger: `x/slashing/abci.go`, function `BeginBlocker` [4](#0-3) 

- Resize trigger check: `x/slashing/keeper/infractions.go` [5](#0-4) 

**Intended logic:**
The validation function should enforce reasonable upper bounds on `SignedBlocksWindow` to prevent resource exhaustion. The parameter defines a sliding window for tracking validator liveness and should be limited to operationally feasible values. Notably, other parameter validators in the same file (`validateMinSignedPerWindow`, `validateSlashFractionDoubleSign`, `validateSlashFractionDowntime`) all include upper bound checks, indicating this is the expected pattern.

**Actual logic:**
The validation only checks `v > 0` with no upper bound. When an extremely large value is set (e.g., 10^10 or higher), the system attempts to allocate massive boolean arrays during window expansion:
1. `ParseBitGroupsToBoolArray` allocates `make([]bool, window)` - first allocation
2. `ResizeMissedBlockArray` allocates `make([]bool, window)` again - second allocation  
3. These double allocations occur concurrently for ALL validators in BeginBlocker
4. With 100 validators and window=10^12: 100 validators × 2 arrays × 10^12 bytes = 200 TB concurrent memory requirement

**Exploitation path:**
1. Governance proposal submitted with large `SignedBlocksWindow` (e.g., 10^12) - could be accidental typo
2. Proposal passes weak validation that only checks positivity via `Subspace.Update` [6](#0-5) 
3. Parameter updated through governance handler [7](#0-6) 
4. Next block's BeginBlocker executes, spawning concurrent goroutines for all validators
5. Each validator's `HandleValidatorSignatureConcurrent` detects window size change and calls `ResizeMissedBlockArray`
6. Double memory allocation per validator (ParseBitGroupsToBoolArray + newArray allocation)
7. All nodes crash with OOM errors attempting to allocate terabytes of memory
8. Network completely halts - no blocks can be produced
9. Recovery requires hard fork since normal governance cannot function with network down

**Security guarantee broken:**
The system fails to enforce safe bounds on governance parameters, allowing configurations that exceed physical resource constraints. While governance is a trusted mechanism for parameter adjustments, it should not be able to inadvertently trigger catastrophic network failure beyond its intended authority. The system should protect against both malicious and accidental misconfigurations that cause total network shutdown.

## Impact Explanation

**Affected Components:**
- All validator nodes and full nodes network-wide
- Block production and consensus mechanism
- Transaction processing and finality
- Network availability and liveness

**Severity of Impact:**
- **Total network shutdown**: All nodes crash attempting to allocate impossible amounts of memory (200+ TB with 100 validators)
- **Hard fork required for recovery**: Normal governance mechanisms cannot fix the issue since the network is completely down and the malicious parameter persists in chain state
- **Complete transaction halt**: No new blocks can be produced or transactions confirmed
- **Accidental trigger risk**: A simple typo in a governance proposal (e.g., adding extra zeros: "1000000000000" instead of "100000") can trigger this catastrophic failure

This precisely matches the explicitly listed Medium severity impact: **"Network not being able to confirm new transactions (total network shutdown)"**

## Likelihood Explanation

**Who can trigger:**
- Any participant who can submit and pass a governance proposal
- Requires majority token holder approval
- **Critical point**: Accidental misconfiguration is a realistic scenario through:
  - Typos when entering large numbers
  - Unit confusion (seconds vs blocks)
  - Copy-paste errors in proposals
  - Lack of understanding of resource implications

**Conditions required:**
1. Submit governance proposal with excessively large `SignedBlocksWindow` value
2. Proposal passes governance voting (standard mechanism for parameter updates)
3. Next block automatically triggers vulnerability through normal BeginBlocker execution

**Likelihood assessment:**
While governance approval is required, this vulnerability has **moderate likelihood** because:
- Governance is the intended and standard mechanism for parameter changes (not an attack vector)
- Human error in proposal creation is realistic and has precedent in blockchain governance
- The catastrophic impact (total network shutdown) far exceeds governance's intended authority (safe parameter tuning)
- Defensive validation is missing despite being present for other parameters in the same file
- The system lacks basic sanity checks that should exist

**Exception clause applicability:**
This meets the privileged role exception criteria: "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority" because:
1. Governance is trusted for parameter tuning, NOT network destruction
2. Inadvertent trigger through typo is realistic
3. Failure is unrecoverable (requires hard fork)
4. Impact exceeds intended scope of governance authority

## Recommendation

Add upper bound validation to `validateSignedBlocksWindow` consistent with the pattern used for other parameters in the same file:

```go
func validateSignedBlocksWindow(i interface{}) error {
    v, ok := i.(int64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v <= 0 {
        return fmt.Errorf("signed blocks window must be positive: %d", v)
    }

    // Add maximum bound to prevent resource exhaustion
    // Based on operational requirements: ~1.5 years at 0.4s blocks
    // 365 * 24 * 3600 / 0.4 ≈ 78,840,000 blocks/year
    const maxSignedBlocksWindow = int64(100_000_000)
    if v > maxSignedBlocksWindow {
        return fmt.Errorf("signed blocks window exceeds maximum allowed value (max %d): %d", 
            maxSignedBlocksWindow, v)
    }

    return nil
}
```

This prevents unbounded allocations while maintaining backward compatibility (default 108,000 is well within limits).

## Proof of Concept

**Test Location:** `x/slashing/keeper/infractions_test.go`

**Setup:**
- Initialize test application with simapp
- Create validator with consensus address
- Set initial `SignedBlocksWindow` to normal value (100)
- Initialize validator signing info by running BeginBlocker once
- Verify normal operation with small window size

**Action:**
- Update governance parameter to large value via `SetParams`:
  - Safe testing: 1,000,000 (demonstrates O(n) behavior and memory scaling)
  - Actual exploitation: 10,000,000,000+ (causes OOM crash)
- Trigger next block's BeginBlocker with vote information
- BeginBlocker spawns concurrent goroutines for all validators
- Each calls HandleValidatorSignatureConcurrent which detects window size change
- ResizeMissedBlockArray performs double allocation per validator

**Result:**
- For moderate values (1M): Significant memory allocation spike and processing delay demonstrating O(window) scaling behavior
- For extreme values (10B+): Out-of-memory crash or system hang
- Demonstrates vulnerability is automatically triggered on next block after parameter change
- Memory profiling would show concurrent allocations proportional to validators × 2 × window size
- Extrapolation: if 1M window takes X memory/time, then 1B window takes 1000× more

**Code outline:**
```go
func TestExcessiveSignedBlocksWindowMemoryAllocation(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Setup validator and initialize signing info
    // Run initial BeginBlocker with normal window (100)
    
    // Update to large value
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = 1_000_000 // Safe for testing
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Measure resource consumption for next block
    start := time.Now()
    slashing.BeginBlocker(ctx.WithBlockHeight(2), req, app.SlashingKeeper)
    duration := time.Since(start)
    
    // Assert excessive resource consumption
    // With linear scaling: 1M → X seconds, 1B → 1000×X seconds
}
```

## Notes

This vulnerability represents a critical defensive programming failure in parameter validation. While governance is a trusted mechanism, the absence of basic sanity checks exposes the system to:

1. **Accidental misconfiguration**: Realistic human errors in proposal creation (typos, unit confusion)
2. **Catastrophic cascading failure**: Single parameter error causes total network shutdown affecting all participants
3. **Recovery complexity**: Requires hard fork coordination, cannot use normal governance processes
4. **Inconsistent validation pattern**: Other parameters in the same file properly check upper bounds, indicating this is a missed implementation rather than intentional design

The fix is straightforward, maintains backward compatibility, and follows the established pattern used for other parameters in the module. Parameter validation is a fundamental security best practice in blockchain systems, particularly for consensus-critical modules like slashing that execute automatically in every block.

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

**File:** x/slashing/keeper/signing_info.go (L109-116)
```go
func (k Keeper) ParseBitGroupsToBoolArray(bitGroups []uint64, window int64) []bool {
	boolArray := make([]bool, window)

	for i := int64(0); i < window; i++ {
		boolArray[i] = k.GetBooleanFromBitGroups(bitGroups, i)
	}
	return boolArray
}
```

**File:** x/slashing/keeper/infractions.go (L52-54)
```go
	if found && missedInfo.WindowSize != window {
		missedInfo, signInfo, index = k.ResizeMissedBlockArray(missedInfo, signInfo, window, index)
	}
```

**File:** x/slashing/keeper/infractions.go (L157-181)
```go
func (k Keeper) ResizeMissedBlockArray(missedInfo types.ValidatorMissedBlockArray, signInfo types.ValidatorSigningInfo, window int64, index int64) (types.ValidatorMissedBlockArray, types.ValidatorSigningInfo, int64) {
	// we need to resize the missed block array AND update the signing info accordingly
	switch {
	case missedInfo.WindowSize < window:
		// missed block array too short, lets expand it
		boolArray := k.ParseBitGroupsToBoolArray(missedInfo.MissedBlocks, missedInfo.WindowSize)
		newArray := make([]bool, window)
		copy(newArray[0:index], boolArray[0:index])
		if index+1 < missedInfo.WindowSize {
			// insert `0`s corresponding to the difference between the new window size and old window size
			copy(newArray[index+(window-missedInfo.WindowSize):], boolArray[index:])
		}
		missedInfo.MissedBlocks = k.ParseBoolArrayToBitGroups(newArray)
		missedInfo.WindowSize = window
	case missedInfo.WindowSize > window:
		// if window size is reduced, we would like to make a clean state so that no validators are unexpectedly jailed due to more recent missed blocks
		newMissedBlocks := make([]bool, window)
		missedInfo.MissedBlocks = k.ParseBoolArrayToBitGroups(newMissedBlocks)
		signInfo.MissedBlocksCounter = int64(0)
		missedInfo.WindowSize = window
		signInfo.IndexOffset = 0
		index = 0
	}
	return missedInfo, signInfo, index
}
```

**File:** x/slashing/abci.go (L36-50)
```go
	for i, _ := range allVotes {
		wg.Add(1)
		go func(valIndex int) {
			defer wg.Done()
			vInfo := allVotes[valIndex]
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
			slashingWriteInfo[valIndex] = &SlashingWriteInfo{
				ConsAddr:    consAddr,
				MissedInfo:  missedInfo,
				SigningInfo: signInfo,
				ShouldSlash: shouldSlash,
				SlashInfo:   slashInfo,
			}
		}(i)
	}
```

**File:** x/params/types/subspace.go (L196-219)
```go
func (s Subspace) Update(ctx sdk.Context, key, value []byte) error {
	attr, ok := s.table.m[string(key)]
	if !ok {
		panic(fmt.Sprintf("parameter %s not registered", string(key)))
	}

	ty := attr.ty
	dest := reflect.New(ty).Interface()
	s.GetIfExists(ctx, key, dest)

	if err := s.legacyAmino.UnmarshalJSON(value, dest); err != nil {
		return err
	}

	// destValue contains the dereferenced value of dest so validation function do
	// not have to operate on pointers.
	destValue := reflect.Indirect(reflect.ValueOf(dest)).Interface()
	if err := s.Validate(ctx, key, destValue); err != nil {
		return err
	}

	s.Set(ctx, key, dest)
	return nil
}
```

**File:** x/params/proposal_handler.go (L26-39)
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
```
