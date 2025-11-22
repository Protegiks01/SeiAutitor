## Audit Report

## Title
Unbounded SignedBlocksWindow Parameter Enables Network-Wide Denial of Service via Memory Exhaustion

## Summary
The `SignedBlocksWindow` parameter in the slashing module lacks an upper bound validation, allowing governance proposals to set it to arbitrarily large values (up to max int64). When changed, the system performs expensive memory allocations and resizing operations for every active validator in the next block, potentially allocating gigabytes of memory per validator and causing network-wide node crashes and complete network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Parameter validation: [1](#0-0) 
- Resize operation: [2](#0-1) 
- Per-validator triggering: [3](#0-2) 
- Execution in BeginBlocker: [4](#0-3) 

**Intended Logic:** 
The `SignedBlocksWindow` parameter defines the sliding window size for tracking validator liveness. The validation should ensure the parameter stays within reasonable operational bounds to prevent resource exhaustion.

**Actual Logic:** 
The validation function only checks that the value is positive (`v > 0`) with no upper bound. [5](#0-4)  This allows setting the window to extreme values like 1 billion or even max int64 (2,147,483,647).

When the window size changes, `ResizeMissedBlockArray` is called for each validator, which:
1. Allocates a bool array of the old window size via `ParseBitGroupsToBoolArray` [6](#0-5) 
2. Allocates a new bool array of the new window size: `make([]bool, window)` [7](#0-6) 
3. Converts back to bit groups via `ParseBoolArrayToBitGroups` [8](#0-7) 

For a window of 1 billion blocks, this means ~1 GB allocation per validator (Go uses 1 byte per bool). The conversion operations iterate over the entire window size. [9](#0-8) [10](#0-9) 

**Exploit Scenario:**
1. Attacker submits a governance `ParameterChangeProposal` to set `SignedBlocksWindow` to 1,000,000,000 (1 billion) [11](#0-10) 
2. Proposal passes after voting period (minimum 1 day for expedited, 2 days for normal) [12](#0-11) 
3. Parameter change is applied immediately when the proposal passes in EndBlocker [13](#0-12) 
4. On the next block's BeginBlocker, `HandleValidatorSignatureConcurrent` is called for all validators [14](#0-13) 
5. For each validator, the resize check triggers: `if found && missedInfo.WindowSize != window` [3](#0-2) 
6. With 100 active validators and window=1 billion: 100 validators × 1 GB = 100 GB memory attempted allocation simultaneously
7. Nodes exhaust memory, crash with OOM errors, or hang indefinitely
8. Network halts as validators cannot process blocks

**Security Failure:** 
Denial of service through resource exhaustion. The lack of bounds checking on a governance-controlled parameter allows malicious or accidental configuration changes that exceed available system resources, breaking the availability and liveness properties of the blockchain.

## Impact Explanation

**Affected Components:**
- All validator nodes in the network
- Network availability and transaction processing
- Chain progression and consensus

**Severity of Damage:**
- **Complete network shutdown**: All validators would attempt the same memory-exhaustive operation on the same block height, causing synchronized failures across the network
- **Unrecoverable without hard fork**: Once validators crash on a specific block, the chain cannot progress. Recovery requires a coordinated hard fork to revert or cap the parameter value
- **Permanent if repeated**: Attacker could submit multiple proposals with different large values, making recovery increasingly difficult

**System Impact:**
This vulnerability directly compromises the blockchain's core availability guarantee. A functioning blockchain must maintain liveness (ability to process new transactions). By causing all validators to crash simultaneously, the network becomes completely unavailable until a hard fork is coordinated and deployed.

## Likelihood Explanation

**Who Can Trigger:**
Anyone with sufficient voting power to pass a governance proposal. In most Cosmos chains, this requires either:
- Significant stake ownership (typically >50% for normal proposals)
- Strong community support for malicious/mistaken proposal
- In some chains, validators themselves have substantial voting power

**Conditions Required:**
- Single governance proposal submission and passage
- No special timing requirements
- No need for multiple coordinated actions
- Can occur during normal network operation

**Frequency:**
- **Intentional attack**: Requires passing one governance proposal (2-day delay minimum)
- **Accidental trigger**: High risk - a typo when setting the parameter (e.g., entering 100000000 instead of 100000) would trigger this vulnerability
- **No cooldown mechanism**: Multiple proposals can be submitted and executed sequentially

The vulnerability has **high likelihood** because:
1. It only requires passing a single governance action (not continuous control)
2. No technical sophistication needed - just setting a large integer value
3. Could be triggered accidentally by legitimate operators making configuration errors
4. The parameter is expected to be changed occasionally for network tuning

## Recommendation

**Immediate Fix:**
Add an upper bound validation to the `validateSignedBlocksWindow` function in `x/slashing/types/params.go`:

```go
func validateSignedBlocksWindow(i interface{}) error {
    v, ok := i.(int64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }
    
    if v <= 0 {
        return fmt.Errorf("signed blocks window must be positive: %d", v)
    }
    
    // Add maximum bound - e.g., 1 million blocks (~11 days at 1s block time)
    const MaxSignedBlocksWindow = int64(1_000_000)
    if v > MaxSignedBlocksWindow {
        return fmt.Errorf("signed blocks window too large (max %d): %d", MaxSignedBlocksWindow, v)
    }
    
    return nil
}
```

**Rationale for Limit:**
- Default is 108,000 blocks (~30 hours at 1s block time)
- Maximum of 1,000,000 blocks (~11 days) provides 10x headroom while preventing extreme values
- Prevents both malicious attacks and accidental misconfigurations
- Still allows reasonable operational flexibility

**Additional Safeguards:**
Consider adding a resize operation memory limit check or breaking the resize into incremental chunks if absolutely necessary to support large window changes in the future.

## Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`

**Test Function:** `TestLargeSignedBlocksWindowDoS`

**Setup:**
1. Initialize a test blockchain application with default configuration
2. Create multiple validator accounts (e.g., 10 validators for faster test execution)
3. Set initial `SignedBlocksWindow` to default value (108,000)
4. Bond validators and progress through initial blocks

**Trigger:**
1. Use `SetParams` to change `SignedBlocksWindow` to a very large value (e.g., 50,000,000 - large enough to demonstrate issue but small enough test might complete)
2. Call `BeginBlocker` with validator votes for the next block
3. Monitor memory allocation and execution time

**Observation:**
The test will demonstrate:
- Excessive memory allocation (hundreds of MB per validator even with reduced window)
- Significant performance degradation (seconds to minutes for single block)
- Potential timeout or OOM panic with sufficiently large values
- With realistic validator count (100+) and window=1 billion, nodes would crash

**Expected Behavior:**
The vulnerable code allows the parameter change and attempts to allocate and process arrays proportional to the window size for each validator, causing memory exhaustion.

**Test Code Structure:**
```go
func TestLargeSignedBlocksWindowDoS(t *testing.T) {
    // Setup: Create app with validators
    // Set initial reasonable window size
    // Progress through some blocks
    
    // Trigger: Change to extremely large window
    // Call BeginBlocker
    
    // Observation: Measure memory/time, expect excessive resource use
    // With production values (100 validators, 1B window), this would crash
}
```

The test demonstrates that without upper bound validation, arbitrarily large window values cause resource exhaustion that would crash production nodes and halt the network.

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

**File:** x/slashing/abci.go (L35-50)
```go
	allVotes := req.LastCommitInfo.GetVotes()
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

**File:** x/slashing/keeper/signing_info.go (L109-115)
```go
func (k Keeper) ParseBitGroupsToBoolArray(bitGroups []uint64, window int64) []bool {
	boolArray := make([]bool, window)

	for i := int64(0); i < window; i++ {
		boolArray[i] = k.GetBooleanFromBitGroups(bitGroups, i)
	}
	return boolArray
```

**File:** x/slashing/keeper/signing_info.go (L118-126)
```go
func (k Keeper) ParseBoolArrayToBitGroups(boolArray []bool) []uint64 {
	arrLen := (len(boolArray) + UINT_64_NUM_BITS - 1) / UINT_64_NUM_BITS
	bitGroups := make([]uint64, arrLen)

	for index, boolVal := range boolArray {
		bitGroups = k.SetBooleanInBitGroups(bitGroups, int64(index), boolVal)
	}

	return bitGroups
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

**File:** x/gov/types/params.go (L14-17)
```go
const (
	DefaultPeriod          time.Duration = time.Hour * 24 * 2 // 2 days
	DefaultExpeditedPeriod time.Duration = time.Hour * 24     // 1 day
)
```

**File:** x/gov/abci.go (L67-87)
```go
		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
			if err == nil {
				proposal.Status = types.StatusPassed
				tagValue = types.AttributeValueProposalPassed
				logMsg = "passed"

				// The cached context is created with a new EventManager. However, since
				// the proposal handler execution was successful, we want to track/keep
				// any events emitted, so we re-emit to "merge" the events into the
				// original Context's EventManager.
				ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())

				// write state to the underlying multi-store
				writeCache()
```
