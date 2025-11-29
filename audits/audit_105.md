# Audit Report

## Title
Unbounded SignedBlocksWindow Parameter Enables Network-Wide Denial of Service via Memory Exhaustion

## Summary
The `SignedBlocksWindow` parameter in the slashing module lacks upper bound validation, allowing governance proposals to set it to arbitrarily large values. When changed, the system allocates memory proportional to the window size for every validator in the next block, potentially causing network-wide out-of-memory crashes and complete network shutdown.

## Impact
**Medium**

## Finding Description

**Location:**
- Parameter validation: [1](#0-0) 
- Resize operation with memory allocation: [2](#0-1) 
- Per-validator triggering: [3](#0-2) 
- Execution in BeginBlocker: [4](#0-3) 

**Intended Logic:**
The `SignedBlocksWindow` parameter defines the sliding window size for tracking validator liveness. Parameter validation should ensure values stay within reasonable operational bounds to prevent resource exhaustion and maintain network stability.

**Actual Logic:**
The validation function only checks that the value is positive (`v > 0`) with no upper bound check. [1](#0-0)  This allows setting the window to extreme values up to max int64 (9,223,372,036,854,775,807).

When the window size changes, `ResizeMissedBlockArray` allocates bool arrays of size `window` for each validator: [2](#0-1)  The function calls `ParseBitGroupsToBoolArray` which allocates `make([]bool, window)` [5](#0-4)  and then creates another array `make([]bool, window)` for the new window size. It then converts back via `ParseBoolArrayToBitGroups`. [6](#0-5) 

Since Go uses 1 byte per bool, a window of 1 billion blocks means ~1 GB allocation per validator, with temporary 2x overhead during resize operations.

**Exploitation Path:**
1. Attacker (or legitimate user making a typo) submits a governance `ParameterChangeProposal` to set `SignedBlocksWindow` to 1,000,000,000 [7](#0-6) 
2. Proposal passes after voting period (governance validates and applies the parameter)
3. On the next block's BeginBlocker, `HandleValidatorSignatureConcurrent` is called for all validators in parallel [4](#0-3) 
4. For each validator, the resize check triggers when `missedInfo.WindowSize != window` [3](#0-2) 
5. With 100 active validators and window=1 billion: each validator attempts ~2 GB allocation (old + new array), totaling ~200 GB simultaneous memory allocation
6. Nodes exhaust available memory, crash with OOM errors, or hang indefinitely
7. Network halts as validators cannot process blocks, requiring a coordinated hard fork to recover

**Security Guarantee Broken:**
Network liveness and availability. The blockchain must maintain the ability to process new transactions. The lack of bounds checking on a governance-controlled parameter allows configuration changes that exceed system resources, causing total network shutdown.

## Impact Explanation

**Affected Components:**
- All validator nodes across the network
- Network consensus and block production
- Transaction processing capability

**Severity:**
This vulnerability causes complete network shutdown. All validators would attempt the same memory-intensive operation on the same block height, causing synchronized failures. Recovery requires a coordinated hard fork to revert or cap the parameter value, as validators cannot progress past the block that triggers the memory exhaustion. The impact matches the valid severity category: "Network not being able to confirm new transactions (total network shutdown)" classified as **Medium** severity.

## Likelihood Explanation

**Who Can Trigger:**
Anyone with sufficient voting power to pass a governance proposal (typically requires >50% stake support).

**Conditions:**
- Single governance proposal submission and passage
- No special timing or coordination required
- Can occur during normal network operation

**Likelihood Assessment:**
Despite requiring governance approval, this vulnerability has significant likelihood because:

1. **Accidental Trigger**: A typo when setting the parameter (e.g., entering 100000000 instead of 100000) would trigger this vulnerability. This is a realistic operational mistake.

2. **Exception to Privilege Rule**: While governance is a privileged action, the impact (total network shutdown requiring hard fork) is far beyond the intended authority of a parameter change. The platform acceptance rules explicitly allow for issues where "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority."

3. **Validation Bug**: This is fundamentally a validation failure. Systems should validate inputs to prevent resource exhaustion, regardless of the source. Parameter validation exists for precisely this reason - to prevent both malicious and accidental misconfigurations.

4. **No Safeguards**: There are no additional checks, warnings, or gradual rollout mechanisms for parameter changes of this magnitude.

## Recommendation

Add an upper bound validation to the `validateSignedBlocksWindow` function:

```go
func validateSignedBlocksWindow(i interface{}) error {
    v, ok := i.(int64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }
    
    if v <= 0 {
        return fmt.Errorf("signed blocks window must be positive: %d", v)
    }
    
    // Add maximum bound - 1 million blocks (~11 days at 1s block time)
    const MaxSignedBlocksWindow = int64(1_000_000)
    if v > MaxSignedBlocksWindow {
        return fmt.Errorf("signed blocks window too large (max %d): %d", 
            MaxSignedBlocksWindow, v)
    }
    
    return nil
}
```

The maximum of 1,000,000 blocks provides 10x headroom over the default 108,000 blocks while preventing extreme values that could cause resource exhaustion.

## Proof of Concept

**Setup:**
1. Initialize test chain with multiple validators
2. Set initial `SignedBlocksWindow` to default value (108,000)
3. Validators process several blocks normally

**Action:**
1. Use governance mechanism to change `SignedBlocksWindow` to 50,000,000 (or higher)
2. Trigger `BeginBlocker` for the next block with validator votes

**Result:**
- Excessive memory allocation (hundreds of MB to GB per validator)
- Significant performance degradation or timeout
- With production scale (100+ validators, 1 billion window), nodes would crash with OOM errors
- Network unable to progress past the triggering block

The vulnerable code path is clear: parameter validation allows the large value, BeginBlocker triggers resize for all validators simultaneously, and memory allocations proportional to window size cause resource exhaustion.

## Notes

The severity is correctly classified as **Medium** according to the provided impact list ("Network not being able to confirm new transactions (total network shutdown)"), not High as initially claimed in the report. While this requires governance approval to trigger, it represents a critical validation bug where even trusted actors could inadvertently cause unrecoverable network failure beyond their intended authority, which falls under the explicit exception to the privileged action rule.

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

**File:** x/slashing/keeper/signing_info.go (L118-127)
```go
func (k Keeper) ParseBoolArrayToBitGroups(boolArray []bool) []uint64 {
	arrLen := (len(boolArray) + UINT_64_NUM_BITS - 1) / UINT_64_NUM_BITS
	bitGroups := make([]uint64, arrLen)

	for index, boolVal := range boolArray {
		bitGroups = k.SetBooleanInBitGroups(bitGroups, int64(index), boolVal)
	}

	return bitGroups
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
