# Audit Report

## Title
Genesis Import Panic Due to Mismatched Window Sizes and Index Offsets in Validator Missed Block Arrays

## Summary
The slashing module's genesis import accepts `ValidatorMissedBlockArray` data with inconsistent `window_size` values and `ValidatorSigningInfo.index_offset` values without validation. When the first block is processed, the `ResizeMissedBlockArray` function attempts an out-of-bounds slice operation, causing a runtime panic that crashes all nodes and results in total network shutdown.

## Impact
Medium

## Finding Description

**Location:** The vulnerability originates in genesis import at [1](#0-0)  where `SetValidatorMissedBlocks` is called without data consistency validation. The panic occurs during block processing in [2](#0-1)  within the `ResizeMissedBlockArray` function.

**Intended Logic:** The genesis import should only accept `ValidatorMissedBlockArray` data where:
1. The `window_size` field matches the genesis params `SignedBlocksWindow`
2. The corresponding `ValidatorSigningInfo.index_offset` is less than the `window_size`
3. These constraints are validated during genesis import to prevent runtime panics

**Actual Logic:** The genesis validation function [3](#0-2)  only validates parameter ranges but does not check data consistency between `ValidatorMissedBlockArray` and `ValidatorSigningInfo`. During first block processing at [4](#0-3) , when a window size mismatch is detected at [5](#0-4) , the resize logic creates a `boolArray` with length equal to `missedInfo.WindowSize` (line 162), then attempts `copy(newArray[0:index], boolArray[0:index])` where `index` comes from `signInfo.IndexOffset`. If `index > len(boolArray)`, this panics with "slice bounds out of range".

**Exploitation Path:**
1. Genesis file is created with `Params.SignedBlocksWindow = 10000`
2. A `ValidatorMissedBlockArray` has `window_size = 100` 
3. The corresponding `ValidatorSigningInfo` has `index_offset = 5000`
4. Genesis validation passes because consistency checks are absent
5. All nodes import the genesis successfully
6. On first block, `BeginBlocker` processes validator signatures
7. `HandleValidatorSignatureConcurrent` detects window size mismatch (100 vs 10000)
8. `ResizeMissedBlockArray` is called with index=5000
9. The function creates `boolArray` of length 100, then tries to access `boolArray[0:5000]`
10. Runtime panic: "slice bounds out of range"
11. All nodes crash simultaneously

**Security Guarantee Broken:** This violates the **availability** security property. The panic causes immediate node crashes and total network shutdown with no automatic recovery mechanism.

## Impact Explanation

This vulnerability causes total network shutdown affecting:
- **All validator and full nodes**: Every node importing the malformed genesis crashes on the first block
- **Network availability**: No blocks can be produced or transactions confirmed
- **Recovery cost**: Requires emergency coordination and hard fork with corrected genesis data
- **Consensus failure**: The blockchain cannot progress until all nodes restart with fixed state

This matches the Medium severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Who Can Trigger:**
- Chain initiators who create genesis files (privileged role)
- Can occur accidentally through misconfiguration during genesis creation or network upgrades

**Required Conditions:**
- Malformed genesis with mismatched `window_size` and `index_offset` values must be distributed
- At least one validator must have these inconsistent values
- Triggers automatically on first block processing

**Frequency:**
- Occurs once per malformed genesis import
- Affects all nodes simultaneously
- Cannot self-resolve without manual intervention
- While genesis creation is privileged, the lack of validation makes accidental misconfiguration a realistic threat

**Note:** Although genesis creation is a privileged operation, this vulnerability qualifies as valid because even a trusted role inadvertently triggering it causes an unrecoverable security failure (total network shutdown requiring hard fork) that is beyond their intended authority. Privileged operations should still have validation to prevent catastrophic system failures.

## Recommendation

1. **Add genesis validation checks** in [3](#0-2) :
   - Verify each `ValidatorMissedBlockArray.window_size` matches `Params.SignedBlocksWindow`
   - Verify each `ValidatorSigningInfo.index_offset < window_size`
   - Verify `len(missed_blocks) >= (window_size + 63) / 64`

2. **Add defensive bounds checking** in [2](#0-1) :
   - Before line 164, add: `if index > missedInfo.WindowSize { index = 0 }`
   - Ensure slice operations cannot panic on out-of-bounds access

3. **Auto-correction during import**: If mismatches are detected, automatically reset `index_offset` to 0 and resize arrays appropriately rather than accepting invalid state.

## Proof of Concept

**File:** `x/slashing/genesis_test.go`

**Setup:**
- Initialize test app and context
- Create validator with consensus address
- Set genesis params with `SignedBlocksWindow = 10000`
- Create `ValidatorMissedBlockArray` with `window_size = 100` and `MissedBlocks` of 2 uint64s
- Create `ValidatorSigningInfo` with `index_offset = 5000` (exceeds window_size)
- Construct genesis state with these mismatched values

**Action:**
- Import genesis via `slashing.InitGenesis()`
- Create and bond validator
- Call `slashing.BeginBlocker()` with validator signature in first block

**Result:**
- Runtime panic with error: "slice bounds out of range [5000:100]"
- Occurs when `ResizeMissedBlockArray` executes `copy(newArray[0:5000], boolArray[0:5000])` where `len(boolArray) = 100`
- Confirms total network shutdown on first block processing

The PoC demonstrates that all nodes importing this genesis will crash simultaneously, requiring a hard fork to recover.

### Citations

**File:** x/slashing/genesis.go (L32-38)
```go
	for _, array := range data.MissedBlocks {
		address, err := sdk.ConsAddressFromBech32(array.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorMissedBlocks(ctx, address, array)
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

**File:** x/slashing/types/genesis.go (L31-58)
```go
// ValidateGenesis validates the slashing genesis parameters
func ValidateGenesis(data GenesisState) error {
	downtime := data.Params.SlashFractionDowntime
	if downtime.IsNegative() || downtime.GT(sdk.OneDec()) {
		return fmt.Errorf("slashing fraction downtime should be less than or equal to one and greater than zero, is %s", downtime.String())
	}

	dblSign := data.Params.SlashFractionDoubleSign
	if dblSign.IsNegative() || dblSign.GT(sdk.OneDec()) {
		return fmt.Errorf("slashing fraction double sign should be less than or equal to one and greater than zero, is %s", dblSign.String())
	}

	minSign := data.Params.MinSignedPerWindow
	if minSign.IsNegative() || minSign.GT(sdk.OneDec()) {
		return fmt.Errorf("min signed per window should be less than or equal to one and greater than zero, is %s", minSign.String())
	}

	downtimeJail := data.Params.DowntimeJailDuration
	if downtimeJail < 1*time.Minute {
		return fmt.Errorf("downtime unjail duration must be at least 1 minute, is %s", downtimeJail.String())
	}

	signedWindow := data.Params.SignedBlocksWindow
	if signedWindow < 10 {
		return fmt.Errorf("signed blocks window must be at least 10, is %d", signedWindow)
	}

	return nil
```

**File:** x/slashing/abci.go (L41-41)
```go
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```
