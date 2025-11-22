## Audit Report

## Title
Genesis Import Panic Due to Mismatched Window Sizes and Index Offsets in Validator Missed Block Arrays

## Summary
The genesis import function in the slashing module accepts `ValidatorMissedBlockArray` data with inconsistent `window_size` values relative to genesis parameters and `ValidatorSigningInfo.index_offset` values without validation. When the first block is processed, the resize logic attempts to slice arrays out of bounds, causing a panic that crashes all nodes and results in total network shutdown. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability originates in the genesis import at [2](#0-1)  where `keeper.SetValidatorMissedBlocks` is called without validation of the data consistency. The panic occurs during block processing in [3](#0-2)  within the `ResizeMissedBlockArray` function.

**Intended Logic:** 
The genesis import should only accept `ValidatorMissedBlockArray` data where:
1. The `window_size` field matches the genesis params `SignedBlocksWindow`
2. The corresponding `ValidatorSigningInfo.index_offset` is less than the `window_size`
3. The `missed_blocks` array has sufficient capacity for the `window_size`

The genesis validation function [4](#0-3)  validates params but does not check these data consistency constraints.

**Actual Logic:**
The genesis import directly stores the `ValidatorMissedBlockArray` data without validation. When the first block is processed:
1. `BeginBlocker` calls [5](#0-4)  `HandleValidatorSignatureConcurrent`
2. At [6](#0-5)  it detects `missedInfo.WindowSize != window` mismatch
3. It calls `ResizeMissedBlockArray` to resize the array
4. At [7](#0-6)  it parses the bit groups to a bool array of length `missedInfo.WindowSize` and attempts to copy: `copy(newArray[0:index], boolArray[0:index])`
5. If `index` (from `signInfo.IndexOffset`) >= `len(boolArray)` (which equals `missedInfo.WindowSize`), the slice operation `boolArray[0:index]` panics with "slice bounds out of range"

**Exploit Scenario:**
1. An attacker crafts a malicious genesis file with:
   - `Params.SignedBlocksWindow = 10000`
   - A `ValidatorMissedBlockArray` with `window_size = 100` and a small `missed_blocks` array
   - A `ValidatorSigningInfo` with `index_offset = 5000`
2. The genesis file passes validation because [8](#0-7)  doesn't check these consistency constraints
3. All nodes import this genesis successfully
4. On the first block, when any validator's signature is processed via [9](#0-8)  `HandleValidatorSignatureConcurrent`
5. The resize logic panics attempting to access `boolArray[0:5000]` where `len(boolArray) = 100`
6. All nodes crash simultaneously with "runtime error: slice bounds out of range"

**Security Failure:**
This breaks the **availability** security property. The panic causes immediate node crashes, preventing block processing and resulting in total network shutdown. The network cannot recover without a hard fork to fix the genesis state.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability and consensus
- All validator nodes and full nodes
- Transaction finality and block production

**Severity of Damage:**
- **Total network shutdown**: All nodes importing the malicious genesis will panic on the first block
- **Hard fork required**: Recovery requires creating a new genesis file with corrected data and coordinating all nodes to restart
- **Consensus failure**: No blocks can be produced until the network is restarted with fixed genesis data

**Why This Matters:**
This vulnerability can completely halt the blockchain network. If a malicious or misconfigured genesis is distributed, every node will crash on startup when attempting to process the first block. This represents a critical availability failure requiring emergency coordination and a hard fork to resolve.

## Likelihood Explanation

**Who Can Trigger:**
- Anyone who can influence the genesis file distribution (typically chain initiators)
- Can also occur accidentally through misconfiguration when creating genesis files
- Affects all nodes that import the malicious genesis

**Required Conditions:**
- The malicious/misconfigured genesis must be distributed to nodes
- At least one validator in the genesis must have the mismatched `window_size` and `index_offset` values
- The panic triggers on the first block processing when that validator's signature is handled

**Frequency:**
- Happens once per genesis import with mismatched data
- Affects all nodes simultaneously
- Cannot self-resolve without manual intervention and hard fork
- While genesis files are typically carefully prepared, the lack of validation makes this a realistic threat during network initialization or upgrades

## Recommendation

Add validation to the genesis import and/or the `ValidateGenesis` function to ensure data consistency:

1. In `ValidateGenesis` function [4](#0-3) , add checks to validate:
   - Each `ValidatorMissedBlockArray.window_size` matches `Params.SignedBlocksWindow`
   - Each `ValidatorSigningInfo.index_offset` is less than the corresponding `ValidatorMissedBlockArray.window_size`
   - The `missed_blocks` array length is sufficient: `len(missed_blocks) >= (window_size + 63) / 64`

2. Alternatively, add defensive bounds checking in [10](#0-9)  `ResizeMissedBlockArray` function:
   - Before line 164, add: `if index > missedInfo.WindowSize { index = 0 }` to prevent out-of-bounds access
   - Add validation to ensure the slice operations are safe

3. Consider auto-correction during genesis import: if mismatches are detected, automatically reset `index_offset` to 0 and resize arrays appropriately.

## Proof of Concept

**File:** `x/slashing/genesis_test.go`

**Test Function:** Add a new test function `TestGenesisImportMismatchedWindowSizePanic`

**Setup:**
```go
// Initialize a test app with default configuration
app := simapp.Setup(false)
ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})

// Create a test validator address
pks := simapp.CreateTestPubKeys(1)
addr := sdk.ConsAddress(pks[0].Address())
simapp.AddTestAddrsFromPubKeys(app, ctx, pks, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))

// Set genesis params with large window
params := types.DefaultParams()
params.SignedBlocksWindow = 10000
app.SlashingKeeper.SetParams(ctx, params)

// Create genesis state with mismatched data
// ValidatorMissedBlockArray has small window_size (100)
missedBlockArray := types.ValidatorMissedBlockArray{
    Address:      addr.String(),
    WindowSize:   100,  // Small window
    MissedBlocks: make([]uint64, 2), // Only 2 uint64s = 128 bits capacity
}

// ValidatorSigningInfo has large index_offset (5000)
signingInfo := types.ValidatorSigningInfo{
    Address:             addr.String(),
    StartHeight:         0,
    IndexOffset:         5000, // Large offset > window_size
    JailedUntil:         time.Unix(0, 0).UTC(),
    Tombstoned:          false,
    MissedBlocksCounter: 0,
}

genesisState := types.GenesisState{
    Params:       params,
    SigningInfos: []types.SigningInfo{{Address: addr.String(), ValidatorSigningInfo: signingInfo}},
    MissedBlocks: []types.ValidatorMissedBlockArray{missedBlockArray},
}
```

**Trigger:**
```go
// Import the malicious genesis
slashing.InitGenesis(ctx, app.SlashingKeeper, app.StakingKeeper, &genesisState)

// Create a validator and bond it
tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
valAddr := sdk.ValAddress(pks[0].Address())
tstaking.CreateValidatorWithValPower(valAddr, pks[0], 100, true)
staking.EndBlocker(ctx, app.StakingKeeper)

// Attempt to process first block with validator signature
req := abci.RequestBeginBlock{
    LastCommitInfo: abci.LastCommitInfo{
        Votes: []abci.VoteInfo{{
            Validator: abci.Validator{
                Address: pks[0].Address(),
                Power:   100,
            },
            SignedLastBlock: true,
        }},
    },
}

// This should panic with "slice bounds out of range"
slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
```

**Observation:**
The test will panic with error message: `"runtime error: slice bounds out of range [5000:100]"` when `ResizeMissedBlockArray` attempts to execute `copy(newArray[0:5000], boolArray[0:5000])` where `len(boolArray) = 100`. This confirms the vulnerability causes node crashes and total network shutdown.

To properly test this as a panic test, wrap the `BeginBlocker` call in a panic recovery:
```go
require.Panics(t, func() {
    slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
}, "Expected panic due to slice bounds out of range")
```

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

**File:** x/slashing/keeper/infractions.go (L41-41)
```go

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
