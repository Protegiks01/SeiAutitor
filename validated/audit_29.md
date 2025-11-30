# Audit Report

## Title
Missing Input Validation in ValidatorSigningInfo Enables Network Halt via Negative IndexOffset

## Summary
The slashing module lacks validation for the `IndexOffset` field in `ValidatorSigningInfo`, allowing negative values to be persisted through genesis initialization. When BeginBlocker processes validators with negative `IndexOffset` values, a runtime panic occurs in bit shift operations, causing all validator nodes to crash simultaneously and total network shutdown.

## Impact
Medium

## Finding Description

**Location**: 
- Primary vulnerability: `x/slashing/keeper/signing_info.go` SetValidatorSigningInfo function [1](#0-0) 

- Missing genesis validation: `x/slashing/types/genesis.go` ValidateGenesis function [2](#0-1) 

- Panic trigger: `x/slashing/keeper/signing_info.go` GetBooleanFromBitGroups function [3](#0-2) 

**Intended logic**: The system should validate that `IndexOffset` is non-negative and within the valid range [0, SignedBlocksWindow) before persisting `ValidatorSigningInfo`. The field should only contain valid array indices for the missed blocks tracking system.

**Actual logic**: 
- `SetValidatorSigningInfo` directly marshals and stores any provided value without validation checks [1](#0-0) 

- `ValidateGenesis` only validates the `Params` field while completely skipping validation of the `SigningInfos` array [2](#0-1) 

- The protobuf definition defines `index_offset` as `int64`, which allows negative values [4](#0-3) 

**Exploitation path**:
1. Genesis state contains a `ValidatorSigningInfo` with negative `IndexOffset` (e.g., -5) due to manual error, tooling bug, or state corruption
2. `InitGenesis` iterates through signing infos and calls `SetValidatorSigningInfo` which stores the value without validation [5](#0-4) 

3. First block's `BeginBlocker` executes, processing all validators in parallel [6](#0-5) 

4. `HandleValidatorSignatureConcurrent` reads the IndexOffset directly [7](#0-6) 

5. Calls `GetBooleanFromBitGroups(missedInfo.MissedBlocks, index)` with negative index [8](#0-7) 

6. In `GetBooleanFromBitGroups`, line 81 computes `indexShift := index % UINT_64_NUM_BITS` which yields -5 (Go preserves sign in modulo), then line 86 attempts `indexMask := uint64(1) << indexShift`, causing runtime panic with "negative shift amount" [3](#0-2) 

7. All nodes crash simultaneously due to deterministic genesis state processing

**Security guarantee broken**: The system fails to maintain the critical invariant that `IndexOffset ∈ [0, SignedBlocksWindow)`, leading to undefined behavior (negative bit shift) that crashes the process. This violates fail-safe design principles for consensus-critical code.

## Impact Explanation

**Affected components**: All validator nodes, network consensus, transaction processing capability

**Consequences**:
- **Total network halt**: All nodes panic simultaneously when processing the first block after genesis initialization
- **Permanent service disruption**: Nodes cannot recover without external intervention to fix genesis state
- **Hard fork requirement**: Resolution requires coordinating all validators to restart with corrected genesis data
- **Zero transaction throughput**: No blocks can be produced until the issue is resolved

This completely breaks the blockchain's core purpose of maintaining continuous operation. The deterministic nature of genesis processing ensures all nodes fail identically, making network self-recovery impossible. This matches the Medium severity impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**Triggering conditions**:
- Occurs during genesis initialization or chain restart with exported state
- Any single `ValidatorSigningInfo` with negative `IndexOffset` triggers the vulnerability
- Deterministic impact affecting all nodes without timing dependencies

**Probability**: While genesis files are controlled by privileged operators, this vulnerability can be triggered accidentally through:
- Manual JSON editing errors during chain upgrades
- Bugs in genesis export/import tooling
- State corruption from other vulnerabilities
- Integer underflow in migration or state export code
- Copy-paste errors in configuration

The lack of defensive validation creates a fragile system where subtle errors in privileged operations cause catastrophic, unrecoverable failures beyond the intended scope of administrative control. This qualifies under the privilege exception clause because even a trusted role inadvertently triggering it causes an unrecoverable security failure (network-wide halt requiring hard fork) that far exceeds normal administrative authority.

## Recommendation

Implement comprehensive validation at multiple layers:

**1. Add validation in `SetValidatorSigningInfo`**:
```go
func (k Keeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info types.ValidatorSigningInfo) {
    if info.IndexOffset < 0 {
        panic(fmt.Sprintf("IndexOffset cannot be negative: %d", info.IndexOffset))
    }
    window := k.SignedBlocksWindow(ctx)
    if info.IndexOffset >= window {
        panic(fmt.Sprintf("IndexOffset %d must be less than SignedBlocksWindow %d", info.IndexOffset, window))
    }
    store := ctx.KVStore(k.storeKey)
    bz := k.cdc.MustMarshal(&info)
    store.Set(types.ValidatorSigningInfoKey(address), bz)
}
```

**2. Add validation in `ValidateGenesis`**:
```go
func ValidateGenesis(data GenesisState) error {
    // ... existing Params validation ...
    
    for _, signingInfo := range data.SigningInfos {
        if signingInfo.ValidatorSigningInfo.IndexOffset < 0 {
            return fmt.Errorf("IndexOffset cannot be negative: %d", signingInfo.ValidatorSigningInfo.IndexOffset)
        }
        if signingInfo.ValidatorSigningInfo.IndexOffset >= data.Params.SignedBlocksWindow {
            return fmt.Errorf("IndexOffset %d must be less than SignedBlocksWindow %d", 
                signingInfo.ValidatorSigningInfo.IndexOffset, data.Params.SignedBlocksWindow)
        }
        if signingInfo.ValidatorSigningInfo.MissedBlocksCounter < 0 {
            return fmt.Errorf("MissedBlocksCounter cannot be negative: %d", signingInfo.ValidatorSigningInfo.MissedBlocksCounter)
        }
    }
    
    return nil
}
```

**3. Add defensive check in `GetBooleanFromBitGroups`**:
```go
func (k Keeper) GetBooleanFromBitGroups(bitGroupArray []uint64, index int64) bool {
    if index < 0 {
        return false  // Defensive check similar to CompactBitArray.GetIndex
    }
    indexKey := index / UINT_64_NUM_BITS
    indexShift := index % UINT_64_NUM_BITS
    if indexKey >= int64(len(bitGroupArray)) {
        return false
    }
    indexMask := uint64(1) << indexShift
    missed := (bitGroupArray[indexKey] & indexMask) != 0
    return missed
}
```

## Proof of Concept

**Test file**: `x/slashing/genesis_test.go` (new test to add)

**Setup**:
- Initialize test app with simapp.Setup
- Create validator signing info with negative IndexOffset (-5)
- Store it using SetValidatorSigningInfo (which currently accepts it without validation)
- Set up validator in the staking module and configure missed blocks tracking

**Action**:
- Call BeginBlocker with RequestBeginBlock containing the validator's votes
- The BeginBlocker processes the validator's signing info in HandleValidatorSignatureConcurrent
- HandleValidatorSignatureConcurrent reads the negative IndexOffset value
- GetBooleanFromBitGroups is called with the negative index value
- The modulo operation preserves the negative sign: -5 % 64 = -5 (Go behavior)
- The bit shift operation attempts: uint64(1) << -5

**Result**: 
Runtime panic with error message "negative shift amount", demonstrating the network shutdown scenario. The test would use `require.Panics()` to verify the panic occurs, confirming that all validator nodes would crash simultaneously in this scenario.

## Notes

This vulnerability meets the exception clause for privileged operations because:

1. **Unrecoverable failure**: Total network halt with no self-recovery mechanism - all nodes crash deterministically
2. **Beyond intended authority**: Chain operators cannot fix this without coordinating all validators for a hard fork, far exceeding normal administrative control
3. **Catastrophic scope**: Affects entire network simultaneously (100% of validators), not just the misconfigured component
4. **Fail-unsafe design**: Lacks defensive validation for a critical invariant in consensus-critical code

The impact classification is **Medium** as it precisely matches the provided impact criterion: "Network not being able to confirm new transactions (total network shutdown)".

### Citations

**File:** x/slashing/keeper/signing_info.go (L34-38)
```go
func (k Keeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info types.ValidatorSigningInfo) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&info)
	store.Set(types.ValidatorSigningInfoKey(address), bz)
}
```

**File:** x/slashing/keeper/signing_info.go (L78-90)
```go
func (k Keeper) GetBooleanFromBitGroups(bitGroupArray []uint64, index int64) bool {
	// convert the index into indexKey + indexShift
	indexKey := index / UINT_64_NUM_BITS
	indexShift := index % UINT_64_NUM_BITS
	if indexKey >= int64(len(bitGroupArray)) {
		return false
	}
	// shift 1 by the indexShift value to generate bit mask (to index into the bitGroup)
	indexMask := uint64(1) << indexShift
	// apply the mask and if the value at that `indexShift` is 1 (indicating miss), then the value would be non-zero
	missed := (bitGroupArray[indexKey] & indexMask) != 0
	return missed
}
```

**File:** x/slashing/types/genesis.go (L32-58)
```go
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

**File:** proto/cosmos/slashing/v1beta1/slashing.proto (L40-40)
```text
  int64 index_offset = 3 [(gogoproto.moretags) = "yaml:\"index_offset\""];
```

**File:** x/slashing/genesis.go (L24-29)
```go
	for _, info := range data.SigningInfos {
		address, err := sdk.ConsAddressFromBech32(info.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorSigningInfo(ctx, address, info.ValidatorSigningInfo)
```

**File:** x/slashing/abci.go (L24-50)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	var wg sync.WaitGroup
	// Iterate over all the validators which *should* have signed this block
	// store whether or not they have actually signed it and slash/unbond any
	// which have missed too many blocks in a row (downtime slashing)

	// this allows us to preserve the original ordering for writing purposes
	slashingWriteInfo := make([]*SlashingWriteInfo, len(req.LastCommitInfo.GetVotes()))

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

**File:** x/slashing/keeper/infractions.go (L40-40)
```go
	index := signInfo.IndexOffset
```

**File:** x/slashing/keeper/infractions.go (L55-55)
```go
	previous := k.GetBooleanFromBitGroups(missedInfo.MissedBlocks, index)
```
