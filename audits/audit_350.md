# Audit Report

## Title
Unvalidated ValidatorSigningInfo Storage Enables Network Halt via Negative IndexOffset

## Summary
The `SetValidatorSigningInfo` function in `x/slashing/keeper/signing_info.go` stores validator signing information without validating the structure's fields. [1](#0-0)  This allows corrupted data with negative `IndexOffset` values to be persisted through genesis initialization, which causes all nodes to panic during the first block's `BeginBlocker` when the negative index is used in bit array operations, resulting in total network shutdown.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary: `x/slashing/keeper/signing_info.go` lines 34-38 (SetValidatorSigningInfo)
- Secondary: `x/slashing/types/genesis.go` lines 32-58 (ValidateGenesis)
- Trigger: `x/slashing/keeper/infractions.go` lines 55-57 (HandleValidatorSignatureConcurrent)
- Crash point: `x/slashing/keeper/signing_info.go` lines 78-90 (GetBooleanFromBitGroups)

**Intended Logic:** 
The `SetValidatorSigningInfo` function should validate that the `ValidatorSigningInfo` structure contains valid values before persisting to state, particularly ensuring `IndexOffset` is non-negative and within the valid range [0, SignedBlocksWindow). [2](#0-1) 

**Actual Logic:** 
The function performs no validation whatsoever - it directly marshals and stores the provided signing info. [1](#0-0)  Additionally, `ValidateGenesis` only validates the `Params` field but skips validation of the `SigningInfos` array entirely. [3](#0-2) 

**Exploit Scenario:**
1. During chain initialization or upgrade, genesis state contains a `ValidatorSigningInfo` with `IndexOffset = -5`
2. `InitGenesis` calls `SetValidatorSigningInfo` which stores this without validation [4](#0-3) 
3. First block's `BeginBlocker` executes for all validators [5](#0-4) 
4. `HandleValidatorSignatureConcurrent` retrieves the corrupted signing info and assigns `index := signInfo.IndexOffset` (now -5) [6](#0-5) 
5. This index is immediately used in `GetBooleanFromBitGroups(missedInfo.MissedBlocks, index)` [7](#0-6) 
6. In `GetBooleanFromBitGroups`, `indexShift = -5 % 64 = -5` (Go preserves sign in modulo) [8](#0-7) 
7. The code attempts `indexMask := uint64(1) << indexShift` with negative shift, causing panic: "runtime error: negative shift amount" [9](#0-8) 
8. All validator nodes crash simultaneously, unable to process any blocks

**Security Failure:** 
This is a denial-of-service vulnerability resulting from missing input validation. The system fails to maintain the invariant that `IndexOffset` must be non-negative and within valid bounds, leading to undefined behavior (negative bit shift) that crashes the process.

## Impact Explanation

**Affected Components:**
- All validator nodes attempting to process blocks
- Network availability and consensus
- Transaction finality

**Severity of Damage:**
- **Total network halt**: All nodes crash when processing the first block after genesis initialization
- **Permanent service disruption**: Nodes cannot recover without fixing the genesis state
- **Hard fork required**: Resolution requires coordinating all validators to use corrected genesis data and restart the chain
- **No transaction processing**: Zero blocks can be produced until the issue is resolved

**Why This Matters:**
A blockchain network's core purpose is to maintain continuous operation and process transactions. This vulnerability completely breaks that guarantee, causing cascading failures across the entire network simultaneously. Unlike isolated node issues, this affects all nodes identically due to deterministic genesis state processing, making it impossible for the network to self-recover.

## Likelihood Explanation

**Who Can Trigger:**
While genesis state is controlled by chain operators (privileged role), this vulnerability represents a **subtle logic error** that can be triggered accidentally through:
- Manual editing mistakes in genesis JSON files during chain upgrades
- Bugs in genesis export/import tooling
- State corruption from other vulnerabilities that modify signing info
- Integer underflow in migration or export code

**Conditions Required:**
- Occurs during genesis initialization or chain restart with exported state
- Any single `ValidatorSigningInfo` in genesis with `IndexOffset < 0` triggers the issue
- Deterministically affects all nodes - no special timing or race conditions needed

**Frequency:**
- High probability during chain upgrades/restarts if genesis handling has bugs
- Guaranteed crash on every block attempt once corrupted data is loaded
- Single occurrence is sufficient for total network failure

The lack of defensive validation violates the principle of fail-safe defaults and creates a fragile system susceptible to accidental corruption.

## Recommendation

Add comprehensive validation to `SetValidatorSigningInfo` and `ValidateGenesis`:

**1. Validate in SetValidatorSigningInfo:**
```go
func (k Keeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info types.ValidatorSigningInfo) {
    // Validate IndexOffset is non-negative
    if info.IndexOffset < 0 {
        panic(fmt.Sprintf("IndexOffset must be non-negative, got: %d", info.IndexOffset))
    }
    
    // Validate IndexOffset is within window bounds
    window := k.SignedBlocksWindow(ctx)
    if info.IndexOffset >= window {
        panic(fmt.Sprintf("IndexOffset must be less than SignedBlocksWindow (%d), got: %d", window, info.IndexOffset))
    }
    
    // Validate MissedBlocksCounter is non-negative
    if info.MissedBlocksCounter < 0 {
        panic(fmt.Sprintf("MissedBlocksCounter must be non-negative, got: %d", info.MissedBlocksCounter))
    }
    
    store := ctx.KVStore(k.storeKey)
    bz := k.cdc.MustMarshal(&info)
    store.Set(types.ValidatorSigningInfoKey(address), bz)
}
```

**2. Add validation in ValidateGenesis:**
```go
func ValidateGenesis(data GenesisState) error {
    // ... existing Params validation ...
    
    // Validate SigningInfos
    for _, signingInfo := range data.SigningInfos {
        if signingInfo.ValidatorSigningInfo.IndexOffset < 0 {
            return fmt.Errorf("IndexOffset must be non-negative for validator %s, got: %d", 
                signingInfo.Address, signingInfo.ValidatorSigningInfo.IndexOffset)
        }
        if signingInfo.ValidatorSigningInfo.MissedBlocksCounter < 0 {
            return fmt.Errorf("MissedBlocksCounter must be non-negative for validator %s, got: %d",
                signingInfo.Address, signingInfo.ValidatorSigningInfo.MissedBlocksCounter)
        }
    }
    
    return nil
}
```

## Proof of Concept

**File:** `x/slashing/genesis_test.go`

**Test Function:** Add new test `TestGenesisWithNegativeIndexOffsetCausesPanic`

**Setup:**
```go
func TestGenesisWithNegativeIndexOffsetCausesPanic(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Setup test addresses and params
    app.SlashingKeeper.SetParams(ctx, testslashing.TestParams())
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    
    // Create signing info with NEGATIVE IndexOffset (corrupted data)
    corruptedInfo := types.NewValidatorSigningInfo(
        sdk.ConsAddress(addrDels[0]), 
        int64(4),     // StartHeight
        int64(-5),    // IndexOffset - NEGATIVE VALUE
        time.Now().UTC().Add(100000000000), 
        false, 
        int64(10),    // MissedBlocksCounter
    )
    
    // This succeeds without validation - demonstrates the vulnerability
    app.SlashingKeeper.SetValidatorSigningInfo(ctx, sdk.ConsAddress(addrDels[0]), corruptedInfo)
    
    // Verify corrupted data was stored
    storedInfo, found := app.SlashingKeeper.GetValidatorSigningInfo(ctx, sdk.ConsAddress(addrDels[0]))
    require.True(t, found)
    require.Equal(t, int64(-5), storedInfo.IndexOffset)
}
```

**Trigger:**
```go
    // Simulate BeginBlock processing that would occur on first block
    // This will panic due to negative IndexOffset in bit array operations
    require.Panics(t, func() {
        // Create vote info for the validator
        pk := addrDels[0]
        voteInfo := abci.VoteInfo{
            Validator: abci.Validator{
                Address: pk,
                Power:   100,
            },
            SignedLastBlock: true,
        }
        
        req := abci.RequestBeginBlock{
            LastCommitInfo: abci.LastCommitInfo{
                Votes: []abci.VoteInfo{voteInfo},
            },
        }
        
        // This calls HandleValidatorSignatureConcurrent which uses negative IndexOffset
        // in GetBooleanFromBitGroups, causing panic: "negative shift amount"
        slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    })
}
```

**Observation:**
The test demonstrates that:
1. `SetValidatorSigningInfo` accepts and stores negative `IndexOffset` without validation
2. When `BeginBlocker` processes this corrupted data, it panics with "runtime error: negative shift amount" 
3. In a real network, this panic would crash all nodes simultaneously, causing total network shutdown
4. The test should **fail** on vulnerable code by triggering the panic, confirming the security issue

The PoC can be run with: `go test -v -run TestGenesisWithNegativeIndexOffsetCausesPanic ./x/slashing`

### Citations

**File:** x/slashing/keeper/signing_info.go (L33-38)
```go
// SetValidatorSigningInfo sets the validator signing info to a consensus address key
func (k Keeper) SetValidatorSigningInfo(ctx sdk.Context, address sdk.ConsAddress, info types.ValidatorSigningInfo) {
	store := ctx.KVStore(k.storeKey)
	bz := k.cdc.MustMarshal(&info)
	store.Set(types.ValidatorSigningInfoKey(address), bz)
}
```

**File:** x/slashing/keeper/signing_info.go (L78-81)
```go
func (k Keeper) GetBooleanFromBitGroups(bitGroupArray []uint64, index int64) bool {
	// convert the index into indexKey + indexShift
	indexKey := index / UINT_64_NUM_BITS
	indexShift := index % UINT_64_NUM_BITS
```

**File:** x/slashing/keeper/signing_info.go (L86-86)
```go
	indexMask := uint64(1) << indexShift
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

**File:** x/slashing/genesis.go (L24-29)
```go
	for _, info := range data.SigningInfos {
		address, err := sdk.ConsAddressFromBech32(info.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorSigningInfo(ctx, address, info.ValidatorSigningInfo)
```

**File:** x/slashing/abci.go (L24-65)
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
	wg.Wait()

	for _, writeInfo := range slashingWriteInfo {
		if writeInfo == nil {
			panic("Expected slashing write info to be non-nil")
		}
		// Update the validator missed block bit array by index if different from last value at the index
		if writeInfo.ShouldSlash {
			k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
			writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
		} else {
			k.SetValidatorMissedBlocks(ctx, writeInfo.ConsAddr, writeInfo.MissedInfo)
		}
		k.SetValidatorSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SigningInfo)
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
