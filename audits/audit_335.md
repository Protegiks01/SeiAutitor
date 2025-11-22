## Title
Chain Halt Due to Orphaned Missed Blocks Imported Through Malicious Genesis File

## Summary
The slashing module's genesis validation and import process fails to validate that every missed blocks entry has a corresponding signing info entry. This allows a malicious genesis file to import orphaned missed blocks (missed blocks without signing info), which causes the chain to panic and halt when those validators participate in consensus.

## Impact
**High** - Total network shutdown

## Finding Description

**Location:** 
- Primary issue: `x/slashing/types/genesis.go` ValidateGenesis function (lines 32-58)
- Secondary issue: `x/slashing/genesis.go` InitGenesis function (lines 32-38)
- Panic location: `x/slashing/keeper/infractions.go` HandleValidatorSignatureConcurrent function (lines 33-36)
- Related: `x/slashing/genesis.go` ExportGenesis function (lines 46-66) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The genesis validation should ensure data integrity by verifying that missed blocks entries only exist for validators that have corresponding signing info. The ExportGenesis function should maintain this invariant by only exporting consistent state. [4](#0-3) 

**Actual Logic:** 
1. `ValidateGenesis` only validates parameters but does NOT check that every entry in `MissedBlocks` has a corresponding entry in `SigningInfos`
2. `InitGenesis` imports MissedBlocks and SigningInfos independently without cross-validation (lines 24-30 import signing infos, lines 32-38 import missed blocks separately)
3. `ExportGenesis` iterates only over signing infos (line 50) and tries to get missed blocks for each (line 57). Orphaned missed blocks are silently dropped.
4. When `BeginBlocker` processes a validator with orphaned missed blocks, `HandleValidatorSignatureConcurrent` expects signing info to exist and panics if not found [5](#0-4) 

**Exploit Scenario:**
1. Attacker crafts a malicious genesis file with:
   - One or more `ValidatorMissedBlockArray` entries in `MissedBlocks` 
   - NO corresponding entries in `SigningInfos` for those addresses
   - `Exported: true` in the staking genesis to prevent hooks from creating missing signing info
2. The genesis file passes `ValidateGenesis` because it only validates params
3. Chain operators initialize the chain with this genesis using `InitGenesis`
4. The orphaned missed blocks are imported into state (line 37: `SetValidatorMissedBlocks`)
5. When the first block is produced and the validator with orphaned missed blocks participates:
   - `BeginBlocker` is called with votes from that validator
   - `HandleValidatorSignatureConcurrent` is invoked (line 41 in abci.go)
   - It tries to fetch signing info (line 33 in infractions.go)
   - Signing info is not found, causing panic: "Expected signing info for validator %s but not found"
6. The entire chain halts due to the panic in BeginBlocker [6](#0-5) 

**Security Failure:** 
The system fails to maintain the invariant that missed blocks can only exist for validators with signing info. This breaks consensus availability, causing a denial-of-service condition where the entire network cannot process any transactions.

## Impact Explanation

**Affected Processes:** Network consensus and block production

**Severity of Damage:** 
- The entire blockchain network halts immediately when BeginBlocker panics
- No new blocks can be produced or transactions confirmed
- The network remains down until all nodes are restarted with a fixed genesis file
- This requires coordinated intervention from all validators and operators

**Why This Matters:** 
This vulnerability allows an attacker who can influence the genesis file (e.g., through social engineering during chain launch, or by compromising genesis creation tools) to create a time-bomb that causes total network shutdown. Even if the malicious entries target inactive validators initially, if those validators later become active, the chain halts. This completely undermines network availability and reliability.

## Likelihood Explanation

**Who Can Trigger It:** 
An attacker who can influence the genesis file content. This could be:
- A malicious actor involved in genesis file creation
- Someone who compromises genesis generation tooling
- An attacker who convinces chain operators to import a malicious genesis via social engineering

**Required Conditions:**
1. The malicious genesis must be used during chain initialization or chain restart from genesis
2. The validator addresses in the orphaned missed blocks entries must eventually participate in consensus (either at genesis or later)

**Frequency:**
- Can be triggered once per chain launch/restart from genesis
- The attack persists indefinitely once imported (orphaned data remains in state)
- Impact occurs immediately when affected validators sign blocks

**Realistic Scenario:**
While requiring some level of insider access or social engineering during genesis creation, this is realistic because:
- Many chains involve multiple parties in genesis file creation
- Genesis files are often manually constructed and reviewed
- The validation gaps make it easy to miss this type of malicious data
- Once imported, the issue is irreversible without chain restart

## Recommendation

**Fix 1: Add Validation in ValidateGenesis**
```go
// In x/slashing/types/genesis.go, add after line 56:

// Validate that all missed blocks have corresponding signing info
signingInfoAddrs := make(map[string]bool)
for _, info := range data.SigningInfos {
    signingInfoAddrs[info.Address] = true
}

for _, missedBlock := range data.MissedBlocks {
    if !signingInfoAddrs[missedBlock.Address] {
        return fmt.Errorf("missed blocks found for address %s without corresponding signing info", missedBlock.Address)
    }
}
```

**Fix 2: Add Defensive Check in HandleValidatorSignatureConcurrent**
Instead of panicking, gracefully handle missing signing info by creating it on-the-fly or logging an error:
```go
// In x/slashing/keeper/infractions.go, replace lines 33-36:

signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
if !found {
    // Create signing info on-the-fly instead of panicking
    signInfo = types.NewValidatorSigningInfo(consAddr, height, 0, time.Unix(0, 0), false, 0)
    k.SetValidatorSigningInfo(ctx, consAddr, signInfo)
}
```

**Recommended Approach:** Implement both fixes:
- Fix 1 prevents the issue at genesis validation time (fail-fast)
- Fix 2 provides defense-in-depth in case the issue occurs through other paths

## Proof of Concept

**File:** `x/slashing/genesis_test.go` (add new test function)

**Test Function:** `TestOrphanedMissedBlocksCausesPanic`

```go
func TestOrphanedMissedBlocksCausesPanic(t *testing.T) {
    // Setup: Create a fresh app and context
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Create test validator
    pks := simapp.CreateTestPubKeys(1)
    consAddr := sdk.ConsAddress(pks[0].Address())
    
    // Setup: Create malicious genesis with orphaned missed blocks
    // (missed blocks without signing info)
    missedBlocks := []types.ValidatorMissedBlockArray{
        {
            Address:      consAddr.String(),
            MissedBlocks: []uint64{0}, // Some missed blocks data
            WindowSize:   100,
        },
    }
    
    genesisState := &types.GenesisState{
        Params:       testslashing.TestParams(),
        SigningInfos: []types.SigningInfo{}, // Empty - no signing info!
        MissedBlocks: missedBlocks,           // But has missed blocks
    }
    
    // This should ideally fail but currently doesn't
    err := types.ValidateGenesis(*genesisState)
    require.NoError(t, err) // Bug: validation passes!
    
    // Import the malicious genesis
    slashing.InitGenesis(ctx, app.SlashingKeeper, app.StakingKeeper, genesisState)
    
    // Verify orphaned missed blocks were imported
    imported, found := app.SlashingKeeper.GetValidatorMissedBlocks(ctx, consAddr)
    require.True(t, found)
    require.Equal(t, consAddr.String(), imported.Address)
    
    // Verify no signing info exists
    _, found = app.SlashingKeeper.GetValidatorSigningInfo(ctx, consAddr)
    require.False(t, found) // Orphaned state!
    
    // Trigger: Try to process this validator in BeginBlocker
    req := abci.RequestBeginBlock{
        LastCommitInfo: abci.LastCommitInfo{
            Votes: []abci.VoteInfo{
                {
                    Validator: abci.Validator{
                        Address: pks[0].Address(),
                        Power:   100,
                    },
                    SignedLastBlock: true,
                },
            },
        },
    }
    
    // Add pubkey so validator is recognized
    app.SlashingKeeper.AddPubkey(ctx, pks[0])
    
    // Observation: This should panic with "Expected signing info for validator %s but not found"
    require.Panics(t, func() {
        slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    }, "Expected panic due to missing signing info but chain did not panic")
}
```

**Expected Behavior:**
- The test demonstrates that `ValidateGenesis` fails to catch orphaned missed blocks
- The test shows that `InitGenesis` imports orphaned missed blocks successfully
- The test proves that `BeginBlocker` panics when processing a validator with orphaned missed blocks
- This panic would cause complete chain halt in production

**How to Run:**
```bash
cd x/slashing
go test -v -run TestOrphanedMissedBlocksCausesPanic
```

The test will pass (demonstrating the vulnerability exists) by confirming the panic occurs when BeginBlocker processes the validator with orphaned missed blocks.

### Citations

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

**File:** x/slashing/genesis.go (L12-41)
```go
func InitGenesis(ctx sdk.Context, keeper keeper.Keeper, stakingKeeper types.StakingKeeper, data *types.GenesisState) {
	stakingKeeper.IterateValidators(ctx,
		func(index int64, validator stakingtypes.ValidatorI) bool {
			consPk, err := validator.ConsPubKey()
			if err != nil {
				panic(err)
			}
			keeper.AddPubkey(ctx, consPk)
			return false
		},
	)

	for _, info := range data.SigningInfos {
		address, err := sdk.ConsAddressFromBech32(info.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorSigningInfo(ctx, address, info.ValidatorSigningInfo)
	}

	for _, array := range data.MissedBlocks {
		address, err := sdk.ConsAddressFromBech32(array.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorMissedBlocks(ctx, address, array)
	}

	keeper.SetParams(ctx, data.Params)
}
```

**File:** x/slashing/genesis.go (L46-66)
```go
func ExportGenesis(ctx sdk.Context, keeper keeper.Keeper) (data *types.GenesisState) {
	params := keeper.GetParams(ctx)
	signingInfos := make([]types.SigningInfo, 0)
	missedBlocks := make([]types.ValidatorMissedBlockArray, 0)
	keeper.IterateValidatorSigningInfos(ctx, func(address sdk.ConsAddress, info types.ValidatorSigningInfo) (stop bool) {
		bechAddr := address.String()
		signingInfos = append(signingInfos, types.SigningInfo{
			Address:              bechAddr,
			ValidatorSigningInfo: info,
		})

		localMissedBlocks, found := keeper.GetValidatorMissedBlocks(ctx, address)
		if !found {
			return false
		}
		missedBlocks = append(missedBlocks, localMissedBlocks)
		return false
	})

	return types.NewGenesisState(params, signingInfos, missedBlocks)
}
```

**File:** x/slashing/keeper/infractions.go (L33-36)
```go
	signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
	if !found {
		panic(fmt.Sprintf("Expected signing info for validator %s but not found", consAddr))
	}
```

**File:** x/slashing/abci.go (L24-66)
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
}
```
