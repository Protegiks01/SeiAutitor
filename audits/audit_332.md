## Title
Genesis Import Fails to Validate Signing Info Completeness Leading to Network-Wide Panic on First Block

## Summary
The slashing module's `InitGenesis` function does not validate that signing info exists for all validators imported from the staking module. When the first block is processed after genesis, if any bonded validator lacks signing info, `HandleValidatorSignatureConcurrent` panics, causing total network shutdown across all nodes. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: [2](#0-1) 
- Panic trigger: [3](#0-2) 
- Invocation point: [4](#0-3) 

**Intended Logic:** 
During genesis import, the slashing module should ensure that every validator present in the staking module has corresponding signing info. The signing info tracks validator uptime and is critical for downtime slashing logic. The system expects this invariant: `∀ validator ∈ staking_validators → ∃ signing_info ∈ slashing_signing_infos`.

**Actual Logic:** 
The `InitGenesis` function iterates through validators from the staking keeper and adds their pubkeys, then blindly imports signing info from genesis data without validation. It never checks whether signing info exists for all validators. [5](#0-4) 

The validation function only checks parameter bounds, not data completeness: [6](#0-5) 

**Exploit Scenario:**
1. An operator creates or modifies a genesis file where validators exist in the staking module state but corresponding signing info entries are missing or incomplete in the slashing module state
2. Multiple nodes start using this genesis file
3. During `InitGenesis`, the staking module initializes validators first (per module initialization order): [7](#0-6) 
4. The slashing module's `InitGenesis` runs next, adding pubkeys for all validators but importing incomplete signing info
5. When `BeginBlocker` executes for the first block, it processes validator votes concurrently
6. For each validator vote, `HandleValidatorSignatureConcurrent` is called: [8](#0-7) 
7. This function attempts to retrieve signing info and panics if not found: [3](#0-2) 
8. All nodes panic simultaneously, causing total network shutdown

**Security Failure:** 
This breaks the availability invariant. The system assumes genesis data is well-formed but lacks defensive validation. A single missing signing info entry causes a panic that cascades across all network nodes, creating a denial-of-service condition where no blocks can be produced.

## Impact Explanation

**Affected Assets/Processes:**
- Network availability: All nodes crash simultaneously
- Transaction processing: The network cannot process any transactions
- Block production: No blocks can be produced after genesis
- Network liveness: Complete halt of the blockchain

**Severity:**
This is a total network shutdown scenario. Every validator node and full node will panic when attempting to process the first block. The network becomes completely inoperable until:
1. The genesis file is corrected to include all missing signing info
2. A coordinated restart is performed across all nodes
3. Potentially requires a new genesis file distribution

**Why It Matters:**
This vulnerability can be triggered during legitimate operations like chain upgrades, genesis exports/imports, or testnet setups. It doesn't require malicious intent - a simple error in genesis file preparation causes catastrophic failure. The impact matches the "High: Network not being able to confirm new transactions (total network shutdown)" severity category.

## Likelihood Explanation

**Who Can Trigger:**
- Anyone preparing or modifying genesis files (validators, chain operators, governance participants during upgrades)
- Accidental trigger during chain migrations, exports, or validator set changes
- No special privileges needed once a malformed genesis file is distributed

**Conditions Required:**
- Genesis file has validators in staking module without corresponding signing info in slashing module
- Can occur during: chain initialization, chain upgrades, genesis export/import, or manual genesis modifications
- Happens during normal operation (first block after genesis)

**Frequency:**
- High risk during chain upgrades or mainnet launches
- Can happen with any genesis file that wasn't properly validated
- Once triggered, affects 100% of network nodes simultaneously
- Relatively easy to accidentally create this condition when manually constructing or modifying genesis files

## Recommendation

Add validation in `InitGenesis` to ensure signing info exists for all bonded validators:

```go
func InitGenesis(ctx sdk.Context, keeper keeper.Keeper, stakingKeeper types.StakingKeeper, data *types.GenesisState) {
    // Build map of signing info for quick lookup
    signingInfoMap := make(map[string]bool)
    for _, info := range data.SigningInfos {
        signingInfoMap[info.Address] = true
    }
    
    // Add pubkeys and validate signing info exists
    stakingKeeper.IterateValidators(ctx,
        func(index int64, validator stakingtypes.ValidatorI) bool {
            consPk, err := validator.ConsPubKey()
            if err != nil {
                panic(err)
            }
            keeper.AddPubkey(ctx, consPk)
            
            // Validate signing info exists for bonded validators
            consAddr, err := validator.GetConsAddr()
            if err != nil {
                panic(err)
            }
            if validator.IsBonded() && !signingInfoMap[consAddr.String()] {
                panic(fmt.Sprintf("missing signing info for bonded validator %s", consAddr))
            }
            return false
        },
    )
    
    // Continue with existing logic...
}
```

Alternatively, auto-create missing signing info with safe defaults during `InitGenesis`.

## Proof of Concept

**File:** `x/slashing/genesis_test.go`

**Test Function:** `TestMissingSigningInfoPanicsOnFirstBlock`

```go
func TestMissingSigningInfoPanicsOnFirstBlock(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 0})
    
    // Create validator keys
    pks := simapp.CreateTestPubKeys(2)
    simapp.AddTestAddrsFromPubKeys(app, ctx, pks, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    // Create two validators
    addr1, pk1 := sdk.ValAddress(pks[0].Address()), pks[0]
    addr2, pk2 := sdk.ValAddress(pks[1].Address()), pks[1]
    
    tstaking.CreateValidatorWithValPower(addr1, pk1, 100, true)
    tstaking.CreateValidatorWithValPower(addr2, pk2, 100, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Export genesis with both validators
    stakingGenesis := staking.ExportGenesis(ctx, app.StakingKeeper)
    slashingGenesis := slashing.ExportGenesis(ctx, app.SlashingKeeper)
    
    // Create malformed genesis: remove signing info for validator 2
    // This simulates a genesis file where signing info is incomplete
    malformedSlashingGenesis := types.GenesisState{
        Params:       slashingGenesis.Params,
        SigningInfos: slashingGenesis.SigningInfos[:1], // Only keep first validator's info
        MissedBlocks: slashingGenesis.MissedBlocks[:1],
    }
    
    // Create new app and initialize with malformed genesis
    app2 := simapp.Setup(false)
    ctx2 := app2.BaseApp.NewContext(false, tmproto.Header{Height: 0})
    
    // Initialize staking module (creates validators)
    staking.InitGenesis(ctx2, app2.StakingKeeper, app2.AccountKeeper, app2.BankKeeper, stakingGenesis)
    
    // Initialize slashing module with incomplete signing info
    // This should ideally fail here, but currently it doesn't validate
    slashing.InitGenesis(ctx2, app2.SlashingKeeper, app2.StakingKeeper, &malformedSlashingGenesis)
    
    // Verify validator 2 has no signing info
    consAddr2 := sdk.ConsAddress(pk2.Address())
    _, found := app2.SlashingKeeper.GetValidatorSigningInfo(ctx2, consAddr2)
    require.False(t, found, "Validator 2 should not have signing info")
    
    // Now attempt to process first block with both validators voting
    // This should panic because validator 2 has no signing info
    ctx2 = ctx2.WithBlockHeight(1)
    req := abci.RequestBeginBlock{
        LastCommitInfo: abci.LastCommitInfo{
            Votes: []abci.VoteInfo{
                {
                    Validator: abci.Validator{
                        Address: pk1.Address(),
                        Power:   100,
                    },
                    SignedLastBlock: true,
                },
                {
                    Validator: abci.Validator{
                        Address: pk2.Address(), // This validator has no signing info!
                        Power:   100,
                    },
                    SignedLastBlock: true,
                },
            },
        },
    }
    
    // This should panic with "Expected signing info for validator ... but not found"
    require.Panics(t, func() {
        slashing.BeginBlocker(ctx2, req, app2.SlashingKeeper)
    }, "BeginBlocker should panic when signing info is missing for a validator")
}
```

**Setup:** Creates two validators in the staking module, exports genesis, then constructs a malformed genesis with signing info for only one validator.

**Trigger:** Calls `BeginBlocker` with votes from both validators, where the second validator lacks signing info.

**Observation:** The test expects a panic with message "Expected signing info for validator ... but not found", confirming the vulnerability causes network-wide crashes.

This PoC demonstrates that the missing validation allows malformed genesis files to pass initialization, but causes immediate panic when the first block is processed, resulting in total network shutdown.

### Citations

**File:** x/slashing/genesis.go (L10-41)
```go
// InitGenesis initialize default parameters
// and the keeper's address to pubkey map
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

**File:** x/slashing/keeper/infractions.go (L33-36)
```go
	signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
	if !found {
		panic(fmt.Sprintf("Expected signing info for validator %s but not found", consAddr))
	}
```

**File:** x/slashing/abci.go (L36-51)
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
	wg.Wait()
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

**File:** simapp/app.go (L386-392)
```go
	app.mm.SetOrderInitGenesis(
		capabilitytypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName, distrtypes.ModuleName, stakingtypes.ModuleName,
		slashingtypes.ModuleName, govtypes.ModuleName, minttypes.ModuleName, crisistypes.ModuleName,
		genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName,
		paramstypes.ModuleName, upgradetypes.ModuleName, vestingtypes.ModuleName, acltypes.ModuleName,
	)
```
