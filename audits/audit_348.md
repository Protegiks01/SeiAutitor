## Title
Genesis Validators with Bonded Status Cause Network Panic Due to Missing Signing Info

## Summary
When validators are initialized in genesis state with `Status = Bonded`, the `AfterValidatorBonded` hook is never called, resulting in missing `ValidatorSigningInfo` records. When the slashing module's `BeginBlocker` attempts to track validator signatures, it panics with "Expected signing info for validator but not found", causing total network shutdown.

## Impact
High

## Finding Description

**Location:** 
- Hook implementation: [1](#0-0) 
- State transition logic: [2](#0-1) 
- Panic location: [3](#0-2) 
- Genesis initialization: [4](#0-3) 

**Intended Logic:** 
When a validator becomes bonded, the `AfterValidatorBonded` hook should be called to create the `ValidatorSigningInfo` record. This signing info is essential for the slashing module to track validator liveness and missed blocks. The hook checks if signing info exists and creates it if missing. [1](#0-0) 

**Actual Logic:** 
During genesis initialization, when validators are created with `Status = Bonded`, the staking module's `ApplyAndReturnValidatorSetUpdates` function is called. [5](#0-4)  This function iterates through validators and only calls state transition functions (which trigger hooks) for validators transitioning from `Unbonded` or `Unbonding` to `Bonded`. For validators already in `Bonded` status, it does nothing - no state transition occurs and no hook is called. [6](#0-5) 

The slashing module's `InitGenesis` only sets signing info from the provided genesis data and does not create signing info for validators that lack it. [7](#0-6) 

**Exploit Scenario:**
1. An operator creates a genesis file with validators that have `Status: stakingtypes.Bonded` (as demonstrated in test helpers). [8](#0-7) 
2. The slashing genesis state either has no signing info or is missing signing info for these bonded validators
3. During `InitChain`, staking `InitGenesis` runs first, setting validators with bonded status but not triggering the `AfterValidatorBonded` hook
4. Slashing `InitGenesis` runs after, but doesn't create missing signing info
5. When `FinalizeBlock` is called for the first block, it triggers `BeginBlock`
6. The slashing `BeginBlocker` calls `HandleValidatorSignatureConcurrent` for each validator vote [9](#0-8) 
7. This function attempts to fetch signing info and panics if not found: [3](#0-2) 
8. The entire chain halts with a panic

**Security Failure:** 
This breaks the availability property of the system. The chain cannot process any blocks because the panic in `BeginBlocker` prevents block finalization. This is a total denial of service causing network shutdown.

## Impact Explanation

This vulnerability causes **total network shutdown**. Once the chain is initialized with bonded validators missing signing info, the very first block processing will panic and halt all nodes. 

- **Affected processes**: Block production and finalization completely stops
- **Severity**: All validator nodes crash simultaneously on the same panic, preventing any blocks from being produced or finalized
- **System-wide impact**: The chain cannot recover without a hard fork to fix the genesis state or code

This matters critically because:
1. The network becomes completely non-functional - no transactions can be confirmed
2. All nodes experience identical panics, so there's no subset that can continue operating
3. Recovery requires coordinated manual intervention (hard fork) by all validators

## Likelihood Explanation

**Who can trigger it:**
This requires operators/validators setting up a new network or performing chain upgrades. It's not exploitable by unprivileged external attackers, but it's a critical bug that can be accidentally triggered during legitimate operations.

**Conditions required:**
1. Genesis file creation where validators are initialized with `Bonded` status
2. Missing or incomplete slashing genesis state (no signing info for those validators)
3. This pattern exists in the codebase's own test utilities [10](#0-9) 

**Frequency:**
- Can occur during testnet setup using patterns similar to `SetupWithGenesisValSet`
- Can occur during state exports/imports if signing info is not properly exported
- Can occur during chain upgrades or migrations
- While not exploitable by external attackers, it's a realistic scenario during normal operational procedures

## Recommendation

Modify the staking module's `InitGenesis` function to explicitly call `AfterValidatorBonded` for all validators in `Bonded` status during non-exported genesis initialization:

```go
// In x/staking/genesis.go, after setting validators (around line 64)
if !data.Exported {
    for _, validator := range data.Validators {
        if validator.IsBonded() {
            consAddr, err := validator.GetConsAddr()
            if err != nil {
                panic(err)
            }
            keeper.AfterValidatorBonded(ctx, consAddr, validator.GetOperator())
        }
    }
}
```

Alternatively, add validation in slashing `InitGenesis` to verify signing info exists for all bonded validators and create it if missing, or validate during genesis state validation that all bonded validators have corresponding signing info.

## Proof of Concept

**File:** `x/slashing/genesis_panic_test.go` (new file)

**Setup:**
1. Create a genesis state with a validator having `Status = Bonded`
2. Do not include signing info for this validator in slashing genesis state
3. Initialize the chain with `InitChain`
4. Create a vote from this validator

**Trigger:**
Call `BeginBlocker` with the vote information from the bonded validator

**Observation:**
The test should panic with message "Expected signing info for validator %s but not found"

```go
func TestGenesisValidatorBondedWithoutSigningInfoPanics(t *testing.T) {
    // Setup app
    app, genesisState := setup(true, 5)
    
    // Create a validator with Bonded status
    pk := ed25519.GenPrivKey().PubKey()
    pkAny, _ := codectypes.NewAnyWithValue(pk)
    validator := stakingtypes.Validator{
        OperatorAddress:   sdk.ValAddress(pk.Address()).String(),
        ConsensusPubkey:   pkAny,
        Status:            stakingtypes.Bonded,
        Tokens:            sdk.NewInt(1000000),
        DelegatorShares:   sdk.OneDec(),
    }
    
    // Set staking genesis with bonded validator
    stakingGenesis := stakingtypes.NewGenesisState(
        stakingtypes.DefaultParams(), 
        []stakingtypes.Validator{validator}, 
        []stakingtypes.Delegation{},
    )
    genesisState[stakingtypes.ModuleName] = app.AppCodec().MustMarshalJSON(stakingGenesis)
    
    // Set slashing genesis WITHOUT signing info for this validator
    slashingGenesis := slashingtypes.DefaultGenesisState()
    genesisState[slashingtypes.ModuleName] = app.AppCodec().MustMarshalJSON(slashingGenesis)
    
    stateBytes, _ := json.MarshalIndent(genesisState, "", " ")
    
    // Initialize chain
    app.InitChain(context.Background(), &abci.RequestInitChain{
        AppStateBytes: stateBytes,
    })
    
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Create vote from bonded validator
    vote := abci.VoteInfo{
        Validator: abci.Validator{
            Address: pk.Address(),
            Power:   100,
        },
        SignedLastBlock: true,
    }
    
    req := abci.RequestBeginBlock{
        LastCommitInfo: abci.LastCommitInfo{
            Votes: []abci.VoteInfo{vote},
        },
    }
    
    // This should panic with "Expected signing info for validator but not found"
    require.Panics(t, func() {
        slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    })
}
```

This test demonstrates that when a validator is bonded at genesis without signing info, the slashing `BeginBlocker` panics, causing network shutdown.

### Citations

**File:** x/slashing/keeper/hooks.go (L12-26)
```go
func (k Keeper) AfterValidatorBonded(ctx sdk.Context, address sdk.ConsAddress, _ sdk.ValAddress) {
	// Update the signing info start height or create a new signing info
	_, found := k.GetValidatorSigningInfo(ctx, address)
	if !found {
		signingInfo := types.NewValidatorSigningInfo(
			address,
			ctx.BlockHeight(),
			0,
			time.Unix(0, 0),
			false,
			0,
		)
		k.SetValidatorSigningInfo(ctx, address, signingInfo)
	}
}
```

**File:** x/staking/keeper/val_state_change.go (L143-161)
```go
		// apply the appropriate state change if necessary
		switch {
		case validator.IsUnbonded():
			validator, err = k.unbondedToBonded(ctx, validator)
			if err != nil {
				return
			}
			amtFromNotBondedToBonded = amtFromNotBondedToBonded.Add(validator.GetTokens())
		case validator.IsUnbonding():
			validator, err = k.unbondingToBonded(ctx, validator)
			if err != nil {
				return
			}
			amtFromNotBondedToBonded = amtFromNotBondedToBonded.Add(validator.GetTokens())
		case validator.IsBonded():
			// no state change
		default:
			panic("unexpected validator status")
		}
```

**File:** x/slashing/keeper/infractions.go (L33-36)
```go
	signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
	if !found {
		panic(fmt.Sprintf("Expected signing info for validator %s but not found", consAddr))
	}
```

**File:** x/staking/genesis.go (L39-64)
```go
	for _, validator := range data.Validators {
		keeper.SetValidator(ctx, validator)

		// Manually set indices for the first time
		keeper.SetValidatorByConsAddr(ctx, validator)
		keeper.SetValidatorByPowerIndex(ctx, validator)

		// Call the creation hook if not exported
		if !data.Exported {
			keeper.AfterValidatorCreated(ctx, validator.GetOperator())
		}

		// update timeslice if necessary
		if validator.IsUnbonding() {
			keeper.InsertUnbondingValidatorQueue(ctx, validator)
		}

		switch validator.GetStatus() {
		case types.Bonded:
			bondedTokens = bondedTokens.Add(validator.GetTokens())
		case types.Unbonding, types.Unbonded:
			notBondedTokens = notBondedTokens.Add(validator.GetTokens())
		default:
			panic("invalid validator status")
		}
	}
```

**File:** x/staking/genesis.go (L149-161)
```go
	} else {
		var err error
		legacyUpdates, err := keeper.ApplyAndReturnValidatorSetUpdates(ctx)
		if err != nil {
			log.Fatal(err)
		}
		res = utils.Map(legacyUpdates, func(v abci.ValidatorUpdate) abci.ValidatorUpdate {
			return abci.ValidatorUpdate{
				PubKey: v.PubKey,
				Power:  v.Power,
			}
		})
	}
```

**File:** x/slashing/genesis.go (L24-30)
```go
	for _, info := range data.SigningInfos {
		address, err := sdk.ConsAddressFromBech32(info.Address)
		if err != nil {
			panic(err)
		}
		keeper.SetValidatorSigningInfo(ctx, address, info.ValidatorSigningInfo)
	}
```

**File:** simapp/test_helpers.go (L93-166)
```go
func SetupWithGenesisValSet(t *testing.T, valSet *tmtypes.ValidatorSet, genAccs []authtypes.GenesisAccount, balances ...banktypes.Balance) *SimApp {
	app, genesisState := setup(true, 5)
	// set genesis accounts
	authGenesis := authtypes.NewGenesisState(authtypes.DefaultParams(), genAccs)
	genesisState[authtypes.ModuleName] = app.AppCodec().MustMarshalJSON(authGenesis)

	validators := make([]stakingtypes.Validator, 0, len(valSet.Validators))
	delegations := make([]stakingtypes.Delegation, 0, len(valSet.Validators))

	bondAmt := sdk.NewInt(1000000)

	for _, val := range valSet.Validators {
		pk, err := cryptocodec.FromTmPubKeyInterface(val.PubKey)
		require.NoError(t, err)
		pkAny, err := codectypes.NewAnyWithValue(pk)
		require.NoError(t, err)
		validator := stakingtypes.Validator{
			OperatorAddress:   sdk.ValAddress(val.Address).String(),
			ConsensusPubkey:   pkAny,
			Jailed:            false,
			Status:            stakingtypes.Bonded,
			Tokens:            bondAmt,
			DelegatorShares:   sdk.OneDec(),
			Description:       stakingtypes.Description{},
			UnbondingHeight:   int64(0),
			UnbondingTime:     time.Unix(0, 0).UTC(),
			Commission:        stakingtypes.NewCommission(sdk.ZeroDec(), sdk.ZeroDec(), sdk.ZeroDec()),
			MinSelfDelegation: sdk.ZeroInt(),
		}
		validators = append(validators, validator)
		delegations = append(delegations, stakingtypes.NewDelegation(genAccs[0].GetAddress(), val.Address.Bytes(), sdk.OneDec()))

	}
	// set validators and delegations
	stakingGenesis := stakingtypes.NewGenesisState(stakingtypes.DefaultParams(), validators, delegations)
	genesisState[stakingtypes.ModuleName] = app.AppCodec().MustMarshalJSON(stakingGenesis)

	totalSupply := sdk.NewCoins()
	for _, b := range balances {
		// add genesis acc tokens and delegated tokens to total supply
		totalSupply = totalSupply.Add(b.Coins.Add(sdk.NewCoin(sdk.DefaultBondDenom, bondAmt))...)
	}

	// add bonded amount to bonded pool module account
	balances = append(balances, banktypes.Balance{
		Address: authtypes.NewModuleAddress(stakingtypes.BondedPoolName).String(),
		Coins:   sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, bondAmt)},
	})

	// update total supply
	bankGenesis := banktypes.NewGenesisState(banktypes.DefaultGenesisState().Params, balances, totalSupply, []banktypes.Metadata{}, []banktypes.WeiBalance{})
	genesisState[banktypes.ModuleName] = app.AppCodec().MustMarshalJSON(bankGenesis)

	stateBytes, err := json.MarshalIndent(genesisState, "", " ")
	require.NoError(t, err)

	// init chain will set the validator set and initialize the genesis accounts
	app.InitChain(
		context.Background(), &abci.RequestInitChain{
			Validators:      []abci.ValidatorUpdate{},
			ConsensusParams: DefaultConsensusParams,
			AppStateBytes:   stateBytes,
		},
	)

	// commit genesis changes
	app.Commit(context.Background())
	app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
		Height:             app.LastBlockHeight() + 1,
		Hash:               app.LastCommitID().Hash,
		NextValidatorsHash: valSet.Hash(),
	})

	return app
```

**File:** x/slashing/abci.go (L41-41)
```go
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```
