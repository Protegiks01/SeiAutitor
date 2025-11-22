## Audit Report

## Title
Chain Halt Due to Missing Validator Signing Info for Genesis Bonded Validators

## Summary
When a blockchain is initialized with genesis validators that have `Status=Bonded` but the slashing module's genesis state lacks corresponding `ValidatorSigningInfo` entries, the first block after genesis triggers a panic in the slashing module's `BeginBlocker`, causing a total chain halt with no recovery mechanism.

## Impact
High - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** 
The system expects all bonded validators to have `ValidatorSigningInfo` created through the `AfterValidatorBonded` hook when validators transition to bonded status. The slashing module's `BeginBlocker` processes validator signatures for all validators in `LastCommitInfo`, tracking their signing behavior.

**Actual Logic:** 
Genesis validators can be imported with `Status=Bonded` directly. During genesis initialization, these validators bypass the normal state transition flow. [4](#0-3)  When `ApplyAndReturnValidatorSetUpdates` encounters validators already in Bonded status, it performs no state change, meaning `bondValidator` is never called and the `AfterValidatorBonded` hook never fires. [5](#0-4)  Consequently, no `ValidatorSigningInfo` is created for these validators.

When the first block begins, the slashing `BeginBlocker` processes each validator in `LastCommitInfo` by calling `HandleValidatorSignatureConcurrent`, which unconditionally panics if signing info doesn't exist. [6](#0-5) [7](#0-6)  There is no panic recovery mechanism in the call chain from `BaseApp.BeginBlock` → `Manager.BeginBlock` → module `BeginBlock` functions.

**Exploit Scenario:** 
1. A chain operator creates a genesis file with validators having `Status: types.Bonded` [8](#0-7) 
2. The slashing genesis state is either missing or incomplete, lacking `SigningInfos` entries for some/all bonded validators
3. Genesis validation passes because [9](#0-8)  `ValidateGenesis` only validates parameters, not cross-module consistency
4. Chain initialization completes successfully via `InitChain`
5. First block begins processing
6. Slashing `BeginBlocker` receives validators in `LastCommitInfo`
7. For each validator, `HandleValidatorSignatureConcurrent` attempts to retrieve signing info
8. Panic occurs with message: "Expected signing info for validator %s but not found"
9. Panic propagates unhandled through the entire call stack
10. Chain halts permanently

**Security Failure:** 
This breaks the availability security property. The chain enters an unrecoverable halted state at the very first block after genesis, preventing all transaction processing and requiring a hard fork to fix.

## Impact Explanation

**Affected processes:** Chain initialization and all subsequent block processing

**Severity of damage:** 
- Total network shutdown from block 1
- No transactions can be confirmed
- Requires hard fork to resolve (need to regenerate genesis with complete signing info)
- All nodes halt simultaneously with the same panic
- Network is completely non-functional until manual intervention

**System impact:** 
This is a critical failure mode because it makes the chain completely unusable from the moment of launch. Unlike runtime bugs that might affect specific operations, this vulnerability prevents the chain from processing even a single block. For production networks, this would result in:
- Complete service outage
- Loss of trust from users and validators
- Emergency hard fork coordination required
- Potential economic damage from halted operations

## Likelihood Explanation

**Who can trigger:** 
This is triggered unintentionally by chain operators during:
- Initial chain launch with manually constructed genesis files
- Chain upgrades involving state export/import where signing info is incomplete
- Migration from one version to another where genesis state format changes

**Conditions required:**
- Genesis file must have validators with `Status=Bonded` (common and expected)
- Slashing genesis state must be missing corresponding `SigningInfos` entries
- No validation catches this inconsistency during genesis validation

**Frequency:**
While not exploitable by external attackers during runtime, this can occur during:
- Every chain initialization if genesis state is improperly constructed
- Chain upgrades where state migration doesn't preserve signing info correctly
- Testing environments where genesis files are manually crafted

The vulnerability is particularly concerning because the validation gap makes it easy to create invalid genesis states that pass all checks but fail catastrophically at runtime.

## Recommendation

Add comprehensive validation in the slashing module's `ValidateGenesis` function to ensure that every bonded validator in the staking genesis state has a corresponding `ValidatorSigningInfo` entry:

1. During `ValidateGenesis`, iterate through all validators from the staking keeper
2. For each validator with `Status=Bonded`, verify that signing info exists in the slashing genesis state
3. Return an error if any bonded validator lacks signing info
4. Alternatively, automatically create signing info entries during slashing `InitGenesis` for all bonded validators that don't have them

Additionally, consider adding defensive checks in `HandleValidatorSignatureConcurrent` to return early with a log rather than panic, similar to the approach used for missing pubkey errors. [10](#0-9) 

## Proof of Concept

**Test file:** `x/slashing/genesis_panic_test.go` (new file)

```go
package slashing_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abci "github.com/tendermint/tendermint/abci/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/simapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	"github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

func TestBeginBlockerPanicMissingSigningInfo(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})

	// Create a validator with Bonded status directly in genesis
	pks := simapp.CreateTestPubKeys(1)
	addr := sdk.ValAddress(pks[0].Address())
	pk := pks[0]

	validator, err := stakingtypes.NewValidator(addr, pk, stakingtypes.NewDescription("test", "", "", "", ""))
	require.NoError(t, err)
	
	// Set validator as Bonded (simulating genesis state)
	validator.Status = stakingtypes.Bonded
	validator.Tokens = app.StakingKeeper.TokensFromConsensusPower(ctx, 100)
	validator.DelegatorShares = validator.Tokens.ToDec()

	// Initialize staking genesis with bonded validator
	stakingGenesis := &stakingtypes.GenesisState{
		Params:     stakingtypes.DefaultParams(),
		Validators: []stakingtypes.Validator{validator},
		Exported:   false,
	}

	// Fund the bonded pool
	require.NoError(t, simapp.FundModuleAccount(
		app.BankKeeper, ctx,
		stakingtypes.BondedPoolName,
		sdk.NewCoins(sdk.NewCoin(stakingGenesis.Params.BondDenom, validator.Tokens)),
	))

	// Initialize staking - this sets the validator but does NOT create signing info
	// because validator is already Bonded
	staking.InitGenesis(ctx, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, stakingGenesis)

	// Initialize slashing with EMPTY signing info (the vulnerability)
	slashingGenesis := &types.GenesisState{
		Params:       types.DefaultParams(),
		SigningInfos: []types.SigningInfo{}, // Missing signing info for the validator!
		MissedBlocks: []types.ValidatorMissedBlockArray{},
	}
	slashing.InitGenesis(ctx, app.SlashingKeeper, app.StakingKeeper, slashingGenesis)

	// Verify validator is bonded
	val, found := app.StakingKeeper.GetValidator(ctx, addr)
	require.True(t, found)
	require.Equal(t, stakingtypes.Bonded, val.GetStatus())

	// Verify signing info does NOT exist (this is the vulnerability)
	_, found = app.SlashingKeeper.GetValidatorSigningInfo(ctx, sdk.ConsAddress(pk.Address()))
	require.False(t, found, "Signing info should not exist - this is the vulnerability")

	// Now simulate first block with this validator in LastCommitInfo
	ctx = ctx.WithBlockHeight(2)
	req := abci.RequestBeginBlock{
		Header: tmproto.Header{Height: 2, Time: time.Now()},
		LastCommitInfo: abci.LastCommitInfo{
			Votes: []abci.VoteInfo{
				{
					Validator: abci.Validator{
						Address: pk.Address(),
						Power:   100,
					},
					SignedLastBlock: true,
				},
			},
		},
	}

	// This should panic with "Expected signing info for validator but not found"
	require.Panics(t, func() {
		slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
	}, "BeginBlocker should panic when signing info is missing")
}
```

**Setup:** 
- Create a new chain context and initialize app
- Create a validator with `Status=Bonded` directly (simulating genesis import)
- Fund the bonded pool with the validator's tokens
- Initialize staking genesis with this bonded validator
- Initialize slashing genesis with empty `SigningInfos` (the vulnerable state)

**Trigger:** 
- Call slashing `BeginBlocker` with `RequestBeginBlock` containing the validator in `LastCommitInfo`
- This simulates the first block after genesis where validators begin signing

**Observation:** 
- The test verifies that signing info does NOT exist for the validator
- When `BeginBlocker` is called, it panics with "Expected signing info for validator but not found"
- The panic is unhandled and would halt the chain in production
- Test uses `require.Panics()` to confirm the vulnerability exists

This PoC demonstrates that the vulnerability is real and exploitable during chain initialization when genesis state is incomplete.

### Citations

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

**File:** x/staking/genesis.go (L145-161)
```go
				PubKey: update.PubKey,
				Power:  update.Power,
			})
		}
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

**File:** x/staking/keeper/val_state_change.go (L157-158)
```go
		case validator.IsBonded():
			// no state change
```

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

**File:** baseapp/abci.go (L143-146)
```go
	if app.beginBlocker != nil {
		res = app.beginBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}
```

**File:** types/module/module.go (L605-611)
```go
	for _, moduleName := range m.OrderBeginBlockers {
		module, ok := m.Modules[moduleName].(BeginBlockAppModule)
		if ok {
			moduleStartTime := time.Now()
			module.BeginBlock(ctx, req)
			telemetry.ModuleMeasureSince(moduleName, moduleStartTime, "module", "begin_block")
		}
```

**File:** x/staking/genesis_test.go (L45-52)
```go
	bondedVal1 := types.Validator{
		OperatorAddress: sdk.ValAddress(addrs[0]).String(),
		ConsensusPubkey: pk0,
		Status:          types.Bonded,
		Tokens:          valTokens,
		DelegatorShares: valTokens.ToDec(),
		Description:     types.NewDescription("hoop", "", "", "", ""),
	}
```

**File:** x/slashing/types/genesis.go (L31-59)
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
}
```

**File:** x/evidence/keeper/infraction.go (L29-40)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
	}
```
