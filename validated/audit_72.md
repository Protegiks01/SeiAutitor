# Audit Report

## Title
Chain Halt Due to Missing Validator Signing Info for Genesis Bonded Validators

## Summary
When a blockchain is initialized with genesis validators that have `Status=Bonded` but the slashing module's genesis state lacks corresponding `ValidatorSigningInfo` entries, the chain halts with an unrecoverable panic at the first block that processes validator signatures, requiring a hard fork to fix.

## Impact
High

## Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Intended logic:** 
All bonded validators should have `ValidatorSigningInfo` entries created through the `AfterValidatorBonded` hook when validators transition to bonded status. The slashing module's `BeginBlocker` expects to find signing info for all validators in `LastCommitInfo`.

**Actual logic:**
Genesis validators can be imported with `Status=Bonded` directly. [3](#0-2)  During genesis initialization, when `ApplyAndReturnValidatorSetUpdates` encounters validators already in Bonded status, it performs no state change - the `bondValidator` function is never called. [4](#0-3)  Consequently, the `AfterValidatorBonded` hook never fires [5](#0-4)  and no `ValidatorSigningInfo` is created.

When BeginBlocker processes validators in `LastCommitInfo`, `HandleValidatorSignatureConcurrent` unconditionally panics if signing info doesn't exist. There is no panic recovery mechanism in the call chain. [6](#0-5) [7](#0-6) 

**Exploitation path:**
1. Chain operator creates genesis file with validators having `Status=Bonded`
2. Slashing genesis state lacks `SigningInfos` entries for these validators
3. Genesis validation passes because `ValidateGenesis` only validates parameters, not cross-module consistency [8](#0-7) 
4. Chain initialization via `InitChain` completes successfully
5. At the first block where validators appear in `LastCommitInfo`, slashing `BeginBlocker` is called
6. `HandleValidatorSignatureConcurrent` attempts to retrieve signing info and panics
7. Panic propagates unhandled through the call stack, halting all nodes simultaneously

**Security guarantee broken:**
This breaks the availability guarantee of the blockchain. The chain enters an unrecoverable halted state, preventing all transaction processing.

## Impact Explanation

This vulnerability causes total network shutdown from the first block that processes validator signatures. The impact includes:

- Complete inability to confirm any transactions
- All validator nodes halt simultaneously with the same panic message
- Requires emergency hard fork with regenerated genesis file to recover
- Complete service outage for the network
- Loss of confidence from users and validators

This is particularly severe because:
- The chain appears to initialize successfully, giving false confidence
- The failure occurs at runtime rather than during validation, making it harder to detect
- No automatic recovery mechanism exists
- The only fix is manual intervention requiring coordination for a hard fork

## Likelihood Explanation

**Who can trigger:**
This is triggered unintentionally by chain operators during:
- Initial chain launch with manually constructed genesis files
- Chain upgrades involving state export/import where signing info is incomplete
- State migration between versions where genesis format changes
- Testing environments with manually crafted genesis files

**Conditions required:**
- Genesis file has validators with `Status=Bonded` (common pattern confirmed in tests)
- Slashing genesis state missing corresponding `SigningInfos` entries
- No validation catches this cross-module inconsistency

**Frequency:**
While not exploitable by external attackers at runtime, this vulnerability is concerning because:
- The validation gap makes it easy to inadvertently create invalid genesis states
- Genesis files are often manually constructed or programmatically generated
- State migration tools may not preserve all cross-module dependencies
- Testing environments frequently use simplified genesis configurations

The fact that genesis validation passes despite the inconsistency significantly increases the likelihood of this occurring in production.

## Recommendation

**Primary fix:** Add cross-module validation in slashing module's `ValidateGenesis` function:

1. Accept a reference to the staking keeper or staking genesis state
2. Iterate through all validators from staking genesis
3. For each validator with `Status=Bonded`, verify corresponding `ValidatorSigningInfo` exists
4. Return validation error if any bonded validator lacks signing info

**Alternative fix:** Automatically create missing signing info during slashing `InitGenesis`:

1. After loading signing info from genesis, query all bonded validators from staking keeper
2. For each bonded validator without signing info, create default `ValidatorSigningInfo` entry
3. This provides defensive initialization rather than failing at runtime

**Additional hardening:** Add defensive checks in `HandleValidatorSignatureConcurrent` to log and return early rather than panic when signing info is missing, similar to the graceful error handling in the evidence keeper. [9](#0-8) 

## Proof of Concept

**Test file:** `x/slashing/genesis_panic_test.go` (new test)

**Setup:**
1. Create chain context with `simapp.Setup(false)`
2. Create validator with `Status=Bonded` directly (simulating genesis import)
3. Initialize staking genesis with this bonded validator
4. Fund bonded pool with validator's tokens
5. Initialize slashing genesis with empty `SigningInfos` array (vulnerable state)
6. Verify validator is bonded and signing info does NOT exist

**Action:**
Call `slashing.BeginBlocker` with `RequestBeginBlock` containing the validator in `LastCommitInfo.Votes`, simulating the first block where validators sign

**Result:**
The function panics with message "Expected signing info for validator %s but not found", demonstrating the unrecoverable chain halt. The test uses `require.Panics()` to confirm the vulnerability exists.

The provided PoC test demonstrates that:
- Genesis state with bonded validators but missing signing info is accepted during initialization
- No validation prevents this invalid state
- When validators appear in `LastCommitInfo`, the chain halts with panic
- The panic is unhandled and would halt all nodes in production

## Notes

This vulnerability represents a critical gap in genesis validation that can cause catastrophic failure at chain initialization. While it requires a configuration error by chain operators, it meets the criteria for a valid HIGH severity finding because:

1. **Matches defined impact:** "Network not being able to confirm new transactions (total network shutdown)" - explicitly listed as HIGH severity
2. **Unrecoverable failure beyond intended authority:** Chain operators intend to launch a functioning chain; the system accepts their configuration as valid (passes genesis validation), but later fails catastrophically
3. **No protective validation:** The cross-module inconsistency is not caught by existing validation
4. **Requires hard fork:** The only recovery mechanism is manual intervention with a new genesis file

The evidence keeper's graceful error handling for similar scenarios (missing pubkeys) demonstrates that defensive error handling is the expected pattern, making the slashing module's unconditional panic a design flaw rather than acceptable behavior.

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
