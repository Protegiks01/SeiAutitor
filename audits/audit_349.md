# Audit Report

## Title
Missing Invariant Check Allows Genesis State with Bonded Validators Without Signing Info Leading to Chain Halt

## Summary
The slashing module lacks invariant checks to ensure every bonded validator has corresponding signing info, and the genesis validation does not verify this relationship. This allows an invalid genesis state where bonded validators exist without signing info, causing the chain to panic in the first BeginBlock when attempting to process validator signatures.

## Impact
High

## Finding Description

**Location:** The vulnerability spans multiple components:
- Slashing module invariant registration: [1](#0-0) 
- Genesis validation: [2](#0-1) 
- Genesis initialization: [3](#0-2) 
- BeginBlock signature processing: [4](#0-3) 

**Intended Logic:** Every bonded validator should have corresponding `ValidatorSigningInfo` created when they become bonded through the `AfterValidatorBonded` hook. [5](#0-4)  Genesis state should be validated to ensure this invariant holds.

**Actual Logic:** 
1. The slashing module's `RegisterInvariants` is empty - no invariants check the signing info relationship
2. When validators are marked as `Bonded` in genesis state, they bypass the state transition hooks because `ApplyAndReturnValidatorSetUpdates` doesn't call `bondValidator` for already-bonded validators [6](#0-5) 
3. The slashing module's `InitGenesis` only loads signing info from the genesis data but doesn't create missing entries for bonded validators
4. `ValidateGenesis` only checks parameter validity, not the validator-to-signing-info relationship
5. During `BeginBlocker`, `HandleValidatorSignatureConcurrent` expects all validators to have signing info and panics if not found

**Exploit Scenario:**
1. Create a genesis state with bonded validators in the staking module
2. Omit or only partially include signing info for these validators in the slashing module's genesis data
3. The `ValidateGenesis` passes because it only validates parameters
4. Initialize the chain with this genesis state
5. In the first block's `BeginBlocker`, when processing validator signatures via `HandleValidatorSignatureConcurrent`, the function panics when it cannot find signing info for a bonded validator

**Security Failure:** This breaks the liveness property of the blockchain. The panic in `BeginBlocker` causes a total chain halt at block 1, preventing any transactions from being processed. This is a consensus failure resulting in network shutdown.

## Impact Explanation

**Affected processes:** Network availability and consensus operation

**Severity:** The entire blockchain network halts immediately after genesis, unable to process any blocks or transactions. All nodes panic with the same error during BeginBlock, causing total network shutdown.

**Why this matters:** This vulnerability allows an invalid genesis configuration to be accepted and deployed, resulting in a dead-on-arrival blockchain that requires a complete re-genesis to fix. For a live network, if such a state could be reached through other means (though genesis is the most likely vector), it would cause immediate and complete network failure. This falls under the "Network not being able to confirm new transactions (total network shutdown)" impact category.

## Likelihood Explanation

**Who can trigger:** This primarily affects chain initialization. Whoever generates and distributes the genesis file can (intentionally or accidentally) create this condition. For existing chains, this is less likely but could theoretically occur if genesis state is exported and re-imported with missing data.

**Conditions required:** 
- Genesis state must have at least one bonded validator in the staking module
- That validator must not have corresponding signing info in the slashing module's genesis data
- The genesis validation passes (which it will, since it doesn't check this relationship)

**Frequency:** Low under normal circumstances because most genesis generation tools properly initialize all required state. However, the lack of validation means human error or tooling bugs could easily introduce this issue. Once triggered, the impact is immediate and total.

## Recommendation

Implement the following fixes:

1. **Add Invariant Check:** Create an invariants.go file in the slashing keeper with a function that verifies:
   - Every bonded validator has corresponding signing info
   - Every signing info entry corresponds to an existing validator

2. **Enhance Genesis Validation:** Modify `ValidateGenesis` in the slashing module to cross-check with the staking keeper during InitGenesis to ensure all bonded validators have signing info

3. **Add Auto-Creation in InitGenesis:** Modify slashing `InitGenesis` to iterate through all bonded validators from the staking keeper and create signing info for any that are missing, setting appropriate start heights

4. **Register Invariants:** Implement the `RegisterInvariants` method to actually register the invariant checks instead of leaving it empty

## Proof of Concept

**File:** Add to `x/slashing/genesis_test.go` (new file)

**Test Function:** `TestGenesisValidatorWithoutSigningInfoCausesPanic`

**Setup:**
1. Create a test app with default genesis state
2. Create a validator with bonded status in the staking module's genesis
3. Intentionally omit that validator's signing info from the slashing module's genesis
4. Initialize the chain with this malformed genesis state
5. Attempt to process the first BeginBlock with the validator's vote

**Trigger:**
Call `BeginBlocker` with a vote from the validator that lacks signing info

**Observation:**
The test should observe that `BeginBlocker` panics with the message "Expected signing info for validator %s but not found" when it tries to call `HandleValidatorSignatureConcurrent` for the validator without signing info. [7](#0-6) 

The panic occurs because the code explicitly checks for signing info existence and panics if not found, rather than handling it gracefully. This demonstrates that the lack of invariant checking and genesis validation allows an invalid state that causes immediate chain failure.

### Citations

**File:** x/slashing/module.go (L130-130)
```go
func (am AppModule) RegisterInvariants(_ sdk.InvariantRegistry) {}
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

**File:** x/slashing/keeper/infractions.go (L32-36)
```go
	// fetch signing info
	signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
	if !found {
		panic(fmt.Sprintf("Expected signing info for validator %s but not found", consAddr))
	}
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

**File:** x/staking/keeper/val_state_change.go (L157-158)
```go
		case validator.IsBonded():
			// no state change
```
