# Audit Report

## Title
Chain Halt Due to Orphaned Missed Blocks in Genesis State

## Summary
The slashing module's `ValidateGenesis` function fails to validate the consistency between missed blocks and signing info entries. Combined with an implementation that panics instead of using default values (as specified in documentation), this allows genesis files with orphaned missed blocks to cause total network shutdown when affected validators participate in consensus.

## Impact
High

## Finding Description

**Location:**
- Validation gap: [1](#0-0) 
- Independent import without cross-validation: [2](#0-1) 
- Panic trigger: [3](#0-2) 
- Hook bypass mechanism: [4](#0-3) 

**Intended Logic:**
According to the specification [5](#0-4) , the system should use a 0-value default signing info if not present. Genesis validation should enforce the invariant that missed blocks entries only exist for validators with corresponding signing info.

**Actual Logic:**
1. `ValidateGenesis` only validates slashing parameters but does NOT validate the relationship between `MissedBlocks` and `SigningInfos` [1](#0-0) 

2. `InitGenesis` imports signing infos and missed blocks independently without cross-validation [2](#0-1) 

3. When `Exported: true` is set in staking genesis, validator creation hooks are skipped [4](#0-3) , preventing automatic signing info creation via the `AfterValidatorBonded` hook [6](#0-5) 

4. When a validator with orphaned missed blocks participates in consensus, `HandleValidatorSignatureConcurrent` panics [3](#0-2)  instead of using default values as specified

**Exploitation Path:**
1. Genesis file is created with `ValidatorMissedBlockArray` entries but no corresponding `SigningInfo` entries, with `Exported: true` in staking genesis (can occur through manual construction, custom tooling bugs, or merging multiple genesis sources)
2. Genesis validation passes because `ValidateGenesis` only checks parameters
3. Chain operators initialize using `InitGenesis`, importing the orphaned missed blocks
4. When the validator participates in consensus, `BeginBlocker` invokes `HandleValidatorSignatureConcurrent` [7](#0-6) 
5. The function panics with "Expected signing info for validator %s but not found"
6. Entire chain halts due to consensus failure

**Security Guarantee Broken:**
The system fails to maintain the critical invariant that missed blocks can only exist for validators with signing info. The implementation contradicts the specification by panicking instead of using default values.

## Impact Explanation

This vulnerability causes **total network shutdown**, which is explicitly listed in the acceptance criteria as a HIGH severity impact: "Network not being able to confirm new transactions (total network shutdown)."

When the panic occurs in `BeginBlocker` during consensus:
- The entire blockchain network halts immediately
- No new blocks can be produced or transactions confirmed
- The network remains down until all validators coordinate to restart with a corrected genesis file
- Recovery requires complex coordination and potentially a hard fork

This is a consensus-breaking failure that impacts the entire network simultaneously, not an application-level error affecting individual transactions.

## Likelihood Explanation

**Who Can Trigger:**
Genesis file creators during chain launch or network restart, including:
- Participants in multi-party genesis coordination (standard for blockchain launches)
- Those using custom genesis generation tooling
- Anyone manually constructing or merging genesis files

**Required Conditions:**
1. Genesis file with orphaned missed blocks must be used during chain initialization
2. The validator addresses in orphaned missed blocks must participate in consensus
3. `Exported: true` must be set in staking genesis (standard for chain upgrades/restarts)

**Likelihood Assessment:**
This is realistic because:
- Multi-party genesis coordination is standard practice
- The validation gap makes it easy to miss this inconsistency during review
- Genesis files passing `ValidateGenesis` gives false confidence of correctness
- Specification states missing signing info should be handled gracefully, suggesting this edge case was intended to be supported
- Once imported, the issue persists as a "time bomb" until triggered

The specification-implementation mismatch is critical: even a trusted genesis creator following the documented behavior could inadvertently create this state, causing an unrecoverable security failure (total chain halt) beyond their intended authority of setting initial chain state.

## Recommendation

**Fix 1: Add Validation in ValidateGenesis**
Add cross-validation in `x/slashing/types/genesis.go` after line 56 to ensure all missed blocks have corresponding signing info:
- Create a map of signing info addresses
- Iterate through missed blocks and verify each has a corresponding signing info entry
- Return an error if orphaned missed blocks are found

**Fix 2: Implement Graceful Handling (Defense-in-Depth)**
Align implementation with specification in `x/slashing/keeper/infractions.go` lines 33-36 by creating default signing info instead of panicking, as documented in the specification.

**Recommended Approach:** Implement both fixes for defense-in-depth:
- Fix 1 prevents the issue at genesis validation time (fail-fast)
- Fix 2 aligns implementation with specification and provides fallback protection

## Proof of Concept

While the report references a test `TestOrphanedMissedBlocksCausesPanic`, the vulnerability is demonstrable through code analysis:

**Setup:**
1. Create a genesis state with a `ValidatorMissedBlockArray` entry for a validator address
2. Do NOT include a corresponding `SigningInfo` entry for that address
3. Set `Exported: true` in the staking genesis to bypass hook-based signing info creation
4. Verify the malformed genesis passes `ValidateGenesis` (it will, as it only checks parameters)

**Action:**
5. Import the genesis using `InitGenesis`
6. Trigger `BeginBlocker` with a validator vote for the address with orphaned missed blocks

**Result:**
7. The chain panics in `HandleValidatorSignatureConcurrent` with "Expected signing info for validator %s but not found" [3](#0-2) 
8. This causes total network shutdown

The vulnerability is confirmed by the discrepancy between the specification [5](#0-4)  (which states default values should be used) and the implementation (which panics), combined with the validation gap in [1](#0-0) .

## Notes

This vulnerability represents a critical gap where the system fails to enforce its own documented invariants. The specification explicitly states that missing signing info should be handled gracefully with default values, but the implementation panics instead. This discrepancy, combined with incomplete validation, creates a scenario where even trusted parties can inadvertently create genesis files that cause total network shutdown - an impact far beyond the intended authority of setting initial chain state.

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

**File:** x/slashing/genesis.go (L24-38)
```go
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
```

**File:** x/slashing/keeper/infractions.go (L33-36)
```go
	signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
	if !found {
		panic(fmt.Sprintf("Expected signing info for validator %s but not found", consAddr))
	}
```

**File:** x/staking/genesis.go (L47-49)
```go
		if !data.Exported {
			keeper.AfterValidatorCreated(ctx, validator.GetOperator())
		}
```

**File:** x/slashing/spec/04_begin_block.md (L35-36)
```markdown
  // signed. We use the 0-value default signing info if not present, except for
  // start height.
```

**File:** x/slashing/keeper/hooks.go (L12-25)
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
```

**File:** x/slashing/abci.go (L41-41)
```go
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```
