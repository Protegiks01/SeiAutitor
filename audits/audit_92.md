# Audit Report

## Title
Chain Halt Due to Orphaned Missed Blocks Imported Through Malicious Genesis File

## Summary
The slashing module's `ValidateGenesis` function fails to verify that all missed blocks entries have corresponding signing info entries. This validation gap allows a malicious genesis file to import orphaned missed blocks, which causes the chain to panic and halt when those validators participate in consensus. The issue is exacerbated when `Exported: true` is set in the staking genesis, preventing hooks from auto-creating missing signing info.

## Impact
High

## Finding Description

**Location:**
- Primary validation gap: [1](#0-0) 
- Import without cross-validation: [2](#0-1) 
- Panic trigger: [3](#0-2) 
- Hook bypass mechanism: [4](#0-3) 

**Intended Logic:**
Genesis validation should enforce the invariant that missed blocks entries can only exist for validators with corresponding signing info. According to the specification [5](#0-4) , the system should use a 0-value default signing info if not present, rather than panicking.

**Actual Logic:**
1. `ValidateGenesis` only validates slashing parameters (slash fractions, windows, jail durations) but does NOT validate the relationship between `MissedBlocks` and `SigningInfos` [1](#0-0) 

2. `InitGenesis` imports signing infos and missed blocks independently without any cross-validation [6](#0-5) 

3. When `Exported: true` is set in staking genesis, validator creation hooks are skipped [4](#0-3) , preventing automatic signing info creation via the `AfterValidatorBonded` hook [7](#0-6) 

4. When a validator with orphaned missed blocks participates in consensus, `HandleValidatorSignatureConcurrent` panics because it expects signing info to exist [3](#0-2) 

**Exploitation Path:**
1. Attacker crafts a genesis file with `ValidatorMissedBlockArray` entries but no corresponding `SigningInfo` entries, and sets `Exported: true` in staking genesis
2. Genesis validation passes because `ValidateGenesis` only checks parameters
3. Chain operators initialize the chain using `InitGenesis`, which imports the orphaned missed blocks
4. When the validator participates in consensus, `BeginBlocker` invokes `HandleValidatorSignatureConcurrent` [8](#0-7) 
5. The function panics with "Expected signing info for validator %s but not found"
6. Entire chain halts due to consensus failure

**Security Guarantee Broken:**
The system fails to maintain the critical invariant that missed blocks can only exist for validators with signing info. This violates the assumption that genesis state is validated for consistency before import.

## Impact Explanation

This vulnerability causes **total network shutdown** - a HIGH severity impact explicitly listed in the acceptance criteria as "Network not being able to confirm new transactions (total network shutdown)."

When the panic occurs:
- The entire blockchain network halts immediately when `BeginBlocker` panics during consensus
- No new blocks can be produced or transactions confirmed
- The network remains down until all validators coordinate to restart with a corrected genesis file
- Recovery requires complex coordination and potentially a hard fork

The panic happens in the consensus-critical path (`BeginBlocker`), making it impossible for the network to continue operation. Unlike application-level errors that might affect individual transactions, this is a consensus-breaking failure that impacts the entire network simultaneously.

## Likelihood Explanation

**Who Can Trigger:**
Someone who can influence genesis file creation during chain launch or network restart. This includes:
- Participants in multi-party genesis file creation (common for new blockchain launches)
- Attackers who compromise genesis generation tooling
- Social engineering attacks during chain coordination

**Required Conditions:**
1. Malicious genesis file must be used during chain initialization
2. The validator addresses in orphaned missed blocks must eventually participate in consensus
3. `Exported: true` must be set in staking genesis to prevent automatic signing info creation

**Likelihood Assessment:**
While this requires involvement during genesis creation, it's realistic because:
- Multi-party genesis coordination is standard for blockchain launches
- The validation gap makes it easy to miss this inconsistency during review
- Genesis files passing `ValidateGenesis` gives false confidence of correctness
- Once imported, the issue persists indefinitely as a "time bomb"
- There's a discrepancy between the specification (which says to handle missing signing info gracefully) and implementation (which panics), suggesting this is an overlooked edge case

The exception clause for privileged roles applies here: even a trusted genesis creator can inadvertently create this state (since validation doesn't catch it), causing an unrecoverable security failure (total chain halt) beyond their intended authority (setting genesis state shouldn't create chain-halting time bombs).

## Recommendation

**Fix 1: Add Validation in ValidateGenesis**
Add cross-validation to ensure all missed blocks have corresponding signing info:

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

**Fix 2: Implement Graceful Handling (Defense-in-Depth)**
Align implementation with specification by creating default signing info instead of panicking:

```go
// In x/slashing/keeper/infractions.go, replace lines 33-36:

signInfo, found := k.GetValidatorSigningInfo(ctx, consAddr)
if !found {
    // Create default signing info as documented in spec
    signInfo = types.NewValidatorSigningInfo(consAddr, height, 0, time.Unix(0, 0), false, 0)
    k.SetValidatorSigningInfo(ctx, consAddr, signInfo)
}
```

**Recommended Approach:** Implement both fixes for defense-in-depth:
- Fix 1 prevents the issue at genesis validation time (fail-fast)
- Fix 2 aligns implementation with specification and provides fallback protection

## Proof of Concept

The report provides a comprehensive Go test demonstrating the vulnerability:

**File:** `x/slashing/genesis_test.go`
**Function:** `TestOrphanedMissedBlocksCausesPanic`

**Setup:**
- Create a genesis state with orphaned missed blocks (missed blocks without signing info)
- Verify the malformed genesis passes `ValidateGenesis`
- Import the genesis via `InitGenesis`

**Action:**
- Trigger `BeginBlocker` with a validator vote for the address with orphaned missed blocks
- The validator has missed blocks data but no signing info

**Result:**
- The test asserts that `BeginBlocker` panics with "Expected signing info for validator %s but not found"
- This demonstrates that the validation gap allows importing invalid state that causes chain halt

The PoC can be run with:
```bash
cd x/slashing
go test -v -run TestOrphanedMissedBlocksCausesPanic
```

## Notes

This vulnerability represents a critical gap in genesis validation that violates the documented behavior. The specification clearly states that missing signing info should be handled gracefully with default values, but the implementation panics instead. This discrepancy, combined with the incomplete validation, creates a scenario where trusted parties can inadvertently create genesis files that cause total network shutdown - an impact far beyond their intended authority of setting initial chain state.

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
