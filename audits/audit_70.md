# Audit Report

## Title
Evidence Duplicate Submission DoS via Timestamp Manipulation Bypassing Hash-Based Duplicate Check

## Summary
The evidence module's `SubmitEvidence` function uses hash-based duplicate detection that can be bypassed by manipulating timestamps. The `HandleEquivocationEvidence` function violates the Handler interface specification by returning void instead of error, preventing proper error propagation when evidence is rejected. This allows attackers to submit semantically identical evidence with different timestamps, causing separate storage of duplicate entries and enabling storage exhaustion attacks.

## Impact
Medium

## Finding Description

**Location:**
- Duplicate check: [1](#0-0) 
- Unconditional storage: [2](#0-1) 
- Hash calculation includes all fields: [3](#0-2) 
- Handler void return (interface violation): [4](#0-3) 
- Early return when tombstoned: [5](#0-4) 

**Intended Logic:**
The Handler interface specifies that evidence handlers must return error [6](#0-5)  to signal when evidence is invalid or rejected. The duplicate check should prevent the same misbehavior evidence from being stored multiple times, identified by semantic properties (validator address, height, type) rather than submission metadata.

**Actual Logic:**
The `HandleEquivocationEvidence` function has void return type, violating the Handler interface specification. When a validator is already tombstoned, the function returns early without signaling an error. The duplicate check compares full evidence hashes, which include the user-controlled Time field. Different timestamps produce different hashes, bypassing the duplicate check. `SubmitEvidence` unconditionally stores evidence after handler execution if no error is returned.

**Exploitation Path:**
1. Attacker submits evidence E1 via `MsgSubmitEvidence` transaction with timestamp T1 for validator V at height H
2. Duplicate check passes (first submission)
3. Handler processes evidence: validator gets slashed, jailed, and tombstoned
4. Evidence stored with hash H1 = Hash(V, H, T1, ...)
5. Attacker submits evidence E2 with same validator V and height H but timestamp T2 ≠ T1
6. Hash H2 = Hash(V, H, T2, ...) ≠ H1 due to different timestamp
7. Duplicate check passes (different hash)
8. Handler detects validator already tombstoned, returns early (void, no error signal)
9. `SubmitEvidence` still stores evidence with hash H2 (unconditional storage after handler)
10. Attacker repeats with timestamps T3, T4, ..., Tn, creating n storage entries for single misbehavior

**Security Guarantee Broken:**
The duplicate detection mechanism is defeated. Evidence uniqueness should be based on the misbehavior event itself (validator, height, type), not submission metadata (timestamp). The system stores semantically duplicate evidence as distinct entries, enabling storage exhaustion attacks.

## Impact Explanation

The vulnerability enables storage exhaustion attacks affecting all network validators:
- **Storage Growth**: Each evidence submission (~100 bytes) is permanently stored. An attacker can submit thousands of evidence instances for a single misbehavior event.
- **Network-Wide Impact**: All validators must store and synchronize redundant evidence, increasing disk usage and state sync costs.
- **Permanent Bloat**: Evidence entries persist indefinitely without automatic pruning.

This qualifies as Medium severity under: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the evidence module is layer 1 Cosmos SDK code exhibiting unintended behavior (storing semantic duplicates).

## Likelihood Explanation

**Trigger Conditions:**
- Any user can submit evidence via `MsgSubmitEvidence` [7](#0-6) 
- No privileged access required
- Evidence validation only checks timestamp > 0 [8](#0-7) 

**Likelihood Assessment:**
- **High**: Exploitation is straightforward - submit evidence with incrementing timestamps
- **Low Cost**: Attacker pays gas per transaction but creates disproportionate storage burden
- **Production Pattern**: Handler wrappers naturally return nil when wrapping void functions, making the vulnerability likely in real deployments
- **No Detection**: The duplicate check cannot detect semantic duplicates with varying timestamps

## Recommendation

Implement semantic duplicate detection and fix the Handler interface violation:

**Option 1 - Fix Handler Interface Violation:**
Modify `HandleEquivocationEvidence` signature to return `error`:
```go
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) error
```
Return appropriate errors for rejection conditions (already tombstoned, too old, validator not found). Only return `nil` when evidence is successfully processed. Update `SubmitEvidence` to only store evidence when handler returns `nil`.

**Option 2 - Semantic Duplicate Detection:**
Check duplicates using composite key `(ConsensusAddress, Height, Type)` instead of full hash. Store evidence indexed by this semantic key to prevent duplicate misbehavior evidence regardless of submission metadata.

**Option 3 - Canonical Evidence:**
Normalize evidence before hashing by using canonical timestamps (e.g., block time at infraction height) rather than user-provided submission time.

## Proof of Concept

**Test File:** `x/evidence/keeper/keeper_test.go`

**Setup:**
- Create keeper with router wrapping `HandleEquivocationEvidence` (realistic production pattern)
- Handler wrapper returns `nil` (cannot detect void return from `HandleEquivocationEvidence`)
- Initialize validators and set up chain context

**Action:**
- Submit evidence with timestamp T1 (unix 100) for validator at height 1
- Verify validator gets tombstoned
- Submit evidence with timestamp T2 (unix 200) - same validator, same height, different timestamp
- Submit 10 more evidence instances with timestamps T3-T12
- All submissions succeed despite representing same misbehavior

**Result:**
- All 12 evidence instances stored separately (retrievable via `GetAllEvidence`)
- All have same height and validator address
- All have different timestamps and hashes
- Demonstrates bypass of duplicate detection via timestamp manipulation

The PoC confirms that semantic duplicates (same misbehavior) are stored as distinct evidence entries, validating the storage exhaustion vulnerability.

## Notes

This is a design flaw arising from three compounding issues:
1. **Interface Violation**: `HandleEquivocationEvidence` returns void instead of error as specified by Handler interface [6](#0-5) 
2. **Hash Includes Mutable Fields**: Evidence hash computed from all protobuf fields including user-controlled timestamp
3. **Unconditional Storage**: Evidence stored after handler execution regardless of early returns

The specification documentation [9](#0-8)  clearly states handlers should return errors, confirming this is a bug rather than intentional design. The combination enables storage exhaustion attacks by allowing semantic duplicates to bypass duplicate detection through timestamp manipulation.

### Citations

**File:** x/evidence/keeper/keeper.go (L79-81)
```go
	if _, ok := k.GetEvidence(ctx, evidence.Hash()); ok {
		return sdkerrors.Wrap(types.ErrEvidenceExists, evidence.Hash().String())
	}
```

**File:** x/evidence/keeper/keeper.go (L98-98)
```go
	k.SetEvidence(ctx, evidence)
```

**File:** x/evidence/types/evidence.go (L36-43)
```go
func (e *Equivocation) Hash() tmbytes.HexBytes {
	bz, err := e.Marshal()
	if err != nil {
		panic(err)
	}
	b := sha256.Sum256(bz)
	return b[:]
}
```

**File:** x/evidence/types/evidence.go (L46-61)
```go
func (e *Equivocation) ValidateBasic() error {
	if e.Time.Unix() <= 0 {
		return fmt.Errorf("invalid equivocation time: %s", e.Time)
	}
	if e.Height < 1 {
		return fmt.Errorf("invalid equivocation height: %d", e.Height)
	}
	if e.Power < 1 {
		return fmt.Errorf("invalid equivocation validator power: %d", e.Power)
	}
	if e.ConsensusAddress == "" {
		return fmt.Errorf("invalid equivocation validator consensus address: %s", e.ConsensusAddress)
	}

	return nil
}
```

**File:** x/evidence/keeper/infraction.go (L25-25)
```go
func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) {
```

**File:** x/evidence/keeper/infraction.go (L78-86)
```go
	if k.slashingKeeper.IsTombstoned(ctx, consAddr) {
		logger.Info(
			"ignored equivocation; validator already tombstoned",
			"validator", consAddr,
			"infraction_height", infractionHeight,
			"infraction_time", infractionTime,
		)
		return
	}
```

**File:** x/evidence/types/router.go (L15-15)
```go
	Handler func(sdk.Context, exported.Evidence) error
```

**File:** x/evidence/keeper/msg_server.go (L23-29)
```go
func (ms msgServer) SubmitEvidence(goCtx context.Context, msg *types.MsgSubmitEvidence) (*types.MsgSubmitEvidenceResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	evidence := msg.GetEvidence()
	if err := ms.Keeper.SubmitEvidence(ctx, evidence); err != nil {
		return nil, err
	}
```

**File:** x/evidence/spec/01_concepts.md (L72-77)
```markdown
```go
// Handler defines an agnostic Evidence handler. The handler is responsible
// for executing all corresponding business logic necessary for verifying the
// evidence as valid. In addition, the Handler may execute any necessary
// slashing and potential jailing.
type Handler func(sdk.Context, Evidence) error
```
