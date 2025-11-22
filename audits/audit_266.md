## Audit Report

## Title
Evidence Duplicate Submission DoS via Timestamp Manipulation Bypassing Hash-Based Duplicate Check

## Summary
The evidence module's `SubmitEvidence` function uses hash-based duplicate detection, but the hash includes all evidence fields including the timestamp. This allows attackers to bypass duplicate checks by submitting identical misbehavior evidence with different timestamps, causing each submission to be stored separately and enabling storage exhaustion attacks.

## Impact
Medium

## Finding Description

**Location:** 
- Duplicate check: [1](#0-0) 
- Unconditional storage: [2](#0-1) 
- Hash calculation includes timestamp: [3](#0-2) 

**Intended Logic:** 
The duplicate check is meant to prevent the same evidence from being submitted and stored multiple times. Evidence should be uniquely identified by the validator misbehavior it represents (validator address, height, type of misbehavior).

**Actual Logic:** 
The duplicate check compares evidence by hash, where the hash is computed from ALL fields including the `Time` field [3](#0-2) . An attacker can submit identical evidence for the same misbehavior but with different timestamps, generating different hashes that bypass the duplicate check. Each submission gets stored separately even though they represent the same misbehavior event.

**Exploit Scenario:**
1. Attacker observes or triggers validator misbehavior at height H for validator V
2. Attacker submits evidence E1: `{Height: H, Time: T1, Power: P, ConsensusAddress: V}`
3. First submission processes: validator gets slashed/jailed/tombstoned, evidence stored
4. Attacker submits evidence E2: `{Height: H, Time: T2, Power: P, ConsensusAddress: V}` where T2 ≠ T1
5. Hash(E2) ≠ Hash(E1) due to different timestamps
6. Duplicate check passes (different hash) [1](#0-0) 
7. If handler wraps `HandleEquivocationEvidence` (which has void return), it returns early when validator is already tombstoned [4](#0-3)  but doesn't signal error
8. `SubmitEvidence` still stores E2 [2](#0-1) 
9. Attacker repeats with T3, T4, T5... causing storage bloat

**Security Failure:** 
Denial of service through storage exhaustion. The hash-based duplicate detection is ineffective because it includes mutable fields (timestamp) that don't affect the semantic identity of the misbehavior evidence.

## Impact Explanation

The vulnerability affects blockchain state storage:
- **Storage Growth**: An attacker can submit thousands of evidence instances for a single misbehavior, with each instance stored separately (~100 bytes each)
- **Node Resource Consumption**: All validators must store this redundant evidence, increasing disk usage and state synchronization costs
- **Economic Efficiency**: The duplicate check becomes meaningless as it can be trivially bypassed

This constitutes a Medium severity issue per the scope definition: "Increasing network processing node resource consumption by at least 30% without brute force actions" - though the attacker must submit transactions (paying gas), they can create disproportionate storage impact by exploiting the design flaw in duplicate detection.

## Likelihood Explanation

**Trigger Conditions:**
- Any user can submit evidence via `MsgSubmitEvidence` transaction
- Applications that configure an evidence handler (required for user-submitted evidence to work)
- The handler pattern naturally wraps `HandleEquivocationEvidence`, which has a void return type making proper error handling impossible [5](#0-4) 

**Likelihood:**
- High: Once an application enables user-submitted evidence, any attacker can exploit this
- The attack is straightforward: submit the same evidence with incremented timestamps
- Each timestamp within the evidence validity window (before MaxAgeDuration) generates a unique hash
- Cost to attacker: transaction fees per submission, but creates persistent storage burden on all validators

## Recommendation

Implement semantic duplicate detection based on the logical identity of the misbehavior rather than the full evidence hash:

1. **Option 1 - Composite Key**: Check for duplicates using `(ConsensusAddress, Height, Type)` as the key rather than the full hash. Store evidence indexed by this composite key.

2. **Option 2 - Canonical Evidence**: Normalize evidence before hashing by using a canonical timestamp (e.g., block time at the infraction height) rather than submission time.

3. **Option 3 - Handler Error Signaling**: Modify `HandleEquivocationEvidence` to return an error when evidence is rejected (already tombstoned, too old, etc.), and ensure `SubmitEvidence` only stores evidence when the handler succeeds without error.

Example fix for Option 3:
- Change `HandleEquivocationEvidence` signature to return `error`
- Return appropriate errors for early-exit conditions (already tombstoned, too old, validator not found)
- Only return `nil` when evidence is successfully processed and stored
- Handler wrappers can then properly propagate these errors to prevent redundant storage

## Proof of Concept

**File:** `x/evidence/keeper/keeper_test.go`

**Test Function:** Add this test to the existing `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestSubmitEvidence_TimestampBypassDoS() {
	ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1)
	suite.populateValidators(ctx)
	
	// Configure handler that wraps HandleEquivocationEvidence (realistic production pattern)
	evidenceKeeper := keeper.NewKeeper(
		suite.app.AppCodec(), 
		suite.app.GetKey(types.StoreKey), 
		suite.app.StakingKeeper, 
		suite.app.SlashingKeeper,
	)
	router := types.NewRouter()
	router = router.AddRoute(types.RouteEquivocation, func(ctx sdk.Context, e exported.Evidence) error {
		ee := e.(*types.Equivocation)
		evidenceKeeper.HandleEquivocationEvidence(ctx, ee)
		return nil  // Handler can't detect if evidence was rejected
	})
	evidenceKeeper.SetRouter(router)
	suite.app.EvidenceKeeper = *evidenceKeeper
	
	pk := pubkeys[0]
	consAddr := sdk.ConsAddress(pk.Address())
	
	// Submit evidence with timestamp T1
	evidence1 := &types.Equivocation{
		Height:           1,
		Time:             time.Unix(100, 0),  // T1
		Power:            100,
		ConsensusAddress: consAddr.String(),
	}
	
	err := suite.app.EvidenceKeeper.SubmitEvidence(ctx, evidence1)
	suite.Require().NoError(err)
	
	// Verify validator is tombstoned
	suite.True(suite.app.SlashingKeeper.IsTombstoned(ctx, consAddr))
	
	// Submit same evidence with different timestamp T2
	evidence2 := &types.Equivocation{
		Height:           1,  // Same height
		Time:             time.Unix(200, 0),  // T2 - different!
		Power:            100,  // Same power
		ConsensusAddress: consAddr.String(),  // Same validator
	}
	
	// Should fail duplicate check but doesn't due to different hash
	err = suite.app.EvidenceKeeper.SubmitEvidence(ctx, evidence2)
	suite.Require().NoError(err)  // Succeeds when it should fail
	
	// Submit multiple more instances with different timestamps
	for i := 300; i < 310; i++ {
		evidenceN := &types.Equivocation{
			Height:           1,
			Time:             time.Unix(int64(i), 0),
			Power:            100,
			ConsensusAddress: consAddr.String(),
		}
		err = suite.app.EvidenceKeeper.SubmitEvidence(ctx, evidenceN)
		suite.Require().NoError(err)
	}
	
	// Verify all evidence instances are stored
	allEvidence := suite.app.EvidenceKeeper.GetAllEvidence(ctx)
	suite.Require().Len(allEvidence, 12)  // 1 + 1 + 10 = 12 instances stored
	
	// All represent the SAME misbehavior but bypass duplicate check
	for _, ev := range allEvidence {
		e := ev.(*types.Equivocation)
		suite.Equal(int64(1), e.Height)  // All same height
		suite.Equal(consAddr.String(), e.ConsensusAddress)  // All same validator
		// But different timestamps and hashes
	}
}
```

**Expected Result:** The test demonstrates that 12 separate evidence instances are stored for a single misbehavior event, bypassing the duplicate check via timestamp manipulation. This confirms the storage DoS vulnerability.

## Notes

The root cause is a design flaw where:
1. Evidence hash includes all fields including mutable/attacker-controlled timestamps
2. `HandleEquivocationEvidence` has no return value, preventing proper error propagation
3. `SubmitEvidence` unconditionally stores evidence after handler execution (if no error)

This combination allows semantic duplicates (same misbehavior) to be stored as distinct evidence entries, defeating the purpose of duplicate detection and enabling storage exhaustion attacks.

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

**File:** x/evidence/types/evidence.go (L36-42)
```go
func (e *Equivocation) Hash() tmbytes.HexBytes {
	bz, err := e.Marshal()
	if err != nil {
		panic(err)
	}
	b := sha256.Sum256(bz)
	return b[:]
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
