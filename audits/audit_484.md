# Audit Report

## Title
Governance Parameter Race Condition Allows Manipulation of Concurrent Proposal Outcomes

## Summary
When multiple governance proposals end their voting period in the same block, a parameter change proposal that modifies x/gov's own parameters (threshold, quorum, veto threshold) can alter the evaluation criteria for subsequently processed proposals in the same block, causing proposals to pass or fail based on parameters different from those in effect during their voting period. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in the governance module's EndBlocker execution flow, specifically in how proposals are sequentially processed and how parameter changes take immediate effect. [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
Governance proposals should be evaluated against the tally parameters (quorum, threshold, veto threshold) that were in effect during their voting period. Each proposal's outcome should be determined independently based on stable, predictable parameters.

**Actual Logic:**
In the EndBlocker, proposals are processed sequentially in a loop. For each proposal:
1. The tally parameters are fetched from the current context at tally time
2. If the proposal passes and executes successfully, parameter changes are immediately written back to the context via `writeCache()`
3. Subsequent proposals in the same iteration see the modified parameters

When a parameter change proposal targeting x/gov's own parameters (e.g., "gov/tallyparams") executes before another proposal in the same block, the second proposal is evaluated using the modified parameters rather than the original ones. [4](#0-3) 

The submission validation only checks that parameters exist in the subspace, not whether modifying them would create cross-proposal dependencies. The validation at proposal.go:23-40 allows proposals to target the "gov" subspace without restrictions.

**Exploit Scenario:**
1. Initial state: TallyParams has Threshold = 50%
2. Attacker monitors active proposals and identifies Proposal B (ID=11) with 45% Yes votes that will end soon
3. Attacker submits Proposal A (ID=10): "Lower governance threshold to 40% for faster decision-making"
4. Attacker times Proposal A to end voting at the exact same block as Proposal B
5. Attacker secures 51% votes for Proposal A
6. Both proposals reach their voting end time in Block N
7. In EndBlocker:
   - Proposal A (lower ID) is tallied first with original 50% threshold → passes (51% > 50%)
   - Proposal A executes → Threshold changes to 40%
   - Proposal B is tallied with NEW 40% threshold → passes (45% > 40%)
8. Proposal B passes even though it failed to achieve the 50% threshold that was in effect during its entire voting period

**Security Failure:**
This breaks the governance determinism invariant - proposals should be evaluated against stable parameters. Voters on Proposal B made their voting decisions based on a 50% threshold requirement, but the proposal was ultimately evaluated against a 40% threshold. This undermines trust in the governance system and enables manipulation of governance outcomes.

## Impact Explanation

This vulnerability affects the integrity of the governance process:

- **Governance Manipulation**: An attacker with sufficient voting power to pass a parameter change proposal can manipulate the outcomes of other concurrent proposals, causing them to pass when they should fail or vice versa.

- **Voter Expectation Violation**: Token holders vote on proposals with specific parameter expectations (e.g., "this needs 50% to pass"). If parameters change mid-evaluation, their votes have different weight than intended.

- **Potential for Secondary Impacts**: If manipulated proposals involve critical actions like protocol upgrades, fund transfers, or parameter changes affecting economic security, this could lead to unintended smart contract behavior or system state changes that affect users.

While this doesn't directly steal funds, it compromises the governance layer that controls all protocol decisions, including those that do affect funds and security parameters.

## Likelihood Explanation

**Who can trigger it:** Any participant with sufficient voting power to pass a parameter change proposal (typically requiring majority or supermajority voting power).

**Conditions required:**
- At least two proposals must end their voting period in the same block
- One proposal must be a parameter change targeting x/gov parameters
- The attacker must be able to time proposal submission to achieve concurrent ending times
- The attacker needs voting power to pass the parameter change proposal

**Frequency:** Since voting periods are fixed durations, attackers can calculate exact end times and deliberately create this scenario. This could occur during periods of high governance activity when multiple proposals are naturally active. The attack requires coordination but is feasible for actors with significant voting power.

## Recommendation

**Option 1 (Preferred):** Snapshot governance parameters at the start of each proposal's voting period and use those snapshotted parameters for tallying, regardless of any changes that occur after the snapshot.

**Option 2:** Process proposals in a two-phase commit: first tally all proposals using current parameters, then execute only the passed proposals. This prevents parameter changes from affecting concurrent tallies.

**Option 3:** Prevent parameter change proposals from targeting x/gov's own governance parameters (threshold, quorum, veto threshold) and require such changes through a different mechanism or with additional safeguards.

**Option 4:** Add a delay mechanism where parameter changes to governance parameters only take effect in the next block or after a cooling-off period, preventing same-block interference.

## Proof of Concept

**File:** `x/gov/abci_test.go`

**Test Function:** Add a new test `TestGovernanceParameterRaceCondition`

**Setup:**
1. Initialize test app with default governance parameters (Threshold = 50%)
2. Create validators with voting power
3. Submit Proposal A (ID=1): Parameter change to lower threshold to 40%
4. Submit Proposal B (ID=2): Text proposal  
5. Deposit sufficient funds on both to activate voting
6. Vote 51% Yes on Proposal A
7. Vote 45% Yes on Proposal B
8. Advance time so both proposals end voting in the same block

**Trigger:**
Call `gov.EndBlocker(ctx, app.GovKeeper)` to process both proposals in the same block

**Observation:**
- Proposal A should pass (51% > 50% original threshold) ✓
- Proposal B should FAIL (45% < 50% original threshold) ✗
- **Bug**: Proposal B actually PASSES because it's evaluated with 40% threshold after Proposal A executes
- Verification: Check `proposal.Status` for both proposals - B shows StatusPassed when it should show StatusRejected

This test would demonstrate that Proposal B's outcome is determined by parameters modified by Proposal A rather than the parameters in effect during B's voting period, violating the governance determinism invariant.

### Citations

**File:** x/gov/abci.go (L48-92)
```go
	keeper.IterateActiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		var tagValue, logMsg string

		passes, burnDeposits, tallyResults := keeper.Tally(ctx, proposal)

		// If an expedited proposal fails, we do not want to update
		// the deposit at this point since the proposal is converted to regular.
		// As a result, the deposits are either deleted or refunded in all casses
		// EXCEPT when an expedited proposal fails.
		if !(proposal.IsExpedited && !passes) {
			if burnDeposits {
				keeper.DeleteDeposits(ctx, proposal.ProposalId)
			} else {
				keeper.RefundDeposits(ctx, proposal.ProposalId)
			}
		}

		keeper.RemoveFromActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)

		if passes {
			handler := keeper.Router().GetRoute(proposal.ProposalRoute())
			cacheCtx, writeCache := ctx.CacheContext()

			// The proposal handler may execute state mutating logic depending
			// on the proposal content. If the handler fails, no state mutation
			// is written and the error message is logged.
			err := handler(cacheCtx, proposal.GetContent())
			if err == nil {
				proposal.Status = types.StatusPassed
				tagValue = types.AttributeValueProposalPassed
				logMsg = "passed"

				// The cached context is created with a new EventManager. However, since
				// the proposal handler execution was successful, we want to track/keep
				// any events emitted, so we re-emit to "merge" the events into the
				// original Context's EventManager.
				ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())

				// write state to the underlying multi-store
				writeCache()
			} else {
				proposal.Status = types.StatusFailed
				tagValue = types.AttributeValueProposalFailed
				logMsg = fmt.Sprintf("passed, but failed on execution: %s", err)
			}
```

**File:** x/gov/keeper/tally.go (L89-89)
```go
	tallyParams := keeper.GetTallyParams(ctx)
```

**File:** x/params/proposal_handler.go (L26-42)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
```

**File:** x/gov/keeper/proposal.go (L23-40)
```go
	if content.ProposalType() == proposal.ProposalTypeChange {
		paramProposal, ok := content.(*proposal.ParameterChangeProposal)
		if !ok {
			return types.Proposal{}, sdkerrors.Wrap(types.ErrInvalidProposalContent, "proposal content is not a ParameterChangeProposal")
		}

		// Validate each parameter change exists
		for _, change := range paramProposal.Changes {
			subspace, ok := keeper.paramsKeeper.GetSubspace(change.Subspace)
			if !ok {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s/%s does not exist", change.Subspace, change.Key)
			}
			validKey := subspace.Has(ctx, []byte(change.Key))
			if !validKey {
				return types.Proposal{}, sdkerrors.Wrapf(types.ErrInvalidProposalContent, "parameter %s not found in subspace %s", change.Key, change.Subspace)
			}
		}
	}
```
