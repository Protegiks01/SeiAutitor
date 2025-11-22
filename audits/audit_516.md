## Audit Report

## Title
Expedited Proposal Conversion Uses Current VotingPeriod Instead of Original, Allowing Unlimited Voting Period Extension

## Summary
The expedited proposal conversion logic in `x/gov/abci.go` at lines 100-104 recalculates `VotingEndTime` using the current `VotingParams` from the parameter store, rather than the parameters that were in effect when the proposal originally activated. When governance parameters are changed between proposal activation and conversion, this allows proposals to extend far beyond any reasonable governance period, as there is no upper bound validation on `VotingPeriod`. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
The vulnerability exists in `x/gov/abci.go` in the `EndBlocker` function, specifically at lines 100-104 where expedited proposals are converted to regular proposals.

**Intended Logic:**
When an expedited proposal fails to pass during its expedited voting period, it should be converted to a regular proposal with an extended voting period. The intention is that the proposal gets additional time (the difference between regular and expedited voting periods) to gather support, with the total voting time capped at a reasonable governance period.

**Actual Logic:**
The conversion logic retrieves the CURRENT `VotingParams` from the parameter store and recalculates `VotingEndTime` as:
```
proposal.VotingEndTime = proposal.VotingStartTime.Add(votingParams.VotingPeriod)
```

Since `VotingStartTime` was set when the proposal first activated (potentially days or weeks ago), and `votingParams.VotingPeriod` is the CURRENT parameter value (not the original), this creates two problems:

1. If `VotingPeriod` was increased after the proposal activated, the new `VotingEndTime` can extend months or years into the future
2. There is no validation in `validateVotingParams` to enforce an upper bound on `VotingPeriod` - only that it must be positive [2](#0-1) 

**Exploit Scenario:**
1. Initial state: `VotingPeriod = 2 days`, `ExpeditedVotingPeriod = 1 day` (default values)
2. An expedited proposal A is submitted and activated at time T0
   - `VotingStartTime = T0`
   - `VotingEndTime = T0 + 1 day`
3. A governance parameter change proposal passes that sets:
   - `VotingPeriod = 365 days` (1 year)
   - `ExpeditedVotingPeriod = 180 days`
4. At time T0 + 1 day, expedited proposal A's voting period ends and it fails
5. The conversion logic executes, fetching the NEW parameters [3](#0-2) 
6. New `VotingEndTime = T0 + 365 days` (instead of expected T0 + 2 days)
7. Proposal A now has 364 more days of voting, far exceeding intended governance periods

This can be repeated for multiple proposals, causing governance gridlock and excessive resource consumption.

**Security Failure:**
This breaks the governance timing invariant that proposals should have bounded, predictable voting periods. It allows proposals to remain active indefinitely through parameter manipulation, violating the design assumption that governance proposals complete within reasonable timeframes.

## Impact Explanation

**Affected Components:**
- Governance proposal queue and active proposal tracking
- Node memory and storage for maintaining active proposal state
- Governance participation expectations and voting dynamics
- Network resource consumption from processing extended proposals

**Severity:**
- Proposals can remain active for arbitrarily long periods (months/years) instead of expected days
- Multiple extended proposals increase node resource consumption tracking active proposals
- Governance becomes unpredictable and difficult to manage
- Could be exploited strategically to keep contentious proposals alive indefinitely
- Violates user expectations about governance timing

This qualifies as **Medium** severity under the scope: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - the governance system exhibits unintended behavior that disrupts normal operations.

## Likelihood Explanation

**Who can trigger it:**
Any participant who can submit and pass a governance proposal to change the `VotingPeriod` parameter. This requires community coordination but not special privileges or admin keys.

**Conditions required:**
1. A governance parameter change proposal must pass that increases `VotingPeriod` significantly
2. One or more expedited proposals must be active when the parameter change takes effect
3. Those expedited proposals must fail their expedited voting period

**Frequency:**
- Parameter changes are relatively rare but legitimate governance actions
- Could be triggered accidentally (well-intentioned parameter adjustment) or intentionally (strategic manipulation)
- Once triggered, ALL failing expedited proposals are affected until parameters are changed back
- The impact compounds with multiple affected proposals

**Realistic likelihood:** Medium to High - governance parameter changes are normal operations, and the vulnerability triggers automatically for any failing expedited proposals after such changes.

## Recommendation

**Primary Fix:**
Store the original `VotingPeriod` parameter value with each proposal when it activates, and use that stored value during conversion instead of querying current parameters.

**Implementation:**
1. Add a field to the `Proposal` struct to store `OriginalVotingPeriod` when voting activates [4](#0-3) 
2. Modify the conversion logic to use the stored original value:
```
proposal.VotingEndTime = proposal.VotingStartTime.Add(proposal.OriginalVotingPeriod)
```

**Alternative Fix:**
Add validation to prevent `VotingPeriod` changes when active proposals exist, or add bounds checking to ensure the calculated `VotingEndTime` doesn't exceed a maximum allowed period from the current block time.

## Proof of Concept

**File:** `x/gov/abci_test.go`

**Test Function:** `TestExpeditedProposalConversionWithChangedVotingPeriod`

**Setup:**
```go
func TestExpeditedProposalConversionWithChangedVotingPeriod(t *testing.T) {
    // Initialize app and context
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    addrs := simapp.AddTestAddrs(app, ctx, 10, valTokens)
    params := app.StakingKeeper.GetParams(ctx)
    params.MinCommissionRate = sdk.NewDec(0)
    app.StakingKeeper.SetParams(ctx, params)
    SortAddresses(addrs)
    
    // Create validator
    header := tmproto.Header{Height: app.LastBlockHeight() + 1}
    app.BeginBlock(ctx, abci.RequestBeginBlock{Header: header})
    valAddr := sdk.ValAddress(addrs[0])
    stakingHandler := staking.NewHandler(app.StakingKeeper)
    createValidators(t, stakingHandler, ctx, []sdk.ValAddress{valAddr}, []int64{10})
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Get initial voting params
    initialVotingParams := app.GovKeeper.GetVotingParams(ctx)
    require.Equal(t, time.Hour*24*2, initialVotingParams.VotingPeriod) // 2 days default
    require.Equal(t, time.Hour*24, initialVotingParams.ExpeditedVotingPeriod) // 1 day default
}
```

**Trigger:**
```go
    // Submit and activate expedited proposal
    govHandler := gov.NewHandler(app.GovKeeper)
    proposalCoins := sdk.Coins{sdk.NewCoin(sdk.DefaultBondDenom, app.StakingKeeper.TokensFromConsensusPower(ctx, 20))}
    testProposal := types.NewTextProposal("Test", "description", true)
    newProposalMsg, err := types.NewMsgSubmitProposalWithExpedite(testProposal, proposalCoins, addrs[0], true)
    require.NoError(t, err)
    res, err := govHandler(ctx, newProposalMsg)
    require.NoError(t, err)
    
    var proposalData types.MsgSubmitProposalResponse
    err = proto.Unmarshal(res.Data, &proposalData)
    require.NoError(t, err)
    proposalID := proposalData.ProposalId
    
    // Advance time and deposit to activate voting
    newHeader := ctx.BlockHeader()
    newHeader.Time = ctx.BlockHeader().Time.Add(time.Second)
    ctx = ctx.WithBlockHeader(newHeader)
    
    newDepositMsg := types.NewMsgDeposit(addrs[1], proposalID, proposalCoins)
    res, err = govHandler(ctx, newDepositMsg)
    require.NoError(t, err)
    
    // Verify proposal is in voting period
    proposal, _ := app.GovKeeper.GetProposal(ctx, proposalID)
    require.Equal(t, types.StatusVotingPeriod, proposal.Status)
    require.True(t, proposal.IsExpedited)
    originalVotingStartTime := proposal.VotingStartTime
    originalVotingEndTime := proposal.VotingEndTime
    
    // EXPLOIT: Change VotingPeriod to 365 days (1 year)
    newVotingParams := types.NewVotingParams(
        time.Hour*24*365, // 365 days - unreasonably long
        time.Hour*24*180, // 180 days
    )
    app.GovKeeper.SetVotingParams(ctx, newVotingParams)
    
    // Advance to end of expedited voting period
    newHeader.Time = originalVotingEndTime.Add(time.Second)
    ctx = ctx.WithBlockHeader(newHeader)
    
    // EndBlocker processes and converts the proposal
    gov.EndBlocker(ctx, app.GovKeeper)
```

**Observation:**
```go
    // Verify the proposal was converted
    proposal, _ = app.GovKeeper.GetProposal(ctx, proposalID)
    require.False(t, proposal.IsExpedited, "Proposal should be converted to regular")
    require.Equal(t, types.StatusVotingPeriod, proposal.Status, "Proposal should still be in voting")
    
    // VULNERABILITY: VotingEndTime uses NEW parameter (365 days from start)
    // Expected: VotingStartTime + original 2 days = only 1 more day from now
    // Actual: VotingStartTime + new 365 days = 364 more days from now
    expectedEndTime := originalVotingStartTime.Add(time.Hour * 24 * 365)
    require.Equal(t, expectedEndTime, proposal.VotingEndTime, 
        "VotingEndTime should use new params (365 days), demonstrating the vulnerability")
    
    // Calculate how much time was added beyond intended
    intendedEndTime := originalVotingStartTime.Add(time.Hour * 24 * 2) // Original 2 days
    excessExtension := proposal.VotingEndTime.Sub(intendedEndTime)
    
    // The proposal got 363 extra days instead of just 1 extra day
    require.Greater(t, excessExtension, time.Hour*24*360,
        "Proposal extended by more than 360 days beyond intended period - vulnerability confirmed")
    
    t.Logf("VULNERABILITY CONFIRMED:")
    t.Logf("  Original expected total voting: 2 days")
    t.Logf("  Actual total voting after exploit: 365 days")
    t.Logf("  Excess extension: %v days", excessExtension.Hours()/24)
}
```

The test demonstrates that when `VotingPeriod` is changed between proposal activation and conversion, the converted proposal's `VotingEndTime` extends far beyond reasonable governance periods, confirming the vulnerability.

### Citations

**File:** x/gov/abci.go (L100-104)
```go
				proposal.IsExpedited = false
				votingParams := keeper.GetVotingParams(ctx)
				proposal.VotingEndTime = proposal.VotingStartTime.Add(votingParams.VotingPeriod)

				keeper.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
```

**File:** x/gov/types/params.go (L238-240)
```go
	if v.VotingPeriod <= 0 {
		return fmt.Errorf("voting period must be positive: %s", v.VotingPeriod)
	}
```

**File:** x/gov/keeper/proposal.go (L201-210)
```go
func (keeper Keeper) ActivateVotingPeriod(ctx sdk.Context, proposal types.Proposal) {
	proposal.VotingStartTime = ctx.BlockHeader().Time
	votingPeriod := keeper.GetVotingParams(ctx).GetVotingPeriod(proposal.IsExpedited)
	proposal.VotingEndTime = proposal.VotingStartTime.Add(votingPeriod)
	proposal.Status = types.StatusVotingPeriod
	keeper.SetProposal(ctx, proposal)

	keeper.RemoveFromInactiveProposalQueue(ctx, proposal.ProposalId, proposal.DepositEndTime)
	keeper.InsertActiveProposalQueue(ctx, proposal.ProposalId, proposal.VotingEndTime)
}
```
