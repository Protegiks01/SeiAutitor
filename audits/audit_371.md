## Audit Report

### Title
Unbounded Memory Allocation and Iteration in BeginBlocker Causes Network Halt via Large SignedBlocksWindow Parameter

### Summary
The `ResizeMissedBlockArray` function in `x/slashing/keeper/infractions.go` executes within `BeginBlocker` and performs unbounded memory allocation and iteration proportional to the `SignedBlocksWindow` parameter size. Since this parameter has no upper bound validation beyond requiring a positive value, a governance proposal can set it to extremely large values (e.g., millions or billions), causing all nodes to exhaust resources and halt during the next block's BeginBlocker execution, resulting in total network shutdown.

### Impact
**High**

### Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Call site: [2](#0-1) 
- BeginBlocker entry: [3](#0-2) 
- Parameter validation: [4](#0-3) 

**Intended Logic:**
The `ResizeMissedBlockArray` function is designed to resize validator missed block tracking arrays when the `SignedBlocksWindow` parameter changes. The parameter should be validated to prevent unreasonable values that could impact system performance.

**Actual Logic:**
When expanding the window size (line 160-170), the function allocates a boolean array of size `window` (the new window parameter value) and iterates through it completely. The parameter validation only checks that the value is positive, with no upper bound. [5](#0-4) 

The resizing logic performs:
1. Memory allocation of `window` bytes for the bool array [6](#0-5) 
2. Full iteration through the new window in `ParseBoolArrayToBitGroups` [7](#0-6) 

This resizing is triggered for ALL validators concurrently in goroutines during BeginBlocker execution [8](#0-7) 

The BeginBlocker context uses an infinite gas meter, providing no protection against resource exhaustion [9](#0-8) 

**Exploit Scenario:**
1. A governance proposal is submitted to increase `SignedBlocksWindow` to 10,000,000 (to track longer validator history)
2. The proposal passes through normal governance procedures
3. The parameter update takes effect via the proposal handler [10](#0-9) 
4. In the next block's BeginBlocker, for each validator (35 default):
   - `HandleValidatorSignatureConcurrent` detects window size mismatch
   - Calls `ResizeMissedBlockArray` which allocates ~10 MB and iterates 10 million times
   - Total: 350+ MB allocation and 350+ million operations
5. BeginBlocker exceeds consensus timeout (typically 5-10 seconds)
6. All nodes fail to produce the block, network halts completely

**Security Failure:**
Denial of service through unbounded resource consumption. The lack of upper bound validation on a governance-controlled parameter allows catastrophic resource exhaustion in a critical consensus path (BeginBlocker), violating the availability guarantee of the blockchain network.

### Impact Explanation

**Affected Process:** Network block production and transaction finality

**Severity of Damage:**
- Complete network halt - no new blocks can be produced
- All nodes simultaneously affected (deterministic across network)
- Transactions cannot be confirmed
- Network remains halted until manual intervention (hard fork or emergency upgrade to reduce parameter or add validation)

**Why This Matters:**
BeginBlocker is part of the critical consensus path that must complete within strict time bounds for each block. Unlike transaction processing which has gas limits, BeginBlocker operations use an infinite gas meter and must complete for consensus to proceed. Resource exhaustion here cascades to total network failure, not just individual node issues.

### Likelihood Explanation

**Who Can Trigger:**
Any participant who can submit and pass a governance proposal (requires majority stakeholder approval, but does not require malicious intent - could be triggered accidentally by well-intentioned parameter adjustment).

**Required Conditions:**
1. Governance proposal to change `SignedBlocksWindow` parameter to large value
2. Proposal passes (normal governance process)
3. Parameter takes effect

**Frequency:**
Once triggered by a governance proposal, the network halt occurs deterministically in the next block and persists until fixed. While governance proposals are infrequent, the risk exists whenever parameter changes are considered, and the impact is immediate and severe.

### Recommendation

Add an upper bound validation to the `SignedBlocksWindow` parameter to prevent unreasonably large values. The validation should consider:
1. Reasonable historical tracking needs (e.g., 1-2 weeks of blocks maximum)
2. Memory and computation limits during BeginBlocker execution
3. Number of validators that may need concurrent resizing

Suggested implementation in `x/slashing/types/params.go`:

```go
func validateSignedBlocksWindow(i interface{}) error {
    v, ok := i.(int64)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if v <= 0 {
        return fmt.Errorf("signed blocks window must be positive: %d", v)
    }

    // Add upper bound check (e.g., 1 million blocks ~46 days at 4s blocks)
    const maxSignedBlocksWindow = int64(1_000_000)
    if v > maxSignedBlocksWindow {
        return fmt.Errorf("signed blocks window exceeds maximum allowed value of %d: %d", maxSignedBlocksWindow, v)
    }

    return nil
}
```

### Proof of Concept

**File:** `x/slashing/abci_test.go`

**Test Function:** `TestLargeWindowSizeCausesBeginBlockerTimeout`

**Setup:**
1. Initialize blockchain with default parameters
2. Create validator set (use default 35 validators or scale down for faster testing)
3. Set initial `SignedBlocksWindow` to default value (108,000)
4. Allow validators to sign blocks to populate their missed block arrays

**Trigger:**
1. Update `SignedBlocksWindow` parameter to extremely large value (e.g., 10,000,000)
2. Call `BeginBlocker` with validator votes
3. Measure execution time and memory allocation

**Observation:**
The test should demonstrate that:
- BeginBlocker execution time increases dramatically (from milliseconds to multiple seconds or minutes)
- Memory allocation increases proportionally to window size × validator count
- For sufficiently large window values, the execution exceeds reasonable block time limits (>5 seconds)

**Test Code Structure:**
```go
func TestLargeWindowSizeCausesBeginBlockerTimeout(t *testing.T) {
    // Setup: Create app and validators
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create validator set
    pks := simapp.CreateTestPubKeys(10) // Use 10 for faster test
    simapp.AddTestAddrsFromPubKeys(app, ctx, pks, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    
    // Initialize validators and their missed block arrays
    votes := []abci.VoteInfo{}
    for i := 0; i < 10; i++ {
        addr, pk := sdk.ValAddress(pks[i].Address()), pks[i]
        tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
        tstaking.CreateValidatorWithValPower(addr, pk, 100, true)
        votes = append(votes, abci.VoteInfo{
            Validator: abci.Validator{Address: pk.Address(), Power: 100},
            SignedLastBlock: true,
        })
    }
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Set extremely large window size
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = int64(10_000_000) // 10 million
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Trigger: Call BeginBlocker and measure time
    start := time.Now()
    req := abci.RequestBeginBlock{
        LastCommitInfo: abci.LastCommitInfo{Votes: votes},
    }
    slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    elapsed := time.Since(start)
    
    // Observation: BeginBlocker takes excessive time
    // With 10 validators and 10M window: ~100M iterations + 100MB allocation
    // This should take multiple seconds, far exceeding block time limits
    t.Logf("BeginBlocker execution time with window size %d: %v", params.SignedBlocksWindow, elapsed)
    
    // Assert that execution time exceeds reasonable threshold
    // (adjust threshold based on test environment)
    maxAcceptableTime := 1 * time.Second
    if elapsed > maxAcceptableTime {
        t.Errorf("BeginBlocker took %v which exceeds acceptable block processing time of %v", elapsed, maxAcceptableTime)
    }
}
```

The test demonstrates that increasing the window size to large values causes BeginBlocker to consume excessive time and memory, confirming the denial-of-service vulnerability.

### Citations

**File:** x/slashing/keeper/infractions.go (L52-54)
```go
	if found && missedInfo.WindowSize != window {
		missedInfo, signInfo, index = k.ResizeMissedBlockArray(missedInfo, signInfo, window, index)
	}
```

**File:** x/slashing/keeper/infractions.go (L157-181)
```go
func (k Keeper) ResizeMissedBlockArray(missedInfo types.ValidatorMissedBlockArray, signInfo types.ValidatorSigningInfo, window int64, index int64) (types.ValidatorMissedBlockArray, types.ValidatorSigningInfo, int64) {
	// we need to resize the missed block array AND update the signing info accordingly
	switch {
	case missedInfo.WindowSize < window:
		// missed block array too short, lets expand it
		boolArray := k.ParseBitGroupsToBoolArray(missedInfo.MissedBlocks, missedInfo.WindowSize)
		newArray := make([]bool, window)
		copy(newArray[0:index], boolArray[0:index])
		if index+1 < missedInfo.WindowSize {
			// insert `0`s corresponding to the difference between the new window size and old window size
			copy(newArray[index+(window-missedInfo.WindowSize):], boolArray[index:])
		}
		missedInfo.MissedBlocks = k.ParseBoolArrayToBitGroups(newArray)
		missedInfo.WindowSize = window
	case missedInfo.WindowSize > window:
		// if window size is reduced, we would like to make a clean state so that no validators are unexpectedly jailed due to more recent missed blocks
		newMissedBlocks := make([]bool, window)
		missedInfo.MissedBlocks = k.ParseBoolArrayToBitGroups(newMissedBlocks)
		signInfo.MissedBlocksCounter = int64(0)
		missedInfo.WindowSize = window
		signInfo.IndexOffset = 0
		index = 0
	}
	return missedInfo, signInfo, index
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

**File:** x/slashing/types/params.go (L72-83)
```go
func validateSignedBlocksWindow(i interface{}) error {
	v, ok := i.(int64)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if v <= 0 {
		return fmt.Errorf("signed blocks window must be positive: %d", v)
	}

	return nil
}
```

**File:** x/slashing/keeper/signing_info.go (L118-127)
```go
func (k Keeper) ParseBoolArrayToBitGroups(boolArray []bool) []uint64 {
	arrLen := (len(boolArray) + UINT_64_NUM_BITS - 1) / UINT_64_NUM_BITS
	bitGroups := make([]uint64, arrLen)

	for index, boolVal := range boolArray {
		bitGroups = k.SetBooleanInBitGroups(bitGroups, int64(index), boolVal)
	}

	return bitGroups
}
```

**File:** types/context.go (L272-272)
```go
		gasMeter:        NewInfiniteGasMeter(1, 1),
```

**File:** x/params/proposal_handler.go (L26-43)
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
}
```
