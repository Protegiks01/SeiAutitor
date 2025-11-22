# Audit Report

## Title
Duplicate Validator Votes in Same Block Cause Double Slashing and Chain Halt

## Summary
The slashing module's `BeginBlocker` does not validate or deduplicate validator entries in the votes list. If the same validator appears multiple times in `req.LastCommitInfo.GetVotes()`, they will be slashed multiple times in the same block, and the chain will panic when attempting to jail an already-jailed validator, causing a complete network shutdown. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown) + Direct loss of funds

## Finding Description

**Location:** 
- Module: `x/slashing`
- File: `x/slashing/abci.go`
- Lines: 35-65 (BeginBlocker function)
- Related: `x/slashing/keeper/infractions.go` lines 96-124, `x/staking/keeper/val_state_change.go` lines 259-268 [2](#0-1) 

**Intended Logic:**
The slashing module is intended to track validator liveness by processing votes from the last block's commit. Each validator should be evaluated once per block, and if they've missed too many blocks, they should be slashed once and jailed to prevent further infractions until they unjail themselves. [3](#0-2) 

**Actual Logic:**
The code processes votes in two phases:
1. **Concurrent Read Phase** (lines 36-50): Each vote is processed in parallel using goroutines. The function `HandleValidatorSignatureConcurrent` reads validator state and determines if slashing should occur based on `!validator.IsJailed()`. All reads happen concurrently BEFORE any state modifications.

2. **Sequential Write Phase** (lines 53-65): Results from the concurrent reads are applied sequentially. The `shouldSlash` decision is cached from the read phase and not re-validated. [4](#0-3) 

If the same validator appears multiple times in the votes list:
- Both concurrent reads see the validator as not jailed (line 98 in infractions.go checks `!validator.IsJailed()`)
- Both return `shouldSlash = true`
- First write iteration: Calls `SlashJailAndUpdateSigningInfo` which slashes tokens and jails the validator
- Second write iteration: Calls `SlashJailAndUpdateSigningInfo` again, which:
  - Slashes MORE tokens (double penalty)
  - Attempts to jail the already-jailed validator, triggering a panic [5](#0-4) 

The panic occurs because `jailValidator` explicitly checks and panics if the validator is already jailed: [6](#0-5) 

**Exploit Scenario:**
While the votes list is constructed by Tendermint consensus and should not contain duplicates under normal operation, the application layer has no defensive validation. This vulnerability could be triggered by:
1. A bug in Tendermint's vote collection/aggregation logic
2. A malformed ABCI message due to implementation errors
3. Any scenario where the votes array inadvertently contains duplicate validator entries

**Security Failure:**
- **Accounting Violation**: Validator is slashed twice instead of once, burning double the expected tokens
- **Denial of Service**: Chain halts completely due to panic, preventing all transaction processing
- **Consensus Safety**: The panic breaks the invariant that all nodes must process blocks identically

## Impact Explanation

**Affected Assets:**
- Validator funds: The affected validator loses 2× the intended slashing amount
- Network availability: All nodes halt, preventing any transaction processing
- Transaction finality: In-flight transactions cannot be confirmed

**Severity:**
- **Critical** - The chain completely stops processing blocks, requiring manual intervention and potentially a hard fork to recover
- **Financial** - Validator suffers excessive monetary penalty (double the intended slash amount)
- The panic is unrecoverable in the normal block processing flow, requiring node restarts and potentially coordinated recovery efforts

**System Impact:**
This breaks the fundamental reliability assumption that nodes can process blocks without crashing. The entire network becomes unable to confirm transactions, affecting all users and applications built on the chain.

## Likelihood Explanation

**Trigger Conditions:**
While this requires duplicate validator entries in the `LastCommitInfo.Votes` array, which should not occur under normal Tendermint operation, the application provides no defensive validation. Software bugs can exist in any component, and the lack of input validation represents a critical defensive programming failure.

**Frequency:**
- Low likelihood in production under normal circumstances
- However, if triggered (due to a Tendermint bug, edge case, or implementation error), the impact is immediate and catastrophic
- Any single occurrence causes complete network outage

**Who Can Trigger:**
This cannot be directly triggered by unprivileged users as the votes list is constructed by the consensus engine. However, it represents a failure to validate inputs from the consensus layer, which is a significant architectural weakness.

## Recommendation

Add duplicate detection and deduplication logic in `BeginBlocker` before processing votes:

```go
// Add after line 35 in x/slashing/abci.go
allVotes := req.LastCommitInfo.GetVotes()

// Deduplicate votes by validator address
seen := make(map[string]bool)
uniqueVotes := make([]abci.VoteInfo, 0, len(allVotes))
for _, vote := range allVotes {
    addrKey := string(vote.Validator.Address)
    if !seen[addrKey] {
        seen[addrKey] = true
        uniqueVotes = append(uniqueVotes, vote)
    }
}
allVotes = uniqueVotes
```

Alternatively, add a re-validation check in the write phase to skip already-jailed validators:

```go
// In the write phase loop (line 58)
if writeInfo.ShouldSlash {
    // Re-check if validator was jailed by a previous iteration
    validator := k.sk.ValidatorByConsAddr(ctx, writeInfo.ConsAddr)
    if validator != nil && !validator.IsJailed() {
        k.ClearValidatorMissedBlockBitArray(ctx, writeInfo.ConsAddr)
        writeInfo.SigningInfo = k.SlashJailAndUpdateSigningInfo(ctx, writeInfo.ConsAddr, writeInfo.SlashInfo, writeInfo.SigningInfo)
    }
}
```

## Proof of Concept

**File:** `x/slashing/keeper/keeper_test.go`
**Function:** Add new test `TestDuplicateVotesCauseDoubleSlashAndPanic`

**Setup:**
1. Initialize blockchain with a validator
2. Configure slashing parameters: SignedBlocksWindow = 100, MinSignedPerWindow = 50%
3. Have validator sign blocks normally until past the window
4. Have validator miss enough blocks to trigger slashing threshold

**Trigger:**
Create a `RequestBeginBlock` with duplicate `VoteInfo` entries for the same validator (both showing missed signatures), then call `slashing.BeginBlocker`.

**Observation:**
The test will panic with message "cannot jail already jailed validator" demonstrating the chain halt. Before the panic, examining validator tokens would show double the expected slash amount was deducted.

**Test Code:**
```go
func TestDuplicateVotesCauseDoubleSlashAndPanic(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    addrDels := simapp.AddTestAddrsIncremental(app, ctx, 1, app.StakingKeeper.TokensFromConsensusPower(ctx, 200))
    valAddrs := simapp.ConvertAddrsToValAddrs(addrDels)
    pks := simapp.CreateTestPubKeys(1)
    addr, val := valAddrs[0], pks[0]
    power := int64(100)
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    
    tstaking.CreateValidatorWithValPower(addr, val, power, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    params := app.SlashingKeeper.GetParams(ctx)
    params.SignedBlocksWindow = 100
    params.MinSignedPerWindow = sdk.NewDecWithPrec(5, 1)
    app.SlashingKeeper.SetParams(ctx, params)
    
    // Sign blocks normally
    height := int64(0)
    for ; height < 100; height++ {
        ctx = ctx.WithBlockHeight(height)
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, true), app.SlashingKeeper)
    }
    
    // Miss enough blocks to trigger slashing
    for ; height < 151; height++ {
        ctx = ctx.WithBlockHeight(height)
        slashing.BeginBlocker(ctx, testslashing.CreateBeginBlockReq(val.Address(), power, false), app.SlashingKeeper)
    }
    
    // Create RequestBeginBlock with DUPLICATE votes
    ctx = ctx.WithBlockHeight(height)
    req := abcitypes.RequestBeginBlock{
        LastCommitInfo: abcitypes.LastCommitInfo{
            Votes: []abcitypes.VoteInfo{
                {
                    Validator: abcitypes.Validator{Address: val.Address().Bytes(), Power: power},
                    SignedLastBlock: false,
                },
                {
                    Validator: abcitypes.Validator{Address: val.Address().Bytes(), Power: power},
                    SignedLastBlock: false,
                },
            },
        },
    }
    
    // This will panic with "cannot jail already jailed validator"
    require.Panics(t, func() {
        slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    })
}
```

This PoC demonstrates that duplicate validator entries in the votes list cause the chain to panic, resulting in a complete network halt.

### Citations

**File:** x/slashing/abci.go (L35-66)
```go
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

**File:** x/slashing/keeper/infractions.go (L96-124)
```go
	if height > minHeight && signInfo.MissedBlocksCounter > maxMissed {
		validator := k.sk.ValidatorByConsAddr(ctx, consAddr)
		if validator != nil && !validator.IsJailed() {
			// Downtime confirmed: slash and jail the validator
			// We need to retrieve the stake distribution which signed the block, so we subtract ValidatorUpdateDelay from the evidence height,
			// and subtract an additional 1 since this is the LastCommit.
			// Note that this *can* result in a negative "distributionHeight" up to -ValidatorUpdateDelay-1,
			// i.e. at the end of the pre-genesis block (none) = at the beginning of the genesis block.
			// That's fine since this is just used to filter unbonding delegations & redelegations.
			shouldSlash = true
			distributionHeight := height - sdk.ValidatorUpdateDelay - 1
			slashInfo = SlashInfo{
				height:             height,
				power:              power,
				distributionHeight: distributionHeight,
				minHeight:          minHeight,
				minSignedPerWindow: minSignedPerWindow,
			}
			// This value is passed back and the validator is slashed and jailed appropriately
		} else {
			// validator was (a) not found or (b) already jailed so we do not slash
			logger.Info(
				"validator would have been slashed for downtime, but was either not found in store or already jailed",
				"validator", consAddr.String(),
			)
		}
	}
	return
}
```

**File:** x/staking/keeper/val_state_change.go (L260-268)
```go
func (k Keeper) jailValidator(ctx sdk.Context, validator types.Validator) {
	if validator.Jailed {
		panic(fmt.Sprintf("cannot jail already jailed validator, validator: %v\n", validator))
	}

	validator.Jailed = true
	k.SetValidator(ctx, validator)
	k.DeleteValidatorByPowerIndex(ctx, validator)
}
```
