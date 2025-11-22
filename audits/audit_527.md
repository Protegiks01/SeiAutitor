## Audit Report

## Title
Mint Module Incorrectly Mints Tokens on First Block for Non-Existent Genesis Block

## Summary
The mint module's `BeginBlocker` function mints tokens on the first block (height 1) claiming to mint "for the previous block", but the previous block (block 0/genesis) is not a real block that executed any transactions or produced work deserving of newly minted tokens. This creates an accounting inconsistency where extra tokens are minted that shouldn't exist, unlike the distribution module which correctly skips the first block.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The mint module should mint new tokens as inflation rewards for blocks that actually execute transactions and produce work. The comment at line 12 states "BeginBlocker mints new tokens for the previous block", indicating rewards should be given for completed blocks.

**Actual Logic:** 
The `BeginBlocker` function executes unconditionally on every block, including height 1 (the first block after genesis/InitChain). At height 1, the "previous block" would be block 0 (genesis), which is not a real block but merely initialization state. The function calculates inflation, annual provisions, and block provisions, then mints tokens and sends them to the fee collector without any check to skip the first block. [2](#0-1) 

**Comparison with Correct Implementation:**
The distribution module correctly implements this logic by explicitly checking the block height before allocating rewards: [3](#0-2) 

Notice line 29 contains the check `if ctx.BlockHeight() > 1` before calling `AllocateTokens`, preventing reward distribution for the non-existent genesis block. The mint module lacks this crucial check.

**Exploit Scenario:** 
This is not an exploitable vulnerability in the traditional sense (no attacker can manipulate it), but it's an unintended protocol behavior that occurs deterministically:
1. Chain initializes via `InitChain` at conceptual height 0 (genesis)
2. First `BeginBlock` is called at height 1
3. Mint module's `BeginBlocker` executes and mints tokens based on: `(Inflation × TotalStakingSupply) / BlocksPerYear`
4. These tokens are sent to the fee collector
5. This minting occurs "for" the genesis block which didn't actually execute any transactions

**Security Failure:** 
This violates the accounting invariant that tokens should only be minted as rewards for actual block production. The protocol exhibits unintended behavior where the total supply is higher than intended by exactly one block's worth of inflation.

## Impact Explanation

**Affected Assets:**
- The total token supply is incorrectly inflated by one block's worth of minting
- The fee collector account receives tokens that shouldn't exist
- With default parameters (13% inflation, assuming 100M staked tokens, 6,307,200 blocks/year), approximately 2 tokens are incorrectly minted per chain at genesis

**Severity:**
While the absolute amount is relatively small, this represents:
1. An accounting error in the protocol's core economics
2. Inconsistent behavior between mint and distribution modules
3. A violation of the stated design ("mints new tokens for the previous block")
4. Unintended module behavior with no funds at direct risk (Medium per scope)

**Systemic Relevance:**
This issue affects every chain deployment using this codebase, and while the per-chain impact is small, it demonstrates incorrect protocol behavior in a critical system component.

## Likelihood Explanation

**Who Can Trigger:**
This occurs automatically and deterministically on every chain initialization. No attacker action is required - it's part of the normal chain startup process.

**Conditions Required:**
- Chain must be initialized (which happens for every new chain)
- First block (height 1 or InitialHeight) must execute `BeginBlock`
- Occurs exactly once per chain at genesis

**Frequency:**
- Guaranteed to occur on every chain deployment
- Cannot be prevented without code changes
- Happens exactly once (not repeatedly exploitable)

## Recommendation

Add a block height check in the mint module's `BeginBlocker` function, consistent with the distribution module's implementation:

```go
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
    defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

    // Skip minting on the first block to avoid minting for the genesis block
    if ctx.BlockHeight() <= 1 {
        return
    }

    // fetch stored minter & params
    minter := k.GetMinter(ctx)
    params := k.GetParams(ctx)
    // ... rest of the function
}
```

Alternatively, if the chain uses `InitialHeight > 1`, the check should be:
```go
if ctx.BlockHeight() <= app.InitialHeight() {
    return
}
```

This ensures tokens are only minted for actual blocks that executed transactions, maintaining consistency with the distribution module's behavior.

## Proof of Concept

**Test File:** `x/mint/keeper/genesis_minting_test.go` (new test file)

**Setup:**
1. Initialize a new SimApp with genesis state
2. Set up genesis accounts with initial balances and staking
3. Record the fee collector balance after genesis (before any blocks)
4. Execute BeginBlock for height 1
5. Record the fee collector balance after height 1

**Expected Behavior:**
No tokens should be minted on height 1 since there was no "previous block" to reward.

**Actual Behavior:**
Tokens are minted and sent to the fee collector on height 1.

**Test Code:**
```go
package keeper_test

import (
    "context"
    "testing"

    "github.com/stretchr/testify/require"
    abci "github.com/tendermint/tendermint/abci/types"
    tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

    "github.com/cosmos/cosmos-sdk/simapp"
    sdk "github.com/cosmos/cosmos-sdk/types"
    authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
    minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
)

func TestGenesisBlockNoMinting(t *testing.T) {
    app := simapp.Setup(false)
    
    // Initialize chain (genesis at height 0)
    app.InitChain(
        context.Background(),
        &abci.RequestInitChain{
            Validators:      []abci.ValidatorUpdate{},
            ConsensusParams: simapp.DefaultConsensusParams,
            AppStateBytes:   []byte("{}"),
            ChainId:         "test-chain",
        },
    )
    
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Get fee collector balance after genesis (should be 0 or genesis allocation)
    feeCollectorAddr := authtypes.NewModuleAddress(authtypes.FeeCollectorName)
    balanceBefore := app.BankKeeper.GetAllBalances(ctx, feeCollectorAddr)
    
    // Execute BeginBlock for height 1 (first real block)
    app.BeginBlock(ctx, abci.RequestBeginBlock{
        Header: tmproto.Header{
            ChainId: "test-chain",
            Height:  1,
            Time:    ctx.BlockTime(),
        },
    })
    
    // Get fee collector balance after first block
    balanceAfter := app.BankKeeper.GetAllBalances(ctx, feeCollectorAddr)
    
    // Calculate minted amount
    mintedAmount := balanceAfter.Sub(balanceBefore)
    
    // VULNERABILITY DEMONSTRATION:
    // Tokens were minted on height 1 "for the previous block" (genesis/height 0)
    // But genesis is not a real block, so no tokens should have been minted
    require.True(t, mintedAmount.IsZero(), 
        "Expected no tokens to be minted on first block for genesis, but got: %s", 
        mintedAmount.String())
}
```

**Observation:**
The test will fail because `mintedAmount` is not zero - tokens were minted on the first block when they shouldn't have been. The minted amount will be approximately `(AnnualProvisions / BlocksPerYear)` worth of tokens in the mint denomination.

To verify the inconsistency with the distribution module, compare with its behavior at height 1, which correctly skips processing due to the check at: [4](#0-3)

### Citations

**File:** x/mint/abci.go (L12-55)
```go
// BeginBlocker mints new tokens for the previous block.
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	// fetch stored minter & params
	minter := k.GetMinter(ctx)
	params := k.GetParams(ctx)

	// recalculate inflation rate
	totalStakingSupply := k.StakingTokenSupply(ctx)
	bondedRatio := k.BondedRatio(ctx)
	minter.Inflation = minter.NextInflationRate(params, bondedRatio)
	minter.AnnualProvisions = minter.NextAnnualProvisions(params, totalStakingSupply)
	k.SetMinter(ctx, minter)

	// mint coins, update supply
	mintedCoin := minter.BlockProvision(params)
	mintedCoins := sdk.NewCoins(mintedCoin)

	err := k.MintCoins(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	// send the minted coins to the fee collector account
	err = k.AddCollectedFees(ctx, mintedCoins)
	if err != nil {
		panic(err)
	}

	if mintedCoin.Amount.IsInt64() {
		defer telemetry.ModuleSetGauge(types.ModuleName, float32(mintedCoin.Amount.Int64()), "minted_tokens")
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeMint,
			sdk.NewAttribute(types.AttributeKeyBondedRatio, bondedRatio.String()),
			sdk.NewAttribute(types.AttributeKeyInflation, minter.Inflation.String()),
			sdk.NewAttribute(types.AttributeKeyAnnualProvisions, minter.AnnualProvisions.String()),
			sdk.NewAttribute(sdk.AttributeKeyAmount, mintedCoin.Amount.String()),
		),
	)
}
```

**File:** x/distribution/abci.go (L13-32)
```go
// BeginBlocker sets the proposer for determining distribution during endblock
// and distribute rewards for the previous block
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	// determine the total power signing the block
	var previousTotalPower, sumPreviousPrecommitPower int64
	for _, voteInfo := range req.LastCommitInfo.GetVotes() {
		previousTotalPower += voteInfo.Validator.Power
		if voteInfo.SignedLastBlock {
			sumPreviousPrecommitPower += voteInfo.Validator.Power
		}
	}

	// TODO this is Tendermint-dependent
	// ref https://github.com/cosmos/cosmos-sdk/issues/3095
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
	}
```
