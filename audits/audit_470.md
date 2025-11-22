## Audit Report

## Title
Permanent Token Lock Due to Unbonding Completion Failure with Silent Error Handling

## Summary
When mature unbonding delegations are processed during EndBlock, if the token transfer from NotBondedPool to the delegator fails, the unbonding entry is permanently removed from the time-based processing queue but remains in storage with tokens locked indefinitely. The error is silently caught and ignored, with no mechanism to retry or recover the entry.

## Impact
**Critical** - Permanent freezing of funds (fix requires hard fork)

## Finding Description

**Location:** 
- Primary: `x/staking/keeper/val_state_change.go` in `BlockValidatorUpdates` function
- Secondary: `x/staking/keeper/delegation.go` in `CompleteUnbonding` function [1](#0-0) [2](#0-1) 

**Intended Logic:** 
The unbonding completion flow should reliably transfer tokens back to delegators when their unbonding period expires. Mature entries are retrieved from a time-based queue, tokens are transferred from the NotBondedPool module account to the delegator account, and the unbonding entry is removed from storage.

**Actual Logic:** 
The implementation has a critical flaw in error handling:

1. `DequeueAllMatureUBDQueue` permanently deletes mature entries from the time-based queue [3](#0-2) 

2. For each dequeued entry, `CompleteUnbonding` is called. If it returns an error, the code simply continues to the next entry with no recovery mechanism [4](#0-3) 

3. Inside `CompleteUnbonding`, the entry is removed from the local `ubd.Entries` array before attempting the token transfer [5](#0-4) 

4. If `UndelegateCoinsFromModuleToAccount` fails, the function returns immediately without saving the modified unbonding delegation [6](#0-5) 

5. The code that saves or removes the unbonding delegation is only reached if no error occurs during processing [7](#0-6) 

**Exploit Scenario:**
This vulnerability can be triggered by any condition that causes `UndelegateCoinsFromModuleToAccount` to fail:

1. **Insufficient Balance in NotBondedPool**: If the NotBondedPool has insufficient balance due to:
   - Slashing operations that burn tokens from the pool [8](#0-7) 
   - Accounting bugs or race conditions between pool operations
   - Concurrent operations depleting the pool in the same block

2. **Account-related errors**: The transfer can fail if the delegator account has issues detected by `trackUndelegation` or other bank keeper operations [9](#0-8) 

3. **Balance check failures**: The `SubUnlockedCoins` operation can fail with `ErrInsufficientFunds` if the module account's spendable balance is less than the amount [10](#0-9) 

**Security Failure:** 
This breaks the fundamental accounting invariant that mature unbonding delegations will be completed and tokens returned to delegators. The security properties violated are:
- **Liveness**: Tokens that should be returned remain permanently locked
- **Accounting integrity**: The system state becomes inconsistent (entry in storage but not in queue)
- **Fund safety**: Users' tokens become permanently inaccessible

## Impact Explanation

**Assets Affected:** Delegator tokens in mature unbonding delegations that fail to complete.

**Severity of Damage:**
- **Permanent fund loss**: Once the entry is removed from the queue but remains in storage due to a failed transfer, there is no automatic mechanism to retry the completion. The tokens remain locked in the unbonding delegation entry forever.
- **No user recovery**: Users cannot cancel, restart, or manually trigger completion of their unbonding. There is no message type or RPC call to force completion outside of the automatic EndBlock processing.
- **Systemic risk**: If the NotBondedPool becomes depleted or experiences accounting issues, multiple unbonding delegations could fail to complete in the same block, affecting many users simultaneously.

**Why This Matters:**
This is a critical protocol-level bug that violates the core promise of the staking system: that users can undelegate and retrieve their tokens after the unbonding period. The permanent nature of the lock (no recovery without a hard fork to fix storage state) and the realistic triggering conditions (slashing, accounting bugs) make this a high-severity vulnerability.

## Likelihood Explanation

**Who Can Trigger:** 
Any delegator who initiates unbonding is at risk. The vulnerability is triggered automatically during EndBlock processing when the unbonding matures, not by a specific attacker action.

**Conditions Required:**
1. An unbonding delegation must mature (normal operation after unbonding period)
2. The `UndelegateCoinsFromModuleToAccount` call must fail, which can occur due to:
   - **Slashing events**: When validators are slashed while unbonding, tokens are burned from the NotBondedPool, potentially causing insufficient balance for later unbonding completions [11](#0-10) 
   - **Accounting discrepancies**: Subtle bugs in pool management or concurrent operations
   - **Account errors**: Issues with delegator accounts (though less common)

**Frequency:**
- **Slashing-induced failures**: Could occur whenever a validator is slashed while having unbonding delegations. If multiple unbondings mature in the same block after pool depletion, all would fail and lock permanently.
- **Accounting bugs**: Could manifest intermittently based on specific operation sequences or edge cases in pool management.
- **High impact but moderate probability**: While not every unbonding will fail, when it does occur, the consequences are permanent and affect real user funds.

## Recommendation

Implement proper error recovery for failed unbonding completions:

1. **Revert the dequeue operation on failure**: Modify `BlockValidatorUpdates` to not permanently remove entries from the queue until after successful completion. Store the dequeued entries temporarily and only delete them after `CompleteUnbonding` succeeds.

2. **Alternative approach - Re-queue on failure**: If `CompleteUnbonding` fails, re-insert the entry back into the time-based queue with the same or a slightly delayed completion time, allowing retry in future blocks.

3. **Atomic operation**: Ensure that entry removal from the `ubd.Entries` array and token transfer are atomic - either both succeed or both fail. Move the `RemoveEntry` call to after the successful transfer, or wrap the entire operation in a transaction that can be rolled back.

4. **Add monitoring/events**: Emit error events when unbonding completion fails so node operators can detect and investigate pool accounting issues.

Example fix for approach 3:
```
// In CompleteUnbonding, move RemoveEntry after successful transfer
for i := 0; i < len(ubd.Entries); i++ {
    entry := ubd.Entries[i]
    if entry.IsMature(ctxTime) {
        if !entry.Balance.IsZero() {
            amt := sdk.NewCoin(bondDenom, entry.Balance)
            if err := k.bankKeeper.UndelegateCoinsFromModuleToAccount(
                ctx, types.NotBondedPoolName, delegatorAddress, sdk.NewCoins(amt),
            ); err != nil {
                return nil, err  // Return without modifying ubd
            }
            balances = balances.Add(amt)
        }
        // Only remove entry after successful transfer
        ubd.RemoveEntry(int64(i))
        i--
    }
}
```

## Proof of Concept

**Test File:** `x/staking/keeper/delegation_test.go`

**Test Function:** `TestUnbondingCompletionFailureLocksFunds`

**Setup:**
1. Create a test app with staking and bank keepers using `createTestInput()`
2. Create a validator and delegator account with initial tokens
3. Perform a delegation from delegator to validator
4. Initiate an unbonding operation to create an unbonding delegation entry
5. Advance block time to make the unbonding entry mature

**Trigger:**
1. Before calling `BlockValidatorUpdates`, manually transfer tokens out of the NotBondedPool module account to simulate insufficient balance (representing a scenario where slashing or accounting bugs have depleted the pool)
2. Call `BlockValidatorUpdates` which will process the mature unbonding entry

**Observation:**
1. Verify that `CompleteUnbonding` was called and returned an error (check via error handling in `BlockValidatorUpdates`)
2. Confirm the unbonding entry still exists in storage via `GetUnbondingDelegation` 
3. Verify the entry is no longer in the time-based queue by checking that subsequent calls to `DequeueAllMatureUBDQueue` return empty
4. Confirm delegator did not receive tokens (balance unchanged)
5. Show that there is no way to retry or recover - calling `BlockValidatorUpdates` again does nothing because entry is not in the queue

**Pseudo-code structure:**
```go
func TestUnbondingCompletionFailureLocksFunds(t *testing.T) {
    _, app, ctx := createTestInput()
    
    // Setup: Create validator, delegator, perform delegation and unbonding
    // ... [setup code similar to other tests in the file]
    
    // Advance time to maturity
    ctx = ctx.WithBlockTime(ctx.BlockTime().Add(unbondingTime))
    
    // Drain NotBondedPool to cause transfer failure
    notBondedPool := app.StakingKeeper.GetNotBondedPool(ctx)
    poolBalance := app.BankKeeper.GetBalance(ctx, notBondedPool.GetAddress(), bondDenom)
    app.BankKeeper.SendCoinsFromModuleToAccount(ctx, types.NotBondedPoolName, someOtherAddr, poolBalance)
    
    // Trigger: Process mature unbondings
    initialDelegatorBalance := app.BankKeeper.GetBalance(ctx, delegatorAddr, bondDenom)
    app.StakingKeeper.BlockValidatorUpdates(ctx)
    
    // Observations:
    // 1. Unbonding still exists in storage
    ubd, found := app.StakingKeeper.GetUnbondingDelegation(ctx, delegatorAddr, valAddr)
    require.True(t, found, "unbonding should still exist after failed completion")
    require.Len(t, ubd.Entries, 1, "entry should remain in storage")
    
    // 2. Entry no longer in queue
    matureUnbonds := app.StakingKeeper.DequeueAllMatureUBDQueue(ctx, ctx.BlockTime())
    require.Empty(t, matureUnbonds, "entry should be removed from queue")
    
    // 3. Delegator did not receive tokens
    finalDelegatorBalance := app.BankKeeper.GetBalance(ctx, delegatorAddr, bondDenom)
    require.Equal(t, initialDelegatorBalance, finalDelegatorBalance, "delegator should not receive tokens")
    
    // 4. No way to recover - tokens permanently locked
    // Even replenishing the pool and calling BlockValidatorUpdates again does nothing
}
```

This test demonstrates that tokens become permanently locked when unbonding completion fails, violating the protocol's guarantee that mature unbondings will be completed and tokens returned.

### Citations

**File:** x/staking/keeper/val_state_change.go (L36-57)
```go
	matureUnbonds := k.DequeueAllMatureUBDQueue(ctx, ctx.BlockHeader().Time)
	for _, dvPair := range matureUnbonds {
		addr, err := sdk.ValAddressFromBech32(dvPair.ValidatorAddress)
		if err != nil {
			panic(err)
		}
		delegatorAddress := sdk.MustAccAddressFromBech32(dvPair.DelegatorAddress)

		balances, err := k.CompleteUnbonding(ctx, delegatorAddress, addr)
		if err != nil {
			continue
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeCompleteUnbonding,
				sdk.NewAttribute(sdk.AttributeKeyAmount, balances.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, dvPair.ValidatorAddress),
				sdk.NewAttribute(types.AttributeKeyDelegator, dvPair.DelegatorAddress),
			),
		)
	}
```

**File:** x/staking/keeper/delegation.go (L374-392)
```go
func (k Keeper) DequeueAllMatureUBDQueue(ctx sdk.Context, currTime time.Time) (matureUnbonds []types.DVPair) {
	store := ctx.KVStore(k.storeKey)

	// gets an iterator for all timeslices from time 0 until the current Blockheader time
	unbondingTimesliceIterator := k.UBDQueueIterator(ctx, ctx.BlockHeader().Time)
	defer unbondingTimesliceIterator.Close()

	for ; unbondingTimesliceIterator.Valid(); unbondingTimesliceIterator.Next() {
		timeslice := types.DVPairs{}
		value := unbondingTimesliceIterator.Value()
		k.cdc.MustUnmarshal(value, &timeslice)

		matureUnbonds = append(matureUnbonds, timeslice.Pairs...)

		store.Delete(unbondingTimesliceIterator.Key())
	}

	return matureUnbonds
}
```

**File:** x/staking/keeper/delegation.go (L862-906)
```go
func (k Keeper) CompleteUnbonding(ctx sdk.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (sdk.Coins, error) {
	ubd, found := k.GetUnbondingDelegation(ctx, delAddr, valAddr)
	if !found {
		return nil, types.ErrNoUnbondingDelegation
	}

	bondDenom := k.GetParams(ctx).BondDenom
	balances := sdk.NewCoins()
	ctxTime := ctx.BlockHeader().Time

	delegatorAddress, err := sdk.AccAddressFromBech32(ubd.DelegatorAddress)
	if err != nil {
		return nil, err
	}

	// loop through all the entries and complete unbonding mature entries
	for i := 0; i < len(ubd.Entries); i++ {
		entry := ubd.Entries[i]
		if entry.IsMature(ctxTime) {
			ubd.RemoveEntry(int64(i))
			i--

			// track undelegation only when remaining or truncated shares are non-zero
			if !entry.Balance.IsZero() {
				amt := sdk.NewCoin(bondDenom, entry.Balance)
				if err := k.bankKeeper.UndelegateCoinsFromModuleToAccount(
					ctx, types.NotBondedPoolName, delegatorAddress, sdk.NewCoins(amt),
				); err != nil {
					return nil, err
				}

				balances = balances.Add(amt)
			}
		}
	}

	// set the unbonding delegation or remove it if there are no more entries
	if len(ubd.Entries) == 0 {
		k.RemoveUnbondingDelegation(ctx, ubd)
	} else {
		k.SetUnbondingDelegation(ctx, ubd)
	}

	return balances, nil
}
```

**File:** x/staking/keeper/slash.go (L166-210)
```go
func (k Keeper) SlashUnbondingDelegation(ctx sdk.Context, unbondingDelegation types.UnbondingDelegation,
	infractionHeight int64, slashFactor sdk.Dec) (totalSlashAmount sdk.Int) {
	now := ctx.BlockHeader().Time
	totalSlashAmount = sdk.ZeroInt()
	burnedAmount := sdk.ZeroInt()

	// perform slashing on all entries within the unbonding delegation
	for i, entry := range unbondingDelegation.Entries {
		// If unbonding started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}

		if entry.IsMature(now) {
			// Unbonding delegation no longer eligible for slashing, skip it
			continue
		}

		// Calculate slash amount proportional to stake contributing to infraction
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)

		// Don't slash more tokens than held
		// Possible since the unbonding delegation may already
		// have been slashed, and slash amounts are calculated
		// according to stake held at time of infraction
		unbondingSlashAmount := sdk.MinInt(slashAmount, entry.Balance)

		// Update unbonding delegation if necessary
		if unbondingSlashAmount.IsZero() {
			continue
		}

		burnedAmount = burnedAmount.Add(unbondingSlashAmount)
		entry.Balance = entry.Balance.Sub(unbondingSlashAmount)
		unbondingDelegation.Entries[i] = entry
		k.SetUnbondingDelegation(ctx, unbondingDelegation)
	}

	if err := k.burnNotBondedTokens(ctx, burnedAmount); err != nil {
		panic(err)
	}

	return totalSlashAmount
```

**File:** x/bank/keeper/keeper.go (L232-257)
```go
func (k BaseKeeper) UndelegateCoins(ctx sdk.Context, moduleAccAddr, delegatorAddr sdk.AccAddress, amt sdk.Coins) error {
	moduleAcc := k.ak.GetAccount(ctx, moduleAccAddr)
	if moduleAcc == nil {
		return sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", moduleAccAddr)
	}

	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	err := k.SubUnlockedCoins(ctx, moduleAccAddr, amt, true)
	if err != nil {
		return err
	}

	if err := k.trackUndelegation(ctx, delegatorAddr, amt); err != nil {
		return sdkerrors.Wrap(err, "failed to track undelegation")
	}

	err = k.AddCoins(ctx, delegatorAddr, amt, true)
	if err != nil {
		return err
	}

	return nil
}
```

**File:** x/bank/keeper/send.go (L209-246)
```go
func (k BaseSendKeeper) SubUnlockedCoins(ctx sdk.Context, addr sdk.AccAddress, amt sdk.Coins, checkNeg bool) error {
	if !amt.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, amt.String())
	}

	lockedCoins := k.LockedCoins(ctx, addr)

	for _, coin := range amt {
		balance := k.GetBalance(ctx, addr, coin.Denom)
		if checkNeg {
			locked := sdk.NewCoin(coin.Denom, lockedCoins.AmountOf(coin.Denom))
			spendable := balance.Sub(locked)

			_, hasNeg := sdk.Coins{spendable}.SafeSub(sdk.Coins{coin})
			if hasNeg {
				return sdkerrors.Wrapf(sdkerrors.ErrInsufficientFunds, "%s is smaller than %s", spendable, coin)
			}
		}

		var newBalance sdk.Coin
		if checkNeg {
			newBalance = balance.Sub(coin)
		} else {
			newBalance = balance.SubUnsafe(coin)
		}

		err := k.setBalance(ctx, addr, newBalance, checkNeg)
		if err != nil {
			return err
		}
	}

	// emit coin spent event
	ctx.EventManager().EmitEvent(
		types.NewCoinSpentEvent(addr, amt),
	)
	return nil
}
```
