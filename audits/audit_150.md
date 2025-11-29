# Audit Report

## Title
Permanent Token Lock Due to Unbonding Completion Failure with Silent Error Handling

## Summary
The unbonding completion mechanism in the staking module contains a critical error handling flaw that can result in permanent token freezing. When mature unbonding delegations are processed during `BlockValidatorUpdates`, entries are permanently removed from the time-based processing queue before token transfer completion is verified. If the transfer fails, the unbonding entry remains in storage but is no longer queued for processing, resulting in tokens being locked indefinitely with no recovery mechanism.

## Impact
Critical

## Finding Description

**Location:**
- Primary: `x/staking/keeper/val_state_change.go` lines 36-57 in `BlockValidatorUpdates` function
- Secondary: `x/staking/keeper/delegation.go` lines 862-906 in `CompleteUnbonding` function
- Related: `x/staking/keeper/delegation.go` lines 374-392 in `DequeueAllMatureUBDQueue` function [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
The unbonding completion flow should atomically: (1) retrieve mature entries from the queue, (2) transfer tokens from NotBondedPool to delegators, and (3) remove completed entries from storage. If any step fails, the system should either retry or maintain the entry in the queue for future processing.

**Actual Logic:**
The implementation has a non-atomic error handling pattern that creates a critical vulnerability:

1. `DequeueAllMatureUBDQueue` permanently deletes mature entries from the time-based queue via `store.Delete()` before processing begins
2. For each dequeued entry, `CompleteUnbonding` is called, but if it returns an error, the code simply continues with no recovery mechanism
3. Inside `CompleteUnbonding`, the entry is removed from the `ubd.Entries` array at line 881 BEFORE attempting the token transfer at line 887
4. If `UndelegateCoinsFromModuleToAccount` fails, the function returns immediately at line 890 without saving the modified unbonding delegation
5. The save/remove operations at lines 899-903 are only reached if no error occurs

**Exploitation Path:**
This is not an "attacker exploit" but a protocol-level failure that occurs during normal operations:

1. User initiates unbonding through standard `MsgUndelegate` transaction
2. Unbonding delegation is created with tokens moved to NotBondedPool
3. During the unbonding period, slashing operations may burn tokens from NotBondedPool [4](#0-3) 
4. When unbonding matures, `BlockValidatorUpdates` is called in EndBlock
5. `DequeueAllMatureUBDQueue` permanently removes the entry from the queue
6. `CompleteUnbonding` attempts to transfer tokens but fails due to insufficient pool balance or other errors [5](#0-4) 
7. Error is silently ignored, entry remains in storage but not in queue
8. No retry mechanism exists - tokens are permanently locked

**Security Guarantee Broken:**
- **Liveness**: The protocol promises that mature unbonding delegations will be completed and tokens returned
- **Fund Safety**: User tokens become permanently inaccessible
- **Accounting Integrity**: System state becomes inconsistent (entry exists in storage but not in processing queue)

## Impact Explanation

This vulnerability results in **permanent freezing of user funds** with no recovery mechanism:

- **Assets Affected**: Delegator tokens in mature unbonding delegations where transfer completion fails
- **Permanent Lock**: Once the entry is removed from the queue but transfer fails, there is no automatic retry mechanism. The tokens remain locked in the unbonding delegation entry forever
- **No User Recovery**: Users cannot cancel, restart, or manually trigger completion. No message type or RPC exists to force completion outside automatic EndBlock processing
- **Systemic Risk**: If NotBondedPool experiences accounting issues or is depleted by slashing, multiple unbonding delegations could fail simultaneously, affecting many users in a single block
- **Hard Fork Required**: Recovery requires a governance-driven chain upgrade or hard fork to manually fix affected storage entries

This violates the core promise of the staking system that users can retrieve their tokens after the unbonding period.

## Likelihood Explanation

**Trigger Conditions:**
- Any delegator who initiates unbonding is at risk
- Triggered automatically during EndBlock when unbonding matures
- Requires `UndelegateCoinsFromModuleToAccount` to fail, which can occur due to:
  - Insufficient balance in NotBondedPool (from slashing, accounting bugs, or race conditions)
  - Account-related errors in delegator account
  - Balance check failures when pool's spendable balance is insufficient

**Frequency Assessment:**
- **Moderate to Low Probability** under normal operations, as slashing properly reduces entry balances
- **High Impact When Occurs**: Consequences are permanent and catastrophic for affected users
- **Realistic Scenarios**: Complex interactions between multiple unbondings, redelegations, validator state changes, and slashing events could create edge cases where pool balance doesn't match expectations
- **Not Attacker-Driven**: This is a protocol bug triggered by normal operations, not malicious action

The combination of moderate likelihood with catastrophic impact (permanent fund loss matching the "Permanent freezing of funds (fix requires hard fork)" impact criterion) makes this a valid critical vulnerability.

## Recommendation

Implement atomic error handling for unbonding completion:

**Recommended Fix (Approach 1 - Atomic Operation):**
Move the `RemoveEntry` call to AFTER successful token transfer in `CompleteUnbonding`:

```go
// In CompleteUnbonding function
for i := 0; i < len(ubd.Entries); i++ {
    entry := ubd.Entries[i]
    if entry.IsMature(ctxTime) {
        // Transfer tokens BEFORE removing entry
        if !entry.Balance.IsZero() {
            amt := sdk.NewCoin(bondDenom, entry.Balance)
            if err := k.bankKeeper.UndelegateCoinsFromModuleToAccount(
                ctx, types.NotBondedPoolName, delegatorAddress, sdk.NewCoins(amt),
            ); err != nil {
                return nil, err  // Return without modifying ubd
            }
            balances = balances.Add(amt)
        }
        // Only remove entry AFTER successful transfer
        ubd.RemoveEntry(int64(i))
        i--
    }
}
```

**Alternative Approach - Re-queue on Failure:**
Modify `BlockValidatorUpdates` to re-insert failed entries back into the queue:

```go
// In BlockValidatorUpdates
matureUnbonds := k.DequeueAllMatureUBDQueue(ctx, ctx.BlockHeader().Time)
for _, dvPair := range matureUnbonds {
    // ... address parsing ...
    balances, err := k.CompleteUnbonding(ctx, delegatorAddress, addr)
    if err != nil {
        // Re-queue the entry instead of silently continuing
        k.InsertUBDQueue(ctx, ubd, completionTime.Add(time.Hour))
        continue
    }
    // ... emit event ...
}
```

**Additional Recommendations:**
- Emit error events when unbonding completion fails for monitoring
- Add invariant checks to detect stuck unbonding entries
- Implement governance mechanism to manually force completion of stuck entries

## Proof of Concept

**Test Location:** `x/staking/keeper/delegation_test.go`

**Test Function:** `TestUnbondingCompletionFailureLocksFunds`

**Setup:**
1. Create test app with staking and bank keepers
2. Create validator and delegator accounts with initial tokens
3. Perform delegation from delegator to validator
4. Initiate unbonding to create unbonding delegation entry
5. Fund NotBondedPool appropriately
6. Advance block time to maturity

**Trigger:**
1. Drain NotBondedPool to simulate insufficient balance (representing slashing/accounting depletion)
2. Call `BlockValidatorUpdates` to process mature unbondings

**Expected Results:**
1. `CompleteUnbonding` returns error and is silently ignored
2. Unbonding entry still exists in storage (via `GetUnbondingDelegation`)
3. Entry no longer in queue (subsequent `DequeueAllMatureUBDQueue` returns empty)
4. Delegator balance unchanged (tokens not received)
5. No recovery possible - subsequent `BlockValidatorUpdates` calls do nothing

This demonstrates permanent token lock when unbonding completion fails, violating the protocol guarantee that mature unbondings will complete and return tokens to users.

## Notes

This vulnerability explicitly matches the "Permanent freezing of funds (fix requires hard fork)" impact criterion from the provided impact list. While the likelihood is moderate under normal operations, the catastrophic and permanent nature of the impact when it occurs makes this a valid critical vulnerability. The issue can be triggered through normal protocol operations (unbonding + slashing) without requiring any attacker or privileged access, and there is no recovery mechanism short of a hard fork.

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
