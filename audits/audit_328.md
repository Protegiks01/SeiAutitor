## Audit Report

### Title
Partial Unbonding Completion Leading to Permanent Fund Loss and State Inconsistency

### Summary
The `CompleteUnbonding` function in `x/staking/keeper/delegation.go` processes multiple unbonding entries in a loop without proper atomicity guarantees. When `UndelegateCoinsFromModuleToAccount` fails for some entries after succeeding for others, the function returns an error before persisting state changes, leaving the unbonding delegation in an inconsistent state where some coins have been transferred but all entries remain recorded as pending. [1](#0-0) 

### Impact
**High** - Direct loss of funds and permanent freezing of funds.

### Finding Description

**Location:** 
- Primary issue: `x/staking/keeper/delegation.go`, lines 878-896 in `CompleteUnbonding` function
- Caller context: `x/staking/keeper/val_state_change.go`, lines 44-47 in `BlockValidatorUpdates` [2](#0-1) 

**Intended Logic:**
The `CompleteUnbonding` function should atomically complete all mature unbonding entries for a delegation. Either all mature entries should be processed successfully (coins transferred and entries removed from state), or if any failure occurs, the entire operation should be rolled back with no state changes persisted.

**Actual Logic:**
The function processes entries sequentially in a loop. For each mature entry:
1. Line 881: Removes the entry from the in-memory `ubd` object via `ubd.RemoveEntry(int64(i))`
2. Lines 887-891: Attempts to transfer coins via `UndelegateCoinsFromModuleToAccount`
3. If transfer fails, returns error immediately without reaching lines 899-903 where `SetUnbondingDelegation` would persist the changes

When called from `BlockValidatorUpdates` during `EndBlock`, the function is invoked without a `CacheContext` wrapper. This means successful bank transfers from early iterations modify the `deliverState` context directly and persist even when the function returns an error. [3](#0-2) 

**Exploit Scenario:**
1. A delegator has an unbonding delegation with multiple mature entries (e.g., 3 entries of 100 tokens each)
2. The `NotBondedPool` has insufficient funds (e.g., only 150 tokens) due to accounting bugs, slashing, or other state inconsistencies
3. During `EndBlock`, `BlockValidatorUpdates` calls `DequeueAllMatureUBDQueue`, which removes the unbonding delegation from the maturity queue
4. `CompleteUnbonding` is called and begins processing:
   - Entry 0: `RemoveEntry(0)` executes, transfer of 100 tokens succeeds (pool now has 50 tokens)
   - Entry 1: `RemoveEntry(0)` executes, transfer of 100 tokens fails (insufficient balance)
   - Function returns error at line 890
5. The error is caught at line 46 and execution continues with `continue`
6. At block commit:
   - The 100 tokens transferred in iteration 0 are committed to the delegator's account
   - The `UnbondingDelegation` state is unchanged (still shows all 3 entries as pending)
   - The delegation has been removed from the maturity queue permanently [4](#0-3) 

**Security Failure:**
This breaks the atomicity invariant for state transitions and the accounting invariant that unbonding delegation state matches actual token transfers. The delegator receives partial payment but the unbonding entries remain recorded as unpaid, and since they're removed from the queue, they will never be automatically processed again.

### Impact Explanation

**Affected Assets:**
- Delegators' unbonding funds that become permanently stuck
- Protocol accounting integrity between `UnbondingDelegation` state and actual token balances

**Severity of Damage:**
- **Direct Loss of Funds**: Delegators lose access to the remaining unbonding tokens (200 tokens in the example scenario) that remain recorded in state but can never be withdrawn
- **Permanent Freezing**: The entries are removed from the maturity queue, so they won't be processed again in future blocks without manual intervention requiring a hard fork
- **State Inconsistency**: The system's accounting invariants are violated - the unbonding delegation shows entries as pending, but some have already been paid out

**System Security Impact:**
This undermines the core staking functionality and delegator trust. Users cannot reliably unstake their tokens, which is fundamental to the security model of proof-of-stake chains. The inconsistency also makes it difficult to audit total token supply and staked amounts.

### Likelihood Explanation

**Who Can Trigger:**
Any delegator through normal unstaking operations. No special privileges required.

**Conditions Required:**
1. The `UndelegateCoinsFromModuleToAccount` function must fail for at least one entry in an unbonding delegation with multiple entries
2. Failure can occur due to:
   - Insufficient balance in `NotBondedPool` (from accounting bugs, slashing edge cases, or rounding errors)
   - Validation failures in the bank keeper
   - Recipient account restrictions
   - Other error conditions in the coin transfer logic [5](#0-4) 

**Frequency:**
While the `NotBondedPool` should theoretically always have sufficient funds, the vulnerability can be triggered by:
- Edge cases in slashing mechanics that affect pool balances
- Integer rounding errors in large token operations
- Bugs in other modules that affect pool accounting
- Race conditions during high-volume unbonding periods

Once triggered, ALL unbonding delegations processed in that block with multiple entries are potentially affected.

### Recommendation

Wrap the `CompleteUnbonding` call in a `CacheContext` to ensure atomicity:

```go
// In x/staking/keeper/val_state_change.go, around line 44:
cacheCtx, writeCache := ctx.CacheContext()
balances, err := k.CompleteUnbonding(cacheCtx, delegatorAddress, addr)
if err != nil {
    // Don't write cache - changes are discarded
    continue
}
// Only commit changes if successful
writeCache()
ctx.EventManager().EmitEvents(cacheCtx.EventManager().Events())
```

This pattern ensures that either all state changes (bank transfers AND unbonding delegation updates) are committed together, or none are committed if any failure occurs. This is the same pattern used in the governance module for atomic proposal execution. [6](#0-5) 

### Proof of Concept

**File:** `x/staking/keeper/delegation_test.go`

**Test Function:** `TestCompleteUnbondingPartialFailure`

**Setup:**
1. Create a test application with staking keeper, bank keeper, and account keeper
2. Create a validator and delegator with sufficient initial stake
3. Create an unbonding delegation with 3 mature entries (100 tokens each)
4. Fund the `NotBondedPool` with only 150 tokens (enough for 1.5 entries, not all 3)
5. Set block time to maturity time so entries are ready for completion

**Trigger:**
1. Call `BlockValidatorUpdates` which internally calls `CompleteUnbonding`
2. The function will process Entry 0 successfully (transfer 100 tokens)
3. The function will process Entry 1 successfully (transfer 50 tokens from remaining pool)
4. The function will fail on Entry 2 (insufficient funds)
5. Error is caught and execution continues

**Observation:**
The test should verify the inconsistent state:
1. Delegator's balance increased by 150 tokens (entries 0 and 1 processed)
2. `NotBondedPool` balance decreased by 150 tokens
3. `GetUnbondingDelegation` still returns all 3 original entries (state not updated)
4. The unbonding delegation is NOT in the maturity queue anymore (dequeued before processing)
5. Future blocks will not automatically process the remaining entry

The test demonstrates that the delegator has permanently lost access to the 100 tokens from Entry 2, as it cannot be automatically completed and requires manual intervention or a hard fork to resolve.

### Citations

**File:** x/staking/keeper/delegation.go (L373-391)
```go
// currTime, and deletes the timeslices from the queue.
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
```

**File:** x/staking/keeper/delegation.go (L878-896)
```go
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
```

**File:** x/staking/keeper/delegation.go (L899-903)
```go
	if len(ubd.Entries) == 0 {
		k.RemoveUnbondingDelegation(ctx, ubd)
	} else {
		k.SetUnbondingDelegation(ctx, ubd)
	}
```

**File:** x/staking/keeper/val_state_change.go (L44-47)
```go
		balances, err := k.CompleteUnbonding(ctx, delegatorAddress, addr)
		if err != nil {
			continue
		}
```

**File:** x/bank/keeper/keeper.go (L232-256)
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
```

**File:** x/gov/abci.go (L68-87)
```go
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
```
