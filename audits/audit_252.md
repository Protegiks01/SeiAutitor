## Title
Network Halt Due to Unhandled Panic in Distribution Module's AfterValidatorRemoved Hook During EndBlock

## Summary
The distribution module's `AfterValidatorRemoved` hook modifies state and then calls `bankKeeper.SendCoinsFromModuleToAccount` to send validator commission, panicking on failure. Since this hook executes during `EndBlock` which lacks panic recovery, any failure in the coin transfer causes all validators to crash deterministically, resulting in total network shutdown. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Hook implementation: `x/distribution/keeper/hooks.go`, lines 26-76 (`AfterValidatorRemoved` function)
- Hook invocation: `x/staking/keeper/validator.go`, line 180
- EndBlock execution: `x/staking/keeper/val_state_change.go`, line 33 (called from `BlockValidatorUpdates`)
- ABCI EndBlock: `baseapp/abci.go`, lines 177-201

**Intended Logic:**
When a validator is removed after completing unbonding, the system should withdraw their remaining commission to their designated withdrawal address. This operation is intended to be atomic and safe, properly handling any potential failures. [2](#0-1) 

**Actual Logic:**
The `AfterValidatorRemoved` hook performs the following sequence:
1. Retrieves validator commission (line 31)
2. Subtracts commission from outstanding rewards in a local variable (line 34)
3. **Modifies global state** by adding commission remainder to community pool via `SetFeePool` (lines 40-42)
4. Attempts to send truncated commission coins via `SendCoinsFromModuleToAccount` (line 49)
5. **Panics if the send fails** (line 50) [3](#0-2) 

The critical flaw is that this hook executes during `EndBlock`, which has no panic recovery mechanism: [4](#0-3) 

**Exploit Scenario:**
1. A validator completes their unbonding period and becomes eligible for removal
2. During `EndBlock`, `BlockValidatorUpdates` calls `UnbondAllMatureValidators`
3. `UnbondAllMatureValidators` calls `RemoveValidator` for the validator
4. `RemoveValidator` triggers the `AfterValidatorRemoved` hook
5. The hook attempts to send commission to the withdrawal address
6. `SendCoinsFromModuleToAccount` fails due to:
   - Withdrawal address is blocked (checked at bank keeper level)
   - Insufficient balance in distribution module (accounting error)
   - Any other error condition in the transfer logic [5](#0-4) 

7. The hook panics (line 50)
8. The panic propagates through EndBlock (no recovery)
9. The node crashes
10. **All validators crash at the same block height** (deterministic consensus state)
11. Network cannot produce new blocks - total shutdown [6](#0-5) 

**Security Failure:**
This breaks the **availability** property of the blockchain. The lack of panic recovery in EndBlock combined with panic-based error handling in hooks creates a single point of failure that can bring down the entire network deterministically.

## Impact Explanation

**Affected Process:** Network consensus and block production

**Severity of Damage:**
- All validator nodes crash simultaneously at the same block height
- No new blocks can be produced
- All transactions become stuck
- Network experiences total shutdown until manual intervention (hard fork or coordinated restart with patched code)

**Why This Matters:**
Unlike isolated node crashes or non-deterministic failures, this vulnerability causes all validators to fail at the same deterministic point in block execution. This results in complete network unavailability, requiring coordinated manual intervention to recover. Users cannot transact, validators cannot earn rewards, and the chain is effectively frozen.

## Likelihood Explanation

**Who Can Trigger:**
While this requires specific preconditions to trigger, it doesn't require attacker privileges. Any validator reaching the end of their unbonding period can trigger this if conditions align.

**Required Conditions:**
- A validator must complete unbonding and be ready for removal
- One of the following must be true:
  - The distribution module has insufficient funds (due to an accounting bug or edge case)
  - The validator's withdrawal address becomes invalid/blocked through some edge case
  - Any other failure condition in `SendCoinsFromModuleToAccount`

**Frequency:**
While the specific trigger conditions may be rare, the **consequence is catastrophic and deterministic**. The system's fragility to any edge case in this code path represents a significant systemic risk. Even a single occurrence would require emergency intervention and potential hard fork.

## Recommendation

**Immediate Fix:**
Add panic recovery in the `EndBlock` execution path, or refactor hooks to return errors instead of panicking. Specifically:

1. Modify the `AfterValidatorRemoved` hook to handle `SendCoinsFromModuleToAccount` failures gracefully:
   - Check balance before attempting send
   - If send fails, log the error and leave commission in the module account for later manual recovery
   - Do not panic on send failure

2. Alternatively, add panic recovery in `BaseApp.EndBlock` similar to transaction execution:
   - Wrap `app.endBlocker` call in defer/recover
   - Log panics and return error response
   - Allow network to continue operating

3. Review all other hooks called during BeginBlock/EndBlock for similar panic-based error handling patterns.

## Proof of Concept

**Test File:** `x/distribution/keeper/hooks_test.go` (new test to be added)

**Test Function:** `TestAfterValidatorRemovedPanicHandling`

**Setup:**
1. Initialize blockchain state with genesis validators
2. Create a validator with accumulated commission
3. Simulate the validator entering unbonding state
4. Set up conditions where `SendCoinsFromModuleToAccount` will fail:
   - Either set withdrawal address to a blocked address (via state manipulation in test)
   - Or drain the distribution module account to create insufficient balance
5. Advance time to complete unbonding period

**Trigger:**
1. Call `BlockValidatorUpdates` (simulating EndBlock)
2. This triggers `UnbondAllMatureValidators`
3. Which calls `RemoveValidator`
4. Which triggers `AfterValidatorRemoved` hook
5. Hook attempts to send coins and fails
6. Hook panics

**Observation:**
The test should observe that the panic propagates all the way up, demonstrating that there's no recovery mechanism. In production, this would crash all validator nodes.

**Expected behavior:** The test panics, confirming the vulnerability exists.

**Desired behavior after fix:** The hook should handle the error gracefully without panicking, or EndBlock should recover from the panic.

---

**Notes:**
- This vulnerability affects the critical consensus path (EndBlock)
- The impact is deterministic across all validators
- Recovery requires coordinated manual intervention
- The root cause is architectural: mixing panic-based error handling with unprotected execution contexts

### Citations

**File:** x/distribution/keeper/hooks.go (L26-76)
```go
func (h Hooks) AfterValidatorRemoved(ctx sdk.Context, _ sdk.ConsAddress, valAddr sdk.ValAddress) {
	// fetch outstanding
	outstanding := h.k.GetValidatorOutstandingRewardsCoins(ctx, valAddr)

	// force-withdraw commission
	commission := h.k.GetValidatorAccumulatedCommission(ctx, valAddr).Commission
	if !commission.IsZero() {
		// subtract from outstanding
		outstanding = outstanding.Sub(commission)

		// split into integral & remainder
		coins, remainder := commission.TruncateDecimal()

		// remainder to community pool
		feePool := h.k.GetFeePool(ctx)
		feePool.CommunityPool = feePool.CommunityPool.Add(remainder...)
		h.k.SetFeePool(ctx, feePool)

		// add to validator account
		if !coins.IsZero() {
			accAddr := sdk.AccAddress(valAddr)
			withdrawAddr := h.k.GetDelegatorWithdrawAddr(ctx, accAddr)

			if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, coins); err != nil {
				panic(err)
			}
		}
	}

	// Add outstanding to community pool
	// The validator is removed only after it has no more delegations.
	// This operation sends only the remaining dust to the community pool.
	feePool := h.k.GetFeePool(ctx)
	feePool.CommunityPool = feePool.CommunityPool.Add(outstanding...)
	h.k.SetFeePool(ctx, feePool)

	// delete outstanding
	h.k.DeleteValidatorOutstandingRewards(ctx, valAddr)

	// remove commission record
	h.k.DeleteValidatorAccumulatedCommission(ctx, valAddr)

	// clear slashes
	h.k.DeleteValidatorSlashEvents(ctx, valAddr)

	// clear historical rewards
	h.k.DeleteValidatorHistoricalRewards(ctx, valAddr)

	// clear current rewards
	h.k.DeleteValidatorCurrentRewards(ctx, valAddr)
}
```

**File:** x/staking/keeper/validator.go (L153-181)
```go
func (k Keeper) RemoveValidator(ctx sdk.Context, address sdk.ValAddress) {
	// first retrieve the old validator record
	validator, found := k.GetValidator(ctx, address)
	if !found {
		return
	}

	if !validator.IsUnbonded() {
		panic("cannot call RemoveValidator on bonded or unbonding validators")
	}

	if validator.Tokens.IsPositive() {
		panic("attempting to remove a validator which still contains tokens")
	}

	valConsAddr, err := validator.GetConsAddr()
	if err != nil {
		panic(err)
	}

	// delete the old validator record
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetValidatorKey(address))
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
	store.Delete(types.GetValidatorsByPowerIndexKey(validator, k.PowerReduction(ctx)))

	// call hooks
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
}
```

**File:** baseapp/abci.go (L177-201)
```go
// EndBlock implements the ABCI interface.
func (app *BaseApp) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	// Clear DeliverTx Events
	ctx.MultiStore().ResetEvents()

	defer telemetry.MeasureSince(time.Now(), "abci", "end_block")

	if app.endBlocker != nil {
		res = app.endBlocker(ctx, req)
		res.Events = sdk.MarkEventsToIndex(res.Events, app.indexEvents)
	}

	if cp := app.GetConsensusParams(ctx); cp != nil {
		res.ConsensusParamUpdates = legacytm.ABCIToLegacyConsensusParams(cp)
	}

	// call the streaming service hooks with the EndBlock messages
	for _, streamingListener := range app.abciListeners {
		if err := streamingListener.ListenEndBlock(app.deliverState.ctx, req, res); err != nil {
			app.logger.Error("EndBlock listening hook failed", "height", req.Height, "err", err)
		}
	}

	return res
}
```

**File:** x/bank/keeper/keeper.go (L351-364)
```go
func (k BaseKeeper) SendCoinsFromModuleToAccount(
	ctx sdk.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins,
) error {

	senderAddr := k.ak.GetModuleAddress(senderModule)
	if senderAddr == nil {
		panic(sdkerrors.Wrapf(sdkerrors.ErrUnknownAddress, "module account %s does not exist", senderModule))
	}

	if k.BlockedAddr(recipientAddr) {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", recipientAddr)
	}
	return k.SendCoins(ctx, senderAddr, recipientAddr, amt)
}
```

**File:** x/staking/keeper/val_state_change.go (L15-33)
```go
// BlockValidatorUpdates calculates the ValidatorUpdates for the current block
// Called in each EndBlock
func (k Keeper) BlockValidatorUpdates(ctx sdk.Context) []abci.ValidatorUpdate {
	// Calculate validator set changes.
	//
	// NOTE: ApplyAndReturnValidatorSetUpdates has to come before
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}

	// unbond all mature validators from the unbonding queue
	k.UnbondAllMatureValidators(ctx)
```
