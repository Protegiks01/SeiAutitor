## Title
Unhandled Panic in Distribution Hook Causes Chain Halt During Validator Removal in EndBlock

## Summary
A discrepancy exists between address validation in `SetWithdrawAddress` and the actual blocking check during fund transfers. The distribution keeper allows setting coinbase-prefixed addresses as withdrawal addresses, but the bank keeper blocks transfers to these addresses. When a validator with such a withdraw address is removed during `EndBlock`, the distribution hook panics without recovery, causing a complete chain halt.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary panic location: [1](#0-0) 
- Validation discrepancy: [2](#0-1)  vs [3](#0-2) 
- Unprotected call chain: [4](#0-3)  → [5](#0-4) 

**Intended Logic:** 
Distribution hooks should execute safely during validator lifecycle events. The `AfterValidatorRemoved` hook withdraws accumulated commission to the validator's designated withdraw address. Address validation in `SetWithdrawAddr` should prevent setting addresses that would cause send failures.

**Actual Logic:** 
The distribution keeper's `SetWithdrawAddr` only checks if an address exists in the `blockedAddrs` map [6](#0-5) , which contains module accounts. However, the bank keeper's `BlockedAddr` function has an additional check for coinbase-prefixed addresses [7](#0-6)  using the prefix [8](#0-7) . This creates a validation gap where coinbase addresses pass `SetWithdrawAddr` validation but fail during actual transfers.

**Exploit Scenario:**
1. Attacker creates a validator and obtains a validator operator address
2. Attacker crafts an address with coinbase prefix (`evm_coinbase` + 8 bytes, total 20 bytes)
3. Attacker calls `MsgSetWithdrawAddress` to set the coinbase-prefixed address as their withdraw address - this succeeds because distribution keeper only checks `blockedAddrs` map
4. Attacker accumulates some validator commission 
5. Attacker unbonds all delegations from the validator
6. After unbonding period matures, during `EndBlock`:
   - `BlockValidatorUpdates` is called [9](#0-8) 
   - `UnbondAllMatureValidators` processes mature validators [10](#0-9) 
   - Since validator has zero delegator shares, `RemoveValidator` is called [11](#0-10) 
   - This triggers `AfterValidatorRemoved` hook [12](#0-11) 
   - Hook attempts to send commission via `SendCoinsFromModuleToAccount` [1](#0-0) 
   - Bank keeper's `BlockedAddr` returns true for coinbase address [13](#0-12) 
   - Transfer fails with error, hook panics
7. Panic propagates through entire call stack with NO recovery at any level: [14](#0-13) , [15](#0-14) , [16](#0-15) 
8. Chain halts at ABCI interface

**Security Failure:** 
The system violates availability guarantees. An unhandled panic during `EndBlock` bypasses all error handling and propagates to the consensus layer, causing total chain shutdown.

## Impact Explanation

This vulnerability affects the entire blockchain network's availability. When exploited:

- **Network Availability**: All nodes halt simultaneously during `EndBlock` processing, preventing any new blocks from being produced
- **Transaction Finality**: All pending transactions cannot be confirmed
- **Economic Impact**: Network downtime affects all users, validators, and applications
- **Recovery**: Requires emergency coordination among validators to upgrade/patch the software and restart the network

The severity is **High** because this creates a complete denial-of-service condition requiring coordinated hard fork/emergency upgrade to restore network operations.

## Likelihood Explanation

**Who can trigger it:** Any network participant who can create and operate a validator (requires sufficient stake but no special privileges).

**Required conditions:**
- Ability to create a validator (requires minimum stake)
- Ability to set withdraw address (standard validator operation)
- Ability to craft 20-byte address with specific prefix (trivial)
- Validator must accumulate any non-zero commission
- Validator must have zero remaining delegations when removed

**Frequency:** This can be triggered deliberately by an attacker at any time. The attack is:
- Deterministic and reliable
- Low cost (only requires validator creation stake, which can be recovered)
- No timing requirements beyond waiting for unbonding period
- Repeatable if chain restarts without fix

The exploit is straightforward and requires no sophisticated techniques, making it **highly likely** to be discovered and exploited.

## Recommendation

Implement the following fixes:

1. **Immediate mitigation**: Align validation in distribution keeper with bank keeper by checking both `blockedAddrs` map and coinbase prefix in `SetWithdrawAddr`:
```
// In x/distribution/keeper/keeper.go, update SetWithdrawAddr function
if k.blockedAddrs[withdrawAddr.String()] {
    return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", withdrawAddr)
}
// Add coinbase prefix check
if len(withdrawAddr) == len(CoinbaseAddressPrefix)+8 && bytes.Equal(CoinbaseAddressPrefix, withdrawAddr[:len(CoinbaseAddressPrefix)]) {
    return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "coinbase addresses cannot be withdraw addresses")
}
```

2. **Defense in depth**: Add panic recovery in `EndBlock` path:
```
// In baseapp/abci.go, wrap EndBlock call with defer/recover
defer func() {
    if r := recover(); r != nil {
        app.logger.Error("panic in EndBlock", "panic", r)
        // Handle panic gracefully, potentially by skipping problematic operations
    }
}()
```

3. **Long-term fix**: Modify distribution hook to return errors instead of panicking, allowing graceful error handling at higher levels.

## Proof of Concept

**File**: `x/distribution/keeper/keeper_test.go`

**Test Function**: `TestCoinbaseWithdrawAddressCausesEndBlockPanic`

**Setup**:
```go
func TestCoinbaseWithdrawAddressCausesEndBlockPanic(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Create coinbase-prefixed address (12 bytes "evm_coinbase" + 8 bytes)
    coinbaseAddr := append([]byte("evm_coinbase"), []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}...)
    require.Len(t, coinbaseAddr, 20)
    
    // Setup validator
    valAddrs := simapp.AddTestAddrsIncremental(app, ctx, 1, sdk.NewInt(100000000))
    valAddr := sdk.ValAddress(valAddrs[0])
    
    // Enable withdraw address changes
    params := app.DistrKeeper.GetParams(ctx)
    params.WithdrawAddrEnabled = true
    app.DistrKeeper.SetParams(ctx, params)
    
    // Set coinbase address as withdraw address - this should succeed (demonstrating the vulnerability)
    accAddr := sdk.AccAddress(valAddr)
    err := app.DistrKeeper.SetWithdrawAddr(ctx, accAddr, coinbaseAddr)
    require.NoError(t, err) // Passes validation despite being a blocked address
    
    // Create and fund validator
    validator := teststaking.NewValidator(t, valAddr, PKs[0])
    validator, _ = validator.AddTokensFromDel(sdk.NewInt(10000))
    validator = keeper.TestingUpdateValidator(app.StakingKeeper, ctx, validator, true)
    
    // Set some commission
    commission := sdk.DecCoins{sdk.NewDecCoinFromDec("usei", sdk.NewDec(100))}
    app.DistrKeeper.SetValidatorAccumulatedCommission(ctx, valAddr, 
        types.ValidatorAccumulatedCommission{Commission: commission})
    
    // Fund distribution module to have enough balance
    app.DistrKeeper.FundDistributionPool(ctx, sdk.NewCoins(sdk.NewCoin("usei", sdk.NewInt(1000))))
    
    // Unbond all delegations and set validator to unbonded with zero shares
    validator.DelegatorShares = sdk.ZeroDec()
    validator.Status = stakingtypes.Unbonded
    validator.Tokens = sdk.ZeroInt()
    app.StakingKeeper.SetValidator(ctx, validator)
}
```

**Trigger**:
```go
    // Attempt to remove validator - this will trigger the hook
    // In actual EndBlock, this happens via UnbondAllMatureValidators -> RemoveValidator
    require.Panics(t, func() {
        app.StakingKeeper.RemoveValidator(ctx, valAddr)
    }, "Expected panic when trying to send to coinbase address")
```

**Observation**: 
The test demonstrates that:
1. Setting a coinbase-prefixed address as withdraw address succeeds (validation gap)
2. When `RemoveValidator` is called (as happens in `EndBlock`), the hook panics
3. This panic would propagate through `EndBlock` causing chain halt

The panic occurs because `SendCoinsFromModuleToAccount` detects the coinbase address as blocked, returns an error, and the hook panics without recovery. In production, this panic during `EndBlock` would halt the entire chain with no automatic recovery mechanism.

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

**File:** x/distribution/keeper/keeper.go (L64-67)
```go
func (k Keeper) SetWithdrawAddr(ctx sdk.Context, delegatorAddr sdk.AccAddress, withdrawAddr sdk.AccAddress) error {
	if k.blockedAddrs[withdrawAddr.String()] {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", withdrawAddr)
	}
```

**File:** x/bank/keeper/send.go (L20-20)
```go
var CoinbaseAddressPrefix = []byte("evm_coinbase")
```

**File:** x/bank/keeper/send.go (L348-355)
```go
func (k BaseSendKeeper) BlockedAddr(addr sdk.AccAddress) bool {
	if len(addr) == len(CoinbaseAddressPrefix)+8 {
		if bytes.Equal(CoinbaseAddressPrefix, addr[:len(CoinbaseAddressPrefix)]) {
			return true
		}
	}
	return k.blockedAddrs[addr.String()]
}
```

**File:** x/staking/keeper/val_state_change.go (L33-33)
```go
	k.UnbondAllMatureValidators(ctx)
```

**File:** x/staking/keeper/val_state_change.go (L441-444)
```go

```

**File:** x/staking/keeper/validator.go (L160-180)
```go
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
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/bank/keeper/keeper.go (L360-362)
```go
	if k.BlockedAddr(recipientAddr) {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", recipientAddr)
	}
```

**File:** baseapp/abci.go (L178-201)
```go
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

**File:** types/module/module.go (L642-670)
```go
func (m *Manager) EndBlock(ctx sdk.Context, req abci.RequestEndBlock) abci.ResponseEndBlock {
	ctx = ctx.WithEventManager(sdk.NewEventManager())
	validatorUpdates := []abci.ValidatorUpdate{}
	defer telemetry.MeasureSince(time.Now(), "module", "total_end_block")
	for _, moduleName := range m.OrderEndBlockers {
		module, ok := m.Modules[moduleName].(EndBlockAppModule)
		if !ok {
			continue
		}
		moduleStartTime := time.Now()
		moduleValUpdates := module.EndBlock(ctx, req)
		telemetry.ModuleMeasureSince(moduleName, moduleStartTime, "module", "end_block")
		// use these validator updates if provided, the module manager assumes
		// only one module will update the validator set
		if len(moduleValUpdates) > 0 {
			if len(validatorUpdates) > 0 {
				panic("validator EndBlock updates already set by a previous module")
			}

			validatorUpdates = moduleValUpdates
		}

	}

	return abci.ResponseEndBlock{
		ValidatorUpdates: validatorUpdates,
		Events:           ctx.EventManager().ABCIEvents(),
	}
}
```

**File:** x/staking/abci.go (L22-26)
```go
func EndBlocker(ctx sdk.Context, k keeper.Keeper) []abci.ValidatorUpdate {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyEndBlocker)

	return k.BlockValidatorUpdates(ctx)
}
```
