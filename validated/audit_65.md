# Audit Report

## Title
Unhandled Panic in Distribution Hook Causes Chain Halt During Validator Removal in EndBlock

## Summary
A validation discrepancy between the distribution keeper's `SetWithdrawAddr` function and the bank keeper's `BlockedAddr` function allows validators to set coinbase-prefixed addresses as withdrawal addresses. When such a validator is removed during `EndBlock`, the distribution hook panics without recovery, causing complete chain halt.

## Impact
High

## Finding Description

**Location:**
- Panic location: [1](#0-0) 
- Validation gap: [2](#0-1)  vs [3](#0-2) 
- Coinbase prefix definition: [4](#0-3) 

**Intended Logic:**
The distribution keeper should prevent setting withdrawal addresses that would cause send failures. Address validation in `SetWithdrawAddr` should align with the bank keeper's blocking logic to ensure all blocked addresses are rejected upfront.

**Actual Logic:**
The distribution keeper's `SetWithdrawAddr` only validates against the `blockedAddrs` map [5](#0-4) , which contains module accounts. However, the bank keeper's `BlockedAddr` performs an additional check for coinbase-prefixed addresses [6](#0-5) . This creates a validation gap where coinbase addresses (12 bytes "evm_coinbase" + 8 bytes) pass `SetWithdrawAddr` validation but fail during actual coin transfers.

**Exploitation Path:**
1. Attacker creates a validator and obtains validator operator address
2. Attacker constructs a 20-byte address with coinbase prefix ("evm_coinbase" + 8 arbitrary bytes)
3. Attacker submits `MsgSetWithdrawAddress` transaction setting the coinbase address as withdraw address - this succeeds because distribution keeper only checks `blockedAddrs` map
4. Validator accumulates commission through delegations
5. Attacker unbonds all delegations from the validator
6. After unbonding period matures, during `EndBlock`:
   - `BlockValidatorUpdates` is called [7](#0-6) 
   - `UnbondAllMatureValidators` processes mature validators [8](#0-7) 
   - Since validator has zero delegator shares, `RemoveValidator` is called [9](#0-8) 
   - This triggers `AfterValidatorRemoved` hook [10](#0-9) 
   - Hook attempts to send commission via `SendCoinsFromModuleToAccount` [1](#0-0) 
   - `SendCoinsFromModuleToAccount` checks `BlockedAddr` [11](#0-10)  which returns true for coinbase addresses
   - Transfer fails, hook panics with no recovery
7. Panic propagates through call stack with no recovery at any level: [12](#0-11) , [13](#0-12) 
8. Chain halts at ABCI interface

**Security Guarantee Broken:**
The system violates network availability guarantees. An unhandled panic during `EndBlock` bypasses all error handling and propagates to the consensus layer, causing total network shutdown.

## Impact Explanation

This vulnerability causes complete blockchain network unavailability:

- **Network Availability**: All nodes halt simultaneously during `EndBlock` processing, preventing new block production
- **Transaction Finality**: All pending transactions cannot be confirmed
- **Economic Impact**: Network downtime affects all users, validators, and dependent applications
- **Recovery Complexity**: Requires emergency coordination among validators to deploy a patch and restart the network through a coordinated upgrade

The severity is High because this creates a complete denial-of-service condition that can only be resolved through a coordinated hard fork or emergency software upgrade.

## Likelihood Explanation

**Who can trigger**: Any network participant who can create and operate a validator (requires sufficient stake but no special privileges or admin access).

**Required conditions**:
- Ability to create a validator (requires only minimum stake amount)
- Ability to set withdraw address (standard validator operation available to all validators)
- Ability to craft 20-byte address with specific prefix (trivial - just concatenate "evm_coinbase" bytes with 8 arbitrary bytes)
- Validator must accumulate any non-zero commission amount
- Validator must have zero remaining delegations when removed (attacker controls this)

**Frequency**: This can be triggered deliberately at any time by an attacker. The attack is:
- Deterministic and reliable (100% success rate once conditions met)
- Low cost (only requires validator creation stake, which can be recovered through unbonding)
- No timing constraints beyond waiting for standard unbonding period
- Repeatable if chain restarts without fix

The exploit requires no sophisticated techniques and is straightforward to execute, making it highly likely to be discovered and exploited by malicious actors.

## Recommendation

Implement the following fixes:

1. **Immediate mitigation**: Align validation in distribution keeper with bank keeper by adding coinbase prefix check in `SetWithdrawAddr`:
   - Import the `CoinbaseAddressPrefix` from bank keeper
   - Add validation check after the `blockedAddrs` check to reject addresses with coinbase prefix
   - Return appropriate error when coinbase address is detected

2. **Defense in depth**: Add panic recovery in critical paths:
   - Consider wrapping `EndBlock` execution with defer/recover to prevent chain halt
   - Log panic details for debugging while maintaining chain operation
   - Alternatively, modify distribution hook to return errors instead of panicking

3. **Long-term fix**: Refactor hook architecture to use error returns instead of panics, allowing graceful degradation and error handling at higher levels.

## Proof of Concept

**Test Location**: `x/distribution/keeper/keeper_test.go`

**Setup**:
- Create test application and context
- Construct coinbase-prefixed address (12 bytes "evm_coinbase" + 8 bytes = 20 bytes total)
- Create validator with sufficient stake
- Enable withdraw address changes via parameters
- Set coinbase address as withdraw address (demonstrates validation gap - this succeeds)
- Fund distribution module and set validator commission
- Set validator to unbonded status with zero delegator shares

**Action**:
- Call `RemoveValidator` which triggers `AfterValidatorRemoved` hook
- Hook attempts to send commission to coinbase address via `SendCoinsFromModuleToAccount`

**Result**:
- `SendCoinsFromModuleToAccount` blocks the transfer (coinbase address check fails)
- Hook panics with the error
- In production EndBlock context, this panic would propagate without recovery, halting the chain

The test demonstrates:
1. Coinbase-prefixed addresses pass `SetWithdrawAddr` validation (validation gap exists)
2. Validator removal triggers panic when commission withdrawal fails
3. No recovery mechanism exists in the call chain, leading to chain halt

## Notes

This vulnerability has been thoroughly validated through code analysis:
- The validation discrepancy between distribution and bank keepers is confirmed
- The panic propagation path through EndBlock is verified with no recovery mechanisms
- The attack is feasible with standard validator operations requiring no special privileges
- The impact matches the "Network not being able to confirm new transactions (total network shutdown)" category defined as High severity
- Existing tests ( [14](#0-13) ) confirm bank keeper blocks coinbase addresses, but no test validates distribution keeper rejects them during withdraw address setup

### Citations

**File:** x/distribution/keeper/hooks.go (L49-50)
```go
			if err := h.k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, withdrawAddr, coins); err != nil {
				panic(err)
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

**File:** x/staking/abci.go (L25-25)
```go
	return k.BlockValidatorUpdates(ctx)
```

**File:** x/staking/keeper/val_state_change.go (L33-33)
```go
	k.UnbondAllMatureValidators(ctx)
```

**File:** x/staking/keeper/validator.go (L180-180)
```go
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
```

**File:** x/staking/keeper/validator.go (L442-443)
```go
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
```

**File:** x/bank/keeper/keeper.go (L360-362)
```go
	if k.BlockedAddr(recipientAddr) {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive funds", recipientAddr)
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

**File:** x/bank/keeper/send_test.go (L13-21)
```go
func TestBlockedAddr(t *testing.T) {
	k := keeper.NewBaseSendKeeper(nil, nil, nil, paramtypes.Subspace{}, map[string]bool{})
	txIndexBz := make([]byte, 8)
	binary.BigEndian.PutUint64(txIndexBz, uint64(5))
	addr := sdk.AccAddress(append(keeper.CoinbaseAddressPrefix, txIndexBz...))
	require.True(t, k.BlockedAddr(addr))
	addr[0] = 'q'
	require.False(t, k.BlockedAddr(addr))
}
```
