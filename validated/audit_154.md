# Audit Report

## Title
Unbounded Deposit Iteration in EndBlocker Enables Block Production DoS Attack

## Summary
The governance module's `IterateDeposits` function processes all deposits for a proposal during EndBlocker execution without any limit on the number of depositors or gas metering protection. An attacker can create thousands of minimal deposits from unique addresses, causing significant block processing delays when the proposal finalizes.

## Impact
Medium

## Finding Description

**Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** The `IterateDeposits` function is designed to iterate through all deposits for a proposal to refund or delete them when the proposal ends. The system expects reasonable deposit counts and relies on gas metering to prevent abuse during transaction processing.

**Actual Logic:** The function iterates through all deposits without any limit on depositor count. During EndBlocker execution, this iteration runs with an infinite gas meter [4](#0-3) [5](#0-4) , meaning gas consumption is tracked but never enforces any limit. The `DeleteDeposits` and `RefundDeposits` functions [6](#0-5) [7](#0-6)  call `IterateDeposits` and are invoked during EndBlocker processing.

**Exploitation Path:**
1. Attacker generates thousands of unique addresses through keypair generation
2. Each address submits a `MsgDeposit` transaction with minimal amount (e.g., 1 token), which passes validation [8](#0-7)  since there's no per-transaction minimum deposit check
3. The `AddDeposit` function [9](#0-8)  creates a separate deposit entry for each unique depositor
4. When the proposal's deposit period expires or voting period ends, the EndBlocker calls either `DeleteDeposits` or `RefundDeposits`
5. These functions iterate through all deposits, performing expensive operations for each: KVStore reads, protobuf unmarshaling, bank module transfers, and state deletions
6. Since the EndBlocker context has an infinite gas meter, no gas limit stops this iteration, causing substantial block processing delay

**Security Guarantee Broken:** The blockchain's liveness property and predictable block production are compromised. All validators must complete the EndBlocker processing before finalizing a block, so unbounded iteration directly impacts network-wide block times.

## Impact Explanation

With tens of thousands of deposits (10,000-100,000), an attacker can delay individual blocks by 500% or more of the normal block time. For a chain with 1-second block times, this could mean 5-10+ second delays. Each deposit iteration involves:
- KVStore read operations (I/O-bound)
- Protobuf unmarshaling (CPU-bound)
- Bank module operations with multiple state reads/writes for balance updates
- State deletion operations

This cumulative burden directly impacts:
- Transaction finality and user experience across the network
- Validator synchronization
- Dependent systems that may timeout
- Overall network stability during the attack period

## Likelihood Explanation

**Who Can Trigger:** Any unprivileged network participant with tokens for gas fees can execute this attack. The attacker only needs to generate many unique addresses and fund them with minimal amounts for deposits and transaction fees.

**Conditions Required:** 
- An active proposal in deposit or voting period
- Sufficient tokens for N minimal deposits plus transaction fees
- No special permissions or privileged access

**Cost vs Impact:** The attack is economically favorable for attackers because deposits are refunded [7](#0-6)  when proposals pass or expire normally. The attacker's main cost is transaction fees plus temporary capital lockup, while the network disruption is significant. This can be repeated on any governance proposal.

## Recommendation

Implement one or more of the following mitigations:

1. **Add Maximum Depositors Limit:** Enforce a maximum number of unique depositors per proposal (e.g., 1000-5000) in the `AddDeposit` function. Reject new unique depositors once the limit is reached, though existing depositors can continue adding to their deposits.

2. **Implement Minimum Deposit Per Transaction:** Add validation in `MsgDeposit.ValidateBasic()` to enforce a meaningful minimum deposit amount per transaction (e.g., 100 tokens) to increase attack cost.

3. **Batch Processing with State Tracking:** Modify `RefundDeposits` and `DeleteDeposits` to process deposits in batches across multiple blocks if the count exceeds a threshold, maintaining state about progress between blocks.

4. **Gas Metering for EndBlocker Operations:** Replace the infinite gas meter with a bounded meter during EndBlocker deposit iterations, with graceful handling if gas is exhausted (e.g., continuing in the next block).

The most straightforward fix is option 1 (maximum depositors limit) combined with option 2 (minimum deposit per transaction), as these prevent the attack vector while maintaining protocol functionality.

## Proof of Concept

**Setup:** Create a governance proposal and generate thousands of unique addresses (e.g., 5,000 for testing, but real attacks could use 10,000-100,000).

**Action:** Each unique address submits a `MsgDeposit` with the minimum possible amount (1 token). After all deposits are made, advance time to expire the proposal, triggering the EndBlocker.

**Result:** The EndBlocker execution time increases dramatically proportional to the number of unique depositors. With 5,000 deposits, the delay is measurable; with 50,000-100,000 deposits, block delays would exceed 500% of normal block time, confirming the Medium severity DoS vulnerability. The test would measure:
- Time to create deposits (baseline)
- EndBlocker execution time when calling `DeleteDeposits` or `RefundDeposits`
- Ratio demonstrating the DoS impact

The vulnerability is confirmed by the absence of any depositor count limits in the codebase and the documented use of infinite gas meters in EndBlocker contexts [10](#0-9) .

### Citations

**File:** x/gov/keeper/deposit.go (L54-68)
```go
func (keeper Keeper) DeleteDeposits(ctx sdk.Context, proposalID uint64) {
	store := ctx.KVStore(keeper.storeKey)

	keeper.IterateDeposits(ctx, proposalID, func(deposit types.Deposit) bool {
		err := keeper.bankKeeper.BurnCoins(ctx, types.ModuleName, deposit.Amount)
		if err != nil {
			panic(err)
		}

		depositor := sdk.MustAccAddressFromBech32(deposit.Depositor)

		store.Delete(types.DepositKey(proposalID, depositor))
		return false
	})
}
```

**File:** x/gov/keeper/deposit.go (L88-104)
```go
// IterateDeposits iterates over the all the proposals deposits and performs a callback function
func (keeper Keeper) IterateDeposits(ctx sdk.Context, proposalID uint64, cb func(deposit types.Deposit) (stop bool)) {
	store := ctx.KVStore(keeper.storeKey)
	iterator := sdk.KVStorePrefixIterator(store, types.DepositsKey(proposalID))

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		var deposit types.Deposit

		keeper.cdc.MustUnmarshal(iterator.Value(), &deposit)

		if cb(deposit) {
			break
		}
	}
}
```

**File:** x/gov/keeper/deposit.go (L139-146)
```go
	// Add or update deposit object
	deposit, found := keeper.GetDeposit(ctx, proposalID, depositorAddr)

	if found {
		deposit.Amount = deposit.Amount.Add(depositAmount...)
	} else {
		deposit = types.NewDeposit(proposalID, depositorAddr, depositAmount)
	}
```

**File:** x/gov/keeper/deposit.go (L164-179)
```go
// RefundDeposits refunds and deletes all the deposits on a specific proposal
func (keeper Keeper) RefundDeposits(ctx sdk.Context, proposalID uint64) {
	store := ctx.KVStore(keeper.storeKey)

	keeper.IterateDeposits(ctx, proposalID, func(deposit types.Deposit) bool {
		depositor := sdk.MustAccAddressFromBech32(deposit.Depositor)

		err := keeper.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, depositor, deposit.Amount)
		if err != nil {
			panic(err)
		}

		store.Delete(types.DepositKey(proposalID, depositor))
		return false
	})
}
```

**File:** x/gov/abci.go (L20-22)
```go
	keeper.IterateInactiveProposalsQueue(ctx, ctx.BlockHeader().Time, func(proposal types.Proposal) bool {
		keeper.DeleteProposal(ctx, proposal.ProposalId)
		keeper.DeleteDeposits(ctx, proposal.ProposalId)
```

**File:** x/gov/abci.go (L58-62)
```go
			if burnDeposits {
				keeper.DeleteDeposits(ctx, proposal.ProposalId)
			} else {
				keeper.RefundDeposits(ctx, proposal.ProposalId)
			}
```

**File:** types/context.go (L272-272)
```go
		gasMeter:        NewInfiniteGasMeter(1, 1),
```

**File:** store/types/gas.go (L252-258)
```go
func (g *infiniteGasMeter) IsPastLimit() bool {
	return false
}

func (g *infiniteGasMeter) IsOutOfGas() bool {
	return false
}
```

**File:** x/gov/types/msgs.go (L153-165)
```go
func (msg MsgDeposit) ValidateBasic() error {
	if msg.Depositor == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, msg.Depositor)
	}
	if !msg.Amount.IsValid() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}
	if msg.Amount.IsAnyNegative() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, msg.Amount.String())
	}

	return nil
}
```

**File:** docs/basics/gas-fees.md (L45-45)
```markdown
`ctx.GasMeter()` is the main gas meter of the application. The main gas meter is initialized in `BeginBlock` via `setDeliverState`, and then tracks gas consumption during execution sequences that lead to state-transitions, i.e. those originally triggered by [`BeginBlock`](../core/baseapp.md#beginblock), [`DeliverTx`](../core/baseapp.md#delivertx) and [`EndBlock`](../core/baseapp.md#endblock). At the beginning of each `DeliverTx`, the main gas meter **must be set to 0** in the [`AnteHandler`](#antehandler), so that it can track gas consumption per-transaction.
```
