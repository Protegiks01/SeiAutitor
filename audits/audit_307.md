## Title
Max Voting Power Ratio Bypass via Concurrent Unbonding and Delegation in Same Block

## Summary
The maximum voting power ratio check in the `Delegate` function uses a stale `lastTotalPower` value that does not account for unbonding transactions occurring earlier in the same block. This allows an attacker to bypass the voting power concentration limit by strategically combining unbonding and delegation transactions, enabling a validator to exceed the maximum allowed voting power ratio. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
The vulnerability exists in `x/staking/keeper/delegation.go` in the `Delegate` function, specifically in the voting power ratio calculation logic. [1](#0-0) 

**Intended Logic:** 
The code is intended to enforce that no single validator can hold more than `MaxVotingPowerRatio` (default 33%) of the total network voting power after a delegation. This prevents excessive validator centralization.

**Actual Logic:** 
The check uses `lastTotalPower` from the previous block's EndBlock as the baseline. When calculating `newTotalPower`, it only adds the current delegation's power to this cached value. However, if unbonding transactions occur in the same block before a delegation, they immediately reduce validator tokens but `lastTotalPower` remains unchanged until the next EndBlock. [2](#0-1) [3](#0-2) 

This creates a discrepancy:
- **Numerator** (line 654): `validator.Tokens + bondAmt` correctly reflects all state changes in the current block
- **Denominator** (line 649): `lastTotalPower + validatorAddtionalPower` uses stale cached value, overstating the actual network power

The unbonding immediately updates validator state via `RemoveValidatorTokensAndShares`: [4](#0-3) 

But `lastTotalPower` is only updated at EndBlock: [5](#0-4) 

**Exploit Scenario:**
1. Attacker identifies a validator currently at or near the voting power limit
2. In the same block, attacker submits two transactions:
   - **TX1**: Unbond tokens from any validator (including the target validator or others)
   - **TX2**: Delegate tokens to the target validator
3. The delegation check uses `lastTotalPower` that includes the unbonded power, inflating the denominator
4. The calculated ratio appears lower than the actual ratio, allowing the delegation to pass
5. Result: Validator exceeds the maximum voting power ratio

**Security Failure:** 
The protocol's voting power concentration limit is violated. A validator can accumulate more than the intended maximum share of network power, undermining the decentralization guarantees and potentially creating a single point of failure.

## Impact Explanation

This vulnerability affects the core security property of validator decentralization in a proof-of-stake network:

- **Assets Affected**: Network governance power and consensus security
- **Severity**: A validator exceeding the voting power limit gains disproportionate influence over consensus, transaction ordering, and network governance
- **Systemic Risk**: If one validator controls >33% of voting power, they can:
  - Block consensus by refusing to sign
  - Manipulate transaction ordering for MEV extraction
  - Potentially collude to perform consensus attacks

This matters because the max voting power ratio is a fundamental safeguard against validator centralization. Bypassing it degrades the security model from "requires compromising 33%+ of validators" to "requires compromising a single validator."

## Likelihood Explanation

**Who can trigger it:** Any network participant with sufficient funds to perform delegations and unbondings.

**Conditions required:**
- Network total power must exceed `MaxVotingPowerEnforcementThreshold` (default 1,000,000)
- Attacker needs access to delegated/bonded tokens to unbond (can be their own stake)
- Target validator must be close enough to the limit that the exploit makes a meaningful difference

**Frequency:** This can be exploited during normal operation whenever:
- There is organic unbonding activity in the network (which is common)
- Or attacker intentionally creates unbonding transactions before delegating

The exploit is straightforward to execute and requires no special timing or rare conditions. An attacker can reliably trigger it by submitting appropriately sequenced transactions to the mempool, which will naturally be included in the same block due to standard transaction processing.

## Recommendation

Modify the voting power ratio check to account for all power changes within the current block, not just the current delegation. Two potential approaches:

**Approach 1 - Track intra-block power changes:**
Maintain a context-scoped accumulator that tracks the net power change during the block. Update the accumulator on each delegation/unbonding, and use it to adjust the total power calculation:
```
actualTotalPower = lastTotalPower + ctx.GetIntraBlockPowerChange() + validatorAdditionalPower
```

**Approach 2 - Calculate actual current total:**
Instead of using `lastTotalPower`, iterate through all bonded validators to calculate the actual current total power at delegation time. This is more computationally expensive but guarantees correctness:
```
currentTotalPower = calculateCurrentBondedPower(ctx) + validatorAdditionalPower
```

**Preferred Solution:** Approach 1 is more efficient. Add a transient store value that accumulates power deltas during block execution and resets at BeginBlock/EndBlock.

## Proof of Concept

**File:** `x/staking/keeper/delegation_test.go`

**Test Function:** `TestMaxVotingPowerRatioBypassViaUnbonding`

**Setup:**
1. Initialize a test blockchain with 3 validators
2. Set `MaxVotingPowerRatio` to 0.33 (33%)
3. Set `MaxVotingPowerEnforcementThreshold` to 1000
4. Configure initial state:
   - Validator A: 290 tokens
   - Validator B: 710 tokens
   - Total: 1000 tokens
5. Run EndBlock to set `lastTotalPower = 1000`
6. Start a new block

**Trigger:**
1. Execute TX1: Unbond 100 tokens from Validator B
   - Validator B tokens: 710 → 610
   - Actual network power now: 900
   - But `lastTotalPower` still: 1000
2. Execute TX2: Delegate 50 tokens to Validator A
   - The check calculates: ratio = 340 / 1050 = 32.38% < 33% ✓ PASS
   - Delegation succeeds

**Observation:**
1. After both transactions, check Validator A's actual voting power ratio:
   - Actual total power: 900 + 50 = 950
   - Validator A power: 340
   - Actual ratio: 340 / 950 = 35.79%
2. Assert that 35.79% > 33% (exceeds the limit)
3. The test demonstrates the invariant violation: a validator holds more than `MaxVotingPowerRatio` of total power, despite the check passing

The test should fail on the vulnerable code, confirming that the voting power concentration limit can be bypassed through concurrent unbonding and delegation in the same block.

### Citations

**File:** x/staking/keeper/delegation.go (L644-663)
```go
	lastTotalPower := k.GetLastTotalPower(ctx)
	maxVotingPowerEnforcementThreshold := k.MaxVotingPowerEnforcementThreshold(ctx)

	// 1 power = Bond Amount / Power Reduction
	validatorAddtionalPower := bondAmt.Quo(k.PowerReduction(ctx))
	newTotalPower := lastTotalPower.Add(validatorAddtionalPower)

	// If it's beyond genesis then enforce power ratio per validator if there's more than maxVotingPowerEnforcementThreshold
	if newTotalPower.GTE(maxVotingPowerEnforcementThreshold) && ctx.BlockHeight() > 0 {
		// Convert bond amount to power first
		validatorNewTotalPower := validator.Tokens.Add(bondAmt).Quo(k.PowerReduction(ctx))
		// Validator's new total power cannot exceed the max power ratio that's allowed
		newVotingPowerRatio := validatorNewTotalPower.ToDec().Quo(newTotalPower.ToDec())
		maxVotingPowerRatio := k.MaxVotingPowerRatio(ctx)
		if newVotingPowerRatio.GT(maxVotingPowerRatio) {
			k.Logger(ctx).Error(
				fmt.Sprintf("validator's voting power ratio exceeds the max allowed ratio: %s > %s\n", newVotingPowerRatio.String(), maxVotingPowerRatio.String()),
			)
			return sdk.ZeroDec(), types.ErrExceedMaxVotingPowerRatio
		}
```

**File:** x/staking/keeper/delegation.go (L785-787)
```go
	// remove the shares and coins from the validator
	// NOTE that the amount is later (in keeper.Delegation) moved between staking module pools
	validator, amount = k.RemoveValidatorTokensAndShares(ctx, validator, shares)
```

**File:** x/staking/keeper/keeper.go (L80-92)
```go
func (k Keeper) GetLastTotalPower(ctx sdk.Context) sdk.Int {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.LastTotalPowerKey)

	if bz == nil {
		return sdk.ZeroInt()
	}

	ip := sdk.IntProto{}
	k.cdc.MustUnmarshal(bz, &ip)

	return ip.Int
}
```

**File:** x/staking/spec/01_state.md (L11-14)
```markdown
## LastTotalPower

LastTotalPower tracks the total amounts of bonded tokens recorded during the previous end block.
Store entries prefixed with "Last" must remain unchanged until EndBlock.
```

**File:** x/staking/keeper/val_state_change.go (L216-219)
```go
	// set total power on lookup index if there are any updates
	if len(updates) > 0 {
		k.SetLastTotalPower(ctx, totalPower)
	}
```
