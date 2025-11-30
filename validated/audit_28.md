# Audit Report

## Title
Incorrect Slash Accounting for Redelegations When Destination Validator Has Been Slashed

## Summary
The `SlashRedelegation` function returns a theoretical slash amount based on `InitialBalance` while actually burning fewer tokens when the destination validator's exchange rate has decreased due to prior slashing. This creates an accounting mismatch that causes the total tokens burned to be less than the protocol-specified `slashFactor * power`, violating the core slashing invariant.

## Impact
Medium

## Finding Description

**Location:** The vulnerability exists in the `SlashRedelegation` function [1](#0-0)  and its interaction with the main `Slash` function [2](#0-1) .

**Intended Logic:** According to the protocol specification [3](#0-2) , when a validator is slashed, the total amount must equal `slashFactor * power` at the infraction height. Each actual amount slashed from redelegations and unbonding delegations should be subtracted from the total, with the remaining amount slashed from the validator's bonded tokens.

**Actual Logic:** The `SlashRedelegation` function calculates a theoretical slash amount as `slashFactor * entry.InitialBalance` and accumulates this in `totalSlashAmount` (lines 238-240 of slash.go). However, the actual tokens burned are obtained by calling `Unbond()` (line 265) which converts shares to tokens using the destination validator's current exchange rate via `TokensFromShares()` [4](#0-3) . 

When a destination validator has been slashed, its exchange rate decreases because slashing reduces `Tokens` without reducing `DelegatorShares` [5](#0-4) . This causes the actual `tokensToBurn` to be less than the theoretical `slashAmount`. However, the function returns `totalSlashAmount` (theoretical) not the actual burned amount. The main `Slash` function then subtracts this theoretical amount from `remainingSlashAmount`, resulting in total actual tokens burned being less than the protocol-specified amount.

**Exploitation Path:**
1. Validator A commits a slashable infraction at height H1
2. After H1, tokens are redelegated from A to B (creating redelegation entry with `InitialBalance` and `SharesDst`)
3. Validator B is slashed for its own independent infraction, reducing its exchange rate (e.g., from 1.0 to 0.5)
4. Validator A is slashed for the H1 infraction:
   - `SlashRedelegation` calculates theoretical = `slashFactor * InitialBalance`
   - Actual burn via `Unbond` = `slashFactor * SharesDst * currentExchangeRate`
   - Since B was slashed: currentExchangeRate < 1.0, so actual burn < theoretical
   - Function returns theoretical amount
   - Main `Slash` subtracts theoretical from `remainingSlashAmount`
   - Validator A's bonded tokens are slashed by the remaining amount
   - Total actual burn < `slashFactor * power` (protocol violation)

**Security Guarantee Broken:** The protocol invariant that validators must be slashed by exactly `slashFactor * power` at the infraction height is violated. This allows validators to escape proportional punishment through redelegations to subsequently-slashed validators.

## Impact Explanation

This vulnerability weakens the economic security model by enabling systematic under-slashing of misbehaving validators. During cascading slashing events (multiple validators slashed in sequence), the source validator escapes proportional punishment when their redelegations point to validators that get slashed first.

For example, with a validator having 1000 tokens at infraction height, 400 tokens redelegated to a validator that subsequently gets slashed 50%, and then the source validator slashed 50%: the shortfall is 100 tokens (20% of the intended 500-token punishment). This accumulates across multiple redelegations and slashing events, reducing the effectiveness of the slashing mechanism in deterring validator misbehavior. Fewer tokens are burned than the protocol specifies, affecting both token supply accounting and the security guarantee that validators face full financial consequences for infractions.

## Likelihood Explanation

**Who Can Trigger:** Any network participant through normal operations—no special privileges required. Slashing is triggered automatically by the protocol [6](#0-5)  when validators commit infractions (double-signing, downtime, etc.).

**Conditions Required:**
1. A validator commits a slashable infraction
2. After the infraction, delegators redelegate from that validator to another (routine operation)
3. The destination validator gets slashed for its own independent infraction
4. The source validator's infraction is detected and slashed

**Frequency:** This occurs naturally during network instability periods when multiple validators are slashed. The vulnerability is systemic and manifests whenever the conditions align. It can also be strategically exploited by sophisticated actors who commit infractions, then redelegate to risky validators they control or anticipate will be slashed, thereby reducing their total slashing penalty when their original infraction is discovered.

## Recommendation

Modify `SlashRedelegation` to return the actual burned amount rather than the theoretical amount:

1. Track the cumulative actual `tokensToBurn` from all redelegation entries instead of the theoretical `slashAmount`
2. Accumulate `tokensToBurn` (obtained from `Unbond`) to `totalSlashAmount` instead of accumulating the theoretical `slashAmount`
3. Return the sum of actual `tokensToBurn` values

Alternatively, implement a two-phase approach:
1. Record both theoretical and actual amounts during redelegation slashing
2. Track the shortfall between theoretical and actual burns
3. Adjust the validator's bonded token slash to compensate for any shortfall

This ensures the slashing invariant is maintained: total actual tokens burned = `slashFactor * power` at infraction height.

## Proof of Concept

**Test File:** `x/staking/keeper/slash_test.go`
**Function:** `TestSlashRedelegationWithSlashedDestination` (to be added)

**Setup:**
1. Bootstrap test environment with validators A and B, each with 1000 tokens (power=10)
2. Create delegator with sufficient funds
3. Create redelegation from validator A to B of 400 tokens at height 11
4. Mark validator A's infraction at height 10

**Action:**
1. Slash validator B by 50% at height 12 (reduces B's exchange rate from 1.0 to 0.5)
2. Record bonded pool balance before slashing A
3. Slash validator A by 50% at height 13 for infraction at height 10
4. Record bonded pool balance after slashing A

**Result:**
- Theoretical slash for redelegation: 50% × 400 = 200 tokens
- Actual burn from redelegation: 50% × 400 shares × 0.5 exchange rate = 100 tokens
- Total intended slash: 50% × 1000 = 500 tokens
- Redelegation theoretical amount subtracted from remaining: 200 tokens
- Remaining slash from A's bonded tokens: 500 - 200 = 300 tokens
- Total actual tokens burned: 100 + 300 = 400 tokens
- **Expected: 500 tokens, Actual: 400 tokens, Shortfall: 100 tokens (20% under-slash)**

The bonded pool balance decrease confirms only 400 tokens are burned instead of the protocol-specified 500 tokens, demonstrating a violation of the slashing invariant.

## Notes

The function comment [7](#0-6)  indicates that returning theoretical amounts is intentional for handling insufficient stake scenarios. However, this design is incorrectly applied to redelegations when the destination validator has been independently slashed. In this case, the shortfall is not due to previous slashing of the same stake (which the design handles), but due to an independent validator's slashing event changing the exchange rate. This causes the total actual burn to be less than the protocol-specified `slashFactor * power`, violating the fundamental slashing invariant and distinguishing this vulnerability from the intended behavior described in the comment.

### Citations

**File:** x/staking/keeper/slash.go (L93-102)
```go
		// Iterate through redelegations from slashed source validator
		redelegations := k.GetRedelegationsFromSrcValidator(ctx, operatorAddress)
		for _, redelegation := range redelegations {
			amountSlashed := k.SlashRedelegation(ctx, validator, redelegation, infractionHeight, slashFactor)
			if amountSlashed.IsZero() {
				continue
			}

			remainingSlashAmount = remainingSlashAmount.Sub(amountSlashed)
		}
```

**File:** x/staking/keeper/slash.go (L214-217)
```go
// return the amount that would have been slashed assuming
// the unbonding delegation had enough stake to slash
// (the amount actually slashed may be less if there's
// insufficient stake remaining)
```

**File:** x/staking/keeper/slash.go (L219-296)
```go
func (k Keeper) SlashRedelegation(ctx sdk.Context, srcValidator types.Validator, redelegation types.Redelegation,
	infractionHeight int64, slashFactor sdk.Dec) (totalSlashAmount sdk.Int) {
	now := ctx.BlockHeader().Time
	totalSlashAmount = sdk.ZeroInt()
	bondedBurnedAmount, notBondedBurnedAmount := sdk.ZeroInt(), sdk.ZeroInt()

	// perform slashing on all entries within the redelegation
	for _, entry := range redelegation.Entries {
		// If redelegation started before this height, stake didn't contribute to infraction
		if entry.CreationHeight < infractionHeight {
			continue
		}

		if entry.IsMature(now) {
			// Redelegation no longer eligible for slashing, skip it
			continue
		}

		// Calculate slash amount proportional to stake contributing to infraction
		slashAmountDec := slashFactor.MulInt(entry.InitialBalance)
		slashAmount := slashAmountDec.TruncateInt()
		totalSlashAmount = totalSlashAmount.Add(slashAmount)

		// Unbond from target validator
		sharesToUnbond := slashFactor.Mul(entry.SharesDst)
		if sharesToUnbond.IsZero() {
			continue
		}

		valDstAddr, err := sdk.ValAddressFromBech32(redelegation.ValidatorDstAddress)
		if err != nil {
			panic(err)
		}

		delegatorAddress := sdk.MustAccAddressFromBech32(redelegation.DelegatorAddress)

		delegation, found := k.GetDelegation(ctx, delegatorAddress, valDstAddr)
		if !found {
			// If deleted, delegation has zero shares, and we can't unbond any more
			continue
		}

		if sharesToUnbond.GT(delegation.Shares) {
			sharesToUnbond = delegation.Shares
		}

		tokensToBurn, err := k.Unbond(ctx, delegatorAddress, valDstAddr, sharesToUnbond)
		if err != nil {
			panic(fmt.Errorf("error unbonding delegator: %v", err))
		}

		dstValidator, found := k.GetValidator(ctx, valDstAddr)
		if !found {
			panic("destination validator not found")
		}

		// tokens of a redelegation currently live in the destination validator
		// therefor we must burn tokens from the destination-validator's bonding status
		switch {
		case dstValidator.IsBonded():
			bondedBurnedAmount = bondedBurnedAmount.Add(tokensToBurn)
		case dstValidator.IsUnbonded() || dstValidator.IsUnbonding():
			notBondedBurnedAmount = notBondedBurnedAmount.Add(tokensToBurn)
		default:
			panic("unknown validator status")
		}
	}

	if err := k.burnBondedTokens(ctx, bondedBurnedAmount); err != nil {
		panic(err)
	}

	if err := k.burnNotBondedTokens(ctx, notBondedBurnedAmount); err != nil {
		panic(err)
	}

	return totalSlashAmount
}
```

**File:** x/staking/spec/02_state_transitions.md (L131-138)
```markdown
- The total `slashAmount` is calculated as the `slashFactor` (a chain parameter) \* `TokensFromConsensusPower`,
  the total number of tokens bonded to the validator at the time of the infraction.
- Every unbonding delegation and pseudo-unbonding redelegation such that the infraction occured before the unbonding or
  redelegation began from the validator are slashed by the `slashFactor` percentage of the initialBalance.
- Each amount slashed from redelegations and unbonding delegations is subtracted from the
  total slash amount.
- The `remaingSlashAmount` is then slashed from the validator's tokens in the `BondedPool` or
  `NonBondedPool` depending on the validator's status. This reduces the total supply of tokens.
```

**File:** x/staking/types/validator.go (L304-306)
```go
func (v Validator) TokensFromShares(shares sdk.Dec) sdk.Dec {
	return (shares.MulInt(v.Tokens)).Quo(v.DelegatorShares)
}
```

**File:** x/staking/types/validator.go (L393-405)
```go
func (v Validator) RemoveTokens(tokens sdk.Int) Validator {
	if tokens.IsNegative() {
		panic(fmt.Sprintf("should not happen: trying to remove negative tokens %v", tokens))
	}

	if v.Tokens.LT(tokens) {
		panic(fmt.Sprintf("should not happen: only have %v tokens, trying to remove %v", v.Tokens, tokens))
	}

	v.Tokens = v.Tokens.Sub(tokens)

	return v
}
```

**File:** x/slashing/abci.go (L22-66)
```go
// BeginBlocker check for infraction evidence or downtime of validators
// on every begin block
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	var wg sync.WaitGroup
	// Iterate over all the validators which *should* have signed this block
	// store whether or not they have actually signed it and slash/unbond any
	// which have missed too many blocks in a row (downtime slashing)

	// this allows us to preserve the original ordering for writing purposes
	slashingWriteInfo := make([]*SlashingWriteInfo, len(req.LastCommitInfo.GetVotes()))

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
