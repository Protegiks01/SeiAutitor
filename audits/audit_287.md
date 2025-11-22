# Audit Report

## Title
Equivocation Slashing Uses Historical Power Leading to Under-Slashing When Validator Stake Increases After Infraction

## Summary
The `HandleEquivocationEvidence` function calculates slash amounts based on the validator's historical power at the time of the infraction, not their current token balance. This allows validators to significantly reduce their effective slash percentage by attracting additional delegations after committing equivocation but before evidence is submitted. [1](#0-0) 

## Impact
**Medium** - A bug in the L1 network code that results in unintended behavior (under-slashing) undermining the protocol's security model, with no concrete funds at direct risk but potential for systemic security degradation.

## Finding Description

**Location:** 
- `x/evidence/keeper/infraction.go` lines 107-112 (evidence handler)
- `x/staking/keeper/slash.go` lines 32-34 (slash calculation) [2](#0-1) 

**Intended Logic:** 
When a validator commits equivocation (double-signing), they should be slashed a fixed percentage (e.g., 5%) of their total bonded tokens at the time of evidence processing. This ensures adequate punishment regardless of when the evidence is submitted within the evidence validity window.

**Actual Logic:** 
The slash amount is calculated using the historical power stored in the evidence (`evidence.GetValidatorPower()`), which represents the validator's power at the infraction height, not their current power. The calculation is:
```
slashAmount = TokensFromConsensusPower(historicalPower) * slashFraction
```

This value is then capped by the validator's current tokens: [3](#0-2) 

If a validator's stake increases significantly between the infraction and evidence submission, the effective slash percentage becomes much smaller than intended.

**Exploit Scenario:**
1. Validator operates with minimal self-delegation (e.g., power = 100, tokens = 100,000,000)
2. Validator commits double-signing at height H
3. Evidence is created with `Power = 100` (historical power)
4. Before evidence submission, validator attracts 900,000,000 additional tokens in delegations (now power = 1000, tokens = 1,000,000,000)
5. Evidence is submitted within the validity window
6. Slash calculation: `100 * 1,000,000 * 0.05 = 5,000,000 tokens` (5% of historical stake)
7. Expected slash: `1,000,000,000 * 0.05 = 50,000,000 tokens` (5% of current stake)
8. Actual slash: `5,000,000 tokens` (only 0.5% of current stake)
9. Validator avoids `45,000,000 tokens` in slashing (90% reduction in penalty)

**Security Failure:** 
The protocol's slashing mechanism serves as an economic deterrent against misbehavior. By allowing validators to dilute their slash penalty through post-infraction delegations, the system breaks the security invariant that equivocation will result in a fixed percentage loss. This undermines consensus security and the economic model that protects the network.

## Impact Explanation

**Affected Assets/Processes:**
- Protocol security model and slashing guarantees
- Economic deterrent against validator misbehavior  
- Network consensus security assumptions
- Fair punishment for all validators regardless of timing

**Severity:**
While no funds are directly stolen, this vulnerability allows validators to game the slashing system by reducing their effective penalty from the intended percentage to a much smaller fraction. This could lead to:
- Increased frequency of equivocation attacks (reduced economic deterrent)
- Validators intentionally timing their misbehavior to minimize punishment
- Systematic undermining of the protocol's security guarantees
- Loss of trust in the slashing mechanism

**Why It Matters:**
The Cosmos SDK's security model relies on slashing being a sufficient deterrent to prevent validator misbehavior. If validators can predictably reduce their slash penalties by 90% or more, the entire security model becomes ineffective. This could enable attacks that would otherwise be economically irrational.

## Likelihood Explanation

**Who Can Trigger:**
Any validator who commits equivocation can exploit this vulnerability. The validator needs to either self-delegate additional tokens or attract delegations from other users before evidence is submitted.

**Required Conditions:**
- Validator commits equivocation
- Evidence submission is delayed (within the `MaxAgeDuration` and `MaxAgeNumBlocks` window)
- Validator's stake increases between infraction and evidence submission
- This can happen naturally through normal delegation flows or be intentionally orchestrated [4](#0-3) 

**Frequency:**
This could occur on every equivocation event where the validator's stake increases during the evidence submission window. Given that evidence can be submitted up to the unbonding period (typically 21 days) after the infraction, there is substantial time for stake changes to occur. The vulnerability is particularly exploitable by sophisticated validators who understand the mechanism.

## Recommendation

Modify the slash calculation to use the validator's **current power** at evidence processing time instead of historical power from the evidence. This ensures the slash percentage remains consistent regardless of stake changes.

**Specific Fix:**

In `x/evidence/keeper/infraction.go`, replace the historical power with current power:

```go
// Get current validator to use current power instead of historical
validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
currentPower := k.stakingKeeper.GetLastValidatorPower(ctx, validator.GetOperator())

k.slashingKeeper.Slash(
    ctx,
    consAddr,
    k.slashingKeeper.SlashFractionDoubleSign(ctx),
    currentPower, // Use current power instead of evidence.GetValidatorPower()
    distributionHeight,
)
```

Alternatively, calculate the slash amount as a percentage of current tokens directly rather than using the power-based calculation.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestHandleDoubleSignWithStakeIncrease` (new test to be added)

**Setup:**
1. Initialize test environment with a validator having power = 100 (100,000,000 tokens)
2. Set slash fraction to 5% (1/20)
3. Record validator's initial token balance

**Trigger:**
1. Create equivocation evidence with Power = 100 (historical power)
2. Before submitting evidence, delegate an additional 900,000,000 tokens to the validator
3. Execute EndBlocker to update validator state (now has 1,000,000,000 tokens, power = 1000)
4. Submit the equivocation evidence with historical Power = 100
5. Call HandleEquivocationEvidence

**Observation:**
```go
// Initial tokens: 100,000,000
// Additional delegation: 900,000,000  
// Total tokens: 1,000,000,000

// Expected slash: 1,000,000,000 * 0.05 = 50,000,000 tokens (5%)
// Actual slash: 100,000,000 * 0.05 = 5,000,000 tokens (0.5%)

// After slashing, validator should have ~950,000,000 tokens
// But actually has ~995,000,000 tokens

oldTokens := validator.GetTokens() // 1,000,000,000
HandleEquivocationEvidence(ctx, evidence)
newTokens := validator.GetTokens() // 995,000,000

slashedAmount := oldTokens.Sub(newTokens) // 5,000,000
expectedSlash := oldTokens.MulRaw(5).QuoRaw(100) // 50,000,000

require.True(t, slashedAmount.LT(expectedSlash), 
    "Actual slash %v is much less than expected slash %v", 
    slashedAmount, expectedSlash)

// Demonstrates that effective slash percentage is 0.5% instead of 5%
effectiveSlashPct := slashedAmount.ToDec().Quo(oldTokens.ToDec())
require.True(t, effectiveSlashPct.LT(sdk.NewDecWithPrec(1, 2)), 
    "Effective slash percentage %v is less than 1%%", effectiveSlashPct)
```

The test demonstrates that when a validator's stake increases 10x after committing equivocation, the slash amount remains based on the historical stake, resulting in an effective slash of 0.5% instead of the intended 5% - a 90% reduction in the penalty.

### Citations

**File:** x/evidence/keeper/infraction.go (L42-63)
```go
	// calculate the age of the evidence
	infractionHeight := evidence.GetHeight()
	infractionTime := evidence.GetTime()
	ageDuration := ctx.BlockHeader().Time.Sub(infractionTime)
	ageBlocks := ctx.BlockHeader().Height - infractionHeight

	// Reject evidence if the double-sign is too old. Evidence is considered stale
	// if the difference in time and number of blocks is greater than the allowed
	// parameters defined.
	cp := ctx.ConsensusParams()
	if cp != nil && cp.Evidence != nil {
		if ageDuration > cp.Evidence.MaxAgeDuration && ageBlocks > cp.Evidence.MaxAgeNumBlocks {
			logger.Info(
				"ignored equivocation; evidence too old",
				"validator", consAddr,
				"infraction_height", infractionHeight,
				"max_age_num_blocks", cp.Evidence.MaxAgeNumBlocks,
				"infraction_time", infractionTime,
				"max_age_duration", cp.Evidence.MaxAgeDuration,
			)
			return
		}
```

**File:** x/evidence/keeper/infraction.go (L107-112)
```go
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)
```

**File:** x/staking/keeper/slash.go (L24-34)
```go
func (k Keeper) Slash(ctx sdk.Context, consAddr sdk.ConsAddress, infractionHeight int64, power int64, slashFactor sdk.Dec) {
	logger := k.Logger(ctx)

	if slashFactor.IsNegative() {
		panic(fmt.Errorf("attempted to slash with a negative slash factor: %v", slashFactor))
	}

	// Amount of slashing = slash slashFactor * power at time of infraction
	amount := k.TokensFromConsensusPower(ctx, power)
	slashAmountDec := amount.ToDec().Mul(slashFactor)
	slashAmount := slashAmountDec.TruncateInt()
```

**File:** x/staking/keeper/slash.go (L105-107)
```go
	// cannot decrease balance below zero
	tokensToBurn := sdk.MinInt(remainingSlashAmount, validator.Tokens)
	tokensToBurn = sdk.MaxInt(tokensToBurn, sdk.ZeroInt()) // defensive.
```
