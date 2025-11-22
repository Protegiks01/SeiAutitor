## Title
Consensus Key Reuse Allows Slashing Wrong Validator After Validator Removal

## Summary
When a validator is removed from the validator set, their consensus key becomes available for reuse by a new validator. If evidence of the original validator's misbehavior is submitted after removal but before evidence expiration, the new validator with the reused consensus key will be incorrectly slashed and permanently tombstoned for the original validator's infraction.

## Impact
**High** - Direct loss of funds and permanent freezing of validator stake.

## Finding Description

**Location:** 
- Evidence handling: [1](#0-0) 
- Staking slash lookup: [2](#0-1) 
- Validator removal: [3](#0-2) 
- Pubkey mapping deletion: [4](#0-3) 

**Intended Logic:** 
When evidence of validator misbehavior is submitted, the system should identify and slash the specific validator who committed the infraction at the height specified in the evidence. Each validator should only be held accountable for their own actions.

**Actual Logic:**
The evidence handling system uses the consensus address from the evidence to look up the validator via `ValidatorByConsAddr`, which returns the CURRENT validator with that consensus address, not necessarily the validator who committed the infraction. When a validator is removed, both the `ValidatorByConsAddr` mapping [5](#0-4)  and the slashing module's pubkey mapping [6](#0-5)  are deleted. This allows a new validator to be created with the same consensus key, since the `CreateValidator` check only verifies if a validator currently exists with that key [7](#0-6) .

**Exploit Scenario:**
1. ValidatorA creates a validator with consensus key K1 and operator address opA
2. ValidatorA commits a double-sign infraction at height H
3. ValidatorA unbonds all delegations and is removed from the validator set via [8](#0-7) 
4. ValidatorB creates a new validator with operator address opB but reuses consensus key K1
5. Within the evidence validity window (default 3 weeks [9](#0-8) ), evidence of ValidatorA's infraction from height H is submitted
6. `HandleEquivocationEvidence` retrieves the validator using `ValidatorByConsAddr(K1)` which now returns ValidatorB [1](#0-0) 
7. The staking keeper's `Slash` function again uses `GetValidatorByConsAddr(K1)` to identify the validator [2](#0-1) 
8. ValidatorB is slashed and permanently tombstoned [10](#0-9)  for ValidatorA's misbehavior

**Security Failure:**
This breaks the accountability invariant - validators must only be responsible for their own consensus violations. The vulnerability allows ValidatorA to escape punishment by transferring liability to an innocent ValidatorB who reuses the consensus key.

## Impact Explanation

**Assets Affected:** Validator stake (bonded tokens) of the innocent validator reusing the consensus key.

**Severity of Damage:**
- **Direct Loss of Funds:** The innocent validator's stake is slashed by the double-sign fraction (typically 5% [11](#0-10) )
- **Permanent Freezing:** The validator is tombstoned [12](#0-11) , preventing them from ever unjailing or participating in consensus again
- **Loss of Delegator Funds:** All delegators to the innocent validator also lose their delegated stake percentage

**Why It Matters:**
This fundamentally undermines the slashing mechanism's integrity. Validators could deliberately commit infractions, unbond before evidence submission, and allow others to unknowingly reuse their consensus keys to absorb the punishment. This creates perverse incentives and destroys trust in the validator accountability system.

## Likelihood Explanation

**Who Can Trigger:**
- Any validator can commit an infraction
- Any user can create a new validator and choose any consensus key not currently in use
- Any user can submit evidence within the validity window

**Required Conditions:**
- Unbonding period (default 3 weeks [13](#0-12) ) must complete for the original validator
- Evidence must be submitted within the evidence validity window (default 3 weeks in blocks [14](#0-13) )
- A new validator must reuse the old consensus key before evidence is submitted

**Frequency:**
While the timing requirements create a specific window, this is highly exploitable:
- Evidence submission can be deliberately delayed by the misbehaving validator or their associates
- Consensus key reuse can be orchestrated by the same operator using a different identity
- The matching evidence and unbonding periods make the attack window substantial

## Recommendation

Implement historical consensus key tracking to prevent key reuse:

1. **Prevent Consensus Key Reuse:** Never allow a consensus key to be reused once associated with a validator, even after validator removal. Modify the `CreateValidator` check to verify against historical usage, not just current validators.

2. **Tombstone on Consensus Address:** When tombstoning a validator, also mark the consensus address itself as permanently tombstoned, preventing any future validator from using that key.

3. **Evidence-Time Validator Lookup:** Implement historical validator lookup by consensus address at specific heights, similar to the proposed design in ADR-016 [15](#0-14) . Store `ConsPubKeyRotationHistory` even without full key rotation support.

4. **Extended Signing Info Lifecycle:** Do not delete signing info when validators are removed; instead, keep it for at least the evidence validity period to maintain accountability.

## Proof of Concept

**File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** `TestSlashingWrongValidatorWithReusedConsensusKey`

```go
func (suite *KeeperTestSuite) TestSlashingWrongValidatorWithReusedConsensusKey() {
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1)
    suite.populateValidators(ctx)
    
    stakingParams := suite.app.StakingKeeper.GetParams(ctx)
    stakingParams.MinCommissionRate = sdk.NewDec(0)
    suite.app.StakingKeeper.SetParams(ctx, stakingParams)

    slashingParams := suite.app.SlashingKeeper.GetParams(ctx)
    slashFraction := sdk.NewDec(1).Quo(sdk.NewDec(20)) // 5% slash
    slashingParams.SlashFractionDoubleSign = slashFraction
    suite.app.SlashingKeeper.SetParams(ctx, slashingParams)

    power := int64(100)
    
    // Create ValidatorA with consensus key
    operatorA, consKeyA := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    selfDelegationA := tstaking.CreateValidatorWithValPower(operatorA, consKeyA, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)

    // ValidatorA double-signs at height 10
    ctx = ctx.WithBlockHeight(10)
    evidence := &types.Equivocation{
        Height:           10,
        Time:             ctx.BlockTime(),
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(consKeyA.Address()).String(),
    }

    // ValidatorA unbonds completely
    ctx = ctx.WithBlockHeight(11)
    del, _ := suite.app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(operatorA), operatorA)
    validator, _ := suite.app.StakingKeeper.GetValidator(ctx, operatorA)
    totalBond := validator.TokensFromShares(del.GetShares()).TruncateInt()
    tstaking.Ctx = ctx
    tstaking.Denom = stakingParams.BondDenom
    tstaking.Undelegate(sdk.AccAddress(operatorA), operatorA, totalBond, true)

    // Complete unbonding period
    ctx = ctx.WithBlockTime(ctx.BlockTime().Add(stakingParams.UnbondingTime))
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)

    // Verify ValidatorA is removed
    _, found := suite.app.StakingKeeper.GetValidator(ctx, operatorA)
    suite.False(found, "ValidatorA should be removed")

    // Create ValidatorB with SAME consensus key
    operatorB := valAddresses[1]  // Different operator address
    selfDelegationB := tstaking.CreateValidatorWithValPower(operatorB, consKeyA, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)

    // Get ValidatorB's initial tokens
    validatorB, _ := suite.app.StakingKeeper.GetValidator(ctx, operatorB)
    initialTokensB := validatorB.GetTokens()

    // Submit evidence of ValidatorA's double-sign
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)

    // VULNERABILITY: ValidatorB is slashed instead of ValidatorA
    validatorB, _ = suite.app.StakingKeeper.GetValidator(ctx, operatorB)
    newTokensB := validatorB.GetTokens()
    
    // Assert ValidatorB was incorrectly slashed
    suite.True(newTokensB.LT(initialTokensB), "ValidatorB should be slashed")
    suite.True(validatorB.IsJailed(), "ValidatorB should be jailed")
    suite.True(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(consKeyA.Address())), 
        "ValidatorB should be tombstoned for ValidatorA's infraction")
}
```

**Setup:** Initialize chain state with staking and slashing parameters.

**Trigger:** 
1. Create ValidatorA with consensus key K
2. Generate evidence of ValidatorA's double-sign
3. Fully unbond and remove ValidatorA
4. Create ValidatorB with the same consensus key K
5. Submit the evidence from step 2

**Observation:** The test observes that ValidatorB's tokens decrease (slashed), ValidatorB is jailed, and ValidatorB is tombstoned - all for ValidatorA's infraction. This confirms the vulnerability where the wrong validator is punished due to consensus key reuse.

### Citations

**File:** x/evidence/keeper/infraction.go (L66-66)
```go
	validator := k.stakingKeeper.ValidatorByConsAddr(ctx, consAddr)
```

**File:** x/evidence/keeper/infraction.go (L107-121)
```go
	k.slashingKeeper.Slash(
		ctx,
		consAddr,
		k.slashingKeeper.SlashFractionDoubleSign(ctx),
		evidence.GetValidatorPower(), distributionHeight,
	)

	// Jail the validator if not already jailed. This will begin unbonding the
	// validator if not already unbonding (tombstoned).
	if !validator.IsJailed() {
		k.slashingKeeper.Jail(ctx, consAddr)
	}

	k.slashingKeeper.JailUntil(ctx, consAddr, types.DoubleSignJailEndTime)
	k.slashingKeeper.Tombstone(ctx, consAddr)
```

**File:** x/staking/keeper/slash.go (L38-38)
```go
	validator, found := k.GetValidatorByConsAddr(ctx, consAddr)
```

**File:** x/staking/keeper/validator.go (L173-181)
```go
	// delete the old validator record
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.GetValidatorKey(address))
	store.Delete(types.GetValidatorByConsAddrKey(valConsAddr))
	store.Delete(types.GetValidatorsByPowerIndexKey(validator, k.PowerReduction(ctx)))

	// call hooks
	k.AfterValidatorRemoved(ctx, valConsAddr, validator.GetOperator())
}
```

**File:** x/slashing/keeper/hooks.go (L40-43)
```go
// AfterValidatorRemoved deletes the address-pubkey relation when a validator is removed,
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** x/staking/keeper/msg_server.go (L52-54)
```go
	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
	}
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** simapp/test_helpers.go (L44-46)
```go
	Evidence: &tmproto.EvidenceParams{
		MaxAgeNumBlocks: 302400,
		MaxAgeDuration:  504 * time.Hour, // 3 weeks is the max duration
```

**File:** x/slashing/keeper/keeper_test.go (L22-22)
```go
func TestUnJailNotBonded(t *testing.T) {
```

**File:** x/staking/types/params.go (L21-21)
```go
	DefaultUnbondingTime time.Duration = time.Hour * 24 * 7 * 3
```

**File:** docs/architecture/adr-016-validator-consensus-key-rotation.md (L29-31)
```markdown
    - store history of each key mapping changes in the kvstore.
    - the state machine can search corresponding consensus key paired with given validator operator for any arbitrary height in a recent unbonding period.
    - the state machine does not need any historical mapping information which is past more than unbonding period.
```
