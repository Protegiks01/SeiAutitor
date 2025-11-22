# Audit Report

## Title
Tombstoning Can Be Bypassed by Creating New Validator with Different Consensus Key

## Summary
A tombstoned validator operator can bypass permanent tombstoning by waiting for their validator to be removed after the unbonding period, then creating a new validator with a different consensus public key. The new validator receives fresh signing info with `Tombstoned=false`, allowing the operator to participate in consensus again despite being previously tombstoned for offenses like double-signing.

## Impact
Medium

## Finding Description

- **Location:** 
  - [1](#0-0) 
  - [2](#0-1) 
  - [3](#0-2) 

- **Intended Logic:** Tombstoning is designed to be a permanent punishment mechanism. When a validator commits a severe consensus fault (e.g., double-signing), they are tombstoned and should never be able to participate in consensus again. [4](#0-3) 

- **Actual Logic:** Tombstoning is tied to the consensus address (derived from the consensus public key), not the operator address. When a tombstoned validator completes unbonding and has zero delegations, it is removed from state [3](#0-2) , freeing the operator address. The operator can then create a new validator with a different consensus key. When this new validator bonds, `AfterValidatorBonded` creates fresh signing info with `Tombstoned=false` because no signing info exists for the new consensus address [5](#0-4) .

- **Exploit Scenario:**
  1. Validator V1 (operator address O, consensus address A) commits double-signing
  2. Evidence handler tombstones V1, setting `SigningInfo.Tombstoned=true` for address A
  3. V1 is jailed and begins unbonding
  4. After unbonding period completes, V1 is removed from validator set (operator O is freed)
  5. Operator O creates new validator V2 with different consensus public key (consensus address B)
  6. `CreateValidator` succeeds because it only checks if operator already has an active validator [6](#0-5) , not whether operator was previously tombstoned
  7. When V2 bonds, no signing info exists for address B, so new info is created with `Tombstoned=false`
  8. Operator O can now participate in consensus again with V2

- **Security Failure:** The permanent punishment invariant is violated. An operator who committed a consensus fault can re-enter the validator set, undermining the security assumption that tombstoned validators are permanently excluded from consensus participation.

## Impact Explanation

This vulnerability affects the fundamental security and integrity of the consensus mechanism:

- **Process Affected:** The slashing and tombstoning mechanism that enforces permanent punishment for severe consensus violations
- **Severity:** Malicious validators who commit double-signing or other consensus faults can bypass permanent exclusion by simply rotating their consensus keys after unbonding
- **System Impact:** This undermines the deterrent effect of tombstoning and allows repeat offenders to continue threatening consensus safety. While the attacker loses their original delegations and must wait through the unbonding period, they can return with a new validator and potentially commit the same offenses again
- **Trust Assumption Violation:** The protocol assumes tombstoned validators cannot participate in consensus, but this assumption is broken when operators can create new validators with different keys

## Likelihood Explanation

- **Who Can Trigger:** Any validator operator who has been tombstoned can exploit this vulnerability
- **Conditions Required:** 
  - The tombstoned validator must complete the unbonding period
  - The validator must have zero remaining delegations (or all delegations must unbond)
  - The operator needs funds to create a new validator with minimum self-delegation
- **Frequency:** This can be exploited whenever a validator is tombstoned and subsequently removed from state. Given that double-signing is rare but does occur in practice, this could happen periodically
- **Ease of Exploitation:** Straightforward - simply wait for validator removal, generate new consensus keys, and create a new validator with `MsgCreateValidator`

## Recommendation

Implement an operator-level tombstoning check to prevent previously tombstoned operators from creating new validators:

1. Add a mapping from operator addresses to tombstoned status in the slashing keeper
2. When tombstoning a validator, also record the operator address as tombstoned
3. In `CreateValidator`, check if the operator address is tombstoned and reject the creation if so
4. Alternatively, when calling `AfterValidatorBonded`, check if any previous validator for this operator was tombstoned and propagate that status

The fix should ensure that once an operator's validator is tombstoned, that operator cannot create any future validators, regardless of consensus key changes.

## Proof of Concept

**Test File:** `x/evidence/keeper/infraction_test.go`

**Test Function:** Add the following test to the existing test suite:

```go
func (suite *KeeperTestSuite) TestTombstonedOperatorCanCreateNewValidator() {
    ctx := suite.ctx.WithIsCheckTx(false).WithBlockHeight(1)
    suite.populateValidators(ctx)
    
    stakingParams := suite.app.StakingKeeper.GetParams(ctx)
    stakingParams.MinCommissionRate = sdk.NewDec(0)
    suite.app.StakingKeeper.SetParams(ctx, stakingParams)
    
    // Create first validator
    power := int64(100)
    operatorAddr, oldConsPubKey := valAddresses[0], pubkeys[0]
    tstaking := teststaking.NewHelper(suite.T(), ctx, suite.app.StakingKeeper)
    selfDelegation := tstaking.CreateValidatorWithValPower(operatorAddr, oldConsPubKey, power, true)
    
    // Execute end-blocker to bond validator
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Handle signature to set signing info
    req := abcitypes.RequestBeginBlock{
        LastCommitInfo: abcitypes.LastCommitInfo{
            Votes: []abcitypes.VoteInfo{{
                Validator: abcitypes.Validator{
                    Address: oldConsPubKey.Address().Bytes(),
                    Power:   selfDelegation.Int64(),
                },
                SignedLastBlock: true,
            }},
        },
    }
    slashing.BeginBlocker(ctx, req, suite.app.SlashingKeeper)
    
    // Submit double-sign evidence to tombstone validator
    evidence := &types.Equivocation{
        Height:           0,
        Time:             time.Unix(0, 0),
        Power:            power,
        ConsensusAddress: sdk.ConsAddress(oldConsPubKey.Address()).String(),
    }
    suite.app.EvidenceKeeper.HandleEquivocationEvidence(ctx, evidence)
    
    // Verify validator is tombstoned
    suite.True(suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(oldConsPubKey.Address())))
    
    // Undelegate all tokens to prepare for validator removal
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    del, _ := suite.app.StakingKeeper.GetDelegation(ctx, sdk.AccAddress(operatorAddr), operatorAddr)
    validator, _ := suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    totalBond := validator.TokensFromShares(del.GetShares()).TruncateInt()
    tstaking.Ctx = ctx
    tstaking.Denom = stakingParams.BondDenom
    tstaking.Undelegate(sdk.AccAddress(operatorAddr), operatorAddr, totalBond, true)
    
    // Jump past unbonding period and process validator removal
    ctx = ctx.WithBlockTime(time.Unix(1, 0).Add(stakingParams.UnbondingTime))
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Verify validator was removed
    _, found := suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    suite.False(found, "Validator should be removed after unbonding")
    
    // Create NEW validator with SAME operator but DIFFERENT consensus key
    newConsPubKey := pubkeys[3] // Different pubkey
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    
    // This should fail but currently succeeds - the vulnerability
    selfDelegation2 := tstaking.CreateValidatorWithValPower(operatorAddr, newConsPubKey, power, true)
    staking.EndBlocker(ctx, suite.app.StakingKeeper)
    
    // Verify new validator was created successfully
    newValidator, found := suite.app.StakingKeeper.GetValidator(ctx, operatorAddr)
    suite.True(found, "New validator should exist")
    
    // VULNERABILITY: The new validator is NOT tombstoned despite operator being previously tombstoned
    isTombstoned := suite.app.SlashingKeeper.IsTombstoned(ctx, sdk.ConsAddress(newConsPubKey.Address()))
    
    // This assertion demonstrates the vulnerability - it should be true but is false
    suite.False(isTombstoned, "VULNERABILITY: New validator with different consensus key is NOT tombstoned!")
    
    // The operator can now participate in consensus again despite being previously tombstoned
    suite.True(newValidator.IsBonded() || newValidator.IsUnbonding(), "New validator is active in validator set")
}
```

**Setup:** The test initializes a validator, sets up staking and slashing parameters.

**Trigger:** 
1. Creates a validator and tombstones it via double-sign evidence
2. Unbonds all delegations and waits for unbonding period to complete
3. Creates a new validator with the same operator address but different consensus public key

**Observation:** The test demonstrates that:
- The original validator's consensus address is tombstoned
- After removal, a new validator can be created with the same operator
- The new validator's consensus address is NOT tombstoned (Tombstoned=false)
- The operator successfully bypasses permanent tombstoning

This PoC proves the vulnerability by showing that tombstoning is not truly permanent - it can be circumvented by changing consensus keys after validator removal.

### Citations

**File:** x/slashing/keeper/hooks.go (L12-26)
```go
func (k Keeper) AfterValidatorBonded(ctx sdk.Context, address sdk.ConsAddress, _ sdk.ValAddress) {
	// Update the signing info start height or create a new signing info
	_, found := k.GetValidatorSigningInfo(ctx, address)
	if !found {
		signingInfo := types.NewValidatorSigningInfo(
			address,
			ctx.BlockHeight(),
			0,
			time.Unix(0, 0),
			false,
			0,
		)
		k.SetValidatorSigningInfo(ctx, address, signingInfo)
	}
}
```

**File:** x/staking/keeper/msg_server.go (L30-54)
```go
func (k msgServer) CreateValidator(goCtx context.Context, msg *types.MsgCreateValidator) (*types.MsgCreateValidatorResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return nil, err
	}

	if msg.Commission.Rate.LT(k.MinCommissionRate(ctx)) {
		return nil, sdkerrors.Wrapf(types.ErrCommissionLTMinRate, "cannot set validator commission=%s to less than minimum rate of %s", msg.Commission.Rate, k.MinCommissionRate(ctx))
	}

	// check to see if the pubkey or sender has been registered before
	if _, found := k.GetValidator(ctx, valAddr); found {
		return nil, types.ErrValidatorOwnerExists
	}

	pk, ok := msg.Pubkey.GetCachedValue().(cryptotypes.PubKey)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "Expecting cryptotypes.PubKey, got %T", pk)
	}

	if _, found := k.GetValidatorByConsAddr(ctx, sdk.GetConsAddress(pk)); found {
		return nil, types.ErrValidatorPubKeyExists
	}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/slashing/keeper/signing_info.go (L149-151)
```go
	if signInfo.Tombstoned {
		panic("cannot tombstone validator that is already tombstoned")
	}
```
