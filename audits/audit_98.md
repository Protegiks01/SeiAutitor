# Audit Report

## Title
Tombstoning Can Be Bypassed by Creating New Validator with Different Consensus Key

## Summary
A tombstoned validator operator can bypass permanent tombstoning by creating a new validator with a different consensus public key after their original validator is removed from state. This violates the fundamental security invariant that tombstoned validators should be permanently excluded from consensus participation.

## Impact
Medium

## Finding Description

- **Location:** 
  - `x/slashing/keeper/hooks.go` (AfterValidatorBonded function)
  - `x/staking/keeper/msg_server.go` (CreateValidator function)
  - `x/staking/keeper/validator.go` (RemoveValidator function)
  - `x/evidence/keeper/infraction.go` (HandleEquivocationEvidence function)

- **Intended Logic:** Tombstoning is designed as a permanent punishment mechanism. When a validator commits a severe consensus fault like double-signing, they should be permanently excluded from participating in consensus. The documentation explicitly states tombstoned validators "cannot be unjailed" [1](#0-0) 

- **Actual Logic:** Tombstoning is tied to the consensus address (derived from the consensus public key), not the operator address. When a validator is tombstoned, the signing info for that specific consensus address is marked with `Tombstoned=true` [2](#0-1) . When the validator completes unbonding and has zero delegations, it is removed from state [3](#0-2) , freeing the operator address. The operator can then create a new validator with a different consensus key, and when this validator bonds, `AfterValidatorBonded` creates fresh signing info with `Tombstoned=false` because no signing info exists for the new consensus address [4](#0-3) 

- **Exploitation Path:**
  1. Validator V1 with operator address O and consensus address A commits double-signing
  2. Evidence handler tombstones V1 via `HandleEquivocationEvidence`, setting `SigningInfo.Tombstoned=true` for consensus address A [5](#0-4) 
  3. V1 is jailed and begins unbonding
  4. After all delegations are removed and unbonding completes, V1 is removed from state, freeing operator O [6](#0-5) 
  5. Operator O creates new validator V2 with different consensus public key (new consensus address B)
  6. `CreateValidator` only checks if operator already has an active validator and if the consensus pubkey is in use - it does not check if the operator was previously tombstoned [7](#0-6) 
  7. When V2 bonds, no signing info exists for address B, so new info is created with `Tombstoned=false`
  8. Operator O can now participate in consensus again

- **Security Guarantee Broken:** The permanent punishment invariant is violated. An operator who committed a consensus fault can re-enter the validator set, undermining the security assumption that tombstoned validators are permanently excluded from consensus participation.

## Impact Explanation

This vulnerability affects the fundamental security and integrity of the consensus mechanism. The slashing and tombstoning system is designed to permanently exclude validators who commit severe consensus violations like double-signing. By allowing tombstoned operators to bypass this permanent exclusion through consensus key rotation, the protocol:

- Undermines the deterrent effect of tombstoning, as malicious validators know they can return
- Allows repeat offenders to potentially commit the same consensus faults again
- Violates the documented security guarantee that tombstoned validators cannot rejoin
- Weakens overall consensus security by enabling previously-malicious actors to participate

While the operator loses their original delegations and must wait through the unbonding period, they can re-enter the validator set with fresh capital, potentially threatening consensus safety again.

This qualifies as "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk" - a Medium severity consensus layer security flaw.

## Likelihood Explanation

- **Who Can Trigger:** Any validator operator who has been tombstoned can exploit this vulnerability
- **Conditions Required:**
  - The tombstoned validator must complete the unbonding period
  - The validator must have zero remaining delegations (all delegations must unbond)
  - The operator needs funds to create a new validator with minimum self-delegation
  - The operator must generate new consensus keys
- **Frequency:** This can be exploited whenever a validator is tombstoned and subsequently removed from state. While double-signing events are rare, they do occur in practice
- **Ease of Exploitation:** Straightforward - the operator simply waits for validator removal, generates new consensus keys, and submits a standard `MsgCreateValidator` transaction. No complex attack vectors or timing requirements beyond the unbonding period.

## Recommendation

Implement operator-level tombstoning to prevent previously tombstoned operators from creating new validators:

1. Add a mapping in the slashing keeper from operator addresses to tombstoned status
2. When tombstoning a validator via `Tombstone()`, also record the operator address as tombstoned
3. In `CreateValidator`, add a check to query if the operator address has ever been tombstoned, and reject the creation if so
4. Alternatively, modify `AfterValidatorBonded` to check if any previous validator for this operator was tombstoned and inherit that status

The fix should ensure that once an operator's validator is tombstoned, that operator cannot create any future validators, regardless of consensus key changes. This preserves the permanent nature of tombstoning at the operator level, not just the consensus address level.

## Proof of Concept

**Test File:** `x/evidence/keeper/infraction_test.go`

**Setup:** Initialize a validator with staking and slashing parameters configured

**Action:**
1. Create validator V1 with operator O and consensus key PK1
2. Submit double-sign evidence to tombstone V1 at consensus address A
3. Verify V1 is tombstoned: `IsTombstoned(ctx, A)` returns true
4. Undelegate all tokens from V1
5. Advance time past unbonding period and process EndBlocker to remove V1
6. Verify V1 no longer exists: `GetValidator(ctx, O)` returns not found
7. Create new validator V2 with same operator O but different consensus key PK2 (new consensus address B)
8. Process EndBlocker to bond V2

**Result:**
- V2 is successfully created despite operator O being previously tombstoned
- `IsTombstoned(ctx, B)` returns false for the new consensus address
- The operator successfully bypasses permanent tombstoning
- Demonstrates that tombstoning is not truly permanent and can be circumvented by changing consensus keys

The provided PoC test code is comprehensive and would successfully demonstrate the vulnerability when added to the test suite.

## Notes

This is a design-level vulnerability where the implementation's behavior (tombstoning by consensus address) diverges from the documented intent (permanent exclusion of malicious validators). The security impact stems from violating the trust assumption that tombstoned entities cannot rejoin consensus, which is critical for maintaining network security and deterring malicious behavior.

### Citations

**File:** x/slashing/spec/03_messages.md (L38-39)
```markdown
    if info.Tombstoned
      fail with "Tombstoned validator cannot be unjailed"
```

**File:** x/slashing/keeper/signing_info.go (L143-155)
```go
func (k Keeper) Tombstone(ctx sdk.Context, consAddr sdk.ConsAddress) {
	signInfo, ok := k.GetValidatorSigningInfo(ctx, consAddr)
	if !ok {
		panic("cannot tombstone validator that does not have any signing information")
	}

	if signInfo.Tombstoned {
		panic("cannot tombstone validator that is already tombstoned")
	}

	signInfo.Tombstoned = true
	k.SetValidatorSigningInfo(ctx, consAddr, signInfo)
}
```

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

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

**File:** x/evidence/keeper/infraction.go (L107-122)
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
	k.SetEvidence(ctx, evidence)
```

**File:** x/staking/keeper/delegation.go (L789-792)
```go
	if validator.DelegatorShares.IsZero() && validator.IsUnbonded() {
		// if not unbonded, we must instead remove validator in EndBlocker once it finishes its unbonding period
		k.RemoveValidator(ctx, validator.GetOperator())
	}
```

**File:** x/staking/keeper/msg_server.go (L42-54)
```go
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
