## Title
Chain Halt via Validator Pubkey Removal Race Condition in BeginBlocker

## Summary
A timing vulnerability exists in the slashing module's `HandleValidatorSignatureConcurrent` function where a validator's pubkey can be deleted during block N-1's EndBlocker but their signature still appears in block N's BeginBlocker, causing a deterministic panic that halts the entire chain. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Vulnerable code: [2](#0-1) 
- Validator removal logic: [3](#0-2) 
- Pubkey deletion hook: [4](#0-3) 
- Unbonding completion: [5](#0-4) 

**Intended Logic:** 
The `HandleValidatorSignatureConcurrent` function is called during BeginBlocker to process validator signatures from the previous block's commit. It expects all validators who signed the previous block to have their pubkeys available in the slashing keeper's store.

**Actual Logic:** 
When a validator completes unbonding with zero delegator shares, they are removed during the EndBlocker phase via `RemoveValidator`, which triggers the `AfterValidatorRemoved` hook that deletes their pubkey mapping. However, this validator's signature is still present in the next block's `LastCommitInfo` because they were active when signing the previous block. When BeginBlocker processes this signature, `GetPubkey` fails and triggers a panic. [6](#0-5) 

**Exploit Scenario:**
1. A validator enters the unbonding state (either through self-unbonding or losing all delegations)
2. After the unbonding period expires (typically 21 days), block N-1's EndBlocker calls `UnbondAllMatureValidators`
3. The validator transitions from Unbonding → Unbonded with zero delegator shares
4. `RemoveValidator` is called, triggering `AfterValidatorRemoved` hook
5. The slashing keeper deletes the validator's pubkey mapping via `deleteAddrPubkeyRelation`
6. Block N begins processing with `LastCommitInfo` containing the removed validator's vote
7. `HandleValidatorSignatureConcurrent` is called for each vote in parallel goroutines
8. `GetPubkey(ctx, addr)` returns an error for the removed validator
9. Panic occurs: "Validator consensus-address %s not found"
10. All nodes hit the same deterministic panic, causing complete chain halt [7](#0-6) 

**Security Failure:** 
This breaks the liveness property of the blockchain. The panic is deterministic and will occur on all nodes, causing a total network shutdown requiring emergency intervention or a hard fork to resolve.

## Impact Explanation

**Affected Components:**
- Network availability: Complete chain halt
- Transaction finality: No new transactions can be confirmed
- Consensus: All validators hit the same panic and cannot progress

**Severity:**
- Every node in the network will panic deterministically when processing block N
- The chain cannot recover without manual intervention (emergency patch or hard fork)
- No transactions can be processed during the outage
- The issue persists until the code is patched and all nodes upgrade

**System Reliability:**
This is a critical availability failure. The blockchain loses its fundamental property of being able to process and confirm transactions. Network participants cannot interact with the chain until it's manually restored.

## Likelihood Explanation

**Who Can Trigger:**
Any validator operator can trigger this condition without requiring privileged access:
- A validator can choose to unbond themselves
- Delegators can undelegate from a validator, potentially leaving them with zero delegations
- Natural validator set rotation and delegation changes make this scenario inevitable over time

**Conditions Required:**
1. A validator must be in the unbonding state
2. The validator must have zero delegator shares (no remaining delegations)
3. The unbonding period must expire during block N-1's processing
4. The validator must have signed block N-1 (which they will, as they were active at that time)

**Frequency:**
This can occur naturally during normal network operation whenever a validator completes unbonding with no delegations. Given the typical 21-day unbonding period and validator set dynamics, this is not a rare edge case but a realistic scenario that will eventually occur on any active network.

**Evidence of Prior Recognition:**
The evidence module had this exact issue and fixed it by gracefully handling missing pubkeys instead of panicking: [8](#0-7) 

The comment explicitly states they "used to panic" but changed to ignore evidence that cannot be handled, recognizing the validator might no longer be in the system.

## Recommendation

Apply the same fix used in the evidence module: instead of panicking when a validator's pubkey is not found, gracefully skip processing their signature. The validator is no longer part of the active set, so their signature information is not critical for slashing purposes.

**Suggested fix for `HandleValidatorSignatureConcurrent`:**

Replace the panic at lines 28-30 with:
```go
if _, err := k.GetPubkey(ctx, addr); err != nil {
    // Validator no longer in the system (removed after unbonding)
    // This can occur when a validator is removed in block N-1's EndBlocker
    // but their signature appears in block N's LastCommitInfo
    return
}
```

This allows the function to gracefully handle the case where a validator has been removed between blocks, preventing the chain halt while maintaining correct behavior for active validators.

## Proof of Concept

**File:** `x/slashing/abci_test.go`

**Test Function:** `TestValidatorRemovedBeforeSignatureProcessing`

**Setup:**
1. Initialize a test app with a single validator
2. Create the validator with minimal delegation (1 token)
3. Bond the validator and process EndBlocker to activate them
4. Undelegate all tokens to trigger unbonding
5. Set unbonding time to 0 for instant unbonding (test scenario)
6. Advance time and height to trigger unbonding completion

**Trigger:**
1. Call staking EndBlocker to complete unbonding and remove the validator
2. Construct a BeginBlock request with the removed validator's signature in LastCommitInfo
3. Call slashing BeginBlocker with this request

**Observation:**
The test will panic with "Validator consensus-address %s not found", demonstrating the vulnerability. The panic occurs because the validator was removed in step 1 but their signature is still being processed in step 3.

```go
func TestValidatorRemovedBeforeSignatureProcessing(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{Height: 1})
    
    // Create validator
    pks := simapp.CreateTestPubKeys(1)
    pk := pks[0]
    addr := sdk.ValAddress(pk.Address())
    
    // Add minimal tokens
    tokens := app.StakingKeeper.TokensFromConsensusPower(ctx, 1)
    simapp.AddTestAddrsFromPubKeys(app, ctx, pks, tokens)
    
    // Create and bond validator
    tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)
    tstaking.CreateValidatorWithValPower(addr, pk, 1, true)
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Undelegate to trigger unbonding
    delAddr := sdk.AccAddress(addr)
    _, err := app.StakingKeeper.Undelegate(ctx, delAddr, addr, sdk.OneDec())
    require.NoError(t, err)
    
    // Set unbonding time to 0 for instant completion
    params := app.StakingKeeper.GetParams(ctx)
    params.UnbondingTime = 0
    app.StakingKeeper.SetParams(ctx, params)
    
    // Advance to trigger unbonding completion
    ctx = ctx.WithBlockHeight(2).WithBlockTime(ctx.BlockTime().Add(1))
    
    // EndBlocker removes the validator
    staking.EndBlocker(ctx, app.StakingKeeper)
    
    // Verify validator was removed
    _, found := app.StakingKeeper.GetValidator(ctx, addr)
    require.False(t, found, "Validator should be removed")
    
    // Construct BeginBlock with removed validator's signature
    req := abci.RequestBeginBlock{
        LastCommitInfo: abci.LastCommitInfo{
            Votes: []abci.VoteInfo{
                {
                    Validator: abci.Validator{
                        Address: pk.Address(),
                        Power:   1,
                    },
                    SignedLastBlock: true,
                },
            },
        },
    }
    
    // This will panic: "Validator consensus-address not found"
    require.Panics(t, func() {
        slashing.BeginBlocker(ctx, req, app.SlashingKeeper)
    }, "Expected panic when processing removed validator's signature")
}
```

This test demonstrates that when a validator is removed during EndBlocker but their signature appears in the next block's BeginBlocker, the slashing module panics and would halt the chain.

### Citations

**File:** x/slashing/keeper/infractions.go (L22-30)
```go
func (k Keeper) HandleValidatorSignatureConcurrent(ctx sdk.Context, addr cryptotypes.Address, power int64, signed bool) (consAddr sdk.ConsAddress, missedInfo types.ValidatorMissedBlockArray, signInfo types.ValidatorSigningInfo, shouldSlash bool, slashInfo SlashInfo) {
	logger := k.Logger(ctx)
	height := ctx.BlockHeight()

	// fetch the validator public key
	consAddr = sdk.ConsAddress(addr)
	if _, err := k.GetPubkey(ctx, addr); err != nil {
		panic(fmt.Sprintf("Validator consensus-address %s not found", consAddr))
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

**File:** x/staking/keeper/validator.go (L441-444)
```go
				val = k.UnbondingToUnbonded(ctx, val)
				if val.GetDelegatorShares().IsZero() {
					k.RemoveValidator(ctx, val.GetOperator())
				}
```

**File:** x/slashing/keeper/hooks.go (L40-43)
```go
// AfterValidatorRemoved deletes the address-pubkey relation when a validator is removed,
func (k Keeper) AfterValidatorRemoved(ctx sdk.Context, address sdk.ConsAddress) {
	k.deleteAddrPubkeyRelation(ctx, crypto.Address(address))
}
```

**File:** x/slashing/abci.go (L40-41)
```go
			vInfo := allVotes[valIndex]
			consAddr, missedInfo, signInfo, shouldSlash, slashInfo := k.HandleValidatorSignatureConcurrent(ctx, vInfo.Validator.Address, vInfo.Validator.Power, vInfo.SignedLastBlock)
```

**File:** x/staking/keeper/val_state_change.go (L17-33)
```go
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

**File:** x/evidence/keeper/infraction.go (L29-39)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
```
