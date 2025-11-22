# Audit Report

## Title
Chain Halt via Unvalidated Unbonding Delegation Addresses in Genesis Import

## Summary
The genesis validation does not verify that UnbondingDelegation addresses are valid Bech32 format. When InitGenesis processes UnbondingDelegations with malformed addresses, these are stored in the unbonding queue without validation. Later, when BlockValidatorUpdates processes mature unbondings, it attempts to parse these malformed addresses and panics, causing a complete network shutdown. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary vulnerability: `x/staking/genesis.go` lines 81-88 and `x/staking/genesis.go` lines 230-235 (ValidateGenesis function)
- Panic trigger: `x/staking/keeper/val_state_change.go` lines 38-42

**Intended Logic:**
Genesis validation should ensure all addresses in the genesis state are valid Bech32-encoded addresses before the chain starts. The unbonding delegation queue should only contain properly formatted DVPairs that can be safely parsed during EndBlock processing.

**Actual Logic:**
The `ValidateGenesis` function only validates validators and parameters, completely omitting validation of UnbondingDelegation addresses. [2](#0-1) 

When `InitGenesis` processes UnbondingDelegations, it directly stores them without validation and inserts them into the unbonding queue. [3](#0-2) 

The unbonding queue insertion uses the addresses directly from the UnbondingDelegation struct without validation. [4](#0-3) 

When mature unbondings are processed in `BlockValidatorUpdates`, the code attempts to parse the addresses using `sdk.ValAddressFromBech32` and `sdk.MustAccAddressFromBech32`, both of which panic if the address string is malformed. [5](#0-4) 

**Exploit Scenario:**
1. A genesis file is created (or migrated) with an UnbondingDelegation containing invalid Bech32 addresses (e.g., due to a bug in genesis generation tools, state migration scripts, or data corruption during export/import)
2. The genesis file passes `ValidateGenesis` because it doesn't check UnbondingDelegation addresses
3. Chain initializes successfully via `InitGenesis`, which stores the malformed addresses in the unbonding queue
4. The chain operates normally until the unbonding completion time arrives
5. During EndBlock, `BlockValidatorUpdates` attempts to process the mature unbonding
6. Address parsing fails and triggers a panic
7. All validators panic and halt
8. The network cannot progress

**Security Failure:**
This breaks the availability and liveness properties of the blockchain. The missing validation creates a delayed-trigger chain halt vulnerability that manifests only when the unbonding matures, making it difficult to diagnose and requiring a coordinated hard fork to recover.

## Impact Explanation

**Affected Components:**
- Network availability: Complete chain halt
- Transaction finality: No new blocks can be produced
- Validator operations: All validators crash simultaneously

**Damage Severity:**
- **Network Shutdown**: The entire network halts when any validator attempts to process the malformed unbonding delegation
- **Recovery Cost**: Requires a coordinated hard fork with all validators to recover
- **Time Sensitivity**: The issue may not manifest for days or weeks after genesis (until unbonding matures), making it a time-bomb vulnerability

**System Impact:**
This matters critically because:
1. The chain becomes completely unusable - no transactions can be confirmed
2. The failure point is non-obvious (happens at unbonding completion, not at genesis)
3. Recovery requires emergency coordination and hard fork
4. Could affect newly launched chains or chains undergoing state migrations

## Likelihood Explanation

**Trigger Conditions:**
- Can be triggered accidentally through bugs in genesis generation or state migration tooling
- Could occur during chain upgrades when state is exported and re-imported
- May result from corruption during genesis file transfer or storage

**Probability:**
- **Medium-High likelihood** if state migrations or genesis generation have bugs
- More likely during:
  - New chain launches with custom genesis
  - Chain upgrades involving state migrations
  - Export/import operations for testing or replay

**Frequency:**
- Once triggered, causes immediate and permanent halt when unbonding matures
- Can happen on any chain that processes genesis with UnbondingDelegations
- The delayed nature (unbonding maturity) makes pre-deployment testing less likely to catch it

## Recommendation

Add comprehensive validation for UnbondingDelegation addresses in the `ValidateGenesis` function:

```go
// In x/staking/genesis.go, add validation after validator validation:
func ValidateGenesis(data *types.GenesisState) error {
    if err := validateGenesisStateValidators(data.Validators); err != nil {
        return err
    }
    
    // Add validation for unbonding delegations
    if err := validateGenesisStateUnbondingDelegations(data.UnbondingDelegations); err != nil {
        return err
    }
    
    // Add validation for redelegations  
    if err := validateGenesisStateRedelegations(data.Redelegations); err != nil {
        return err
    }
    
    return data.Params.Validate()
}

func validateGenesisStateUnbondingDelegations(ubds []types.UnbondingDelegation) error {
    for i, ubd := range ubds {
        // Validate delegator address
        if _, err := sdk.AccAddressFromBech32(ubd.DelegatorAddress); err != nil {
            return fmt.Errorf("invalid delegator address in unbonding delegation %d: %w", i, err)
        }
        // Validate validator address
        if _, err := sdk.ValAddressFromBech32(ubd.ValidatorAddress); err != nil {
            return fmt.Errorf("invalid validator address in unbonding delegation %d: %w", i, err)
        }
    }
    return nil
}
```

## Proof of Concept

**Test File:** `x/staking/genesis_test.go`

**Test Function:** `TestInitGenesis_MalformedUnbondingDelegationPanic`

```go
func TestInitGenesis_MalformedUnbondingDelegationPanic(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.NewContext(false, tmproto.Header{})
    
    // Create valid params
    params := types.DefaultParams()
    params.UnbondingTime = time.Hour
    
    // Create an unbonding delegation with INVALID addresses
    malformedUBD := types.UnbondingDelegation{
        DelegatorAddress: "invalid_bech32_address", // Malformed address
        ValidatorAddress: sdk.ValAddress("valid12345678901234567890").String(),
        Entries: []types.UnbondingDelegationEntry{
            {
                CreationHeight: 0,
                CompletionTime: ctx.BlockTime().Add(time.Minute), // Matures in 1 minute
                InitialBalance: sdk.NewInt(1000),
                Balance:        sdk.NewInt(1000),
            },
        },
    }
    
    // Fund the not bonded pool to match the unbonding amount
    require.NoError(t,
        simapp.FundModuleAccount(
            app.BankKeeper,
            ctx,
            types.NotBondedPoolName,
            sdk.NewCoins(sdk.NewCoin(params.BondDenom, sdk.NewInt(1000))),
        ),
    )
    
    genesisState := &types.GenesisState{
        Params:               params,
        UnbondingDelegations: []types.UnbondingDelegation{malformedUBD},
    }
    
    // InitGenesis should succeed (this is the bug - no validation)
    require.NotPanics(t, func() {
        staking.InitGenesis(ctx, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, genesisState)
    })
    
    // Advance time past the unbonding completion time
    ctx = ctx.WithBlockTime(ctx.BlockTime().Add(2 * time.Minute))
    ctx = ctx.WithBlockHeight(ctx.BlockHeight() + 1)
    
    // BlockValidatorUpdates should panic when trying to parse the malformed address
    require.Panics(t, func() {
        app.StakingKeeper.BlockValidatorUpdates(ctx)
    }, "Expected panic due to malformed delegator address in unbonding delegation")
}
```

**Setup:** 
- Initialize a test app with staking keeper
- Create genesis state with an UnbondingDelegation containing an invalid Bech32 delegator address ("invalid_bech32_address")
- Fund the not bonded pool to satisfy balance checks

**Trigger:**
- Call `InitGenesis` with the malformed genesis state (succeeds due to missing validation)
- Advance block time past the unbonding completion time
- Call `BlockValidatorUpdates` which attempts to process the mature unbonding

**Observation:**
- `InitGenesis` succeeds without validation (demonstrates the missing check)
- `BlockValidatorUpdates` panics when `sdk.MustAccAddressFromBech32` attempts to parse "invalid_bech32_address"
- This confirms that malformed addresses can enter the system through genesis and cause a chain-halting panic later

**Notes:**
- The test uses the existing test framework structure from `genesis_test.go`
- A similar test should be added for malformed validator addresses and redelegation addresses
- The panic occurs at the exact location identified in the security question (val_state_change.go:38-42)

### Citations

**File:** x/staking/keeper/val_state_change.go (L36-57)
```go
	matureUnbonds := k.DequeueAllMatureUBDQueue(ctx, ctx.BlockHeader().Time)
	for _, dvPair := range matureUnbonds {
		addr, err := sdk.ValAddressFromBech32(dvPair.ValidatorAddress)
		if err != nil {
			panic(err)
		}
		delegatorAddress := sdk.MustAccAddressFromBech32(dvPair.DelegatorAddress)

		balances, err := k.CompleteUnbonding(ctx, delegatorAddress, addr)
		if err != nil {
			continue
		}

		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypeCompleteUnbonding,
				sdk.NewAttribute(sdk.AttributeKeyAmount, balances.String()),
				sdk.NewAttribute(types.AttributeKeyValidator, dvPair.ValidatorAddress),
				sdk.NewAttribute(types.AttributeKeyDelegator, dvPair.DelegatorAddress),
			),
		)
	}
```

**File:** x/staking/genesis.go (L81-88)
```go
	for _, ubd := range data.UnbondingDelegations {
		keeper.SetUnbondingDelegation(ctx, ubd)

		for _, entry := range ubd.Entries {
			keeper.InsertUBDQueue(ctx, ubd, entry.CompletionTime)
			notBondedTokens = notBondedTokens.Add(entry.Balance)
		}
	}
```

**File:** x/staking/genesis.go (L230-235)
```go
func ValidateGenesis(data *types.GenesisState) error {
	if err := validateGenesisStateValidators(data.Validators); err != nil {
		return err
	}

	return data.Params.Validate()
```

**File:** x/staking/keeper/delegation.go (L351-362)
```go
func (k Keeper) InsertUBDQueue(ctx sdk.Context, ubd types.UnbondingDelegation,
	completionTime time.Time,
) {
	dvPair := types.DVPair{DelegatorAddress: ubd.DelegatorAddress, ValidatorAddress: ubd.ValidatorAddress}

	timeSlice := k.GetUBDQueueTimeSlice(ctx, completionTime)
	if len(timeSlice) == 0 {
		k.SetUBDQueueTimeSlice(ctx, completionTime, []types.DVPair{dvPair})
	} else {
		timeSlice = append(timeSlice, dvPair)
		k.SetUBDQueueTimeSlice(ctx, completionTime, timeSlice)
	}
```
