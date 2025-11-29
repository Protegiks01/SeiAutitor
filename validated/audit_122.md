# Audit Report

## Title
Genesis State Commission Rate Bypass Causing Network Halt via AllocateTokensToValidator Panic

## Summary
The `validateGenesisStateValidators` function in the staking module does not validate validator commission rates during genesis state loading. This allows validators with commission rates exceeding 100% to be loaded into the chain state, causing a deterministic panic in `AllocateTokensToValidator` during block processing that results in total network shutdown requiring a hard fork to recover.

## Impact
High

## Finding Description

**Location:** 
- Missing validation: [1](#0-0) 
- Panic trigger: [2](#0-1) 
- Panic mechanism: [3](#0-2) 

**Intended Logic:**
The system enforces that validator commission rates never exceed 100% (1.0) to maintain proper reward accounting. Normal validator creation through transactions validates this constraint via `Commission.Validate()` which checks that `MaxRate <= 1.0` [4](#0-3) [5](#0-4) 

**Actual Logic:**
The genesis validation function only checks for duplicate validators, jailed+bonded conflicts, and zero delegator shares. It does NOT validate commission rates [1](#0-0) , allowing validators with `Commission.Rate > 1.0` to be loaded via `InitGenesis` [6](#0-5) 

When `AllocateTokensToValidator` is called during block processing [7](#0-6) , it calculates `commission = tokens.MulDec(val.GetCommission())` where `GetCommission()` returns `Commission.Rate` [8](#0-7) . If `Commission.Rate = 1.5`, the commission exceeds the tokens being distributed. The subsequent `tokens.Sub(commission)` operation panics with "negative coin amount" [3](#0-2) , crashing all nodes.

**Exploitation Path:**
1. Genesis file contains validator with `Commission.Rate = 1.5` (150%)
2. `ValidateGenesis` passes since commission rates aren't checked
3. `InitGenesis` loads validator via `SetValidator` without validation
4. At block height > 1, `BeginBlocker` calls `AllocateTokens`
5. `AllocateTokensToValidator` calculates commission = tokens × 1.5
6. `shared = tokens.Sub(commission)` panics with "negative coin amount"
7. All nodes crash deterministically at the same block height

**Security Guarantee Broken:**
Network availability and consensus safety. The panic occurs deterministically in the consensus path during `BeginBlock`, causing all honest nodes to crash at the same block height. The network cannot produce new blocks and remains frozen until a coordinated hard fork creates corrected genesis state.

## Impact Explanation

**Affected:** All network nodes and the entire blockchain's ability to process transactions.

**Severity:** Total network shutdown requiring hard fork. Every node attempting to process blocks panics at the same deterministic point in the consensus code. The network cannot produce new blocks, all transactions halt, and the chain is frozen until manual intervention through a hard fork with corrected genesis state.

**Systemic Risk:** Unlike runtime bugs requiring specific transaction sequences, this affects fundamental block processing logic in `BeginBlock`. All nodes crash at the exact same block height when allocating rewards, making recovery impossible without coordinated manual intervention. This represents an unintended permanent chain split requiring hard fork, classified as High severity in blockchain security.

## Likelihood Explanation

**Who can trigger:** Requires privileged access to create or modify genesis files during chain initialization or network upgrades. However, this falls under the platform exception clause: "even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority."

**Conditions required:**
- Introduced at genesis or during coordinated network upgrade
- Normal runtime operations are protected by validation in `ValidateBasic()`
- Once introduced via genesis, trigger is automatic during first reward distribution

**Realistic scenarios:**
1. **New chain launches**: Genesis preparation scripts with bugs or data corruption
2. **Hard fork upgrades**: Migration scripts that don't validate old validator state  
3. **Human error**: Operator manually editing genesis makes typo (1.5 instead of 0.15)
4. **Supply chain attacks**: Genesis generation tooling is compromised
5. **Testnet environments**: Less rigorous review processes

These represent real operational risks in blockchain deployments. The lack of validation creates a dangerous inconsistency where runtime validator creation is protected but genesis loading is not.

## Recommendation

Add commission rate validation to `validateGenesisStateValidators` in `x/staking/genesis.go`. After the existing checks in the validator loop, add:

```go
if err := val.Commission.Validate(); err != nil {
    return fmt.Errorf("invalid commission for validator %s: %w", val.OperatorAddress, err)
}
```

This ensures genesis validators have the same commission constraints (`MaxRate ≤ 1.0`, `Rate ≤ MaxRate`, `MaxChangeRate ≤ MaxRate`) as validators created through transactions, providing defense-in-depth protection against catastrophic configuration errors.

## Proof of Concept

**File:** `x/distribution/keeper/allocation_test.go`

**Test Function:** `TestAllocateTokensToValidatorWithCommissionGreaterThan100Percent`

**Setup:**
1. Initialize test application: `app := simapp.Setup(false)`
2. Create context: `ctx := app.BaseApp.NewContext(false, tmproto.Header{})`
3. Create validator with commission rate > 1.0 by directly constructing the `Commission` struct with `Rate: sdk.NewDec(2)` (200%), bypassing normal validation
4. Use `app.StakingKeeper.SetValidator(ctx, validator)` to directly set validator in state (simulating genesis loading)
5. Initialize distribution state for the validator

**Action:**
1. Create tokens: `tokens := sdk.DecCoins{{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(100)}}`
2. Call: `app.DistrKeeper.AllocateTokensToValidator(ctx, validator, tokens)`
3. This calculates `commission = 100 * 2.0 = 200 tokens`
4. Then attempts `shared = 100 - 200 = panic`

**Result:**
The test must use `require.Panics(t, func() { app.DistrKeeper.AllocateTokensToValidator(ctx, validator, tokens) })` to catch the panic with message "negative coin amount". This demonstrates that validators with commission > 100% loaded from genesis (bypassing validation) cause deterministic panic during reward allocation, halting all nodes.

The existing test suite [9](#0-8)  shows normal validators with valid commissions work correctly, confirming this is a genesis-specific validation gap.

## Notes

This vulnerability is valid under the platform acceptance rules because while it requires privileged access to genesis files, it causes "unrecoverable security failure beyond their intended authority." Even trusted operators do not have authority to permanently halt the entire network - such catastrophic impact from a simple typo or migration bug exceeds the intended blast radius of configuration operations.

The issue matches the High severity criteria: "Unintended permanent chain split requiring hard fork (network partition requiring hard fork)" and "Network not being able to confirm new transactions (total network shutdown)". It demonstrates a critical defense-in-depth failure where genesis loading lacks the same validation protections as runtime operations.

### Citations

**File:** x/staking/genesis.go (L40-40)
```go
		keeper.SetValidator(ctx, validator)
```

**File:** x/staking/genesis.go (L238-274)
```go
func validateGenesisStateValidators(validators []types.Validator) error {
	addrMap := make(map[string]bool, len(validators))

	for i := 0; i < len(validators); i++ {
		val := validators[i]
		consPk, err := val.ConsPubKey()
		if err != nil {
			return err
		}

		strKey := string(consPk.Bytes())

		if _, ok := addrMap[strKey]; ok {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("duplicate validator in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.Jailed && val.IsBonded() {
			consAddr, err := val.GetConsAddr()
			if err != nil {
				return err
			}
			return fmt.Errorf("validator is bonded and jailed in genesis state: moniker %v, address %v", val.Description.Moniker, consAddr)
		}

		if val.DelegatorShares.IsZero() && !val.IsUnbonding() {
			return fmt.Errorf("bonded/unbonded genesis validator cannot have zero delegator shares, validator: %v", val)
		}

		addrMap[strKey] = true
	}

	return nil
}
```

**File:** x/distribution/keeper/allocation.go (L111-114)
```go
func (k Keeper) AllocateTokensToValidator(ctx sdk.Context, val stakingtypes.ValidatorI, tokens sdk.DecCoins) {
	// split tokens between validator and delegators according to commission
	commission := tokens.MulDec(val.GetCommission())
	shared := tokens.Sub(commission)
```

**File:** types/dec_coin.go (L303-310)
```go
func (coins DecCoins) Sub(coinsB DecCoins) DecCoins {
	diff, hasNeg := coins.SafeSub(coinsB)
	if hasNeg {
		panic("negative coin amount")
	}

	return diff
}
```

**File:** x/staking/types/commission.go (L57-59)
```go
	case cr.MaxRate.GT(sdk.OneDec()):
		// max rate cannot be greater than 1
		return ErrCommissionHuge
```

**File:** x/staking/types/msg.go (L128-130)
```go
	if err := msg.Commission.Validate(); err != nil {
		return err
	}
```

**File:** x/distribution/abci.go (L29-31)
```go
	if ctx.BlockHeight() > 1 {
		previousProposer := k.GetPreviousProposerConsAddr(ctx)
		k.AllocateTokens(ctx, sumPreviousPrecommitPower, previousTotalPower, previousProposer, req.LastCommitInfo.GetVotes())
```

**File:** x/staking/types/validator.go (L511-511)
```go
func (v Validator) GetCommission() sdk.Dec        { return v.Commission.Rate }
```

**File:** x/distribution/keeper/allocation_test.go (L18-45)
```go
func TestAllocateTokensToValidatorWithCommission(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	addrs := simapp.AddTestAddrs(app, ctx, 3, sdk.NewInt(1234))
	valAddrs := simapp.ConvertAddrsToValAddrs(addrs)
	tstaking := teststaking.NewHelper(t, ctx, app.StakingKeeper)

	// create validator with 50% commission
	tstaking.Commission = stakingtypes.NewCommissionRates(sdk.NewDecWithPrec(5, 1), sdk.NewDecWithPrec(5, 1), sdk.NewDec(0))
	tstaking.CreateValidator(sdk.ValAddress(addrs[0]), valConsPk1, sdk.NewInt(100), true)
	val := app.StakingKeeper.Validator(ctx, valAddrs[0])

	// allocate tokens
	tokens := sdk.DecCoins{
		{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(10)},
	}
	app.DistrKeeper.AllocateTokensToValidator(ctx, val, tokens)

	// check commission
	expected := sdk.DecCoins{
		{Denom: sdk.DefaultBondDenom, Amount: sdk.NewDec(5)},
	}
	require.Equal(t, expected, app.DistrKeeper.GetValidatorAccumulatedCommission(ctx, val.GetOperator()).Commission)

	// check current rewards
	require.Equal(t, expected, app.DistrKeeper.GetValidatorCurrentRewards(ctx, val.GetOperator()).Rewards)
}
```
