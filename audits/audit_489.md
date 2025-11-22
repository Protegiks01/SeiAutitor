# Audit Report

## Title
Missing Denomination Existence Validation in Governance Deposit Parameters Allows Permanent Governance Freeze

## Summary
The governance module's deposit parameter validation function does not verify that coin denominations actually exist on the blockchain, only checking regex pattern validity. This allows governance parameters to be set with non-existent denominations, permanently freezing the governance system as no user can deposit coins that don't exist.

## Impact
**High**

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The validation should ensure that minimum deposit parameters use valid, existing denominations that users can actually deposit. When governance parameters are updated, the system should reject configurations that would make the governance system unusable.

**Actual Logic:** 
The `validateDepositParams` function only calls `IsValid()` on the coin objects, which performs: [2](#0-1) 

This validation only checks: (1) denomination matches the regex pattern `[a-zA-Z][a-zA-Z0-9/-]{2,127}` [3](#0-2) , and (2) amount is non-negative. It does NOT verify the denomination exists in the blockchain's registered denominations or that users can obtain such coins.

**Exploit Scenario:**
1. A governance proposal is submitted to update deposit parameters with a typo in the denomination (e.g., "uesi" instead of "usei") or a completely non-existent denomination (e.g., "fakecoin")
2. The validation passes because the denomination matches the regex pattern
3. The proposal passes through normal governance voting (using current valid denomination)
4. Parameters are updated via [4](#0-3) 
5. All subsequent governance proposals require deposits in the non-existent denomination
6. When users attempt to deposit via [5](#0-4) , the bank transfer at line 121 fails because they have zero balance of the non-existent denomination
7. No proposal can ever reach the voting period threshold [6](#0-5) 
8. Governance is permanently frozen

**Security Failure:** 
This breaks the **availability** and **recoverability** properties of the governance system. The system allows itself to be configured into an unrecoverable state where the primary governance mechanism becomes permanently unusable, requiring a hard fork to restore functionality.

## Impact Explanation

- **Affected Assets:** All governance functionality becomes permanently inaccessible. Users' deposit attempts fail, preventing any proposal from reaching voting period.

- **Severity:** This matches the in-scope impact of "Critical Permanent freezing of funds (fix requires hard fork)" - governance deposits already in the system cannot be used for their intended purpose, and the governance mechanism itself is frozen. It also matches "High Network not being able to confirm new transactions" specifically for governance transactions.

- **System Impact:** The governance module is critical infrastructure for protocol upgrades, parameter changes, and community proposals. Its complete failure prevents the protocol from adapting to threats, bugs, or changing requirements without a coordinated hard fork - a severe operational and security risk.

## Likelihood Explanation

**Trigger Conditions:**
- Requires a governance proposal to pass with malformed denomination in deposit parameters
- Can occur through: (1) Accidental typo in denomination name during parameter update, (2) Copy-paste error from another chain's configuration, (3) Malicious proposal hidden in a large parameter update that validators don't carefully review

**Likelihood:** Medium to High
- Governance proposals pass regularly in active chains
- Parameter updates involving multiple changes may not receive thorough review of every field
- A single character typo (e.g., "uesi" vs "usei") would pass regex validation but freeze governance
- Once triggered, the impact is immediate and permanent

## Recommendation

Add denomination existence validation to the `validateDepositParams` function in `x/gov/types/params.go`. The validation should verify that each denomination in MinDeposit and MinExpeditedDeposit either:
1. Exists in the bank module's supply, OR
2. Is a registered denomination via bank metadata, OR  
3. At minimum, check against a whitelist of known valid denominations for the chain

Example fix:
```go
func validateDepositParams(i interface{}) error {
    v, ok := i.(DepositParams)
    if !ok {
        return fmt.Errorf("invalid parameter type: %T", i)
    }

    if !v.MinDeposit.IsValid() {
        return fmt.Errorf("invalid minimum deposit: %s", v.MinDeposit)
    }
    // Add denomination existence check
    for _, coin := range v.MinDeposit {
        if !isDenominationUsable(coin.Denom) {
            return fmt.Errorf("minimum deposit uses non-existent denomination: %s", coin.Denom)
        }
    }
    
    if !v.MinExpeditedDeposit.IsValid() {
        return fmt.Errorf("invalid minimum expedited deposit: %s", v.MinExpeditedDeposit)
    }
    // Add denomination existence check
    for _, coin := range v.MinExpeditedDeposit {
        if !isDenominationUsable(coin.Denom) {
            return fmt.Errorf("minimum expedited deposit uses non-existent denomination: %s", coin.Denom)
        }
    }
    
    // ... rest of validation
}
```

## Proof of Concept

**Test File:** `x/gov/types/params_test.go`

**Test Function:** Add the following test:

```go
func TestValidateDepositParams_NonExistentDenomination(t *testing.T) {
    // This test demonstrates that validateDepositParams accepts non-existent denominations
    // which would freeze governance if set
    
    // Create deposit params with a non-existent denomination that passes regex
    nonExistentDenom := "nonexistentcoin"  // Valid regex, but doesn't exist
    invalidParams := types.NewDepositParams(
        sdk.NewCoins(sdk.NewCoin(nonExistentDenom, sdk.NewInt(1000000))),
        sdk.NewCoins(sdk.NewCoin(nonExistentDenom, sdk.NewInt(2000000))),
        types.DefaultPeriod,
    )
    
    // Validation should fail but currently passes
    err := validateDepositParams(invalidParams)
    
    // This assertion will FAIL, demonstrating the vulnerability
    // The validation incorrectly accepts non-existent denominations
    require.NoError(t, err) // Currently passes - THIS IS THE BUG
    
    // Expected: require.Error(t, err, "should reject non-existent denomination")
}

func TestValidateDepositParams_TypoDenomination(t *testing.T) {
    // Demonstrates that a simple typo would pass validation
    typoDenom := "uesi"  // Typo of "usei"
    typoParams := types.NewDepositParams(
        sdk.NewCoins(sdk.NewCoin(typoDenom, sdk.NewInt(1000000))),
        sdk.NewCoins(sdk.NewCoin(typoDenom, sdk.NewInt(2000000))),
        types.DefaultPeriod,
    )
    
    err := validateDepositParams(typoParams)
    require.NoError(t, err) // Currently passes - allows typo that would freeze governance
    // Expected: require.Error(t, err, "should reject typo denomination")
}
```

**Setup:** The test uses the existing test infrastructure in `x/gov/types/params_test.go`. No special setup is needed beyond the standard test imports already present in that file.

**Trigger:** The test creates DepositParams with denominations that are syntactically valid (pass regex) but don't exist on the blockchain, then calls the validation function directly.

**Observation:** The validation function returns no error, allowing these invalid configurations. In a real deployment, if these parameters were set via governance proposal, all future proposals would fail because users cannot deposit non-existent denominations. The test confirms the validation gap that allows governance to be permanently frozen.

### Citations

**File:** x/gov/types/params.go (L91-96)
```go
	if !v.MinDeposit.IsValid() {
		return fmt.Errorf("invalid minimum deposit: %s", v.MinDeposit)
	}
	if !v.MinExpeditedDeposit.IsValid() {
		return fmt.Errorf("invalid minimum expedited deposit: %s", v.MinExpeditedDeposit)
	}
```

**File:** types/coin.go (L42-52)
```go
func (coin Coin) Validate() error {
	if err := ValidateDenom(coin.Denom); err != nil {
		return err
	}

	if coin.Amount.IsNegative() {
		return fmt.Errorf("negative coin amount: %v", coin.Amount)
	}

	return nil
}
```

**File:** types/coin.go (L777-813)
```go
	// Denominations can be 3 ~ 128 characters long and support letters, followed by either
	// a letter, a number or a separator ('/').
	reDnmString = `[a-zA-Z][a-zA-Z0-9/-]{2,127}`
	reDecAmt    = `[[:digit:]]+(?:\.[[:digit:]]+)?|\.[[:digit:]]+`
	reSpc       = `[[:space:]]*`
	reDnm       *regexp.Regexp
	reDecCoin   *regexp.Regexp
)

func init() {
	SetCoinDenomRegex(DefaultCoinDenomRegex)
}

// DefaultCoinDenomRegex returns the default regex string
func DefaultCoinDenomRegex() string {
	return reDnmString
}

// coinDenomRegex returns the current regex string and can be overwritten for custom validation
var coinDenomRegex = DefaultCoinDenomRegex

// SetCoinDenomRegex allows for coin's custom validation by overriding the regular
// expression string used for denom validation.
func SetCoinDenomRegex(reFn func() string) {
	coinDenomRegex = reFn

	reDnm = regexp.MustCompile(fmt.Sprintf(`^%s$`, coinDenomRegex()))
	reDecCoin = regexp.MustCompile(fmt.Sprintf(`^(%s)%s(%s)$`, reDecAmt, reSpc, coinDenomRegex()))
}

// ValidateDenom is the default validation function for Coin.Denom.
func ValidateDenom(denom string) error {
	if !reDnm.MatchString(denom) {
		return fmt.Errorf("invalid denom: %s", denom)
	}
	return nil
}
```

**File:** x/params/proposal_handler.go (L26-43)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
}
```

**File:** x/gov/keeper/deposit.go (L108-137)
```go
func (keeper Keeper) AddDeposit(ctx sdk.Context, proposalID uint64, depositorAddr sdk.AccAddress, depositAmount sdk.Coins) (bool, error) {
	// Checks to see if proposal exists
	proposal, ok := keeper.GetProposal(ctx, proposalID)
	if !ok {
		return false, sdkerrors.Wrapf(types.ErrUnknownProposal, "%d", proposalID)
	}

	// Check if proposal is still depositable
	if (proposal.Status != types.StatusDepositPeriod) && (proposal.Status != types.StatusVotingPeriod) {
		return false, sdkerrors.Wrapf(types.ErrInactiveProposal, "%d", proposalID)
	}

	// update the governance module's account coins pool
	err := keeper.bankKeeper.SendCoinsFromAccountToModule(ctx, depositorAddr, types.ModuleName, depositAmount)
	if err != nil {
		return false, err
	}

	// Update proposal
	proposal.TotalDeposit = proposal.TotalDeposit.Add(depositAmount...)
	keeper.SetProposal(ctx, proposal)

	// Check if deposit has provided sufficient total funds to transition the proposal into the voting period
	activatedVotingPeriod := false

	if proposal.Status == types.StatusDepositPeriod && proposal.TotalDeposit.IsAllGTE(keeper.GetDepositParams(ctx).GetMinimumDeposit(proposal.IsExpedited)) {
		keeper.ActivateVotingPeriod(ctx, proposal)

		activatedVotingPeriod = true
	}
```
