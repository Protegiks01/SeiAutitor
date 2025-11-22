## Audit Report

# Title
Genesis Validation Bypass: Missing Duplicate Grant Check Allows State Corruption on Chain Initialization

## Summary
The `ValidateGenesis` function in the feegrant module fails to check for duplicate grants (same granter-grantee pairs), allowing genesis state to contain multiple conflicting allowances for the same account pair. During `InitGenesis`, the last duplicate silently overwrites earlier ones, potentially resulting in incorrect fee allowances and unintended fund access. [1](#0-0) 

## Impact
**Medium** - This validation bypass results in unintended blockchain state initialization that could lead to incorrect fee allowances, violating authorization invariants and potentially causing fund access control issues.

## Finding Description

**Location:** The vulnerability exists in the `ValidateGenesis` function in the feegrant module. [1](#0-0) 

**Intended Logic:** Genesis validation should enforce the same invariants as runtime validation. The system maintains that each (granter, grantee) pair should have at most one fee allowance. During normal chain operation, the message server explicitly prevents duplicate grants: [2](#0-1) 

**Actual Logic:** `ValidateGenesis` only validates each grant individually through `grant.ValidateBasic()`, but never checks if the same (granter, grantee) pair appears multiple times in the genesis allowances list. When `InitGenesis` processes the genesis state, it calls `GrantAllowance` for each entry sequentially: [3](#0-2) 

Since `GrantAllowance` uses `store.Set()` which overwrites existing values: [4](#0-3) 

Duplicate grants in genesis will result in later entries silently overwriting earlier ones, with only the last duplicate being stored.

**Exploit Scenario:**
1. Chain operators prepare a genesis file for chain launch or upgrade
2. Due to a bug in genesis generation tools or manual editing errors, duplicate grants are inadvertently included:
   - Grant 1: granter=AccountA, grantee=AccountB, allowance=100 tokens
   - Grant 2: granter=AccountA, grantee=AccountB, allowance=10000 tokens (duplicate with different allowance)
3. `ValidateGenesis` passes since it doesn't check for duplicates
4. During `InitGenesis`, both grants are processed, with Grant 2 overwriting Grant 1
5. The chain initializes with AccountB having 10000 token allowance instead of the intended 100 tokens
6. AccountB can now spend 10000 tokens from AccountA's account, resulting in unauthorized fund access

**Security Failure:** This breaks the authorization invariant that genesis validation should catch all state inconsistencies before chain initialization. The validation bypass allows conflicting authorization rules to pass validation, leading to incorrect fee allowance state that differs from the intended genesis configuration.

## Impact Explanation

**Affected Assets:** Fee grant allowances, which control authorization for accounts to spend transaction fees from other accounts' funds.

**Severity of Damage:**
- **Unauthorized Fund Access:** If a larger allowance overwrites a smaller intended allowance, the grantee gains access to more funds than authorized
- **Denial of Service:** If a smaller allowance overwrites a larger intended allowance, legitimate transactions may fail due to insufficient allowances
- **State Inconsistency:** The initialized chain state differs from the intended genesis configuration, violating the principle that genesis validation ensures correct state

**System Security Impact:** This matters because genesis validation is the trust anchor for chain initialization. Operators rely on `ValidateGenesis` to catch errors before chain launch. This validation bypass undermines that trust and can lead to chains launching with incorrect authorization state. Other modules like auth already implement duplicate checking in their genesis validation, showing this is expected security practice: [5](#0-4) 

## Likelihood Explanation

**Triggering Conditions:**
- Occurs during chain initialization when genesis state contains duplicate grants
- Can happen through automated genesis generation tools with bugs, manual editing errors, or when combining genesis fragments from multiple sources
- No special privileges needed to trigger once duplicates exist in genesis - the chain will initialize with corrupted state automatically

**Frequency:** While genesis files are typically created carefully, the lack of validation means any accidental duplication will go undetected. Given that:
1. Genesis files can be complex with hundreds or thousands of grants
2. Multiple teams may contribute to genesis state
3. Automated tools may have bugs
4. The runtime system explicitly prevents duplicates (showing it's an important invariant)

The likelihood of accidental duplicates is non-negligible, especially for chains with large genesis states or during chain upgrades when merging state from multiple sources.

## Recommendation

Add duplicate grant detection to `ValidateGenesis` following the pattern used in other modules. Use a map to track seen (granter, grantee) pairs and return an error if a duplicate is detected:

```go
func ValidateGenesis(data GenesisState) error {
    grantMap := make(map[string]bool)
    
    for _, f := range data.Allowances {
        // Check for duplicate grants
        key := f.Granter + "|" + f.Grantee
        if _, exists := grantMap[key]; exists {
            return fmt.Errorf("duplicate fee allowance found in genesis state; granter: %s, grantee: %s", f.Granter, f.Grantee)
        }
        grantMap[key] = true
        
        // Existing validation
        grant, err := f.GetGrant()
        if err != nil {
            return err
        }
        err = grant.ValidateBasic()
        if err != nil {
            return err
        }
    }
    return nil
}
```

## Proof of Concept

**File:** `x/feegrant/keeper/genesis_test.go`

**Test Function:** Add the following test to demonstrate the vulnerability:

```go
func (suite *GenesisTestSuite) TestInitGenesisDuplicateGrants() {
    // Setup: Create two duplicate grants with different allowances
    coins1 := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(100)))
    coins2 := sdk.NewCoins(sdk.NewCoin("foo", sdk.NewInt(10000)))
    
    allowance1 := &feegrant.BasicAllowance{SpendLimit: coins1}
    allowance2 := &feegrant.BasicAllowance{SpendLimit: coins2}
    
    grant1, err := feegrant.NewGrant(granterAddr, granteeAddr, allowance1)
    suite.Require().NoError(err)
    
    grant2, err := feegrant.NewGrant(granterAddr, granteeAddr, allowance2)
    suite.Require().NoError(err)
    
    // Create genesis state with duplicate grants (same granter+grantee, different allowances)
    genesisState := &feegrant.GenesisState{
        Allowances: []feegrant.Grant{grant1, grant2},
    }
    
    // Trigger: ValidateGenesis should fail but doesn't
    err = feegrant.ValidateGenesis(*genesisState)
    // Currently this passes, but it should fail
    suite.Require().NoError(err) // BUG: No duplicate check!
    
    // Trigger: InitGenesis processes both, last overwrites first
    err = suite.keeper.InitGenesis(suite.ctx, genesisState)
    suite.Require().NoError(err)
    
    // Observation: Only the second (larger) allowance is stored
    storedAllowance, err := suite.keeper.GetAllowance(suite.ctx, granterAddr, granteeAddr)
    suite.Require().NoError(err)
    
    storedBasic := storedAllowance.(*feegrant.BasicAllowance)
    
    // Demonstrates the vulnerability: Expected 100, but got 10000 (second duplicate overwrote first)
    suite.Require().Equal(coins2, storedBasic.SpendLimit)
    // This is a security issue: if the first grant was intended, 
    // grantee now has 100x more allowance than authorized
}
```

**Observation:** The test demonstrates that:
1. `ValidateGenesis` passes even with duplicate grants (validation bypass)
2. `InitGenesis` silently overwrites the first grant with the second
3. The stored allowance (10000 tokens) differs from the first grant (100 tokens)
4. If the chain operator intended the 100 token limit, the grantee now has unauthorized access to 10000 tokens

This proves the validation bypass allows state corruption during chain initialization, violating authorization invariants and potentially leading to unauthorized fund access.

### Citations

**File:** x/feegrant/genesis.go (L16-29)
```go
// ValidateGenesis ensures all grants in the genesis state are valid
func ValidateGenesis(data GenesisState) error {
	for _, f := range data.Allowances {
		grant, err := f.GetGrant()
		if err != nil {
			return err
		}
		err = grant.ValidateBasic()
		if err != nil {
			return err
		}
	}
	return nil
}
```

**File:** x/feegrant/keeper/msg_server.go (L40-43)
```go
	// Checking for duplicate entry
	if f, _ := k.Keeper.GetAllowance(ctx, granter, grantee); f != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "fee allowance already exists")
	}
```

**File:** x/feegrant/keeper/keeper.go (L49-61)
```go
	store := ctx.KVStore(k.storeKey)
	key := feegrant.FeeAllowanceKey(granter, grantee)
	grant, err := feegrant.NewGrant(granter, grantee, feeAllowance)
	if err != nil {
		return err
	}

	bz, err := k.cdc.Marshal(&grant)
	if err != nil {
		return err
	}

	store.Set(key, bz)
```

**File:** x/feegrant/keeper/keeper.go (L192-214)
```go
// InitGenesis will initialize the keeper from a *previously validated* GenesisState
func (k Keeper) InitGenesis(ctx sdk.Context, data *feegrant.GenesisState) error {
	for _, f := range data.Allowances {
		granter, err := sdk.AccAddressFromBech32(f.Granter)
		if err != nil {
			return err
		}
		grantee, err := sdk.AccAddressFromBech32(f.Grantee)
		if err != nil {
			return err
		}

		grant, err := f.GetGrant()
		if err != nil {
			return err
		}

		err = k.GrantAllowance(ctx, granter, grantee, grant)
		if err != nil {
			return err
		}
	}
	return nil
```

**File:** x/auth/types/genesis.go (L85-103)
```go
// ValidateGenAccounts validates an array of GenesisAccounts and checks for duplicates
func ValidateGenAccounts(accounts GenesisAccounts) error {
	addrMap := make(map[string]bool, len(accounts))

	for _, acc := range accounts {
		// check for duplicated accounts
		addrStr := acc.GetAddress().String()
		if _, ok := addrMap[addrStr]; ok {
			return fmt.Errorf("duplicate account found in genesis state; address: %s", addrStr)
		}

		addrMap[addrStr] = true

		// check account specific validation
		if err := acc.Validate(); err != nil {
			return fmt.Errorf("invalid account found in genesis state; address: %s, error: %s", addrStr, err.Error())
		}
	}
	return nil
```
