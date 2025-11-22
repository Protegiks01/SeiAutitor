## Audit Report

## Title
Node Crash via Unsorted Fee Coins in BasicAllowance.Accept with Multiple Denominations

## Summary
The `SafeSub` operation in `BasicAllowance.Accept` does not validate that the fee coins parameter is sorted before performing subtraction operations. When transaction fees are filtered through `NonZeroAmountsOf` with an unsorted denomination list (constructed from `DefaultBondDenom` + `AllowedFeeDenoms`), the resulting coins array can be unsorted, causing `SafeSub` to panic and crash the node. [1](#0-0) 

## Impact
High

## Finding Description

**Location:** 
- Primary: `x/feegrant/basic_fee.go` lines 26-29 in `BasicAllowance.Accept`
- Contributing: `x/auth/ante/validator_tx_fee.go` line 23 in `CheckTxFeeWithValidatorMinGasPrices`
- Contributing: `types/coin.go` lines 307-309 in `safeAdd` [2](#0-1) 

**Intended Logic:** 
The `BasicAllowance.Accept` method should safely validate and deduct transaction fees from the spend limit, handling all valid coin denominations that may be present in the fee. The `SafeSub` operation is intended to safely subtract one coin set from another and detect when the result would be negative (insufficient allowance). [3](#0-2) 

**Actual Logic:** 
The `SafeSub` operation calls `safeAdd` internally, which has a strict precondition that both coin sets must be sorted in ascending lexicographic order by denomination. This precondition is enforced with a panic, not a graceful error return. [4](#0-3) 

When fees contain multiple denominations and `AllowedFeeDenoms` includes denominations lexicographically less than `DefaultBondDenom` ("usei"), the `NonZeroAmountsOf` function reconstructs the fee coins in the order `["usei", ...AllowedFeeDenoms]`, which is unsorted (e.g., `["usei", "atom"]`). [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. Network governance configures `AllowedFeeDenoms` to include "atom" or any denomination lexicographically less than "usei" (e.g., `AllowedFeeDenoms = ["atom"]`) [7](#0-6) 

2. Attacker creates or uses an existing fee grant with `BasicAllowance` that has a spend limit in multiple denominations [8](#0-7) 

3. Attacker submits a transaction with:
   - Fee: `[{atom, 100}, {usei, 200}]` (properly sorted)
   - FeeGranter: address of the granter

4. During ante handler processing, `CheckTxFeeWithValidatorMinGasPrices` filters the fee through `NonZeroAmountsOf(["usei", "atom"])`, producing unsorted coins `[{usei, 200}, {atom, 100}]`

5. This unsorted fee is passed to `UseGrantedFees` → `Accept` → `SafeSub`

6. `SafeSub` calls `safeAdd(coinsB.negative())`, which calls `isSorted()` and panics with "Wrong argument: coins must be sorted"

7. The node crashes with an unrecovered panic

**Security Failure:** 
This breaks the availability guarantee of the network. An attacker can trigger denial-of-service by crashing any node that processes the malicious transaction, potentially causing network-wide shutdown if exploited systematically.

## Impact Explanation

**Affected Components:**
- Network availability: Nodes crash when processing the malicious transaction
- Transaction processing: All transactions in blocks containing the exploit transaction fail to process
- Consensus: If enough validators crash simultaneously, the network cannot reach consensus

**Severity:**
This vulnerability allows any user with access to fee grants to crash network nodes by submitting a single transaction. The attack requires:
- No special privileges (any user can submit transactions)
- No financial cost beyond normal transaction fees
- No brute force (single transaction can trigger the crash)

If exploited against multiple validators simultaneously, this could cause "Network not being able to confirm new transactions (total network shutdown)" as defined in the High impact category.

The vulnerability is particularly dangerous because:
1. The configuration (`AllowedFeeDenoms = ["atom"]`) is a reasonable governance setting [9](#0-8) 

2. Fee grants are a standard feature for improving user experience
3. The crash is deterministic and repeatable
4. No fix is possible without code changes (restart doesn't help)

## Likelihood Explanation

**Trigger Conditions:**
- Any network participant can trigger this (no special privileges required)
- Requires governance to have configured `AllowedFeeDenoms` with at least one denomination lexicographically less than "usei"
- Requires existence of fee grants on-chain (or attacker can create their own)
- Can be triggered during normal operation with a standard transaction

**Frequency:**
- Once the configuration conditions are met, the attack can be executed repeatedly
- Each execution crashes the affected node
- Multiple transactions can be submitted to affect multiple nodes
- No rate limiting or protection mechanisms exist

**Likelihood Assessment:**
MODERATE to HIGH. While it requires specific governance configuration, using "atom" as an allowed fee denomination alongside "usei" is a reasonable multi-token fee policy. Networks commonly enable multiple fee tokens for user convenience. Once this configuration exists, exploitation is trivial and has severe impact. [10](#0-9) 

## Recommendation

**Immediate Fix:**
Sort the fee coins after filtering in `CheckTxFeeWithValidatorMinGasPrices` before returning them:

```go
feeCoins = feeCoins.NonZeroAmountsOf(append([]string{sdk.DefaultBondDenom}, feeParams.GetAllowedFeeDenoms()...))
feeCoins = feeCoins.Sort() // Add this line
```

**Additional Safeguards:**
1. Validate that `AllowedFeeDenoms` is sorted during governance parameter updates
2. Add defensive validation in `BasicAllowance.Accept` to check coin sorting before calling `SafeSub`, returning a clear error instead of panicking
3. Consider making `SafeSub` return an error for unsorted coins instead of panicking, as panics in transaction processing can crash nodes

**Alternative Fix:**
Ensure the denoms list is sorted before passing to `NonZeroAmountsOf`:
```go
denoms := append([]string{sdk.DefaultBondDenom}, feeParams.GetAllowedFeeDenoms()...)
sort.Strings(denoms)
feeCoins = feeCoins.NonZeroAmountsOf(denoms)
```

## Proof of Concept

**File:** `x/auth/ante/feegrant_test.go`

**Test Function:** `TestFeeGrantPanicWithUnsortedDenoms`

**Setup:**
1. Initialize test environment with `suite.SetupTest(false)`
2. Configure `AllowedFeeDenoms = ["atom"]` in fee params (creates unsorted list `["usei", "atom"]`)
3. Create two accounts: granter (with funds) and grantee (fee grant recipient)
4. Fund granter account with both "atom" and "usei" tokens
5. Create a `BasicAllowance` fee grant from granter to grantee with spend limit in both denominations: `[{atom, 1000}, {usei, 1000}]` (sorted)
6. Grant the allowance via `FeeGrantKeeper.GrantAllowance`

**Trigger:**
1. Create a transaction with grantee as signer and granter as fee granter
2. Set transaction fee to multiple denominations: `[{atom, 50}, {usei, 50}]` (sorted)
3. Process transaction through ante handler: `antehandler(ctx, tx, false)`

**Observation:**
The test will panic with message "Wrong argument: coins must be sorted" when `SafeSub` is called with the unsorted fee coins `[{usei, 50}, {atom, 50}]` produced by `NonZeroAmountsOf`. This confirms the vulnerability.

**Expected Behavior (after fix):**
The transaction should process successfully without panic, properly deducting fees from the allowance.

### Citations

**File:** x/feegrant/basic_fee.go (L20-36)
```go
func (a *BasicAllowance) Accept(ctx sdk.Context, fee sdk.Coins, _ []sdk.Msg) (bool, error) {
	if a.Expiration != nil && a.Expiration.Before(ctx.BlockTime()) {
		return true, sdkerrors.Wrap(ErrFeeLimitExpired, "basic allowance")
	}

	if a.SpendLimit != nil {
		left, invalid := a.SpendLimit.SafeSub(fee)
		if invalid {
			return false, sdkerrors.Wrap(ErrFeeLimitExceeded, "basic allowance")
		}

		a.SpendLimit = left
		return left.IsZero(), nil
	}

	return false, nil
}
```

**File:** types/coin.go (L301-309)
```go
func (coins Coins) safeAdd(coinsB Coins) Coins {
	// probably the best way will be to make Coins and interface and hide the structure
	// definition (type alias)
	if !coins.isSorted() {
		panic("Coins (self) must be sorted")
	}
	if !coinsB.isSorted() {
		panic("Wrong argument: coins must be sorted")
	}
```

**File:** types/coin.go (L393-399)
```go
// SafeSub performs the same arithmetic as Sub but returns a boolean if any
// negative coin amount was returned.
// The function panics if `coins` or  `coinsB` are not sorted (ascending).
func (coins Coins) SafeSub(coinsB Coins) (Coins, bool) {
	diff := coins.safeAdd(coinsB.negative())
	return diff, diff.IsAnyNegative()
}
```

**File:** types/coin.go (L641-651)
```go
// NonZeroAmountsOf returns non-zero coins for provided denoms
func (coins Coins) NonZeroAmountsOf(denoms []string) (subset Coins) {
	subset = Coins{}
	for _, denom := range denoms {
		amt := coins.AmountOf(denom)
		if amt.IsPositive() {
			subset = append(subset, NewCoin(denom, amt))
		}
	}
	return
}
```

**File:** x/auth/ante/validator_tx_fee.go (L21-24)
```go
	feeCoins := feeTx.GetFee()
	feeParams := paramsKeeper.GetFeesParams(ctx)
	feeCoins = feeCoins.NonZeroAmountsOf(append([]string{sdk.DefaultBondDenom}, feeParams.GetAllowedFeeDenoms()...))
	gas := feeTx.GetGas()
```

**File:** x/params/types/types.pb.go (L29-32)
```go
type FeesParams struct {
	GlobalMinimumGasPrices github_com_cosmos_cosmos_sdk_types.DecCoins `protobuf:"bytes,1,rep,name=global_minimum_gas_prices,json=globalMinimumGasPrices,proto3,castrepeated=github.com/cosmos/cosmos-sdk/types.DecCoins" json:"global_minimum_gas_prices"`
	AllowedFeeDenoms       []string                                    `protobuf:"bytes,2,rep,name=allowed_fee_denoms,json=allowedFeeDenoms,proto3" json:"allowed_fee_denoms,omitempty"`
}
```

**File:** x/feegrant/keeper/keeper.go (L147-158)
```go
func (k Keeper) UseGrantedFees(ctx sdk.Context, granter, grantee sdk.AccAddress, fee sdk.Coins, msgs []sdk.Msg) error {
	f, err := k.getGrant(ctx, granter, grantee)
	if err != nil {
		return err
	}

	grant, err := f.GetGrant()
	if err != nil {
		return err
	}

	remove, err := grant.Accept(ctx, fee, msgs)
```

**File:** x/auth/ante/fee_test.go (L365-367)
```go
	feeParam.GlobalMinimumGasPrices = sdk.NewDecCoins(sdk.NewDecCoinFromDec("usei", sdk.NewDec(100)))
	feeParam.AllowedFeeDenoms = []string{"atom"}
	suite.app.ParamsKeeper.SetFeesParams(suite.ctx, feeParam)
```

**File:** types/staking.go (L6-7)
```go
	// default bond denomination
	DefaultBondDenom = "usei"
```
