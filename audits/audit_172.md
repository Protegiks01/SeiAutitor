# Audit Report

## Title
Missing Validation of AllowedFeeDenoms Enables Network-Wide Validator Crash via Invalid Denomination

## Summary
The `FeesParams.Validate()` function fails to validate the `AllowedFeeDenoms` field, allowing invalid denomination strings to be set at genesis or through governance. When transactions use these invalid denominations as fees, all validator nodes panic during transaction validation in `CheckTx`, causing network shutdown.

## Impact
High

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Genesis validation: [2](#0-1) 
- Setter with ignored validation: [3](#0-2) 
- Panic trigger point: [4](#0-3) 

**Intended Logic:**
The `FeesParams.Validate()` function should validate all parameter fields including `AllowedFeeDenoms` to ensure each denomination matches the required regex pattern [5](#0-4)  (`[a-zA-Z][a-zA-Z0-9/-]{2,127}`).

**Actual Logic:**
The validation function only checks `GlobalMinimumGasPrices` and completely ignores the `AllowedFeeDenoms` field [1](#0-0) . Additionally, `SetFeesParams` calls `Validate()` but doesn't check the return value (line 39).

**Exploitation Path:**
1. Genesis file or governance proposal sets `AllowedFeeDenoms` with an invalid denomination (e.g., "!", "", "@#$")
2. Invalid value bypasses validation because `FeesParams.Validate()` doesn't check this field
3. User submits transaction with fee in the invalid denomination (bypasses [6](#0-5)  which only checks nil/negative amounts)
4. Transaction enters `CheckTx` on validator nodes
5. Ante handler calls `CheckTxFeeWithValidatorMinGasPrices` which filters fee coins using [4](#0-3) 
6. `NonZeroAmountsOf` [7](#0-6)  calls `NewCoin` with the invalid denom (line 647)
7. `NewCoin` [8](#0-7)  validates the coin and panics on invalid denom (lines 22-23)
8. Validator node crashes

**Security Guarantee Broken:**
Network availability and consensus safety. Validators should never panic during normal transaction processing. The missing validation allows invalid configuration state that violates the denom format invariant [9](#0-8) .

## Impact Explanation

This vulnerability enables network-wide denial of service through validator crashes. Once invalid denominations are configured in `AllowedFeeDenoms`, any user can submit a transaction with fees in that denomination, causing all validators that process it to panic simultaneously. This leads to:

- **Total network shutdown**: All validators crash when processing the malicious transaction during `CheckTx`
- **Consensus halt**: With validators down, the network cannot confirm new blocks
- **Persistent DoS**: The malicious transaction may remain in mempools, causing repeated crashes on restart
- **Difficult recovery**: Requires coordinated network-wide mempool flush or protocol upgrade

This matches the "Network not being able to confirm new transactions (total network shutdown)" impact category (High severity).

## Likelihood Explanation

**Precondition Setup:**
Invalid `AllowedFeeDenoms` can be set through:
- Genesis file configuration (common during chain launch, often generated programmatically without manual review of every field)
- Governance proposals (any token holder can propose, may not undergo thorough validation)

**Exploitation:**
Once the precondition exists, exploitation is trivial:
- **Who**: Any network participant can trigger by submitting a transaction
- **How**: Simple transaction with fee in the invalid denomination
- **Frequency**: Can be repeated indefinitely until fixed

**Realistic Scenario:**
High likelihood because:
- Genesis files often contain programmatically generated parameters that may not be manually validated
- Governance proposals can introduce typos or copy-paste errors
- The missing validation creates a false sense of security (validation function exists but is incomplete)
- The consequence (network crash) is severely disproportionate to the configuration action (setting fee denoms)

This is an **inadvertent privileged misconfiguration vulnerability** where missing validation allows mistakes (not malicious actions) to cause catastrophic failures beyond the intended authority of the configuration parameter.

## Recommendation

Add comprehensive validation to `FeesParams.Validate()`:

```go
func (fp *FeesParams) Validate() error {
    for _, fee := range fp.GlobalMinimumGasPrices {
        if err := fee.Validate(); err != nil {
            return err
        }
    }
    
    // Validate AllowedFeeDenoms
    for _, denom := range fp.AllowedFeeDenoms {
        if err := sdk.ValidateDenom(denom); err != nil {
            return fmt.Errorf("invalid allowed fee denom %q: %w", denom, err)
        }
    }
    
    return nil
}
```

Additionally, fix `SetFeesParams` to properly handle validation errors:

```go
func (k Keeper) SetFeesParams(ctx sdk.Context, feesParams types.FeesParams) error {
    if err := feesParams.Validate(); err != nil {
        return err
    }
    subspace, exist := k.GetSubspace(types.ModuleName)
    if !exist {
        panic("subspace params should exist")
    }
    subspace.Set(ctx, types.ParamStoreKeyFeesParams, feesParams)
    return nil
}
```

## Proof of Concept

**File:** `x/auth/ante/fee_test.go`

**Setup:**
1. Initialize test suite with validator and accounts
2. Set `AllowedFeeDenoms` to contain invalid denomination "!" using `SetFeesParams`
3. Fund test account with valid coins

**Action:**
1. Create transaction with fee using invalid denom "!" by directly constructing `sdk.Coin{Denom: "!", Amount: sdk.NewInt(100)}`
2. Set context to `CheckTx` mode
3. Execute ante handler chain

**Result:**
Ante handler panics when `NonZeroAmountsOf` calls `NewCoin("!", amt)`, which triggers `ValidateDenom` that returns error for invalid denom, causing `NewCoin` to panic. The panic would crash the validator node in production.

**Test Code Structure:**
```go
func (suite *AnteTestSuite) TestInvalidAllowedFeeDenomCausesNodePanic() {
    // Setup
    suite.SetupTest(true)
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    
    // Set invalid AllowedFeeDenoms
    feeParam := suite.app.ParamsKeeper.GetFeesParams(suite.ctx)
    feeParam.AllowedFeeDenoms = []string{"!"}
    suite.app.ParamsKeeper.SetFeesParams(suite.ctx, feeParam)
    
    // Fund account
    priv1, _, addr1 := testdata.KeyTestPubAddr()
    coins := sdk.NewCoins(sdk.NewCoin("usei", sdk.NewInt(1000000)))
    simapp.FundAccount(suite.app.BankKeeper, suite.ctx, addr1, coins)
    
    // Create transaction with invalid fee denom
    msg := testdata.NewTestMsg(addr1)
    suite.txBuilder.SetMsgs(msg)
    invalidFee := sdk.Coins{sdk.Coin{Denom: "!", Amount: sdk.NewInt(100)}}
    suite.txBuilder.SetFeeAmount(invalidFee)
    suite.txBuilder.SetGasLimit(100000)
    
    privs, accNums, accSeqs := []cryptotypes.PrivKey{priv1}, []uint64{0}, []uint64{0}
    tx, _ := suite.CreateTestTx(privs, accNums, accSeqs, suite.ctx.ChainID())
    
    // Execute in CheckTx mode
    suite.ctx = suite.ctx.WithIsCheckTx(true)
    mfd := ante.NewDeductFeeDecorator(suite.app.AccountKeeper, suite.app.BankKeeper, 
                                      suite.app.FeeGrantKeeper, suite.app.ParamsKeeper, nil)
    antehandler, _ := sdk.ChainAnteDecorators(sdk.DefaultWrappedAnteDecorator(mfd))
    
    // Verify panic occurs
    suite.Require().Panics(func() {
        antehandler(suite.ctx, tx, false)
    })
}
```

## Notes

This vulnerability exists because of two compounding bugs:
1. **Incomplete validation**: `FeesParams.Validate()` doesn't check `AllowedFeeDenoms`
2. **Ignored validation results**: `SetFeesParams` calls `Validate()` but doesn't check the return value

While setting `AllowedFeeDenoms` requires privileged access (genesis or governance), this is classified as a valid vulnerability because:
- The validation function exists specifically to catch configuration mistakes (not just malicious actions)
- Inadvertent errors (typos, copy-paste mistakes) in genesis files or governance proposals are realistic
- The consequence (network-wide crash) is catastrophically disproportionate to the intended authority (configuring fee denominations)
- This violates the principle that configuration errors should not cause unrecoverable system failures

### Citations

**File:** x/params/types/params.go (L27-34)
```go
func (fp *FeesParams) Validate() error {
	for _, fee := range fp.GlobalMinimumGasPrices {
		if err := fee.Validate(); err != nil {
			return err
		}
	}
	return nil
}
```

**File:** x/params/types/genesis.go (L37-42)
```go
func (gs GenesisState) Validate() error {
	if err := gs.CosmosGasParams.Validate(); err != nil {
		return err
	}
	return gs.FeesParams.Validate()
}
```

**File:** x/params/keeper/keeper.go (L38-45)
```go
func (k Keeper) SetFeesParams(ctx sdk.Context, feesParams types.FeesParams) {
	feesParams.Validate()
	subspace, exist := k.GetSubspace(types.ModuleName)
	if !exist {
		panic("subspace params should exist")
	}
	subspace.Set(ctx, types.ParamStoreKeyFeesParams, feesParams)
}
```

**File:** x/auth/ante/validator_tx_fee.go (L21-23)
```go
	feeCoins := feeTx.GetFee()
	feeParams := paramsKeeper.GetFeesParams(ctx)
	feeCoins = feeCoins.NonZeroAmountsOf(append([]string{sdk.DefaultBondDenom}, feeParams.GetAllowedFeeDenoms()...))
```

**File:** types/coin.go (L14-27)
```go
// NewCoin returns a new coin with a denomination and amount. It will panic if
// the amount is negative or if the denomination is invalid.
func NewCoin(denom string, amount Int) Coin {
	coin := Coin{
		Denom:  denom,
		Amount: amount,
	}

	if err := coin.Validate(); err != nil {
		panic(err)
	}

	return coin
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

**File:** types/coin.go (L776-784)
```go
var (
	// Denominations can be 3 ~ 128 characters long and support letters, followed by either
	// a letter, a number or a separator ('/').
	reDnmString = `[a-zA-Z][a-zA-Z0-9/-]{2,127}`
	reDecAmt    = `[[:digit:]]+(?:\.[[:digit:]]+)?|\.[[:digit:]]+`
	reSpc       = `[[:space:]]*`
	reDnm       *regexp.Regexp
	reDecCoin   *regexp.Regexp
)
```

**File:** types/coin.go (L807-813)
```go
// ValidateDenom is the default validation function for Coin.Denom.
func ValidateDenom(denom string) error {
	if !reDnm.MatchString(denom) {
		return fmt.Errorf("invalid denom: %s", denom)
	}
	return nil
}
```

**File:** types/tx/types.go (L67-79)
```go
	if fee.Amount.IsAnyNil() {
		return sdkerrors.Wrapf(
			sdkerrors.ErrInsufficientFee,
			"invalid fee provided: null",
		)
	}

	if fee.Amount.IsAnyNegative() {
		return sdkerrors.Wrapf(
			sdkerrors.ErrInsufficientFee,
			"invalid fee provided: %s", fee.Amount,
		)
	}
```
