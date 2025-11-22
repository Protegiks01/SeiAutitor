# Audit Report

## Title
Bech32 Case Sensitivity Bypass in Community Pool Spend Blocked Address Check

## Summary
The `HandleCommunityPoolSpendProposal` function checks if a recipient address is blocked by performing a case-sensitive string lookup in the `blockedAddrs` map. However, blocked addresses are stored in lowercase bech32 format, while the bech32 decoding accepts both uppercase and lowercase addresses. An attacker can bypass this security check by submitting a proposal with an uppercase bech32 address that decodes to the same blocked address, enabling unauthorized fund transfers to module accounts.

## Impact
**High** - Direct loss of funds from the community pool to blocked module accounts.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
The blocked address check is intended to prevent community pool funds from being sent to module accounts (distribution, staking, gov, etc.) which are considered system-controlled addresses that should not receive external funds through governance proposals.

**Actual Logic:** 
The implementation performs a case-sensitive map lookup using the raw recipient string from the proposal: [1](#0-0) 

However, the `blockedAddrs` map is populated with lowercase bech32 addresses. The map initialization in `ModuleAccountAddrs()` creates addresses using `.String()` method: [2](#0-1) 

The `.String()` method on `AccAddress` always produces lowercase bech32 format: [3](#0-2) [4](#0-3) 

The underlying bech32 library accepts both uppercase and lowercase addresses (as long as they are consistently cased): [5](#0-4) 

After the blocked address check, the recipient string is decoded using `AccAddressFromBech32`: [6](#0-5) 

**Exploit Scenario:**
1. An attacker identifies a blocked module account address (e.g., distribution module: `cosmos1jv65s3grqf6v6jl3dp4t6c9t9rk99cd88lyufl`)
2. The attacker creates a `CommunityPoolSpendProposal` with the recipient address in UPPERCASE format (e.g., `COSMOS1JV65S3GRQF6V6JL3DP4T6C9T9RK99CD88LYUFL`)
3. The proposal passes validation because `ValidateBasic()` only checks that the recipient is not empty: [7](#0-6) 
4. When executed, the blocked address check at line 11 fails to find the uppercase string in the `blockedAddrs` map (which contains lowercase strings)
5. The uppercase address successfully decodes to the same `AccAddress` bytes as the lowercase version
6. Funds are transferred to the blocked module account, bypassing the security control

**Security Failure:** 
Authorization bypass - the blocked address protection mechanism is completely circumvented through case manipulation, allowing unauthorized fund transfers to system module accounts.

## Impact Explanation

This vulnerability affects the community pool funds, which represent a significant treasury controlled by governance. Module accounts like the distribution, staking, and governance modules have special permissions and are intentionally blocked from receiving external funds to maintain protocol security boundaries.

By bypassing this check:
- **Direct loss of funds**: Community pool funds can be drained to module accounts where they may become inaccessible or used inappropriately
- **Protocol integrity violation**: Module accounts could accumulate unexpected balances, potentially breaking accounting invariants
- **Governance manipulation**: Attackers could exploit this to move funds into accounts with special privileges, potentially enabling further attacks

The severity is **High** because this represents a direct bypass of an explicit security control protecting treasury funds, with no additional privileges required beyond the ability to create a governance proposal (which typically requires a deposit that is refunded if the proposal passes).

## Likelihood Explanation

**Who can trigger it:** Any user who can submit a governance proposal. In most Cosmos SDK chains, this requires:
- Posting a deposit (typically refundable if proposal passes)
- Getting the proposal to pass through voting

**Conditions required:**
- A successful governance vote (requires majority support from validators/delegators)
- The chain must have funds in the community pool
- Standard operation - no special timing or rare circumstances needed

**Frequency:** 
Once discovered, this could be exploited repeatedly through governance proposals. Each successful malicious proposal could drain portions of the community pool. The exploit is deterministic and reliable - uppercase addresses will always bypass the check while decoding to the correct address.

The primary barrier is social (getting a malicious proposal to pass voting), but this could potentially be achieved through:
- Disguising the uppercase address (social engineering)
- Compromising validator voting keys
- Taking advantage of low voter participation periods

## Recommendation

**Fix 1 (Recommended):** Normalize the recipient address before performing the blocked address check. Convert the proposal's recipient string to an `AccAddress` first, then convert back to string for the map lookup:

```go
func HandleCommunityPoolSpendProposal(ctx sdk.Context, k Keeper, p *types.CommunityPoolSpendProposal) error {
    recipient, err := sdk.AccAddressFromBech32(p.Recipient)
    if err != nil {
        return err
    }
    
    if k.blockedAddrs[recipient.String()] {
        return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", p.Recipient)
    }

    if err := k.DistributeFromFeePool(ctx, p.Amount, recipient); err != nil {
        return err
    }
    
    // ... rest of function
}
```

**Fix 2 (Alternative):** Add bech32 format validation to `ValidateBasic()` in the proposal type to reject non-lowercase addresses early: [7](#0-6) 

Add validation that the recipient can be decoded and matches its normalized form.

## Proof of Concept

**File:** `x/distribution/proposal_handler_test.go`

**Test Function:** Add the following test to the existing test file:

```go
func TestProposalHandlerBlockedAddressBypassWithUppercase(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})

    // Get the distribution module address - this is a blocked address
    distrModuleAddr := app.AccountKeeper.GetModuleAddress(distrtypes.ModuleName)
    
    // Verify it's in the blocked addresses map (lowercase)
    require.True(t, app.DistrKeeper.BlockedAddrs()[distrModuleAddr.String()])
    
    // Fund the community pool
    amount := sdk.NewCoins(sdk.NewCoin(sdk.DefaultBondDenom, sdk.NewInt(1000)))
    macc := app.DistrKeeper.GetDistributionAccount(ctx)
    require.NoError(t, simapp.FundModuleAccount(app.BankKeeper, ctx, macc.GetName(), amount))
    app.AccountKeeper.SetModuleAccount(ctx, macc)
    
    feePool := app.DistrKeeper.GetFeePool(ctx)
    feePool.CommunityPool = sdk.NewDecCoinsFromCoins(amount...)
    app.DistrKeeper.SetFeePool(ctx, feePool)
    
    // Create proposal with UPPERCASE blocked address
    lowercaseAddr := distrModuleAddr.String()
    uppercaseAddr := strings.ToUpper(lowercaseAddr)
    
    // Verify uppercase is different string but decodes to same address
    require.NotEqual(t, lowercaseAddr, uppercaseAddr)
    decodedAddr, err := sdk.AccAddressFromBech32(uppercaseAddr)
    require.NoError(t, err)
    require.Equal(t, distrModuleAddr, decodedAddr)
    
    // Create proposal with uppercase recipient
    tp := &types.CommunityPoolSpendProposal{
        Title:       "Test",
        Description: "description",
        Recipient:   uppercaseAddr,  // UPPERCASE blocked address
        Amount:      amount,
    }
    
    // Execute the proposal - should fail but doesn't due to the bug
    hdlr := distribution.NewCommunityPoolSpendProposalHandler(app.DistrKeeper)
    err = hdlr(ctx, tp)
    
    // BUG: This should return an error because distrModuleAddr is blocked,
    // but it succeeds because the uppercase string bypasses the check
    require.NoError(t, err) // This demonstrates the vulnerability
    
    // Verify funds were transferred to the blocked address
    balances := app.BankKeeper.GetAllBalances(ctx, distrModuleAddr)
    require.Equal(t, amount, balances) // Funds incorrectly sent to blocked address
}
```

**Setup:**
- Initialize a SimApp instance with default configuration
- Fund the community pool with test tokens
- Identify a blocked module address (distribution module)

**Trigger:**
- Convert the blocked address to uppercase bech32 format
- Create a `CommunityPoolSpendProposal` with the uppercase recipient
- Execute the proposal through the handler

**Observation:**
- The proposal succeeds (no error returned) even though the recipient is a blocked module address
- Funds are transferred to the blocked address
- The test demonstrates that uppercase addresses bypass the `blockedAddrs` check while successfully decoding to the same address bytes

This PoC can be run with: `go test -v -run TestProposalHandlerBlockedAddressBypassWithUppercase ./x/distribution/`

### Citations

**File:** x/distribution/keeper/proposal_handler.go (L11-13)
```go
	if k.blockedAddrs[p.Recipient] {
		return sdkerrors.Wrapf(sdkerrors.ErrUnauthorized, "%s is not allowed to receive external funds", p.Recipient)
	}
```

**File:** x/distribution/keeper/proposal_handler.go (L15-18)
```go
	recipient, err := sdk.AccAddressFromBech32(p.Recipient)
	if err != nil {
		return err
	}
```

**File:** simapp/app.go (L607-614)
```go
func (app *SimApp) ModuleAccountAddrs() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range maccPerms {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	return modAccAddrs
}
```

**File:** types/address.go (L273-287)
```go
// String implements the Stringer interface.
func (aa AccAddress) String() string {
	if aa.Empty() {
		return ""
	}

	var key = conv.UnsafeBytesToStr(aa)
	accAddrMu.Lock()
	defer accAddrMu.Unlock()
	addr, ok := accAddrCache.Get(key)
	if ok {
		return addr
	}
	return cacheBech32Addr(GetConfig().GetBech32AccountAddrPrefix(), aa, accAddrCache, key)
}
```

**File:** types/address.go (L663-671)
```go
// cacheBech32Addr is not concurrency safe. Concurrent access to cache causes race condition.
func cacheBech32Addr(prefix string, addr []byte, cache *simplelru.LRU[string, string], cacheKey string) string {
	bech32Addr, err := bech32.ConvertAndEncode(prefix, addr)
	if err != nil {
		panic(err)
	}
	cache.Add(cacheKey, bech32Addr)
	return bech32Addr
}
```

**File:** x/gov/client/rest/rest_test.go (L84-88)
```go
		{
			"get proposal with wrong voter address",
			fmt.Sprintf("%s/gov/proposals/%s/votes/%s", val.APIAddress, "1", "wrongVoterAddress"),
			true, "decoding bech32 failed: string not all lowercase or all uppercase",
		},
```

**File:** x/distribution/types/proposal.go (L44-57)
```go
func (csp *CommunityPoolSpendProposal) ValidateBasic() error {
	err := govtypes.ValidateAbstract(csp)
	if err != nil {
		return err
	}
	if !csp.Amount.IsValid() {
		return ErrInvalidProposalAmount
	}
	if csp.Recipient == "" {
		return ErrEmptyProposalRecipient
	}

	return nil
}
```
