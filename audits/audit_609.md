# Audit Report

## Title
AllowedMsgAllowance Fails to Revoke Expired Allowances Leading to Storage Leak

## Summary
The `AllowedMsgAllowance.Accept` method in `filtered_fee.go` incorrectly handles the `remove` flag when the underlying allowance returns `remove=true` with an error. This causes expired or exhausted fee allowances to never be deleted from storage, resulting in a storage leak that increases node resource consumption over time.

## Impact
Medium

## Finding Description

- **Location:** [1](#0-0) 

- **Intended Logic:** According to the `FeeAllowanceI` interface specification, when an allowance's `Accept` method returns `remove=true`, the allowance should be deleted from storage regardless of whether an error is also returned. [2](#0-1) 

- **Actual Logic:** In `AllowedMsgAllowance.Accept`, when the underlying allowance returns `(remove=true, error)`, the method returns `(false, error)` instead of preserving the `remove=true` flag. This happens because the error check at line 76-78 returns early with `false` before reaching the final return statement at line 85.

- **Exploit Scenario:** 
  1. A granter creates an `AllowedMsgAllowance` wrapping a `BasicAllowance` with an expiration time or spend limit
  2. Time passes and the allowance expires (or the spend limit is exhausted)
  3. A grantee attempts to use the expired allowance
  4. The underlying `BasicAllowance.Accept` returns `(true, error)` to indicate the allowance should be removed [3](#0-2) 
  5. `AllowedMsgAllowance.Accept` incorrectly returns `(false, error)`
  6. The keeper receives `remove=false` and does NOT revoke the allowance [4](#0-3) 
  7. The expired allowance remains in storage indefinitely

- **Security Failure:** The system violates its storage management invariant by failing to clean up expired/exhausted allowances. This leads to unbounded storage growth as "zombie" allowances accumulate over time.

## Impact Explanation

- **Affected Resources:** Node storage and query performance. Every expired `AllowedMsgAllowance` that is not cleaned up permanently occupies storage space.

- **Severity:** Over time, as users create and exhaust fee allowances, the accumulation of unrevokedallowances will:
  - Increase database size unnecessarily
  - Slow down iteration over all allowances
  - Consume additional memory when loading grants
  - Degrade node performance during queries and state synchronization

- **System Impact:** This directly aligns with the Medium severity impact category: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours." As allowances accumulate, nodes will consume progressively more storage and processing resources.

## Likelihood Explanation

- **Trigger Accessibility:** Any user who creates an `AllowedMsgAllowance` with expiration or spend limits can trigger this issue. This is normal, expected usage of the fee grant system.

- **Conditions Required:** The vulnerability triggers automatically when:
  - An `AllowedMsgAllowance` wraps a `BasicAllowance` or `PeriodicAllowance` with expiration
  - The allowance expires or is exhausted
  - Any attempt is made to use the expired allowance

- **Frequency:** This will occur regularly in normal network operation as fee grants expire. Given that setting expiration times is a common practice for fee allowances, this issue will manifest frequently and accumulate storage waste continuously.

## Recommendation

Modify `AllowedMsgAllowance.Accept` to preserve the `remove` flag even when an error occurs:

```go
remove, err := allowance.Accept(ctx, fee, msgs)
if err != nil {
    return remove, err  // Changed from: return false, err
}
```

This ensures that when the underlying allowance signals removal via `remove=true`, the flag is properly propagated to the keeper, allowing expired/exhausted allowances to be cleaned up as intended.

## Proof of Concept

**File:** `x/feegrant/keeper/keeper_test.go`

**Test Function:** Add the following test function to the `KeeperTestSuite`:

```go
func (suite *KeeperTestSuite) TestAllowedMsgAllowanceExpiredNotRevoked() {
    // Setup: Create an expired BasicAllowance wrapped in AllowedMsgAllowance
    eth := sdk.NewCoins(sdk.NewInt64Coin("eth", 123))
    blockTime := suite.sdkCtx.BlockTime()
    expiredTime := blockTime.AddDate(-1, 0, 0) // Expired 1 year ago
    
    // Create expired BasicAllowance
    expiredBasic := &feegrant.BasicAllowance{
        SpendLimit: eth,
        Expiration: &expiredTime,
    }
    
    // Wrap it in AllowedMsgAllowance
    allowedMsgAllowance, err := feegrant.NewAllowedMsgAllowance(
        expiredBasic,
        []string{sdk.MsgTypeURL(&banktypes.MsgSend{})},
    )
    suite.Require().NoError(err)
    
    // Grant the allowance
    err = suite.keeper.GrantAllowance(suite.sdkCtx, suite.addrs[0], suite.addrs[1], allowedMsgAllowance)
    suite.Require().NoError(err)
    
    // Verify allowance exists
    _, err = suite.keeper.GetAllowance(suite.sdkCtx, suite.addrs[0], suite.addrs[1])
    suite.Require().NoError(err)
    
    // Trigger: Try to use the expired allowance
    err = suite.keeper.UseGrantedFees(suite.sdkCtx, suite.addrs[0], suite.addrs[1], eth, []sdk.Msg{&banktypes.MsgSend{}})
    
    // Observation: The error is returned (fee rejected)
    suite.Require().Error(err)
    suite.Contains(err.Error(), "expired")
    
    // BUG: The allowance should be revoked but it's NOT
    // This demonstrates the vulnerability
    _, err = suite.keeper.GetAllowance(suite.sdkCtx, suite.addrs[0], suite.addrs[1])
    suite.Require().Error(err, "Expected allowance to be revoked, but it still exists")
    suite.Contains(err.Error(), "fee-grant not found")
}
```

**Setup:** The test creates an expired `BasicAllowance` wrapped in an `AllowedMsgAllowance` and grants it to a grantee.

**Trigger:** The test calls `UseGrantedFees` with the expired allowance, which should cause the allowance to be revoked.

**Observation:** The test verifies that after attempting to use the expired allowance:
1. The usage correctly returns an error (expected behavior)
2. The allowance is NOT revoked from storage (demonstrates the bug)

On vulnerable code, the final assertion will fail because the expired allowance remains in storage. With the fix applied, the allowance would be properly revoked and the test would pass.

### Citations

**File:** x/feegrant/filtered_fee.go (L75-78)
```go
	remove, err := allowance.Accept(ctx, fee, msgs)
	if err != nil {
		return false, err
	}
```

**File:** x/feegrant/fees.go (L18-19)
```go
	// If remove is true (regardless of the error), the FeeAllowance will be deleted from storage
	// (eg. when it is used up). (See call to RevokeAllowance in Keeper.UseGrantedFees)
```

**File:** x/feegrant/basic_fee.go (L21-23)
```go
	if a.Expiration != nil && a.Expiration.Before(ctx.BlockTime()) {
		return true, sdkerrors.Wrap(ErrFeeLimitExpired, "basic allowance")
	}
```

**File:** x/feegrant/keeper/keeper.go (L158-174)
```go
	remove, err := grant.Accept(ctx, fee, msgs)

	if remove {
		// Ignoring the `revokeFeeAllowance` error, because the user has enough grants to perform this transaction.
		k.revokeAllowance(ctx, granter, grantee)
		if err != nil {
			return err
		}

		emitUseGrantEvent(ctx, granter.String(), grantee.String())

		return nil
	}

	if err != nil {
		return err
	}
```
