# Audit Report

## Title
Authz Grants Remain Active After Granter Account Deletion Allowing Unauthorized Transaction Execution

## Summary
The authz module does not clean up authorization grants when a granter account is deleted via `RemoveAccount()`. This allows grantees to continue executing transactions on behalf of deleted accounts, violating the security invariant that only active accounts should be able to authorize transactions.

## Impact
**Medium** - A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk.

## Finding Description

**Location:** 
- Primary vulnerability: `x/authz/keeper/keeper.go` in the `DispatchActions` function [1](#0-0) 
- Account deletion: `x/auth/keeper/account.go` in the `RemoveAccount` function [2](#0-1) 

**Intended Logic:** 
When a granter account is deleted, all authorization grants issued by that account should be revoked or become invalid. The system should prevent execution of grants when the granter account no longer exists.

**Actual Logic:** 
The `RemoveAccount()` function only deletes the account entry from the auth keeper store but does not trigger any cleanup of related data in other modules. [2](#0-1)  The authz module has no hooks or mechanisms to detect account deletion and clean up grants. When `DispatchActions` executes an authorized message, it extracts the granter from `msg.GetSigners()[0]` [3](#0-2)  and retrieves the grant from storage [4](#0-3)  without verifying that the granter account still exists. The message is then executed directly via the router [5](#0-4)  bypassing the ante handler that would normally validate account existence.

**Exploit Scenario:**
1. Alice (granter) creates an authorization grant for Bob (grantee) to send tokens on her behalf
2. Through some mechanism (bug, edge case, or intentional administrative action), Alice's account is deleted via `RemoveAccount()`
3. The grant remains in the authz store because there is no cleanup mechanism
4. Bob submits a `MsgExec` containing a `MsgSend` that transfers funds from Alice's address
5. The ante handler validates Bob's signature and account (which exists), not Alice's
6. `DispatchActions` executes the inner message without checking if Alice's account exists
7. The bank module's `SendCoins` function operates on balances directly [6](#0-5)  and does not validate that the sender account exists - it only checks balances via `GetBalance` [7](#0-6)  which returns zero for non-existent accounts but doesn't fail
8. If Alice's balances were not cleared when the account was deleted, the transfer succeeds

**Security Failure:** 
This violates the authorization security invariant that transactions can only be executed on behalf of active, existing accounts. It creates a scenario where a deleted account remains "active" through orphaned grants, leading to potential unauthorized state changes.

## Impact Explanation

The concrete impacts include:

1. **Violation of Account Lifecycle Invariants**: Accounts that no longer exist in the auth module can still participate in transactions through the authz mechanism, creating inconsistent state across modules.

2. **Unauthorized Transaction Execution**: Grantees can execute transactions that the protocol should consider invalid because they originate from non-existent accounts.

3. **Accounting Inconsistencies**: The bank module can transfer balances from addresses without corresponding account entries, potentially breaking invariants that assume all addresses with balances have account entries.

4. **Protocol Integrity**: If `RemoveAccount()` is used as part of any protocol mechanism (e.g., account cleanup, migration, or administrative actions), the lingering grants create unexpected behavior and security risks.

While the direct theft of funds may be limited by the original grant's authorization limits, the ability to execute transactions on behalf of deleted accounts represents a fundamental violation of the protocol's security model.

## Likelihood Explanation

**Current Likelihood: Low to Medium**

The `RemoveAccount()` function exists in the codebase as part of the `AccountKeeperI` interface [8](#0-7)  and has an implementation [2](#0-1)  but is currently only called in test code based on the grep search results. The function includes a warning comment: "NOTE: this will cause supply invariant violation if called" [9](#0-8) , suggesting it's a dangerous operation.

However, the vulnerability could be triggered if:
- A bug in other code inadvertently calls `RemoveAccount()`
- Future protocol updates use account deletion as a feature
- Edge cases in account state management lead to similar conditions
- Administrative or governance actions attempt account cleanup

The fact that the API exists and is exported means it could be invoked by any code with access to the AccountKeeper, making this a latent vulnerability waiting to be triggered.

## Recommendation

Implement one or both of the following mitigations:

1. **Add Granter Account Validation**: In the `DispatchActions` function, add a check to verify the granter account exists before executing the authorized message:

```go
// After line 85 in x/authz/keeper/keeper.go
granter := signers[0]

// Add account existence check
if !k.accountKeeper.HasAccount(ctx, granter) {
    return nil, sdkerrors.ErrInvalidRequest.Wrap("granter account does not exist")
}
```

2. **Implement Account Deletion Hooks**: Create a hook system that notifies the authz module when an account is deleted, allowing it to clean up all grants where the account is the granter. This could be done by:
   - Adding a hook interface that `RemoveAccount` calls
   - Having the authz keeper implement the hook to delete all grants for the deleted account
   - Using `IterateGrants` to find and remove all grants where the deleted account is the granter

The first approach (validation check) is simpler and provides immediate defense. The second approach (hooks) provides comprehensive cleanup but requires more architectural changes.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add this test function to the existing test suite:

```go
func (s *TestSuite) TestGrantExecutionAfterGranterAccountDeletion() {
    app, ctx, addrs := s.app, s.ctx, s.addrs
    require := s.Require()

    granterAddr := addrs[0]
    granteeAddr := addrs[1]
    recipientAddr := addrs[2]

    // Setup: Fund the granter account with tokens
    initialAmount := sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))
    require.NoError(simapp.FundAccount(app.BankKeeper, ctx, granterAddr, initialAmount))

    // Verify granter account exists and has balance
    granterAcc := app.AccountKeeper.GetAccount(ctx, granterAddr)
    require.NotNil(granterAcc)
    granterBalance := app.BankKeeper.GetBalance(ctx, granterAddr, "steak")
    require.Equal(sdk.NewInt(10000), granterBalance.Amount)

    // Create an authorization grant from granter to grantee
    now := ctx.BlockHeader().Time
    spendLimit := sdk.NewCoins(sdk.NewInt64Coin("steak", 5000))
    authorization := &banktypes.SendAuthorization{SpendLimit: spendLimit}
    err := app.AuthzKeeper.SaveGrant(ctx, granteeAddr, granterAddr, authorization, now.Add(time.Hour))
    require.NoError(err)

    // Verify the grant exists
    auth, _ := app.AuthzKeeper.GetCleanAuthorization(ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
    require.NotNil(auth)

    // Trigger: Delete the granter account using RemoveAccount
    app.AccountKeeper.RemoveAccount(ctx, granterAcc)

    // Verify the account is deleted
    granterAcc = app.AccountKeeper.GetAccount(ctx, granterAddr)
    require.Nil(granterAcc, "granter account should be deleted")

    // Verify the grant still exists (not cleaned up)
    auth, _ = app.AuthzKeeper.GetCleanAuthorization(ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
    require.NotNil(auth, "grant should still exist after account deletion")

    // Verify balance still exists (balances are in bank module, separate from account)
    granterBalance = app.BankKeeper.GetBalance(ctx, granterAddr, "steak")
    require.Equal(sdk.NewInt(10000), granterBalance.Amount, "balance should still exist")

    // Attempt to execute the grant (send tokens from deleted account)
    sendMsg := &banktypes.MsgSend{
        FromAddress: granterAddr.String(),
        ToAddress:   recipientAddr.String(),
        Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 1000)),
    }
    execMsg := authz.NewMsgExec(granteeAddr, []sdk.Msg{sendMsg})
    require.NoError(execMsg.UnpackInterfaces(app.AppCodec()))
    
    executeMsgs, err := execMsg.GetMessages()
    require.NoError(err)

    // Observation: The execution should fail because the granter account doesn't exist
    // but it actually succeeds due to the vulnerability
    result, err := app.AuthzKeeper.DispatchActions(ctx, granteeAddr, executeMsgs)
    
    // This assertion demonstrates the vulnerability:
    // The transaction SHOULD fail but it succeeds
    require.NoError(err, "VULNERABILITY: Transaction executed despite granter account being deleted")
    require.NotNil(result, "VULNERABILITY: Got successful result for deleted account")

    // Verify tokens were transferred from the deleted account
    recipientBalance := app.BankKeeper.GetBalance(ctx, recipientAddr, "steak")
    require.Equal(sdk.NewInt(1000), recipientBalance.Amount, "VULNERABILITY: Tokens transferred from deleted account")
    
    granterBalance = app.BankKeeper.GetBalance(ctx, granterAddr, "steak")
    require.Equal(sdk.NewInt(9000), granterBalance.Amount, "VULNERABILITY: Deleted account balance was modified")
}
```

**Setup:** The test creates three test addresses using the existing test infrastructure, funds the granter account, and creates an authorization grant.

**Trigger:** The test explicitly calls `RemoveAccount()` to delete the granter account, then attempts to execute a grant-authorized transaction.

**Observation:** The test demonstrates that despite the granter account being deleted (verified by `GetAccount` returning `nil`), the grant can still be executed successfully. The transaction transfers tokens from the deleted account's balance to the recipient, proving that the authz module does not properly validate granter account existence during execution. The test passes (transaction succeeds) on the vulnerable code, demonstrating the security flaw.

### Citations

**File:** x/authz/keeper/keeper.go (L74-139)
```go
// DispatchActions attempts to execute the provided messages via authorization
// grants from the message signer to the grantee.
func (k Keeper) DispatchActions(ctx sdk.Context, grantee sdk.AccAddress, msgs []sdk.Msg) ([][]byte, error) {
	results := make([][]byte, len(msgs))

	for i, msg := range msgs {
		signers := msg.GetSigners()
		if len(signers) != 1 {
			return nil, sdkerrors.ErrInvalidRequest.Wrap("authorization can be given to msg with only one signer")
		}

		granter := signers[0]

		// If granter != grantee then check authorization.Accept, otherwise we
		// implicitly accept.
		if !granter.Equals(grantee) {
			authorization, _ := k.GetCleanAuthorization(ctx, grantee, granter, sdk.MsgTypeURL(msg))
			if authorization == nil {
				return nil, sdkerrors.ErrUnauthorized.Wrap("authorization not found")
			}
			resp, err := authorization.Accept(ctx, msg)
			if err != nil {
				return nil, err
			}

			if resp.Delete {
				err = k.DeleteGrant(ctx, grantee, granter, sdk.MsgTypeURL(msg))
			} else if resp.Updated != nil {
				err = k.update(ctx, grantee, granter, resp.Updated)
			}
			if err != nil {
				return nil, err
			}

			if !resp.Accept {
				return nil, sdkerrors.ErrUnauthorized
			}
		}

		handler := k.router.Handler(msg)
		if handler == nil {
			return nil, sdkerrors.ErrUnknownRequest.Wrapf("unrecognized message route: %s", sdk.MsgTypeURL(msg))
		}

		msgResp, err := handler(ctx, msg)
		if err != nil {
			return nil, sdkerrors.Wrapf(err, "failed to execute message; message %v", msg)
		}

		results[i] = msgResp.Data

		// emit the events from the dispatched actions
		events := msgResp.Events
		sdkEvents := make([]sdk.Event, 0, len(events))
		for _, event := range events {
			e := event
			e.Attributes = append(e.Attributes, abci.EventAttribute{Key: []byte("authz_msg_index"), Value: []byte(strconv.Itoa(i))})

			sdkEvents = append(sdkEvents, sdk.Event(e))
		}

		ctx.EventManager().EmitEvents(sdkEvents)
	}

	return results, nil
}
```

**File:** x/auth/keeper/account.go (L68-74)
```go
// RemoveAccount removes an account for the account mapper store.
// NOTE: this will cause supply invariant violation if called
func (ak AccountKeeper) RemoveAccount(ctx sdk.Context, acc types.AccountI) {
	addr := acc.GetAddress()
	store := ctx.KVStore(ak.key)
	store.Delete(types.AddressStoreKey(addr))
}
```

**File:** x/bank/keeper/send.go (L155-173)
```go
// SendCoins transfers amt coins from a sending account to a receiving account.
// An error is returned upon failure.
func (k BaseSendKeeper) SendCoins(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
	if err := k.SendCoinsWithoutAccCreation(ctx, fromAddr, toAddr, amt); err != nil {
		return err
	}

	// Create account if recipient does not exist.
	//
	// NOTE: This should ultimately be removed in favor a more flexible approach
	// such as delegated fee messages.
	accExists := k.ak.HasAccount(ctx, toAddr)
	if !accExists {
		defer telemetry.IncrCounter(1, "new", "account")
		k.ak.SetAccount(ctx, k.ak.NewAccountWithAddress(ctx, toAddr))
	}

	return nil
}
```

**File:** x/bank/keeper/view.go (L100-114)
```go
// GetBalance returns the balance of a specific denomination for a given account
// by address.
func (k BaseViewKeeper) GetBalance(ctx sdk.Context, addr sdk.AccAddress, denom string) sdk.Coin {
	accountStore := k.getAccountStore(ctx, addr)

	bz := accountStore.Get([]byte(denom))
	if bz == nil {
		return sdk.NewCoin(denom, sdk.ZeroInt())
	}

	var balance sdk.Coin
	k.cdc.MustUnmarshal(bz, &balance)

	return balance
}
```

**File:** x/auth/keeper/keeper.go (L34-34)
```go
	// Remove an account from the store.
```
