## Title
Unlimited Fund Drainage via GenericAuthorization for Financial Messages

## Summary
The `GenericAuthorization.Accept` method always returns `Accept: true` without any usage limits or spend tracking. When accidentally granted for financial message types like `MsgSend`, it allows a grantee to execute unlimited transactions and drain the granter's entire account until the authorization expires, with no safeguards preventing this dangerous misconfiguration. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Primary issue: `x/authz/generic_authorization.go`, lines 24-26 (Accept method)
- Grant creation: `x/authz/keeper/msg_server.go`, lines 14-42 (no validation)
- CLI interface: `x/authz/client/cli/tx.go`, lines 101-107 (allows dangerous configs) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
Authorizations for financial operations should track usage and enforce limits. The `SendAuthorization` implementation demonstrates this pattern by maintaining a `SpendLimit`, decrementing it on each use, and either deleting the grant when exhausted or returning an updated authorization with the reduced limit. [4](#0-3) 

**Actual Logic:**
`GenericAuthorization.Accept` unconditionally returns `Accept: true` with neither `Delete` nor `Updated` set in the response. This means the authorization persists indefinitely until expiration, allowing unlimited executions. The system provides no validation to prevent granting `GenericAuthorization` for financial message types that should use limited authorizations.

**Exploit Scenario:**
1. User Alice wants to authorize Bob to send up to 1000 tokens on her behalf
2. Alice accidentally creates a `GenericAuthorization` for `MsgSend` instead of a `SendAuthorization` with a proper spend limit
3. Bob can now execute unlimited `MsgSend` transactions from Alice's account
4. Bob drains Alice's entire balance (e.g., 1,000,000 tokens) through repeated executions
5. The authorization remains active until its expiration date (potentially months away)

The `DispatchActions` flow calls `authorization.Accept()` and respects the response, but `GenericAuthorization` never signals deletion or updates: [5](#0-4) 

**Security Failure:**
Authorization accounting and access control is completely bypassed. The system fails to enforce spend limits on financial operations, breaking the fundamental security invariant that authorized actions should be bounded and tracked.

## Impact Explanation

**Affected Assets:** All tokens in the granter's account that can be transferred via the authorized message type.

**Severity of Damage:** 
- Complete fund drainage: A grantee can transfer all available funds from the granter's account
- No automatic termination: The authorization continues until expiration
- Irreversible: Once funds are transferred, they cannot be recovered without the grantee's cooperation

**System Impact:**
This undermines the entire authz security model. Users cannot safely delegate limited permissions because the system allows unlimited authorization without safeguards. This could lead to massive fund losses across the network as users misuse `GenericAuthorization` for financial operations.

## Likelihood Explanation

**Who can trigger:** Any grantee who receives a `GenericAuthorization` for a financial message type can exploit this, either maliciously or accidentally through repeated legitimate uses that exceed intended limits.

**Required conditions:**
- Granter creates `GenericAuthorization` for a financial message type (e.g., `MsgSend`, `MsgDelegate`)
- This is easily done via CLI and is not prevented by any validation
- The authorization has not yet expired

**Frequency:**
This can occur during normal operation whenever users misunderstand the authorization types. The CLI explicitly supports creating `GenericAuthorization` for any message type, making this misconfiguration readily accessible. Given that `SendAuthorization` and `GenericAuthorization` are both available options, user confusion is highly likely, especially for users familiar with generic authorization patterns in other systems.

## Recommendation

Implement validation in the `Grant` message handler to reject `GenericAuthorization` for message types that have specialized authorization implementations with built-in limits:

1. Maintain a registry of message types that require limited authorizations (e.g., `MsgSend` → `SendAuthorization`, `MsgDelegate` → `StakeAuthorization`)
2. In `Keeper.Grant()`, check if the authorization is `GenericAuthorization` and the message type is in the restricted registry
3. Return an error if `GenericAuthorization` is attempted for a restricted message type, instructing users to use the appropriate limited authorization

Alternatively, modify `GenericAuthorization` to accept an optional usage limit parameter that decrements on each use, similar to `SendAuthorization`'s spend limit pattern.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Test Function:** `TestGenericAuthorizationUnlimitedExploit` (add after existing tests)

**Setup:**
- Initialize test app with 3 addresses: granter, grantee, recipient
- Fund granter's account with 10,000 tokens
- Create a `GenericAuthorization` for `MsgSend` (instead of `SendAuthorization`) with 1-hour expiration

**Trigger:**
- Execute 100 consecutive `MsgSend` transactions through `DispatchActions`, each sending 50 tokens
- This transfers 5,000 tokens total, far exceeding any reasonable authorization intent
- Continue executing until the granter's balance is exhausted

**Observation:**
- All 100+ transactions succeed without the authorization being deleted or updated
- The granter's balance is fully drained
- The authorization remains active in storage
- Compare with a parallel test using `SendAuthorization` with a 50-token limit, which correctly fails after the first transaction

This test demonstrates that `GenericAuthorization` allows unlimited fund drainage, while proper authorization implementations prevent this through spend tracking and automatic deletion.

### Citations

**File:** x/authz/generic_authorization.go (L24-26)
```go
func (a GenericAuthorization) Accept(ctx sdk.Context, msg sdk.Msg) (AcceptResponse, error) {
	return AcceptResponse{Accept: true}, nil
}
```

**File:** x/authz/keeper/msg_server.go (L14-42)
```go
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return nil, err
	}

	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return nil, err
	}

	authorization := msg.GetAuthorization()
	if authorization == nil {
		return nil, sdkerrors.ErrUnpackAny.Wrap("Authorization is not present in the msg")
	}

	t := authorization.MsgTypeURL()
	if k.router.HandlerByTypeURL(t) == nil {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "%s doesn't exist.", t)
	}

	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration)
	if err != nil {
		return nil, err
	}

	return &authz.MsgGrantResponse{}, nil
}
```

**File:** x/authz/client/cli/tx.go (L101-107)
```go
			case "generic":
				msgType, err := cmd.Flags().GetString(FlagMsgType)
				if err != nil {
					return err
				}

				authorization = authz.NewGenericAuthorization(msgType)
```

**File:** x/bank/types/send_authorization.go (L26-40)
```go
func (a SendAuthorization) Accept(ctx sdk.Context, msg sdk.Msg) (authz.AcceptResponse, error) {
	mSend, ok := msg.(*MsgSend)
	if !ok {
		return authz.AcceptResponse{}, sdkerrors.ErrInvalidType.Wrap("type mismatch")
	}
	limitLeft, isNegative := a.SpendLimit.SafeSub(mSend.Amount)
	if isNegative {
		return authz.AcceptResponse{}, sdkerrors.ErrInsufficientFunds.Wrapf("requested amount is more than spend limit")
	}
	if limitLeft.IsZero() {
		return authz.AcceptResponse{Accept: true, Delete: true}, nil
	}

	return authz.AcceptResponse{Accept: true, Delete: false, Updated: &SendAuthorization{SpendLimit: limitLeft}}, nil
}
```

**File:** x/authz/keeper/keeper.go (L94-110)
```go
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
```
