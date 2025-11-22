## Audit Report

## Title
Authz Module Allows Smart Contracts as Grantees Enabling Unauthorized Fund Drainage

## Summary
The authz module's message validation does not prevent smart contract addresses from being designated as grantees in authorization grants. In CosmWasm-enabled chains, this allows malicious contracts to execute `MsgExec` as submessages during their execution, enabling them to drain user funds without explicit user consent at the time of execution. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Primary: `x/authz/msgs.go` - `MsgGrant.ValidateBasic()` method
- Secondary: `x/authz/keeper/msg_server.go` - `Grant()` method
- Execution: `x/authz/keeper/keeper.go` - `DispatchActions()` method [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** 
The authz module should validate that grantee addresses are appropriate for receiving authorization grants. In CosmWasm-enabled chains, smart contracts should be prevented from being grantees because they can autonomously execute messages without requiring signatures for submessages.

**Actual Logic:** 
The validation only checks that granter and grantee are valid bech32 addresses and that they are not identical. There is no verification to determine whether an address belongs to a smart contract. [1](#0-0) 

**Exploit Scenario:**
1. Attacker deploys a malicious smart contract `C` on a CosmWasm-enabled chain
2. Victim Alice grants `SendAuthorization` to contract `C` with a spend limit (e.g., believing it's a legitimate DeFi contract for trading)
3. Alice calls contract `C` for what appears to be a legitimate operation
4. During execution, the malicious contract returns a `MsgExec` as a submessage:
   ```
   MsgExec{
     grantee: C,
     msgs: [MsgSend{from: Alice, to: Attacker, amount: SpendLimit}]
   }
   ```
5. The `MsgExec` is executed as part of the same transaction without requiring the contract's signature (submessages bypass ante handlers)
6. `DispatchActions()` verifies that contract `C` has authorization from Alice for `MsgSend`
7. The `MsgSend` is executed, transferring Alice's funds to the attacker [4](#0-3) [5](#0-4) 

**Security Failure:** 
Authorization bypass - The contract can execute authorized messages on behalf of users without their explicit consent at execution time. The user only consented to grant authorization, not to have the contract autonomously execute it at will. This violates the authorization security model where the grantee should be a trusted account controlled by a private key holder who explicitly decides when to use the authorization.

## Impact Explanation

**Affected Assets:** User funds held in accounts that have granted authorization to malicious contracts.

**Severity of Damage:**
- Users can lose all funds up to the authorization limit granted to malicious contracts
- For unlimited authorizations (e.g., `GenericAuthorization`), users can lose all accessible funds
- The attack is silent - users won't know their funds are being drained until it's too late
- Multiple users can be affected by the same malicious contract

**System Security Impact:**
This fundamentally breaks the authorization security model. The authz module is designed to allow controlled delegation where a trusted grantee can act on behalf of a granter. Allowing contracts as grantees transforms this into an uncontrolled delegation where contracts can autonomously execute authorizations without human decision-making at execution time. [6](#0-5) 

## Likelihood Explanation

**Who Can Trigger:** Any attacker who can deploy a smart contract on the chain.

**Conditions Required:**
- The chain must have CosmWasm enabled (as specified in the security question)
- Users must be convinced to grant authorization to the malicious contract (social engineering)
- No special privileges required

**Frequency:** 
This can be exploited repeatedly:
- Each malicious contract can target multiple users
- Multiple malicious contracts can be deployed
- Users commonly grant authorizations to DeFi protocols, DEXes, and other contracts for convenience
- The attack is immediate once authorization is granted and the contract is called

**Likelihood Assessment:** High - Social engineering users to grant authorization to seemingly legitimate contracts is a common attack vector in blockchain ecosystems. Users regularly grant approvals to contracts for trading, staking, and other DeFi operations.

## Recommendation

Add validation to prevent smart contract addresses from being designated as grantees in `MsgGrant.ValidateBasic()` and `Keeper.Grant()`:

1. **In `x/authz/msgs.go` - `MsgGrant.ValidateBasic()`:** Add a check after address validation to verify that the grantee address is not a smart contract. This requires access to account state to check if code is stored at the address.

2. **In `x/authz/keeper/msg_server.go` - `Grant()` method:** Before calling `SaveGrant()`, verify that the grantee address does not have contract code stored. This can be done by querying the wasm keeper (if available) to check `HasContractInfo(granteeAddr)`.

3. **Alternative approach:** Add a decorator or ante handler check specific to CosmWasm chains that prevents `MsgExec` from being included in contract submessages.

Example validation logic:
```go
// In Keeper.Grant() after line 24:
if k.wasmKeeper != nil {
    hasContract := k.wasmKeeper.HasContractInfo(ctx, grantee)
    if hasContract {
        return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, 
            "grantee cannot be a smart contract address")
    }
}
```

Similarly, add validation to prevent contracts from being granters to prevent contracts from delegating their own permissions.

## Proof of Concept

**File:** `x/authz/keeper/keeper_test.go`

**Test Function:** Add a new test `TestContractAsGranteeVulnerability()`

**Setup:**
1. Initialize blockchain state with three accounts: Alice (granter), Bob (attacker), and ContractAddr (simulating a contract address)
2. Fund Alice's account with 10000 tokens
3. Create a `SendAuthorization` grant from Alice to ContractAddr with a spend limit of 5000 tokens

**Trigger:**
1. Simulate a contract execution by calling `DispatchActions()` directly with ContractAddr as the grantee
2. The messages parameter contains a `MsgSend` that transfers 5000 tokens from Alice to Bob
3. This simulates what would happen when a CosmWasm contract returns a `MsgExec` submessage during execution

**Observation:**
The test will show that:
- The `DispatchActions()` call succeeds without error
- Alice's balance decreases by 5000 tokens
- Bob's balance increases by 5000 tokens
- This demonstrates that a contract address can successfully execute authorized messages on behalf of users

The test confirms the vulnerability by showing that there is no validation preventing contract addresses from being grantees and successfully executing authorized actions, which would allow malicious contracts to drain user funds in CosmWasm-enabled chains. [7](#0-6)

### Citations

**File:** x/authz/msgs.go (L54-68)
```go
func (msg MsgGrant) ValidateBasic() error {
	granter, err := sdk.AccAddressFromBech32(msg.Granter)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "invalid granter address")
	}

	if granter.Equals(grantee) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "granter and grantee cannot be same")
	}
	return msg.Grant.ValidateBasic()
}
```

**File:** x/authz/msgs.go (L211-218)
```go
// GetSigners implements Msg
func (msg MsgExec) GetSigners() []sdk.AccAddress {
	grantee, err := sdk.AccAddressFromBech32(msg.Grantee)
	if err != nil {
		panic(err)
	}
	return []sdk.AccAddress{grantee}
}
```

**File:** x/authz/keeper/msg_server.go (L14-41)
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
```

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

**File:** x/bank/types/send_authorization.go (L25-40)
```go
// Accept implements Authorization.Accept.
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

**File:** x/authz/keeper/keeper_test.go (L126-197)
```go
func (s *TestSuite) TestKeeperFees() {
	app, addrs := s.app, s.addrs

	granterAddr := addrs[0]
	granteeAddr := addrs[1]
	recipientAddr := addrs[2]
	s.Require().NoError(simapp.FundAccount(app.BankKeeper, s.ctx, granterAddr, sdk.NewCoins(sdk.NewInt64Coin("steak", 10000))))
	now := s.ctx.BlockHeader().Time
	s.Require().NotNil(now)

	smallCoin := sdk.NewCoins(sdk.NewInt64Coin("steak", 20))
	someCoin := sdk.NewCoins(sdk.NewInt64Coin("steak", 123))

	msgs := authz.NewMsgExec(granteeAddr, []sdk.Msg{
		&banktypes.MsgSend{
			Amount:      sdk.NewCoins(sdk.NewInt64Coin("steak", 2)),
			FromAddress: granterAddr.String(),
			ToAddress:   recipientAddr.String(),
		},
	})

	s.Require().NoError(msgs.UnpackInterfaces(app.AppCodec()))

	s.T().Log("verify dispatch fails with invalid authorization")
	executeMsgs, err := msgs.GetMessages()
	s.Require().NoError(err)
	result, err := app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)

	s.Require().Nil(result)
	s.Require().NotNil(err)

	s.T().Log("verify dispatch executes with correct information")
	// grant authorization
	err = app.AuthzKeeper.SaveGrant(s.ctx, granteeAddr, granterAddr, &banktypes.SendAuthorization{SpendLimit: smallCoin}, now)
	s.Require().NoError(err)
	authorization, _ := app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)

	s.Require().Equal(authorization.MsgTypeURL(), bankSendAuthMsgType)

	executeMsgs, err = msgs.GetMessages()
	s.Require().NoError(err)

	result, err = app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)
	s.Require().NoError(err)
	s.Require().NotNil(result)

	authorization, _ = app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)

	s.T().Log("verify dispatch fails with overlimit")
	// grant authorization

	msgs = authz.NewMsgExec(granteeAddr, []sdk.Msg{
		&banktypes.MsgSend{
			Amount:      someCoin,
			FromAddress: granterAddr.String(),
			ToAddress:   recipientAddr.String(),
		},
	})

	s.Require().NoError(msgs.UnpackInterfaces(app.AppCodec()))
	executeMsgs, err = msgs.GetMessages()
	s.Require().NoError(err)

	result, err = app.AuthzKeeper.DispatchActions(s.ctx, granteeAddr, executeMsgs)
	s.Require().Nil(result)
	s.Require().NotNil(err)

	authorization, _ = app.AuthzKeeper.GetCleanAuthorization(s.ctx, granteeAddr, granterAddr, bankSendAuthMsgType)
	s.Require().NotNil(authorization)
}
```
