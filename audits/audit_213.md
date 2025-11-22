# Audit Report

## Title
Nil Pointer Dereference in Grant.ValidateBasic() Causes Node Crash on Malformed Authorization

## Summary
The `Grant.ValidateBasic()` method in the authz module calls `GetCachedValue()` on the `Authorization` field without checking if it is nil first. Since the authorization field is optional in proto3, an attacker can craft a `MsgGrant` transaction with a nil authorization, causing a nil pointer dereference panic that crashes any node processing the transaction.

## Impact
**Medium** - This vulnerability enables an attacker to crash network processing nodes without brute force actions, potentially shutting down 30% or more of the network.

## Finding Description

**Location:** The vulnerability exists in the `Grant.ValidateBasic()` method. [1](#0-0) 

**Intended Logic:** The `ValidateBasic()` method should validate that the Grant contains a valid Authorization and return an error if validation fails. It should handle edge cases gracefully without causing panics.

**Actual Logic:** The method directly calls `g.Authorization.GetCachedValue()` without first checking if `g.Authorization` is nil. In proto3, all fields are optional by default [2](#0-1) , so the authorization field can be nil. When `UnpackInterfaces` is called on a Grant with nil authorization, it succeeds because `UnpackAny` gracefully handles nil input and returns nil without error [3](#0-2) . This leaves the Authorization field as nil, and subsequently calling a method on it causes a panic.

**Exploit Scenario:**
1. Attacker creates a `MsgGrant` transaction with `Grant.Authorization = nil`
2. Transaction is decoded successfully (proto3 allows nil fields)
3. During unmarshaling, `UnpackInterfaces` is called [4](#0-3)  which succeeds for nil authorization
4. In `baseapp.runTx()`, `validateBasicTxMsgs()` is called before the ante handler [5](#0-4) 
5. This calls `msg.ValidateBasic()` which chains to `Grant.ValidateBasic()`
6. `Grant.ValidateBasic()` attempts to call `g.Authorization.GetCachedValue()` on a nil pointer, causing a panic
7. The panic crashes the node

**Security Failure:** This breaks memory safety and availability guarantees. The system panics instead of gracefully handling invalid input, causing denial-of-service.

## Impact Explanation

This vulnerability affects **network availability**. When nodes receive and process a malformed `MsgGrant` transaction:
- The processing node crashes due to the nil pointer dereference panic
- The node becomes unavailable and stops processing transactions
- An attacker can repeatedly broadcast such transactions to crash multiple nodes
- If 30% or more of network nodes are crashed, network performance and reliability severely degrade

This matters because blockchain networks must maintain availability and handle invalid input gracefully. A single malformed transaction should not crash nodes.

## Likelihood Explanation

**Who can trigger it:** Any network participant can submit a `MsgGrant` transaction. No special privileges are required.

**Conditions required:** The attacker only needs to craft a `MsgGrant` with a nil authorization field, which is trivial to do by manually constructing the protobuf message or modifying transaction bytes.

**Frequency:** This can be exploited continuously. An attacker can broadcast multiple malformed transactions in rapid succession to maximize the number of crashed nodes. Every node that processes such a transaction will crash.

## Recommendation

Add a nil check before calling `GetCachedValue()` in `Grant.ValidateBasic()`:

```go
func (g Grant) ValidateBasic() error {
    if g.Authorization == nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidType, "authorization cannot be nil")
    }
    av := g.Authorization.GetCachedValue()
    a, ok := av.(Authorization)
    if !ok {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", (Authorization)(nil), av)
    }
    return a.ValidateBasic()
}
```

This mirrors the nil check pattern already used in `GetAuthorization()` [6](#0-5) .

## Proof of Concept

**File:** `x/authz/authorization_grant_test.go`

**Test Function:** Add this test to demonstrate the panic:

```go
func TestGrantValidateBasicWithNilAuthorization(t *testing.T) {
    // Create a Grant with nil Authorization
    grant := authz.Grant{
        Authorization: nil, // This is allowed in proto3
        Expiration:    time.Now().Add(time.Hour),
    }
    
    // This should panic with nil pointer dereference
    // Wrap in recover to catch the panic and verify it occurs
    defer func() {
        if r := recover(); r == nil {
            t.Error("Expected panic due to nil pointer dereference, but no panic occurred")
        }
    }()
    
    // This call will panic when it tries to call GetCachedValue() on nil Authorization
    _ = grant.ValidateBasic()
    
    t.Error("Should not reach here - ValidateBasic should have panicked")
}
```

**Setup:** No special setup required. The test uses the standard authz package types.

**Trigger:** Call `ValidateBasic()` on a Grant with nil Authorization field.

**Observation:** The test catches the panic that occurs when `g.Authorization.GetCachedValue()` is called on a nil pointer. In production, this panic would crash the node. The test demonstrates that the code does not gracefully handle nil authorization and instead causes a panic.

To demonstrate the full attack path through transaction processing, an integration test could be added to `x/authz/keeper/keeper_test.go` that attempts to submit a `MsgGrant` with nil authorization through the message handler, which would crash during `ValidateBasic()` before reaching the keeper's nil check [7](#0-6) .

### Citations

**File:** x/authz/authorization_grant.go (L46-55)
```go
func (g Grant) GetAuthorization() Authorization {
	if g.Authorization == nil {
		return nil
	}
	a, ok := g.Authorization.GetCachedValue().(Authorization)
	if !ok {
		return nil
	}
	return a
}
```

**File:** x/authz/authorization_grant.go (L57-64)
```go
func (g Grant) ValidateBasic() error {
	av := g.Authorization.GetCachedValue()
	a, ok := av.(Authorization)
	if !ok {
		return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", (Authorization)(nil), av)
	}
	return a.ValidateBasic()
}
```

**File:** proto/cosmos/authz/v1beta1/authz.proto (L24-26)
```text
message Grant {
  google.protobuf.Any       authorization = 1 [(cosmos_proto.accepts_interface) = "Authorization"];
  google.protobuf.Timestamp expiration    = 2 [(gogoproto.stdtime) = true, (gogoproto.nullable) = false];
```

**File:** codec/types/interface_registry.go (L250-253)
```go
	// here we gracefully handle the case in which `any` itself is `nil`, which may occur in message decoding
	if any == nil {
		return nil
	}
```

**File:** codec/proto_codec.go (L80-90)
```go
func (pc *ProtoCodec) Unmarshal(bz []byte, ptr ProtoMarshaler) error {
	err := ptr.Unmarshal(bz)
	if err != nil {
		return err
	}
	err = types.UnpackInterfaces(ptr, pc.interfaceRegistry)
	if err != nil {
		return err
	}
	return nil
}
```

**File:** baseapp/baseapp.go (L921-925)
```go
	msgs := tx.GetMsgs()

	if err := validateBasicTxMsgs(msgs); err != nil {
		return sdk.GasInfo{}, nil, nil, 0, nil, nil, ctx, err
	}
```

**File:** x/authz/keeper/msg_server.go (L26-29)
```go
	authorization := msg.GetAuthorization()
	if authorization == nil {
		return nil, sdkerrors.ErrUnpackAny.Wrap("Authorization is not present in the msg")
	}
```
