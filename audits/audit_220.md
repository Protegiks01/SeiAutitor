## Title
Nil Pointer Dereference in Grant.ValidateBasic() Causes Node Panic

## Summary
The `Grant.ValidateBasic()` method in the authz module attempts to dereference `g.Authorization` without checking if it is nil, leading to a nil pointer panic. An attacker can exploit this by crafting a `MsgGrant` transaction with a nil `Authorization` field, causing any node that processes the transaction to crash. [1](#0-0) 

## Impact
**Medium**

## Finding Description

- **Location:** The vulnerability exists in `x/authz/authorization_grant.go`, specifically in the `Grant.ValidateBasic()` method at line 58.

- **Intended Logic:** The `ValidateBasic()` method is supposed to validate that a Grant contains a valid Authorization. It should safely check if the Authorization field exists before attempting to access it.

- **Actual Logic:** The method directly calls `g.Authorization.GetCachedValue()` without first verifying that `g.Authorization` is not nil. This causes a nil pointer dereference panic when Authorization is nil. [1](#0-0) 
  
  In contrast, the `GetAuthorization()` method properly handles the nil case: [2](#0-1) 

- **Exploit Scenario:**
  1. Attacker creates a `MsgGrant` protobuf message with `Grant.Authorization = nil` (bypassing the Go constructor which would reject nil)
  2. Attacker broadcasts this transaction to network nodes
  3. When a node receives the transaction, it calls `UnpackInterfaces()` which gracefully handles nil and returns no error: [3](#0-2) 
  
  4. The node then calls `ValidateBasic()` on the message before processing it (standard Cosmos SDK flow)
  5. `MsgGrant.ValidateBasic()` calls `msg.Grant.ValidateBasic()`: [4](#0-3) 
  
  6. `Grant.ValidateBasic()` attempts to call `g.Authorization.GetCachedValue()` on a nil pointer
  7. The node panics with a nil pointer dereference

- **Security Failure:** This breaks the availability property of the network. The panic occurs during transaction validation, which is executed before the transaction reaches the message handler. This means the node crashes before it can properly reject the invalid transaction, causing a denial-of-service condition.

## Impact Explanation

This vulnerability affects the availability of the blockchain network:

- **Affected Processes:** All validator nodes and full nodes that process transactions are vulnerable. When they receive a malicious transaction with nil Authorization, they will panic and crash.

- **Severity:** An attacker can broadcast a single malicious transaction to crash multiple nodes simultaneously. If enough nodes crash (≥30% of network processing nodes), this meets the "Medium" severity criteria defined in the scope.

- **Why This Matters:** Network availability is critical for blockchain operation. Crashing nodes disrupts consensus, prevents transaction processing, and can cause temporary network outages. While nodes can restart after crashing, repeated attacks could cause sustained disruption.

## Likelihood Explanation

This vulnerability is highly likely to be exploited:

- **Who Can Trigger:** Any user can trigger this vulnerability. No special privileges are required - just the ability to broadcast a transaction to the network.

- **Required Conditions:** The attack requires only:
  1. Crafting a protobuf MsgGrant message with nil Authorization field
  2. Broadcasting it to the network
  
  No special timing, network conditions, or state prerequisites are needed.

- **Frequency:** An attacker can repeatedly broadcast such transactions. Each malicious transaction will crash any node that processes it during validation. The attack is cheap to execute (just transaction broadcast costs) and can be automated.

## Recommendation

Add a nil check in `Grant.ValidateBasic()` before calling `GetCachedValue()`:

```go
func (g Grant) ValidateBasic() error {
    if g.Authorization == nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "authorization cannot be nil")
    }
    av := g.Authorization.GetCachedValue()
    a, ok := av.(Authorization)
    if !ok {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expected %T, got %T", (Authorization)(nil), av)
    }
    return a.ValidateBasic()
}
```

This follows the same defensive pattern used in `GetAuthorization()` and would properly reject invalid grants with nil Authorization before attempting to dereference the pointer.

## Proof of Concept

**File:** `x/authz/msgs_test.go`

**Test Function:** Add this new test function to the existing test file:

```go
func TestMsgGrantValidateBasicWithNilAuthorization(t *testing.T) {
    require := require.New(t)
    
    // Create a MsgGrant with nil Authorization by directly constructing it
    // This bypasses NewMsgGrant which would reject nil
    msg := &authz.MsgGrant{
        Granter: granter.String(),
        Grantee: grantee.String(),
        Grant: authz.Grant{
            Expiration: time.Now().Add(time.Hour),
            Authorization: nil, // Explicitly set to nil
        },
    }
    
    // This should panic with nil pointer dereference
    // Demonstrating the vulnerability
    require.Panics(func() {
        msg.ValidateBasic()
    }, "ValidateBasic should panic when Authorization is nil")
}
```

**Setup:** Uses existing test infrastructure in `x/authz/msgs_test.go` with the predefined `granter` and `grantee` addresses.

**Trigger:** Creates a `MsgGrant` directly (bypassing the constructor) with `Grant.Authorization = nil`, then calls `ValidateBasic()`.

**Observation:** The test uses `require.Panics()` to verify that calling `ValidateBasic()` on a Grant with nil Authorization causes a panic. This confirms the vulnerability exists and demonstrates that malicious transactions with this structure will crash nodes during validation.

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

**File:** codec/types/interface_registry.go (L250-253)
```go
	// here we gracefully handle the case in which `any` itself is `nil`, which may occur in message decoding
	if any == nil {
		return nil
	}
```

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
