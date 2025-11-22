## Audit Report

## Title
Nil Pointer Dereference in Fee Grant Query Handler Causes Node Crash

## Summary
The `GetGrant()` method in `x/feegrant/grant.go` does not check if the `Allowance` field is nil before dereferencing it, causing a panic when processing fee grant queries or genesis initialization with corrupted grant data. This occurs before the proto marshaling code at lines 42-50 of `grpc_query.go` can execute. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** `x/feegrant/grant.go`, function `GetGrant()` at line 58

**Intended Logic:** The `GetGrant()` method should safely unpack the allowance from a `Grant` struct and return it, handling all edge cases including missing or corrupted allowance data gracefully.

**Actual Logic:** The code directly calls `a.Allowance.GetCachedValue()` without checking if `a.Allowance` is nil. Since the protobuf `Grant` struct defines `Allowance` as `*types.Any` (an optional pointer), it can be nil when a Grant is unmarshaled from storage or genesis data. When `a.Allowance` is nil, calling `.GetCachedValue()` on it causes a nil pointer dereference panic. [2](#0-1) 

**Exploit Scenario:**
1. An attacker crafts a genesis JSON file or proposes a chain upgrade with a `Grant` entry where the `allowance` field is omitted or set to `null`
2. When nodes attempt to start with this genesis or query fee allowances, the code path leads to `GetGrant()`
3. The `UnpackInterfaces` method handles nil `Any` gracefully (returns nil without error) [3](#0-2) 
4. However, `GetGrant()` then attempts to dereference the nil `Allowance` pointer, causing a panic
5. The node crashes before reaching the proto marshaling code in `grpc_query.go`

**Security Failure:** This is a denial-of-service vulnerability that breaks availability. Any query or operation that calls `GetGrant()` on a corrupted grant will crash the node.

## Impact Explanation

**Affected Components:**
- gRPC query handler `Allowance()` which calls `GetAllowance()` → `GetGrant()` [4](#0-3) 
- Genesis initialization via `InitGenesis()` which calls `f.GetGrant()` [5](#0-4) 
- Fee grant validation via `ValidateGenesis()` which calls `f.GetGrant()` [6](#0-5) 
- Fee grant usage via `UseGrantedFees()` which calls `grant.GetGrant()` [7](#0-6) 

**Severity:** Nodes cannot start if genesis contains such corrupted grants, and running nodes crash when queried. This affects network availability and can be triggered by malicious genesis data or storage corruption.

## Likelihood Explanation

**Triggering Conditions:**
- Any network participant can submit a query that triggers this if corrupted grant data exists in state
- Genesis files are validated during chain initialization, but if `ValidateGenesis` is not called or if validation is bypassed, corrupted grants can enter the system
- Storage corruption or manual database manipulation could introduce grants with nil allowances

**Frequency:** Once corrupted grant data exists, every query or operation involving that grant will trigger the crash. For genesis-based attacks, all nodes attempting to start with the malicious genesis will crash immediately.

**Likelihood:** Medium to High. While normal operation through `GrantAllowance()` validates allowances via `NewGrant()`, alternative paths like genesis import may not always enforce validation, and the protobuf schema allows nil optional fields. [8](#0-7) 

## Recommendation

Add a nil check for `a.Allowance` in the `GetGrant()` method before dereferencing:

```go
func (a Grant) GetGrant() (FeeAllowanceI, error) {
    if a.Allowance == nil {
        return nil, sdkerrors.Wrap(ErrNoAllowance, "allowance is nil")
    }
    allowance, ok := a.Allowance.GetCachedValue().(FeeAllowanceI)
    if !ok {
        return nil, sdkerrors.Wrap(ErrNoAllowance, "failed to get allowance")
    }
    return allowance, nil
}
```

Additionally, ensure `ValidateGenesis` is always called before `InitGenesis` in the application initialization flow.

## Proof of Concept

**File:** `x/feegrant/keeper/grpc_query_test.go`

**Test Function:** Add the following test case to demonstrate the vulnerability:

```go
func (suite *KeeperTestSuite) TestNilAllowancePanic() {
    // Setup: Manually create a Grant with nil Allowance to simulate corrupted storage
    granter := suite.addrs[0]
    grantee := suite.addrs[1]
    
    // Create a Grant struct with nil Allowance (bypassing normal validation)
    corruptedGrant := feegrant.Grant{
        Granter:   granter.String(),
        Grantee:   grantee.String(),
        Allowance: nil, // This is the corrupted state
    }
    
    // Marshal and store directly to bypass NewGrant validation
    store := suite.sdkCtx.KVStore(suite.keeper.storeKey)
    key := feegrant.FeeAllowanceKey(granter, grantee)
    bz, err := suite.app.AppCodec().Marshal(&corruptedGrant)
    suite.Require().NoError(err)
    store.Set(key, bz)
    
    // Trigger: Query the corrupted grant via gRPC handler
    req := &feegrant.QueryAllowanceRequest{
        Granter: granter.String(),
        Grantee: grantee.String(),
    }
    
    // Observation: This will panic with nil pointer dereference
    // The test should catch the panic to demonstrate the vulnerability
    suite.Require().Panics(func() {
        _, _ = suite.keeper.Allowance(suite.ctx, req)
    }, "Expected panic due to nil Allowance pointer dereference")
}
```

**Expected Behavior:** The test will panic when `GetGrant()` attempts to call `GetCachedValue()` on a nil `Allowance` pointer, demonstrating the vulnerability. With the fix, the method would return an error instead of panicking.

### Citations

**File:** x/feegrant/grant.go (L17-32)
```go
func NewGrant(granter, grantee sdk.AccAddress, feeAllowance FeeAllowanceI) (Grant, error) {
	msg, ok := feeAllowance.(proto.Message)
	if !ok {
		return Grant{}, sdkerrors.Wrapf(sdkerrors.ErrPackAny, "cannot proto marshal %T", feeAllowance)
	}

	any, err := types.NewAnyWithValue(msg)
	if err != nil {
		return Grant{}, err
	}

	return Grant{
		Granter:   granter.String(),
		Grantee:   grantee.String(),
		Allowance: any,
	}, nil
```

**File:** x/feegrant/grant.go (L57-64)
```go
func (a Grant) GetGrant() (FeeAllowanceI, error) {
	allowance, ok := a.Allowance.GetCachedValue().(FeeAllowanceI)
	if !ok {
		return nil, sdkerrors.Wrap(ErrNoAllowance, "failed to get allowance")
	}

	return allowance, nil
}
```

**File:** x/feegrant/feegrant.pb.go (L221-229)
```go
// Grant is stored in the KVStore to record a grant with full context
type Grant struct {
	// granter is the address of the user granting an allowance of their funds.
	Granter string `protobuf:"bytes,1,opt,name=granter,proto3" json:"granter,omitempty"`
	// grantee is the address of the user being granted an allowance of another user's funds.
	Grantee string `protobuf:"bytes,2,opt,name=grantee,proto3" json:"grantee,omitempty"`
	// allowance can be any of basic and filtered fee allowance.
	Allowance *types1.Any `protobuf:"bytes,3,opt,name=allowance,proto3" json:"allowance,omitempty"`
}
```

**File:** codec/types/interface_registry.go (L250-253)
```go
	// here we gracefully handle the case in which `any` itself is `nil`, which may occur in message decoding
	if any == nil {
		return nil
	}
```

**File:** x/feegrant/keeper/grpc_query.go (L37-40)
```go
	feeAllowance, err := q.GetAllowance(ctx, granterAddr, granteeAddr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
```

**File:** x/feegrant/keeper/keeper.go (L153-156)
```go
	grant, err := f.GetGrant()
	if err != nil {
		return err
	}
```

**File:** x/feegrant/keeper/keeper.go (L204-207)
```go
		grant, err := f.GetGrant()
		if err != nil {
			return err
		}
```

**File:** x/feegrant/genesis.go (L18-22)
```go
	for _, f := range data.Allowances {
		grant, err := f.GetGrant()
		if err != nil {
			return err
		}
```
