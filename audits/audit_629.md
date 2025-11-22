## Audit Report

## Title
Nil Pointer Dereference in Fee Grant Message Validation Causes Node Resource Exhaustion

## Summary
The keeper does not validate that the `feeAllowance` parameter is non-nil before using it in `GrantAllowance`. [1](#0-0)  This lack of validation forces the validation to occur in the message layer, where `MsgGrantAllowance.GetFeeAllowanceI()` fails to check if `msg.Allowance` is nil before dereferencing it, causing a nil pointer panic. [2](#0-1) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/feegrant/msgs.go`, function `GetFeeAllowanceI()`, line 85
- Related: `x/feegrant/keeper/keeper.go`, function `GrantAllowance`, lines 51-54

**Intended Logic:** 
The keeper's `GrantAllowance` function should validate that the `feeAllowance` parameter is not nil before processing it. Since the keeper doesn't perform this validation, the validation is delegated to the message layer's `ValidateBasic()` method, which calls `GetFeeAllowanceI()` to retrieve and validate the allowance. [3](#0-2) 

**Actual Logic:** 
In `GetFeeAllowanceI()`, the code directly calls `msg.Allowance.GetCachedValue()` without checking if `msg.Allowance` is nil. [4](#0-3)  When `msg.Allowance` is nil (which is valid in proto3 as the field is optional [5](#0-4) ), this causes a nil pointer dereference panic.

**Exploit Scenario:**
1. Attacker crafts a `MsgGrantAllowance` transaction with the `Allowance` field set to nil (omitted in protobuf encoding)
2. Transaction is submitted to a node via mempool
3. During `CheckTx` processing, the transaction is decoded and `validateBasicTxMsgs` is called [6](#0-5) 
4. `msg.ValidateBasic()` is invoked, which calls `msg.GetFeeAllowanceI()`
5. Nil pointer dereference occurs at `msg.Allowance.GetCachedValue()`
6. Panic is caught by baseapp's recovery mechanism [7](#0-6)  and converted to an error
7. Transaction is rejected, but attacker can repeatedly spam such transactions

**Security Failure:** 
The panic/recovery path consumes significantly more CPU resources than normal validation error handling. An attacker can spam CheckTx with malformed transactions to cause resource exhaustion without paying any gas (panic occurs before ante handler executes).

## Impact Explanation
This vulnerability affects network node availability and resource consumption. Attackers can:
- Submit unlimited malformed transactions to CheckTx without gas cost
- Force nodes to execute panic/recovery code paths repeatedly
- Degrade node performance and responsiveness
- Potentially prevent nodes from processing legitimate transactions efficiently

While individual panics are recovered and don't crash nodes, sustained spam of such transactions can significantly increase CPU usage and memory allocation overhead from panic/recovery mechanics, affecting the node's ability to service legitimate requests.

## Likelihood Explanation
**Trigger Conditions:**
- Any unprivileged user can trigger this by crafting a transaction with nil `Allowance` field
- No special permissions or timing requirements needed
- Can be triggered repeatedly without cost to attacker

**Frequency:**
- Attacker can submit transactions at high rate to CheckTx
- Each malformed transaction triggers the panic
- Can be sustained indefinitely as attacker pays no gas for rejected transactions

## Recommendation
Add nil validation in `GetFeeAllowanceI()` before dereferencing:

```go
func (msg MsgGrantAllowance) GetFeeAllowanceI() (FeeAllowanceI, error) {
    if msg.Allowance == nil {
        return nil, sdkerrors.Wrap(ErrNoAllowance, "allowance cannot be nil")
    }
    allowance, ok := msg.Allowance.GetCachedValue().(FeeAllowanceI)
    if !ok {
        return nil, sdkerrors.Wrap(ErrNoAllowance, "failed to get allowance")
    }
    return allowance, nil
}
```

Additionally, add defensive validation in the keeper as requested by the security question:
```go
func (k Keeper) GrantAllowance(ctx sdk.Context, granter, grantee sdk.AccAddress, feeAllowance feegrant.FeeAllowanceI) error {
    if feeAllowance == nil {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "fee allowance cannot be nil")
    }
    // ... rest of function
}
```

## Proof of Concept

**File:** `x/feegrant/msgs_test.go`

**Test Function:** Add this test to demonstrate the panic:

```go
func TestMsgGrantAllowanceNilAllowance(t *testing.T) {
    addr1, _ := sdk.AccAddressFromBech32("cosmos1aeuqja06474dfrj7uqsvukm6rael982kk89mqr")
    addr2, _ := sdk.AccAddressFromBech32("cosmos1nph3cfzk6trsmfxkeu943nvach5qw4vwstnvkl")
    
    // Craft MsgGrantAllowance with nil Allowance field
    msg := &feegrant.MsgGrantAllowance{
        Granter:   addr1.String(),
        Grantee:   addr2.String(),
        Allowance: nil,  // This is the malformed field
    }
    
    // This should panic with nil pointer dereference
    require.Panics(t, func() {
        msg.ValidateBasic()
    })
}
```

**Setup:** Initialize test addresses as shown above.

**Trigger:** Call `ValidateBasic()` on a `MsgGrantAllowance` with nil `Allowance` field.

**Observation:** The test demonstrates that `ValidateBasic()` panics when `msg.Allowance` is nil, confirming the nil pointer dereference vulnerability. In production, this panic is recovered by baseapp but causes resource overhead. An attacker can exploit this by repeatedly submitting such malformed transactions to degrade node performance.

### Citations

**File:** x/feegrant/keeper/keeper.go (L51-54)
```go
	grant, err := feegrant.NewGrant(granter, grantee, feeAllowance)
	if err != nil {
		return err
	}
```

**File:** x/feegrant/msgs.go (L40-57)
```go
func (msg MsgGrantAllowance) ValidateBasic() error {
	if msg.Granter == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing granter address")
	}
	if msg.Grantee == "" {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "missing grantee address")
	}
	if msg.Grantee == msg.Granter {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidAddress, "cannot self-grant fee authorization")
	}

	allowance, err := msg.GetFeeAllowanceI()
	if err != nil {
		return err
	}

	return allowance.ValidateBasic()
}
```

**File:** x/feegrant/msgs.go (L84-91)
```go
func (msg MsgGrantAllowance) GetFeeAllowanceI() (FeeAllowanceI, error) {
	allowance, ok := msg.Allowance.GetCachedValue().(FeeAllowanceI)
	if !ok {
		return nil, sdkerrors.Wrap(ErrNoAllowance, "failed to get allowance")
	}

	return allowance, nil
}
```

**File:** proto/cosmos/feegrant/v1beta1/tx.proto (L33-33)
```text
  google.protobuf.Any allowance = 3 [(cosmos_proto.accepts_interface) = "FeeAllowanceI"];
```

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
```

**File:** baseapp/baseapp.go (L923-923)
```go
	if err := validateBasicTxMsgs(msgs); err != nil {
```
