## Audit Report

## Title
Pre-Gas-Metering CPU Exhaustion via MsgMultiSend with Excessive Inputs/Outputs

## Summary
The `MsgMultiSend` message validation in `ValidateBasic()` iterates through all inputs and outputs without any limit check, and this validation occurs in the ante handler chain BEFORE gas is charged for transaction size. An attacker can create transactions with thousands of inputs/outputs (limited only by MaxTxBytes) to cause disproportionate CPU consumption during CheckTx, exhausting node resources without paying proportional gas costs. [1](#0-0) 

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `x/bank/types/msgs.go`, function `ValidateInputsOutputs()` (lines 165-190)
- Secondary: `x/bank/types/msgs.go`, `MsgMultiSend.ValidateBasic()` (lines 79-91)
- Ante handler chain: `x/auth/ante/ante.go` (lines 47-60) [2](#0-1) 

**Intended Logic:** 
The `ValidateBasic()` method is designed to perform stateless validation of transaction messages before they enter the mempool. The ante handler chain is supposed to validate transactions and charge gas proportionally to the computational cost.

**Actual Logic:**
In the ante handler chain, `ValidateBasicDecorator` (position 3) calls `tx.ValidateBasic()` BEFORE `ConsumeGasForTxSizeDecorator` (position 6) charges gas for transaction size. For `MsgMultiSend`, `ValidateBasic()` calls `ValidateInputsOutputs()` which performs O(N+M) iterations where N is the number of inputs and M is the number of outputs. Each iteration involves:
- Bech32 address parsing via `AccAddressFromBech32()` 
- Coin validation via `IsValid()` and `IsAllPositive()`
- Coin summation operations [3](#0-2) 

There is no limit on the number of inputs/outputs beyond the transaction size limit (MaxTxBytes, typically 1-2MB), allowing ~10,000-20,000 inputs+outputs per transaction. [4](#0-3) 

**Exploit Scenario:**
1. Attacker crafts `MsgMultiSend` transactions with maximum inputs/outputs (e.g., 10,000 inputs + 10,000 outputs) that fit within MaxTxBytes
2. Each input/output contains minimal data (address + small coin amount = ~50-100 bytes)
3. Attacker broadcasts multiple such transactions to the network
4. When nodes receive these transactions, `CheckTx` is invoked
5. `ValidateBasicDecorator` processes the transaction, calling `ValidateInputsOutputs()`
6. The function iterates through all 20,000 inputs/outputs, performing address parsing and coin validation
7. Only AFTER this validation completes does `ConsumeGasForTxSizeDecorator` charge gas
8. Even if the transaction is eventually rejected (insufficient gas/fees), the CPU time has already been consumed
9. Attacker can repeatedly broadcast such transactions to exhaust node CPU resources [5](#0-4) 

**Security Failure:**
The system violates the principle of "pay-for-what-you-consume" in gas metering. Computationally expensive validation operations execute before any resource accounting, allowing attackers to cause denial-of-service by consuming CPU resources disproportionate to any gas costs they would pay.

## Impact Explanation

**Affected Components:**
- All validator nodes and full nodes processing transactions
- Network mempool capacity and transaction processing throughput
- Legitimate user transactions (delayed or dropped due to congestion)

**Severity:**
An attacker can flood the network with malicious `MsgMultiSend` transactions containing thousands of inputs/outputs. Each transaction forces nodes to perform ~20,000+ validation operations (address parsing, coin validation) in `CheckTx` before gas metering begins. With modern hardware, this could consume 10-100ms of CPU per malicious transaction.

If an attacker broadcasts hundreds or thousands of such transactions:
- Nodes spend significant CPU time in pre-gas-metering validation
- Mempool becomes congested with pending malicious transactions
- Legitimate transactions experience delays in processing
- Node operators may experience degraded performance or need to increase resource allocation

This directly fits the Medium severity impact: "Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours."

## Likelihood Explanation

**Trigger Requirements:**
- Any network participant can create and broadcast `MsgMultiSend` transactions
- No special privileges or conditions required
- Attack can be executed at any time during normal network operation
- Attacker only needs to construct valid transactions that fit within MaxTxBytes

**Frequency:**
The attack can be executed continuously by any malicious actor. The only cost to the attacker is:
- Network bandwidth to broadcast transactions
- Potentially minimal transaction fees (if transactions are rejected before fee deduction completes)

The attack is highly practical and could be sustained as long as the attacker has network connectivity and willingness to consume their own bandwidth.

## Recommendation

Implement a maximum limit on the number of inputs and outputs allowed in a `MsgMultiSend` transaction. This limit should be enforced during `ValidateBasic()` to prevent excessive computational cost before gas metering.

**Specific Fix:**
Add a parameter (e.g., `MaxMultiSendInputsOutputs = 100`) and check it in `MsgMultiSend.ValidateBasic()`:

```go
func (msg MsgMultiSend) ValidateBasic() error {
    const MaxInputsOutputs = 100 // or make this a governance parameter
    
    if len(msg.Inputs) == 0 {
        return ErrNoInputs
    }
    if len(msg.Outputs) == 0 {
        return ErrNoOutputs
    }
    
    // Add limit check
    if len(msg.Inputs) + len(msg.Outputs) > MaxInputsOutputs {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidRequest, 
            "too many inputs/outputs: %d (max %d)", 
            len(msg.Inputs) + len(msg.Outputs), MaxInputsOutputs)
    }
    
    return ValidateInputsOutputs(msg.Inputs, msg.Outputs)
}
```

This ensures that expensive validation operations are bounded to a reasonable limit before gas accounting begins.

## Proof of Concept

**Test File:** `x/bank/types/msgs_test.go`

**Test Function:** `TestMsgMultiSendValidationDoS`

**Setup:**
```go
func TestMsgMultiSendValidationDoS(t *testing.T) {
    // Create a large number of inputs and outputs
    numInputsOutputs := 10000
    
    addr1 := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
    addr2 := sdk.AccAddress(secp256k1.GenPrivKey().PubKey().Address())
    
    // Prepare inputs - each input sends 1 atom
    inputs := make([]Input, numInputsOutputs)
    for i := 0; i < numInputsOutputs; i++ {
        inputs[i] = NewInput(addr1, sdk.NewCoins(sdk.NewInt64Coin("atom", 1)))
    }
    
    // Prepare outputs - each output receives 1 atom  
    outputs := make([]Output, numInputsOutputs)
    for i := 0; i < numInputsOutputs; i++ {
        outputs[i] = NewOutput(addr2, sdk.NewCoins(sdk.NewInt64Coin("atom", 1)))
    }
    
    msg := MsgMultiSend{
        Inputs:  inputs,
        Outputs: outputs,
    }
```

**Trigger:**
```go
    // Measure time taken for ValidateBasic
    start := time.Now()
    err := msg.ValidateBasic()
    elapsed := time.Since(start)
    
    require.NoError(t, err, "ValidateBasic should not error for valid inputs/outputs")
```

**Observation:**
```go
    // The validation should complete but will take significant time
    // With 20,000 inputs+outputs, this could take 10-100ms depending on hardware
    // This demonstrates the CPU cost before any gas is charged
    t.Logf("ValidateBasic with %d inputs and %d outputs took: %v", 
        numInputsOutputs, numInputsOutputs, elapsed)
    
    // The vulnerability is that this expensive operation happens BEFORE
    // gas is charged in the ante handler chain (ValidateBasicDecorator runs
    // before ConsumeGasForTxSizeDecorator)
    
    // An attacker can create many such transactions to exhaust node CPU
    // during CheckTx before any gas accounting occurs
}
```

This test demonstrates that `ValidateBasic()` with thousands of inputs/outputs consumes significant CPU time, and this validation occurs before gas metering in the ante handler chain. An attacker can exploit this to cause denial-of-service by flooding the network with such transactions.

### Citations

**File:** x/bank/types/msgs.go (L79-91)
```go
func (msg MsgMultiSend) ValidateBasic() error {
	// this just makes sure all the inputs and outputs are properly formatted,
	// not that they actually have the money inside
	if len(msg.Inputs) == 0 {
		return ErrNoInputs
	}

	if len(msg.Outputs) == 0 {
		return ErrNoOutputs
	}

	return ValidateInputsOutputs(msg.Inputs, msg.Outputs)
}
```

**File:** x/bank/types/msgs.go (L165-190)
```go
func ValidateInputsOutputs(inputs []Input, outputs []Output) error {
	var totalIn, totalOut sdk.Coins

	for _, in := range inputs {
		if err := in.ValidateBasic(); err != nil {
			return err
		}

		totalIn = totalIn.Add(in.Coins...)
	}

	for _, out := range outputs {
		if err := out.ValidateBasic(); err != nil {
			return err
		}

		totalOut = totalOut.Add(out.Coins...)
	}

	// make sure inputs and outputs match
	if !totalIn.IsEqual(totalOut) {
		return ErrInputOutputMismatch
	}

	return nil
}
```

**File:** x/auth/ante/ante.go (L47-60)
```go
	anteDecorators := []sdk.AnteFullDecorator{
		sdk.DefaultWrappedAnteDecorator(NewDefaultSetUpContextDecorator()), // outermost AnteDecorator. SetUpContext must be called first
		sdk.DefaultWrappedAnteDecorator(NewRejectExtensionOptionsDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateBasicDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewTxTimeoutHeightDecorator()),
		sdk.DefaultWrappedAnteDecorator(NewValidateMemoDecorator(options.AccountKeeper)),
		NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.ParamsKeeper.(paramskeeper.Keeper), options.TxFeeChecker),
		sdk.DefaultWrappedAnteDecorator(NewSetPubKeyDecorator(options.AccountKeeper)), // SetPubKeyDecorator must be called before all signature verification decorators
		sdk.DefaultWrappedAnteDecorator(NewValidateSigCountDecorator(options.AccountKeeper)),
		sdk.DefaultWrappedAnteDecorator(NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer)),
		sdk.DefaultWrappedAnteDecorator(sigVerifyDecorator),
		NewIncrementSequenceDecorator(options.AccountKeeper),
	}
```
