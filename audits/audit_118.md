# Audit Report

## Title
Silent Uint64 Sequence Number Overflow Enables Replay Attack Vector

## Summary
The `IncrementSequenceDecorator` in `sigverify.go` lines 360-363 fails to correctly handle sequence number overflow. When an account's sequence reaches `math.MaxUint64`, the arithmetic operation `acc.GetSequence() + 1` silently wraps to 0 before being passed to `SetSequence()`, bypassing the intended panic-based error handling and resetting the account's sequence to zero, which destroys replay protection. [1](#0-0) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** `x/auth/ante/sigverify.go`, function `IncrementSequenceDecorator.AnteHandle`, lines 360-363

**Intended Logic:** The code intends to increment an account's sequence number and panic if `SetSequence()` returns an error, presumably to catch overflow or other sequence-related errors. Sequence numbers are critical for replay attack prevention - each transaction must have a unique, incrementing sequence number.

**Actual Logic:** The vulnerability occurs because:
1. At line 361, the expression `acc.GetSequence() + 1` is evaluated first
2. In Go, uint64 arithmetic wraps silently on overflow (no panic, no error)
3. When `acc.GetSequence()` returns `math.MaxUint64` (18446744073709551615), adding 1 wraps to 0
4. The wrapped value (0) is then passed to `SetSequence(0)`
5. `SetSequence()` always returns `nil` (never an error), as shown in the implementation [2](#0-1) 
6. Therefore, the panic at line 362 never executes, even on overflow

**Exploit Scenario:**
1. An account exists with sequence number at or near `math.MaxUint64` (this could occur through genesis file initialization during chain migration, state corruption, or initialization bug)
2. Account holder creates a valid transaction with sequence = `math.MaxUint64`
3. `SigVerificationDecorator` validates the transaction (sequence matches current account sequence) [3](#0-2) 
4. Transaction proceeds through ante handlers successfully
5. `IncrementSequenceDecorator` executes: `acc.SetSequence(MaxUint64 + 1)` = `acc.SetSequence(0)`
6. Account sequence is now 0, identical to the account's initial state
7. All previously signed transactions with sequences 0, 1, 2, ..., MaxUint64 can now be replayed, as the signature verification will pass (transactions were validly signed in the past)

**Security Failure:** The replay protection invariant is violated. Sequence numbers must be strictly increasing to prevent transaction replay. When the sequence wraps to 0, the system loses all historical replay protection for that account, enabling attackers to resubmit any previously executed transaction.

## Impact Explanation

**Assets Affected:** All funds controlled by accounts that experience sequence overflow. Any transaction previously signed by the account can be replayed, potentially including:
- Token transfers that could be executed multiple times
- Contract interactions that could drain funds
- Staking/delegation operations that could be replayed maliciously

**Severity:** The damage is catastrophic for affected accounts:
- Complete loss of replay protection
- Unlimited replay of historical transactions
- Direct theft of funds through re-execution of transfer transactions
- Permanent security breach until account is abandoned

**System Impact:** This vulnerability undermines a fundamental security property of the blockchain - nonce-based replay protection. While the authentication module documentation explicitly states that sequences "prevent replay attacks," [4](#0-3)  this guarantee is violated when overflow occurs.

## Likelihood Explanation

**Trigger Conditions:** The vulnerability requires an account to have a sequence number at `math.MaxUint64`. 

**Likelihood Assessment - LOW but NON-ZERO:**
- Normal operation: Practically impossible (would require 18+ quintillion transactions)
- Genesis initialization: Possible during chain migration if account state from another chain contains high sequence numbers
- State corruption: Possible due to bugs in state management or migration tooling
- Malicious genesis: If genesis file is crafted with high sequence values

**Exploitability:** Once the condition exists, exploitation is trivial - any user can submit a transaction when their sequence is at max, causing the wrap. The account holder themselves might trigger it unknowingly.

**Frequency:** While rare in normal circumstances, chain migrations and upgrades represent realistic scenarios where this could manifest. Several Cosmos chains have undergone migrations where account state was imported from legacy chains.

## Recommendation

Add explicit overflow detection before the increment operation:

```go
acc := isd.ak.GetAccount(ctx, addr)
currentSeq := acc.GetSequence()

// Check for overflow before incrementing
if currentSeq == math.MaxUint64 {
    return ctx, sdkerrors.Wrapf(
        sdkerrors.ErrInvalidSequence,
        "sequence overflow: account %s has reached maximum sequence number",
        addr.String(),
    )
}

if err := acc.SetSequence(currentSeq + 1); err != nil {
    panic(err)
}
isd.ak.SetAccount(ctx, acc)
```

Additionally, consider adding validation in `SetSequence()` itself to return an error on edge cases, though the primary fix should occur before the arithmetic operation to prevent silent overflow.

## Proof of Concept

**File:** `x/auth/ante/sigverify_test.go`

**Test Function:** Add the following test function to demonstrate the vulnerability:

```go
func (suite *AnteTestSuite) TestSequenceOverflowVulnerability() {
    suite.SetupTest(true)
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    
    // Create account with sequence at MaxUint64
    priv, _, addr := testdata.KeyTestPubAddr()
    acc := suite.app.AccountKeeper.NewAccountWithAddress(suite.ctx, addr)
    suite.Require().NoError(acc.SetAccountNumber(uint64(50)))
    
    // Set sequence to MaxUint64 to simulate near-overflow condition
    suite.Require().NoError(acc.SetSequence(math.MaxUint64))
    suite.app.AccountKeeper.SetAccount(suite.ctx, acc)
    
    // Verify starting sequence
    storedAcc := suite.app.AccountKeeper.GetAccount(suite.ctx, addr)
    suite.Require().Equal(uint64(math.MaxUint64), storedAcc.GetSequence(), 
        "Account should start with MaxUint64 sequence")
    
    // Create valid transaction with sequence = MaxUint64
    msgs := []sdk.Msg{testdata.NewTestMsg(addr)}
    suite.Require().NoError(suite.txBuilder.SetMsgs(msgs...))
    suite.txBuilder.SetFeeAmount(testdata.NewTestFeeAmount())
    suite.txBuilder.SetGasLimit(testdata.NewTestGasLimit())
    
    privs := []cryptotypes.PrivKey{priv}
    accNums := []uint64{50}
    accSeqs := []uint64{math.MaxUint64}
    
    tx, err := suite.CreateTestTx(privs, accNums, accSeqs, suite.ctx.ChainID())
    suite.Require().NoError(err)
    
    // Run IncrementSequenceDecorator
    isd := sdk.DefaultWrappedAnteDecorator(ante.NewIncrementSequenceDecorator(suite.app.AccountKeeper))
    antehandler, _ := sdk.ChainAnteDecorators(isd)
    
    // Execute - this should panic or error, but instead succeeds
    _, err = antehandler(suite.ctx, tx, false)
    suite.Require().NoError(err, "Expected error or panic on overflow, but got none")
    
    // VULNERABILITY: Sequence has wrapped to 0 instead of erroring
    storedAcc = suite.app.AccountKeeper.GetAccount(suite.ctx, addr)
    actualSeq := storedAcc.GetSequence()
    
    suite.Require().Equal(uint64(0), actualSeq, 
        "VULNERABILITY CONFIRMED: Sequence wrapped to 0 instead of panicking")
    
    // This demonstrates the replay attack vector:
    // All previous transactions with sequences 0 through MaxUint64 can now be replayed
    suite.T().Logf("CRITICAL: Account sequence wrapped from MaxUint64 to 0, enabling replay attacks")
}
```

**Setup:** The test creates an account and sets its sequence to `math.MaxUint64` (simulating a migrated account or state corruption).

**Trigger:** A valid transaction is created and processed through `IncrementSequenceDecorator`.

**Observation:** The test confirms that:
1. No panic occurs (the panic handler is bypassed)
2. No error is returned
3. The sequence silently wraps to 0
4. This confirms the vulnerability: replay protection is destroyed

The test will pass on the current vulnerable code, demonstrating that the overflow is not caught. A proper fix would cause this test to fail with an appropriate error before the sequence wraps.

### Citations

**File:** x/auth/ante/sigverify.go (L270-278)
```go
		if sig.Sequence != acc.GetSequence() {
			params := svd.ak.GetParams(ctx)
			if !params.GetDisableSeqnoCheck() {
				return ctx, sdkerrors.Wrapf(
					sdkerrors.ErrWrongSequence,
					"account sequence mismatch, expected %d, got %d", acc.GetSequence(), sig.Sequence,
				)
			}
		}
```

**File:** x/auth/ante/sigverify.go (L358-359)
```go
	// increment sequence of all signers
	for _, addr := range sigTx.GetSigners() {
```

**File:** x/auth/ante/sigverify.go (L360-363)
```go
		acc := isd.ak.GetAccount(ctx, addr)
		if err := acc.SetSequence(acc.GetSequence() + 1); err != nil {
			panic(err)
		}
```

**File:** x/auth/types/account.go (L116-119)
```go
func (acc *BaseAccount) SetSequence(seq uint64) error {
	acc.Sequence = seq
	return nil
}
```
