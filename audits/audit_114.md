# Audit Report

## Title
Sequence Number Check Bypass Enables Replay Attacks with SIGN_MODE_DIRECT When DisableSeqnoCheck is True

## Summary
When the `DisableSeqnoCheck` parameter is set to `true`, the sequence number validation in `SigVerificationDecorator.AnteHandle` is bypassed, enabling replay attacks for transactions using `SIGN_MODE_DIRECT`. This allows users to submit multiple transactions with the same sequence number, completely defeating the replay protection mechanism and enabling duplicate transaction execution. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
The vulnerability exists in `x/auth/ante/sigverify.go` in the `SigVerificationDecorator.AnteHandle` function, specifically at lines 270-278 where sequence number validation occurs. [2](#0-1) 

**Intended Logic:**
The sequence number mechanism is designed to prevent replay attacks by ensuring each transaction from an account uses a unique, incrementing sequence number. The code should verify that the sequence number in the transaction signature matches the current account sequence, rejecting any mismatches.

**Actual Logic:**
When `params.GetDisableSeqnoCheck()` returns `true`, the sequence number validation is completely bypassed. Combined with how `SIGN_MODE_DIRECT` signature verification works, this creates a critical vulnerability.

For `SIGN_MODE_DIRECT`, the signature is computed over `DirectSignBytes(bodyBz, authInfoBz, chainID, accountNumber)` - notably excluding the `SignerData.Sequence` field from the verification process. [3](#0-2) 

During signature verification, the `SignerData` is constructed with the current account sequence, but this value is NOT used in the signature verification for SIGN_MODE_DIRECT: [4](#0-3) 

**Exploit Scenario:**

1. Attacker has an account with sequence 0
2. Attacker creates transaction TX1 with sequence 0 in the SignerInfo, signs it, and submits it
3. TX1 executes successfully, and the `IncrementSequenceDecorator` increments the account sequence to 1
4. Attacker creates a NEW transaction TX2, again with sequence 0 in the SignerInfo
5. Because `DisableSeqnoCheck` is true, the check at line 270-272 is bypassed
6. During signature verification (line 295), even though `SignerData.Sequence` is set to 1 (the current account sequence), the SIGN_MODE_DIRECT verification only uses chainID and accountNumber from SignerData - not the sequence
7. The signature is valid because it was signed over authInfoBz containing sequence 0
8. TX2 executes successfully with the same sequence number
9. This can be repeated indefinitely, allowing the same messages to be executed multiple times [5](#0-4) 

**Security Failure:**
This breaks the fundamental replay protection invariant of blockchain systems. The sequence number mechanism is the primary defense against transaction replay attacks, and bypassing it allows arbitrary transaction duplication.

## Impact Explanation

**Assets Affected:** All user funds and state transitions are at risk. 

**Severity of Damage:**
- **Direct loss of funds**: If a transaction transfers tokens, the attacker can execute it multiple times, draining their account or sending funds repeatedly to recipients
- **State manipulation**: Any state-changing transaction (staking, governance votes, contract interactions) can be replayed
- **Consensus invariant violation**: The fundamental assumption that each transaction executes exactly once is broken

**System Impact:**
This vulnerability fundamentally undermines the blockchain's security model. Users lose control over how many times their transactions execute, leading to unintended financial losses and state corruption. The existing test suite even demonstrates this behavior as "expected" when the parameter is enabled. [6](#0-5) 

## Likelihood Explanation

**Who can trigger it:** Any user can exploit this vulnerability when `DisableSeqnoCheck` is enabled.

**Required conditions:** 
- The `DisableSeqnoCheck` parameter must be set to `true` in the auth module params
- Transactions must use `SIGN_MODE_DIRECT` (which is the default signing mode) [7](#0-6) 

**Frequency:** 
Once the parameter is enabled, this can be exploited continuously by any user. Each user can replay their own transactions as many times as desired. While the parameter may be intended for specific testing or configuration scenarios, if enabled on a production network, the exploitation would be immediate and widespread.

## Recommendation

The `DisableSeqnoCheck` parameter should be removed entirely, or if it must exist for specific testing purposes, it should:

1. Only be allowed in non-production environments
2. Be accompanied by additional safeguards that prevent actual transaction replay

A proper fix would be to remove the conditional bypass and always enforce sequence number checking:

```go
// Check account sequence number.
if sig.Sequence != acc.GetSequence() {
    return ctx, sdkerrors.Wrapf(
        sdkerrors.ErrWrongSequence,
        "account sequence mismatch, expected %d, got %d", acc.GetSequence(), sig.Sequence,
    )
}
```

Alternatively, if the parameter must be retained, ensure it can only be enabled in test builds and add explicit warnings about its security implications.

## Proof of Concept

**File:** `x/auth/ante/ante_test.go`

**Test Function:** Add a new test function `TestDisableSeqNoReplayAttack` to demonstrate the vulnerability more explicitly:

**Setup:**
1. Initialize test suite with `DisableSeqnoCheck` set to `true`
2. Create a test account with initial balance
3. Create a recipient account

**Trigger:**
1. Create a bank send transaction from the test account to recipient with sequence 0, transferring 100 tokens
2. Submit and execute the transaction successfully
3. Verify the account sequence is now 1
4. Create a SECOND bank send transaction with sequence 0 again (not replaying the same tx, but creating a new one)
5. Submit and execute this second transaction

**Observation:**
The test will show that:
- Both transactions with sequence 0 execute successfully
- The recipient receives 200 tokens instead of 100
- The sender's balance is reduced twice
- This demonstrates a complete replay attack where the same sequence number is used multiple times

The existing test at line 1156-1212 already demonstrates this behavior, confirming that transactions with duplicate sequence numbers succeed when `DisableSeqnoCheck` is enabled. The test explicitly shows transaction execution with sequence 0, followed by another transaction with sequence 0, both succeeding. [8](#0-7)

### Citations

**File:** x/auth/ante/sigverify.go (L269-278)
```go
		// Check account sequence number.
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

**File:** x/auth/ante/sigverify.go (L287-291)
```go
		signerData := authsigning.SignerData{
			ChainID:       chainID,
			AccountNumber: accNum,
			Sequence:      acc.GetSequence(),
		}
```

**File:** x/auth/ante/sigverify.go (L352-369)
```go
func (isd IncrementSequenceDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
	}

	// increment sequence of all signers
	for _, addr := range sigTx.GetSigners() {
		acc := isd.ak.GetAccount(ctx, addr)
		if err := acc.SetSequence(acc.GetSequence() + 1); err != nil {
			panic(err)
		}

		isd.ak.SetAccount(ctx, acc)
	}

	return next(ctx, tx, simulate)
}
```

**File:** x/auth/tx/direct.go (L42-42)
```go
	return DirectSignBytes(bodyBz, authInfoBz, data.ChainID, data.AccountNumber)
```

**File:** x/auth/ante/ante_test.go (L1156-1212)
```go
func (suite *AnteTestSuite) TestDisableSeqNo() {
	suite.SetupTest(false) // setup
	authParams := types.Params{
		MaxMemoCharacters:      types.DefaultMaxMemoCharacters,
		TxSigLimit:             types.DefaultTxSigLimit,
		TxSizeCostPerByte:      types.DefaultTxSizeCostPerByte,
		SigVerifyCostED25519:   types.DefaultSigVerifyCostED25519,
		SigVerifyCostSecp256k1: types.DefaultSigVerifyCostSecp256k1,
		DisableSeqnoCheck:      true,
	}
	suite.app.AccountKeeper.SetParams(suite.ctx, authParams)

	// Same data for every test cases
	accounts := suite.CreateTestAccounts(1)
	feeAmount := testdata.NewTestFeeAmount()
	gasLimit := testdata.NewTestGasLimit()

	// Variable data per test case
	var (
		accNums []uint64
		msgs    []sdk.Msg
		privs   []cryptotypes.PrivKey
		accSeqs []uint64
	)

	testCases := []TestCase{
		{
			"good tx from one signer",
			func() {
				msg := testdata.NewTestMsg(accounts[0].acc.GetAddress())
				msgs = []sdk.Msg{msg}

				privs, accNums, accSeqs = []cryptotypes.PrivKey{accounts[0].priv}, []uint64{0}, []uint64{0}
			},
			false,
			true,
			nil,
		},
		{
			"test sending it again succeeds (disable seqno check is true)",
			func() {
				privs, accNums, accSeqs = []cryptotypes.PrivKey{accounts[0].priv}, []uint64{0}, []uint64{0}
			},
			false,
			true,
			nil,
		},
	}
	for _, tc := range testCases {
		suite.Run(fmt.Sprintf("Case %s", tc.desc), func() {
			suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
			tc.malleate()

			suite.RunTestCase(privs, msgs, feeAmount, gasLimit, accNums, accSeqs, suite.ctx.ChainID(), tc)
		})
	}
}
```

**File:** x/auth/types/params.go (L27-27)
```go
	KeyDisableSeqnoCheck      = []byte("KeyDisableSeqnoCheck")
```
