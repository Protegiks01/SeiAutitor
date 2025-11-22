# Audit Report

## Title
DisableSeqnoCheck Parameter Enables Transaction Replay Attacks Leading to Direct Loss of Funds

## Summary
The `DisableSeqnoCheck` parameter in the auth module can be enabled via governance proposals without any validation, which completely disables sequence number verification for transactions. When combined with the SIGN_MODE_DIRECT signing mode (the default), this allows identical transaction bytes to be replayed multiple times, as the signature does not include the sequence number. This results in direct loss of funds as any transaction (e.g., fund transfers) can be executed repeatedly.

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:** 
- Parameter registration: [1](#0-0) 
- Sequence check bypass: [2](#0-1) 
- Signature construction (missing sequence): [3](#0-2) 
- Governance parameter change handler: [4](#0-3) 

**Intended Logic:** 
Account sequence numbers are meant to provide replay protection by ensuring each transaction from an account can only be executed once. The sequence check verifies that the transaction's sequence matches the account's current sequence. After execution, the account sequence is incremented. [5](#0-4) 

**Actual Logic:** 
The `DisableSeqnoCheck` parameter registration has no validation function (returns `nil`), allowing any value to be set. [1](#0-0)  When this parameter is set to `true`, the sequence verification is completely bypassed. [2](#0-1) 

Critically, for SIGN_MODE_DIRECT (the default signing mode), the signature only covers BodyBytes, AuthInfoBytes, ChainID, and AccountNumber - but NOT the sequence number. [3](#0-2)  This means that even after the account sequence is incremented, the original signature remains valid because it never included the sequence in the first place.

**Exploit Scenario:**
1. An attacker observes a legitimate transaction in the mempool (e.g., a MsgSend transferring 1000 tokens)
2. A governance proposal is submitted and passes to set `DisableSeqnoCheck = true` via ParameterChangeProposal [4](#0-3) 
3. The attacker captures the exact transaction bytes (including the original signature)
4. The attacker resubmits these identical transaction bytes multiple times
5. Each submission:
   - Bypasses sequence check due to `DisableSeqnoCheck = true` [2](#0-1) 
   - Passes signature verification because the signature doesn't include sequence [3](#0-2) 
   - Executes the transaction again (transfers 1000 tokens again)
   - Increments the account sequence [5](#0-4) 
6. The victim loses funds equal to the original amount multiplied by the number of replays

**Security Failure:** 
The replay protection mechanism is completely broken. The fundamental security invariant that each signed transaction can only be executed once is violated, leading to unauthorized repeated execution of transactions.

## Impact Explanation

**Assets Affected:** All user funds on the blockchain, particularly any tokens being transferred via MsgSend or similar operations.

**Severity of Damage:** 
- Attackers can drain user accounts by replaying any observed transfer transaction
- The damage scales with transaction volume - higher value transactions result in greater losses
- All users who transact while `DisableSeqnoCheck = true` are vulnerable
- Funds are directly stolen with no recovery mechanism

**System Impact:** This completely undermines the security model of the blockchain. Users cannot safely transact, as any transaction they submit can be replayed indefinitely by observers (including validators, full nodes, or anyone monitoring the mempool). This represents a catastrophic failure of the transaction security model.

## Likelihood Explanation

**Who Can Trigger:** Any network participant who can observe transactions (mempool monitoring, block explorers, or running a full node) can capture and replay transactions once `DisableSeqnoCheck` is enabled.

**Required Conditions:** 
- A governance proposal to set `DisableSeqnoCheck = true` must pass
- The victim must submit a transaction while this parameter is enabled
- The attacker must be able to submit transactions to the network

**Frequency:** Once enabled via governance, this vulnerability can be exploited continuously against every transaction submitted to the network. Given that governance proposals can be submitted by any token holder meeting the minimum deposit requirement, and that the parameter has no validation, this is a realistic attack scenario.

The test at [6](#0-5)  demonstrates that this behavior is intentionally testable and working as coded, confirming the vulnerability is exploitable.

## Recommendation

1. **Immediate:** Remove the `DisableSeqnoCheck` parameter entirely, or make it non-governable and only settable at chain genesis for specific testing purposes
2. **Short-term:** If the parameter must exist, add strict validation that prevents it from being set to `true` on production networks:
   ```go
   func validateDisableSeqnoCheck(i interface{}) error {
       v, ok := i.(bool)
       if !ok {
           return fmt.Errorf("invalid parameter type: %T", i)
       }
       if v {
           return fmt.Errorf("DisableSeqnoCheck cannot be enabled on production networks")
       }
       return nil
   }
   ```
   Replace the empty validator at [1](#0-0)  with this function.

3. **Long-term:** Review all governable parameters to ensure they have proper validation functions that prevent security-compromising values.

## Proof of Concept

**File:** `x/auth/ante/ante_test.go`

**Test Function:** Add a new test function `TestDisableSeqnoCheckReplayAttack`

**Setup:**
1. Initialize test environment with `DisableSeqnoCheck = true`
2. Create two test accounts: sender and recipient
3. Fund the sender account with sufficient tokens
4. Record the initial balances of both accounts

**Trigger:**
1. Create a MsgSend transaction transferring tokens from sender to recipient
2. Sign and submit the transaction - it should succeed
3. Capture the exact transaction bytes (including signature)
4. Submit the exact same transaction bytes again without re-signing
5. Verify the second submission also succeeds (demonstrating replay)
6. Optionally repeat step 4-5 multiple times

**Observation:**
- The first transaction succeeds and transfers X tokens
- The second transaction (with identical bytes) also succeeds and transfers X tokens again
- The recipient's balance increases by 2X (or more with additional replays)
- The sender's balance decreases by 2X (or more)
- The account sequence increments each time, but this doesn't prevent replay since the signature doesn't include the sequence

This confirms that when `DisableSeqnoCheck = true`, the same transaction can be executed multiple times, leading to unauthorized fund transfers and direct loss of funds for the transaction sender.

The existing test [6](#0-5)  already demonstrates this behavior partially, showing that transactions with sequence 0 can be submitted twice when `DisableSeqnoCheck = true`. A complete PoC would use actual fund transfers (MsgSend) instead of test messages to demonstrate the direct financial impact.

### Citations

**File:** x/auth/types/params.go (L59-59)
```go
		paramtypes.NewParamSetPair(KeyDisableSeqnoCheck, &p.DisableSeqnoCheck, func(i interface{}) error { return nil }),
```

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

**File:** x/auth/tx/direct.go (L47-54)
```go
func DirectSignBytes(bodyBytes, authInfoBytes []byte, chainID string, accnum uint64) ([]byte, error) {
	signDoc := types.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       chainID,
		AccountNumber: accnum,
	}
	return signDoc.Marshal()
```

**File:** x/params/proposal_handler.go (L26-42)
```go
func handleParameterChangeProposal(ctx sdk.Context, k keeper.Keeper, p *proposal.ParameterChangeProposal) error {
	for _, c := range p.Changes {
		ss, ok := k.GetSubspace(c.Subspace)
		if !ok {
			return sdkerrors.Wrap(proposal.ErrUnknownSubspace, c.Subspace)
		}

		k.Logger(ctx).Info(
			fmt.Sprintf("attempt to set new parameter value; key: %s, value: %s", c.Key, c.Value),
		)

		if err := ss.Update(ctx, []byte(c.Key), []byte(c.Value)); err != nil {
			return sdkerrors.Wrapf(proposal.ErrSettingParameter, "key: %s, value: %s, err: %s", c.Key, c.Value, err.Error())
		}
	}

	return nil
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
