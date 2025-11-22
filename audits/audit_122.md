## Audit Report

### Title
Transaction Replay Attack Vulnerability When DisableSeqnoCheck is Enabled for SIGN_MODE_DIRECT Transactions

### Summary
When the `DisableSeqnoCheck` parameter is set to `true`, transactions using `SIGN_MODE_DIRECT` (the default signing mode) can be replayed indefinitely, enabling attackers to execute the same transaction multiple times. This occurs because the sequence number check is bypassed, while the signature verification still succeeds using the original sequence number embedded in the transaction's AuthInfo.

### Impact
**High** - Direct loss of funds

### Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Signature verification using transaction's AuthInfo: [2](#0-1) 

**Intended Logic:**
The sequence number mechanism is designed to prevent replay attacks. Each account maintains a sequence counter that increments with each transaction. The system should reject any transaction where the signature's sequence number doesn't match the current account sequence, preventing the same transaction from being executed twice.

**Actual Logic:**
When `DisableSeqnoCheck` is enabled:
1. The sequence number check at [1](#0-0)  is bypassed
2. For `SIGN_MODE_DIRECT`, signature verification uses `AuthInfoBytes` directly from the transaction [3](#0-2) , which contains the original sequence number in the `SignerInfo` structure [4](#0-3) 
3. The `SignDoc` for verification is constructed as: `BodyBytes + AuthInfoBytes + ChainID + AccountNumber` [5](#0-4) 
4. Since `AuthInfoBytes` come from the original transaction and are not reconstructed, the signature remains valid even after the account sequence has been incremented
5. The transaction executes successfully and increments the sequence [6](#0-5) 

**Exploit Scenario:**
1. Alice creates and signs a transaction to send 100 tokens to Bob using sequence number 0
2. The transaction is broadcast and successfully executed
3. Alice's account sequence is incremented to 1
4. An attacker (or Bob) captures the original transaction bytes and rebroadcasts them
5. Since `DisableSeqnoCheck` is true, the sequence check is bypassed
6. The signature verification succeeds because it uses the same `AuthInfoBytes` (containing sequence 0) from the replayed transaction
7. The transaction executes again, sending another 100 tokens to Bob
8. Steps 4-7 can be repeated indefinitely until Alice's account is drained

**Security Failure:**
The replay protection mechanism is completely bypassed. The fundamental security invariant that "each signed transaction can only be executed once" is violated, enabling unlimited replay attacks and direct theft of funds.

### Impact Explanation

**Affected Assets:** All user funds in accounts when `DisableSeqnoCheck` is enabled.

**Severity of Damage:**
- Any transaction (token transfers, delegations, contract calls, etc.) can be replayed unlimited times
- Attackers can drain user accounts by replaying withdrawal transactions
- Automated systems or exchanges could suffer massive losses from replayed deposit/withdrawal transactions
- The attack is completely silent - users may not notice until significant funds are lost

**System Impact:**
This fundamentally breaks the blockchain's security model. Users cannot safely perform any transactions when this parameter is enabled, making the chain unusable for financial operations.

### Likelihood Explanation

**Who can trigger it:** Any network participant who can observe transaction bytes (i.e., anyone with access to the mempool or block data).

**Required conditions:**
- The `DisableSeqnoCheck` parameter must be set to `true` [7](#0-6) 
- Transactions must use `SIGN_MODE_DIRECT` (which is the default signing mode)

**Frequency:** 
Once enabled, this vulnerability can be exploited continuously. Every transaction becomes replayable, and attackers can drain accounts systematically. The test suite even demonstrates that replaying with the same sequence succeeds when this parameter is enabled [8](#0-7) .

### Recommendation

**Immediate Fix:** Never enable `DisableSeqnoCheck` in production environments. This parameter should be removed entirely or restricted to testing/development environments only.

**Alternative Fix:** If there's a legitimate use case for disabling sequence checks, implement a different replay protection mechanism such as:
1. Maintain a nonce/hash registry of executed transactions
2. Add a time-based expiration to transactions
3. Use a different signature scheme that doesn't rely solely on sequence numbers

**Code-level Fix:** Add validation to prevent `DisableSeqnoCheck` from being enabled on mainnet, or modify the signature verification logic to implement alternative replay protection when sequence checks are disabled.

### Proof of Concept

**File:** `x/auth/ante/ante_test.go`

**Test Function:** Add the following test function to demonstrate the replay attack:

```go
func (suite *AnteTestSuite) TestReplayAttackWithDisableSeqnoCheck() {
    suite.SetupTest(false)
    
    // Enable DisableSeqnoCheck
    authParams := types.Params{
        MaxMemoCharacters:      types.DefaultMaxMemoCharacters,
        TxSigLimit:             types.DefaultTxSigLimit,
        TxSizeCostPerByte:      types.DefaultTxSizeCostPerByte,
        SigVerifyCostED25519:   types.DefaultSigVerifyCostED25519,
        SigVerifyCostSecp256k1: types.DefaultSigVerifyCostSecp256k1,
        DisableSeqnoCheck:      true,
    }
    suite.app.AccountKeeper.SetParams(suite.ctx, authParams)
    
    // Create test account
    accounts := suite.CreateTestAccounts(1)
    feeAmount := testdata.NewTestFeeAmount()
    gasLimit := testdata.NewTestGasLimit()
    
    // Create and sign transaction with sequence 0
    msg := testdata.NewTestMsg(accounts[0].acc.GetAddress())
    privs := []cryptotypes.PrivKey{accounts[0].priv}
    accNums := []uint64{0}
    accSeqs := []uint64{0}
    
    suite.txBuilder = suite.clientCtx.TxConfig.NewTxBuilder()
    suite.Require().NoError(suite.txBuilder.SetMsgs(msg))
    suite.txBuilder.SetFeeAmount(feeAmount)
    suite.txBuilder.SetGasLimit(gasLimit)
    
    // Create and execute first transaction
    tx, err := suite.CreateTestTx(privs, accNums, accSeqs, suite.ctx.ChainID())
    suite.Require().NoError(err)
    
    // Get initial account sequence
    acc := suite.app.AccountKeeper.GetAccount(suite.ctx, accounts[0].acc.GetAddress())
    initialSeq := acc.GetSequence()
    suite.Require().Equal(uint64(0), initialSeq)
    
    // Execute transaction first time
    newCtx, err := suite.anteHandler(suite.ctx, tx, false)
    suite.Require().NoError(err)
    suite.ctx = newCtx
    
    // Verify sequence was incremented
    acc = suite.app.AccountKeeper.GetAccount(suite.ctx, accounts[0].acc.GetAddress())
    suite.Require().Equal(uint64(1), acc.GetSequence())
    
    // REPLAY ATTACK: Execute the SAME transaction bytes again
    // This should fail normally but succeeds with DisableSeqnoCheck=true
    newCtx, err = suite.anteHandler(suite.ctx, tx, false)
    suite.Require().NoError(err) // Transaction succeeds - THIS IS THE VULNERABILITY
    suite.ctx = newCtx
    
    // Verify sequence was incremented again
    acc = suite.app.AccountKeeper.GetAccount(suite.ctx, accounts[0].acc.GetAddress())
    suite.Require().Equal(uint64(2), acc.GetSequence())
    
    // REPLAY ATTACK AGAIN: Execute the SAME transaction bytes a third time
    newCtx, err = suite.anteHandler(suite.ctx, tx, false)
    suite.Require().NoError(err) // Still succeeds - unlimited replay possible
    
    acc = suite.app.AccountKeeper.GetAccount(suite.ctx, accounts[0].acc.GetAddress())
    suite.Require().Equal(uint64(3), acc.GetSequence())
}
```

**Setup:** The test initializes a blockchain context with `DisableSeqnoCheck` set to `true` and creates a test account with initial sequence 0.

**Trigger:** The test creates a single transaction signed with sequence 0, then executes it three times using the exact same transaction bytes (representing replay attacks).

**Observation:** All three executions succeed without errors, and the account sequence increments each time (0→1→2→3), proving that the same transaction can be replayed indefinitely. In a normal configuration with sequence checks enabled, the second and third executions would fail with `ErrWrongSequence`. This test demonstrates the complete bypass of replay protection.

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

**File:** x/auth/tx/direct.go (L29-43)
```go
func (signModeDirectHandler) GetSignBytes(mode signingtypes.SignMode, data signing.SignerData, tx sdk.Tx) ([]byte, error) {
	if mode != signingtypes.SignMode_SIGN_MODE_DIRECT {
		return nil, fmt.Errorf("expected %s, got %s", signingtypes.SignMode_SIGN_MODE_DIRECT, mode)
	}

	protoTx, ok := tx.(*wrapper)
	if !ok {
		return nil, fmt.Errorf("can only handle a protobuf Tx, got %T", tx)
	}

	bodyBz := protoTx.getBodyBytes()
	authInfoBz := protoTx.getAuthInfoBytes()

	return DirectSignBytes(bodyBz, authInfoBz, data.ChainID, data.AccountNumber)
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

**File:** types/tx/tx.pb.go (L414-417)
```go
	// sequence is the sequence of the account, which describes the
	// number of committed transactions signed by a given address. It is used to
	// prevent replay attacks.
	Sequence uint64 `protobuf:"varint,3,opt,name=sequence,proto3" json:"sequence,omitempty"`
```

**File:** x/auth/types/params.go (L27-27)
```go
	KeyDisableSeqnoCheck      = []byte("KeyDisableSeqnoCheck")
```

**File:** x/auth/ante/ante_test.go (L1194-1202)
```go
		{
			"test sending it again succeeds (disable seqno check is true)",
			func() {
				privs, accNums, accSeqs = []cryptotypes.PrivKey{accounts[0].priv}, []uint64{0}, []uint64{0}
			},
			false,
			true,
			nil,
		},
```
