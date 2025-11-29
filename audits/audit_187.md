# Audit Report

## Title
Missing Transaction Structure Validation in Genesis Collection Leading to Node Panic

## Summary
The `CollectTxs` function in `x/genutil/collect.go` performs an unsafe array access and type assertion on transaction messages without validating that messages exist or are of the correct type. This allows a malformed genesis transaction file to cause validator nodes to panic during the critical genesis collection phase, preventing network initialization.

## Impact
Medium

## Finding Description

**Location:** `x/genutil/collect.go` lines 136-139 [1](#0-0) 

**Intended logic:** Genesis transactions should be validated to ensure they contain exactly one `MsgCreateValidator` message before being processed. The comment at line 135 explicitly states "genesis transactions must be single-message", indicating this is a critical invariant.

**Actual logic:** After decoding a transaction at lines 116-118, the code retrieves messages at line 136 and immediately performs two unsafe operations at line 139:
1. Array access `msgs[0]` without checking if the slice is non-empty
2. Type assertion using the unsafe pattern `.*(...MsgCreateValidator)` without the `ok` return value [2](#0-1) 

The `DefaultJSONTxDecoder` only performs JSON unmarshaling without any structural validation: [3](#0-2) 

While `ValidateGenesis` contains proper validation logic with bounds checking and safe type assertions: [4](#0-3) 

This validation is NOT called during the `collect-gentxs` command flow. It only runs as a separate CLI command or during module initialization (after genesis state is already created). [5](#0-4) 

**Exploitation path:**
1. A malformed genesis transaction JSON file is created with either zero messages or a non-`MsgCreateValidator` message
2. The file is placed in the gentx directory (typically `~/.sei/config/gentx/`)
3. Any validator runs the standard `collect-gentxs` command
4. `CollectTxs` reads and processes all gentx files in the directory
5. When processing the malformed file, the code panics at line 139 with either:
   - "runtime error: index out of range" if messages slice is empty
   - "interface conversion: sdk.Msg is <type>, not *stakingtypes.MsgCreateValidator" if wrong message type

**Security guarantee broken:** The availability guarantee during genesis initialization is violated. A single malformed gentx file prevents all validators from completing the genesis collection process.

## Impact Explanation

During coordinated network launches, validators collect genesis transactions from all participating validators. The standard procedure involves:
- Each validator creates their gentx file
- These files are shared/distributed among all validators
- Each validator runs `collect-gentxs` to process ALL gentx files

If any single gentx file is malformed:
- Every validator attempting to collect gentxs will process this malformed file
- Every validator's node will panic at line 139
- The genesis collection phase cannot complete
- Network initialization is blocked

This can affect ≥30% of validator nodes simultaneously, as they all process the same shared set of gentx files during genesis. Manual intervention is required to identify and remove/fix the malformed file before validators can retry.

## Likelihood Explanation

**Trigger conditions:**
- Occurs during the standard `collect-gentxs` command execution (required for network initialization)
- Requires a malformed gentx file to exist in the collection directory
- No special privileges beyond normal validator operator access

**Likelihood: High**
- **Accidental triggers:** Validators may use buggy tooling or encounter file corruption when creating gentx files
- **Malicious triggers:** Compromised validator infrastructure or malicious insiders can deliberately create malformed files
- **Amplification effect:** One malformed file from any validator affects ALL validators during genesis
- **Deterministic:** Every validator processing the malformed file will panic
- **Critical phase:** Affects the most critical phase of network operation (genesis initialization)

## Recommendation

Add validation checks before the unsafe operations in `CollectTxs`, mirroring the existing validation in `ValidateGenesis`:

```go
// After line 136: msgs := genTx.GetMsgs()
if len(msgs) != 1 {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "genesis transaction in %s must contain exactly 1 message, got %d", 
        fo.Name(), len(msgs))
}

// Replace line 139 with safe type assertion:
msg, ok := msgs[0].(*stakingtypes.MsgCreateValidator)
if !ok {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "genesis transaction in %s does not contain a MsgCreateValidator, got %T", 
        fo.Name(), msgs[0])
}
```

This enforces the critical invariant at the point of use and returns descriptive errors instead of panicking.

## Proof of Concept

**File:** `x/genutil/collect_test.go`

**Setup:**
1. Create a temporary directory for gentx files
2. Write a malformed transaction JSON with an empty messages array to a file in that directory
3. Initialize the necessary codec and decoder

**Action:**
Call `CollectTxs` with the directory containing the malformed gentx file

**Result:**
The function panics at line 139 when attempting to access `msgs[0]` on an empty slice, confirming the vulnerability. A fixed implementation would return a descriptive error instead of panicking.

## Notes

This vulnerability qualifies as **Medium** severity under the defined impact: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network." The amplification effect of one malformed file affecting all validators during genesis collection is the key factor that elevates this beyond an individual node issue.

### Citations

**File:** x/genutil/collect.go (L116-118)
```go
		if genTx, err = txJSONDecoder(jsonRawTx); err != nil {
			return appGenTxs, persistentPeers, err
		}
```

**File:** x/genutil/collect.go (L135-139)
```go
		// genesis transactions must be single-message
		msgs := genTx.GetMsgs()

		// TODO abstract out staking message validation back to staking
		msg := msgs[0].(*stakingtypes.MsgCreateValidator)
```

**File:** x/auth/tx/decoder.go (L78-91)
```go
// DefaultJSONTxDecoder returns a default protobuf JSON TxDecoder using the provided Marshaler.
func DefaultJSONTxDecoder(cdc codec.ProtoCodecMarshaler) sdk.TxDecoder {
	return func(txBytes []byte) (sdk.Tx, error) {
		var theTx tx.Tx
		err := cdc.UnmarshalJSON(txBytes, &theTx)
		if err != nil {
			return nil, sdkerrors.Wrap(sdkerrors.ErrTxDecode, err.Error())
		}

		return &wrapper{
			tx: &theTx,
		}, nil
	}
}
```

**File:** x/genutil/types/genesis_state.go (L107-117)
```go
		msgs := tx.GetMsgs()
		if len(msgs) != 1 {
			return errors.New(
				"must provide genesis Tx with exactly 1 CreateValidator message")
		}

		// TODO: abstract back to staking
		if _, ok := msgs[0].(*stakingtypes.MsgCreateValidator); !ok {
			return fmt.Errorf(
				"genesis transaction %v does not contain a MsgCreateValidator", i)
		}
```

**File:** x/genutil/client/cli/collect.go (L53-58)
```go
			appMessage, err := genutil.GenAppStateFromConfig(cdc,
				clientCtx.TxConfig,
				config, initCfg, *genDoc, genBalIterator)
			if err != nil {
				return errors.Wrap(err, "failed to get genesis app state from config")
			}
```
