# Audit Report

## Title
Unsafe Array Access in Genesis Transaction Collection Causing Network Initialization Panic

## Summary
The `CollectTxs` function in the genutil module performs unsafe array access on genesis transaction messages without validating the array length, causing all validator nodes to panic when processing a malformed genesis transaction file with an empty messages array during the genesis collection phase. [1](#0-0) 

## Impact
Medium

## Finding Description

- **location**: `x/genutil/collect.go`, lines 135-139

- **intended logic**: Genesis transactions must be validated to contain exactly one `MsgCreateValidator` message before processing. The code comment on line 135 explicitly states "genesis transactions must be single-message". Proper validation logic exists in `ValidateGenesis` function. [2](#0-1) 

- **actual logic**: The `CollectTxs` function retrieves messages via `GetMsgs()` at line 136 and immediately accesses `msgs[0]` at line 139 with a forced type assertion, without checking if the slice is empty. The execution flow from the `collect-gentxs` CLI command bypasses the validation that exists in `ValidateGenesis`. [3](#0-2) 

- **exploitation path**:
  1. Create malformed genesis transaction JSON file with empty messages array: `{"body":{"messages":[]},"auth_info":{},"signatures":[]}`
  2. Place file in the gentx directory (e.g., `~/.sei/config/gentx/malformed.json`)
  3. Validators run the standard `collect-gentxs` command during genesis coordination
  4. `CollectTxs` processes the malformed file and decodes it via `txJSONDecoder` (which only performs JSON unmarshaling without structural validation) [4](#0-3) 
  5. When `GetMsgs()` returns an empty slice (as `res := make([]sdk.Msg, len(anys))` creates an empty slice when `t.Body.Messages` is empty), the code panics with "index out of range [0] with length 0" [5](#0-4) 
  6. All validators processing the same shared gentx files crash simultaneously
  7. Network genesis collection cannot complete, preventing network initialization

- **security guarantee broken**: Availability guarantee during genesis initialization. The network cannot start when any participating validator contributes a malformed gentx file.

## Impact Explanation

During coordinated network launches, all validators must process ALL genesis transaction files from all participants. A single malformed gentx file causes every validator node to panic when processing it, completely blocking the genesis collection phase. This prevents the network from becoming operational, matching the impact category "Network not being able to confirm new transactions (total network shutdown)". Since the network cannot complete initialization, no transactions can ever be processed.

## Likelihood Explanation

**Likelihood: High**
- Triggered during mandatory `collect-gentxs` command execution in standard genesis ceremony
- Can occur accidentally through buggy genesis transaction creation tooling, file corruption during transfer, incomplete file writes, or manual editing errors
- Can occur maliciously through compromised validator infrastructure or intentionally malicious validators
- Amplification effect: one malformed file from any single validator affects ALL validators during coordinated genesis
- Deterministic: 100% probability of panic when any validator processes the malformed file
- Affects the most critical operational phase: network initialization, with no automated recovery path

## Recommendation

Add validation checks in `CollectTxs` before the unsafe operations at line 139, mirroring the existing validation pattern in `ValidateGenesis`:

```go
// After line 136: msgs := genTx.GetMsgs()
if len(msgs) != 1 {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "genesis transaction in %s must contain exactly 1 message, got %d", 
        fo.Name(), len(msgs))
}

// Replace line 139 unsafe type assertion with safe check
msg, ok := msgs[0].(*stakingtypes.MsgCreateValidator)
if !ok {
    return appGenTxs, persistentPeers, fmt.Errorf(
        "genesis transaction in %s does not contain a MsgCreateValidator, got %T", 
        fo.Name(), msgs[0])
}
```

## Proof of Concept

**Setup**:
1. Create temporary directory for gentx files
2. Write malformed transaction JSON file with empty messages array: `{"body":{"messages":[]},"auth_info":{},"signatures":[]}`
3. Initialize genesis document and codec with standard test configuration

**Action**:
Call `CollectTxs` function with the directory containing the malformed gentx file, passing standard parameters (codec, JSON decoder, moniker, directory path, genesis document, balance iterator)

**Result**:
- Function panics at line 139 when accessing `msgs[0]` on the empty slice
- Panic message: `runtime error: index out of range [0] with length 0`
- No error is returned; the process crashes immediately
- With the recommended fix, the function returns a descriptive error instead, allowing validators to identify and exclude the problematic gentx file before retrying genesis collection

## Notes

This vulnerability qualifies as **Medium** severity under the impact criterion "Network not being able to confirm new transactions (total network shutdown)". The complete prevention of network initialization prevents any transactions from being processed. All validators (100%) are affected simultaneously by processing the same shared gentx files during the coordinated genesis ceremony.

### Citations

**File:** x/genutil/collect.go (L135-139)
```go
		// genesis transactions must be single-message
		msgs := genTx.GetMsgs()

		// TODO abstract out staking message validation back to staking
		msg := msgs[0].(*stakingtypes.MsgCreateValidator)
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

**File:** x/auth/tx/decoder.go (L79-90)
```go
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
```

**File:** types/tx/types.go (L22-36)
```go
func (t *Tx) GetMsgs() []sdk.Msg {
	if t == nil || t.Body == nil {
		return nil
	}

	anys := t.Body.Messages
	res := make([]sdk.Msg, len(anys))
	for i, any := range anys {
		cached := any.GetCachedValue()
		if cached == nil {
			panic("Any cached value is nil. Transaction messages must be correctly packed Any values.")
		}
		res[i] = cached.(sdk.Msg)
	}
	return res
```
