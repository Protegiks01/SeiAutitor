## Audit Report

## Title
Missing Transaction Structure Validation in Genesis Collection Leading to Node Panic

## Summary
The `TxJSONDecoder` does not validate transaction structure before returning in `collect.go:116-118`. Subsequently, the code performs an unsafe array access and type assertion at line 139 without checking if the transaction contains any messages or if the first message is of the expected type. This allows a malformed genesis transaction JSON file to cause validator nodes to panic during genesis collection, preventing network initialization.

## Impact
Medium

## Finding Description

**Location:** 
- Primary issue: `x/genutil/collect.go` lines 116-139
- Related decoder: `x/auth/tx/decoder.go` lines 78-91

**Intended Logic:** 
Genesis transactions should be validated to ensure they contain exactly one `MsgCreateValidator` message before being processed. The comment at line 135 states "genesis transactions must be single-message", indicating this is a critical invariant. [1](#0-0) 

**Actual Logic:** 
The `TxJSONDecoder` only performs basic JSON unmarshaling without validating the transaction structure: [2](#0-1) 

After decoding at lines 116-118, the code immediately performs unsafe operations at line 139:
1. `msgs[0]` - array access without checking if `msgs` is non-empty
2. `.(*stakingtypes.MsgCreateValidator)` - type assertion without using the safe `ok` pattern [3](#0-2) 

In contrast, `ValidateGenesis` correctly validates the transaction structure with proper checks: [4](#0-3) 

However, `ValidateGenesis` is only called as a separate CLI command or during module initialization (after genesis state creation), NOT during the `collect-gentxs` command flow. [5](#0-4) 

**Exploit Scenario:**
1. A validator operator (or attacker with file system access) creates a malformed genesis transaction JSON file with either:
   - Zero messages in the transaction body
   - A message that is not a `MsgCreateValidator`
2. The file is placed in the `gentx` directory (typically `~/.sei/config/gentx/`)
3. The validator runs `collect-gentxs` command to collect genesis transactions
4. `CollectTxs` is called, which decodes the malformed transaction
5. At line 139, the code panics with either:
   - "index out of range" if `msgs` is empty
   - "interface conversion: sdk.Msg is <type>, not *stakingtypes.MsgCreateValidator" if wrong message type

**Security Failure:**
This is a denial-of-service vulnerability that breaks the availability property during the critical genesis initialization phase. The node crashes before genesis state can be created, preventing the validator from participating in network initialization.

## Impact Explanation

**Affected Components:**
- Validator nodes during genesis initialization
- Network launch/restart procedures requiring genesis collection

**Severity:**
- Multiple validator nodes can be affected simultaneously if multiple operators have malformed genesis transactions
- Prevents affected validators from completing the genesis collection phase
- Blocks network initialization if a significant portion of validators are affected
- No recovery possible without manual intervention (removing/fixing malformed genesis transactions)

**System Impact:**
This vulnerability can prevent ≥30% of validator nodes from starting during genesis initialization, which qualifies as Medium severity under the defined scope: "Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network."

## Likelihood Explanation

**Trigger Requirements:**
- File system access to a validator node's `gentx` directory
- Occurs during `collect-gentxs` command execution (standard network initialization procedure)
- No special privileges required beyond normal validator operator access

**Likelihood:**
- **High**: This is easily triggerable during normal operations
- Any validator operator can accidentally create a malformed genesis transaction
- Malicious insiders or compromised validator infrastructure can deliberately exploit this
- Affects all networks during genesis initialization phase
- No authentication or authorization bypass required

**Frequency:**
- Occurs every time `collect-gentxs` is run with a malformed genesis transaction present
- Deterministic and repeatable
- Can affect multiple validators simultaneously during coordinated network launches

## Recommendation

Add validation checks before the unsafe array access and type assertion in `CollectTxs`:

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

This mirrors the validation already present in `ValidateGenesis` and ensures the critical invariant is enforced at the point of use.

## Proof of Concept

**File:** `x/genutil/collect_test.go`

**Test Function:** `TestCollectTxsWithEmptyMessages`

```go
// Add this test to x/genutil/collect_test.go
func TestCollectTxsWithEmptyMessages(t *testing.T) {
    testDir, err := ioutil.TempDir(os.TempDir(), "testCollectTxsEmpty")
    if err != nil {
        t.Fatal(err)
    }
    defer os.RemoveAll(testDir)

    // Create a transaction with empty messages
    registry := cdctypes.NewInterfaceRegistry()
    cdc := codec.NewProtoCodec(registry)
    
    // Create malformed transaction JSON with no messages
    malformedTxJSON := []byte(`{
        "body": {
            "messages": [],
            "memo": "test@192.168.1.1:26656"
        },
        "auth_info": {
            "fee": {
                "amount": [],
                "gas_limit": "200000"
            }
        },
        "signatures": []
    }`)
    
    // Write malformed genesis transaction file
    malformedFile := filepath.Join(testDir, "gentx-malformed.json")
    if err := ioutil.WriteFile(malformedFile, malformedTxJSON, 0644); err != nil {
        t.Fatal(err)
    }

    txJSONDecoder := tx.DefaultJSONTxDecoder(cdc)
    gdoc := tmtypes.GenesisDoc{AppState: []byte("{}")}
    balItr := new(doNothingIterator)

    // This should panic with "index out of range" at line 139
    defer func() {
        if r := recover(); r != nil {
            // Expected panic confirms the vulnerability
            t.Logf("Successfully reproduced panic: %v", r)
            return
        }
        t.Fatal("Expected panic from empty messages, but none occurred")
    }()

    _, _, err = genutil.CollectTxs(cdc, txJSONDecoder, "test", testDir, gdoc, balItr)
    // Should not reach here - should panic before returning
}
```

**Setup:**
1. Creates a temporary directory for genesis transactions
2. Constructs a malformed transaction JSON with an empty messages array
3. Writes the malformed transaction to a file in the test directory

**Trigger:**
Calls `CollectTxs` with the directory containing the malformed genesis transaction

**Observation:**
The test expects a panic to occur at line 139 when attempting to access `msgs[0]` on an empty slice. The panic confirms the vulnerability - the code does not validate the transaction structure before performing unsafe operations. A properly fixed implementation would return an error instead of panicking.

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
