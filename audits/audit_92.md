## Title
Nondeterministic Access Operation Ordering Due to Map Iteration in BuildSelectorOps

## Summary
The `BuildSelectorOps` function in `keeper.go` creates an `AccessOperationSet` that uses a Go map internally. When this set is converted to a slice via `ToSlice()`, the map iteration order is nondeterministic, causing different validators to produce different orderings of access operations for the same WASM contract execution. This breaks consensus determinism.

## Impact
**High** - Unintended permanent chain split requiring hard fork

## Finding Description

**Location:** 
- Primary: [1](#0-0) 
- Data structure: [2](#0-1) 
- Conversion point: [3](#0-2) 
- Return point: [4](#0-3) 

**Intended Logic:** 
The access control system is designed to provide deterministic dependency mapping for WASM contracts to enable parallel transaction execution. The `BuildSelectorOps` function should process JQ selectors and other selector types to generate a consistent, deterministic set of access operations that all validators agree upon.

**Actual Logic:** 
The `AccessOperationSet` type uses a Go map for storing access operations [2](#0-1) . When `GetWasmDependencyAccessOps` calls `selectedAccessOps.ToSlice()` [4](#0-3) , the `ToSlice()` method iterates over this map using `for op := range waos.ops` [5](#0-4) . In Go, map iteration order is intentionally randomized and nondeterministic, meaning different validator nodes will produce different orderings of the same set of access operations.

**Exploit Scenario:** 
1. A user deploys a WASM contract with a dependency mapping containing multiple access operations with JQ selectors (e.g., multiple `.send.from`, `.receive.amount`, etc.) [6](#0-5) 
2. The user executes a transaction that calls this WASM contract
3. Each validator calls `GetWasmDependencyAccessOps` → `BuildSelectorOps` → `ToSlice()` to determine the access operations
4. Each validator's Go runtime produces a different random ordering of the map iteration
5. Validators produce different access operation lists in different orders
6. If the consensus mechanism or state machine depends on the ordering of these operations, validators will disagree on the resulting state hash
7. This causes a consensus failure and potential chain split

**Security Failure:** 
The consensus determinism property is broken. All validators must execute transactions identically and produce the same state transitions. The nondeterministic map iteration causes different validators to potentially produce different results from the same input, violating the fundamental requirement for blockchain consensus.

## Impact Explanation

**Affected Components:**
- WASM contract execution with access control dependency mappings
- Parallel transaction execution system
- Consensus state transitions
- All validators participating in block validation

**Severity:**
This vulnerability can cause validators to disagree on state transitions when processing WASM contracts. Depending on how the access operations are used downstream:
- **Best case:** Minor desynchronization that may self-correct
- **Worst case:** Permanent chain split requiring a hard fork if the ordering affects state hash computation or transaction validation

The access control system is fundamental to the parallel execution optimization in Sei, making this a critical component for consensus. Any nondeterminism in consensus-critical paths can lead to network splits, failed block proposals, and validator slashing.

## Likelihood Explanation

**Who can trigger:** Any user who deploys and executes WASM contracts with multiple access operations using selectors (JQ, JQ_BECH32_ADDRESS, JQ_LENGTH_PREFIXED_ADDRESS, etc.).

**Conditions required:**
- A WASM contract with a dependency mapping containing 2 or more access operations that get added to the same `AccessOperationSet`
- Normal contract execution via any transaction
- No special privileges needed

**Frequency:**
- This occurs on **every** WASM contract execution that has multiple access operations
- The nondeterminism manifests every time `ToSlice()` is called on a multi-element map
- Whether it causes observable consensus failures depends on how downstream code uses the ordering

This is highly likely to occur in production as WASM contracts with multiple access operations are a common pattern, as demonstrated in the test suite [7](#0-6) .

## Recommendation

Replace the map-based `AccessOperationSet` with a deterministic data structure that preserves insertion order. Options include:

1. **Use a slice with deduplication:** Change `AccessOperationSet.ops` from a map to a slice, and implement `Add()` to check for duplicates before appending
2. **Sort before returning:** In `ToSlice()`, collect all operations into a slice and sort them by a deterministic key (e.g., concatenation of ResourceType, AccessType, IdentifierTemplate) before returning
3. **Use ordered map library:** Use a third-party ordered map implementation that maintains insertion order

The minimal fix is to sort the operations in `ToSlice()` before returning:

```go
func (waos *AccessOperationSet) ToSlice() []acltypes.AccessOperation {
    res := []acltypes.AccessOperation{}
    hasCommitOp := false
    for op := range waos.ops {
        if op != *CommitAccessOp() {
            res = append(res, op)
        } else {
            hasCommitOp = true
        }
    }
    // Sort for deterministic ordering
    sort.Slice(res, func(i, j int) bool {
        if res[i].ResourceType != res[j].ResourceType {
            return res[i].ResourceType < res[j].ResourceType
        }
        if res[i].AccessType != res[j].AccessType {
            return res[i].AccessType < res[j].AccessType
        }
        return res[i].IdentifierTemplate < res[j].IdentifierTemplate
    })
    if hasCommitOp {
        res = append(res, *CommitAccessOp())
    }
    return res
}
```

## Proof of Concept

**File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** `TestBuildSelectorOpsNondeterminism`

**Setup:**
1. Initialize a test app and context using `simapp.Setup(false)`
2. Create a WASM contract address
3. Create a WASM dependency mapping with multiple JQ selector operations (at least 3-4 operations to increase likelihood of observing different orderings)
4. Set the mapping via `SetWasmDependencyMapping`

**Trigger:**
1. Create a test message info with JSON data that matches all selectors
2. Call `GetWasmDependencyAccessOps` multiple times (e.g., 100 iterations)
3. Collect the returned access operation slices

**Observation:**
The test should observe that across multiple invocations, the ordering of non-commit access operations varies. This can be detected by:
- Converting each result to a string representation
- Storing the orderings in a set/map
- Asserting that more than one distinct ordering was observed

Since Go's map iteration is randomized, running this test multiple times will eventually produce different orderings, demonstrating the nondeterminism. The test confirms that the same input (contract, sender, message) produces different outputs (different operation orderings) across runs, which violates consensus determinism requirements.

**Expected Result:** The test will fail by detecting multiple different orderings of the same set of access operations, proving the nondeterministic behavior.

### Citations

**File:** x/accesscontrol/keeper/keeper.go (L224-224)
```go
	return selectedAccessOps.ToSlice(), nil
```

**File:** x/accesscontrol/keeper/keeper.go (L311-441)
```go
func (k Keeper) BuildSelectorOps(ctx sdk.Context, contractAddr sdk.AccAddress, accessOps []*acltypes.WasmAccessOperation, senderBech string, msgInfo *types.WasmMessageInfo, circularDepLookup ContractReferenceLookupMap) (*types.AccessOperationSet, error) {
	selectedAccessOps := types.NewEmptyAccessOperationSet()
	// when we build selector ops here, we want to generate "*" if the proper fields aren't present
	// if size of circular dep map > 1 then it means we're in a contract reference
	// as a result, if the selector doesn't match properly, we need to conservatively assume "*" for the identifier
	withinContractReference := len(circularDepLookup) > 1
	for _, opWithSelector := range accessOps {
	selectorSwitch:
		switch opWithSelector.SelectorType {
		case acltypes.AccessOperationSelectorType_JQ:
			op, err := jq.Parse(opWithSelector.Selector)
			if err != nil {
				return nil, err
			}
			data, err := op.Apply(msgInfo.MessageFullBody)
			if err != nil {
				if withinContractReference {
					opWithSelector.Operation.IdentifierTemplate = "*"
					break selectorSwitch
				}
				// if the operation is not applicable to the message, skip it
				continue
			}
			trimmedData := strings.Trim(string(data), "\"") // we need to trim the quotes around the string
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString([]byte(trimmedData)),
			)
		case acltypes.AccessOperationSelectorType_JQ_BECH32_ADDRESS:
			op, err := jq.Parse(opWithSelector.Selector)
			if err != nil {
				return nil, err
			}
			data, err := op.Apply(msgInfo.MessageFullBody)
			if err != nil {
				if withinContractReference {
					opWithSelector.Operation.IdentifierTemplate = "*"
					break selectorSwitch
				}
				// if the operation is not applicable to the message, skip it
				continue
			}
			bech32Addr := strings.Trim(string(data), "\"") // we need to trim the quotes around the string
			// we expect a bech32 prefixed address, so lets convert to account address
			accAddr, err := sdk.AccAddressFromBech32(bech32Addr)
			if err != nil {
				return nil, err
			}
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString(accAddr),
			)
		case acltypes.AccessOperationSelectorType_JQ_LENGTH_PREFIXED_ADDRESS:
			op, err := jq.Parse(opWithSelector.Selector)
			if err != nil {
				return nil, err
			}
			data, err := op.Apply(msgInfo.MessageFullBody)
			if err != nil {
				if withinContractReference {
					opWithSelector.Operation.IdentifierTemplate = "*"
					break selectorSwitch
				}
				// if the operation is not applicable to the message, skip it
				continue
			}
			bech32Addr := strings.Trim(string(data), "\"") // we need to trim the quotes around the string
			// we expect a bech32 prefixed address, so lets convert to account address
			accAddr, err := sdk.AccAddressFromBech32(bech32Addr)
			if err != nil {
				return nil, err
			}
			lengthPrefixed := address.MustLengthPrefix(accAddr)
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString(lengthPrefixed),
			)
		case acltypes.AccessOperationSelectorType_SENDER_BECH32_ADDRESS:
			senderAccAddress, err := sdk.AccAddressFromBech32(senderBech)
			if err != nil {
				return nil, err
			}
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString(senderAccAddress),
			)
		case acltypes.AccessOperationSelectorType_SENDER_LENGTH_PREFIXED_ADDRESS:
			senderAccAddress, err := sdk.AccAddressFromBech32(senderBech)
			if err != nil {
				return nil, err
			}
			lengthPrefixed := address.MustLengthPrefix(senderAccAddress)
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString(lengthPrefixed),
			)
		case acltypes.AccessOperationSelectorType_CONTRACT_ADDRESS:
			contractAddress, err := sdk.AccAddressFromBech32(opWithSelector.Selector)
			if err != nil {
				return nil, err
			}
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hex.EncodeToString(contractAddress),
			)
		case acltypes.AccessOperationSelectorType_JQ_MESSAGE_CONDITIONAL:
			op, err := jq.Parse(opWithSelector.Selector)
			if err != nil {
				return nil, err
			}
			_, err = op.Apply(msgInfo.MessageFullBody)
			// if we are in a contract reference, we have to assume that this is necessary
			if err != nil && !withinContractReference {
				// if the operation is not applicable to the message, skip it
				continue
			}
		case acltypes.AccessOperationSelectorType_CONSTANT_STRING_TO_HEX:
			hexStr := hex.EncodeToString([]byte(opWithSelector.Selector))
			opWithSelector.Operation.IdentifierTemplate = fmt.Sprintf(
				opWithSelector.Operation.IdentifierTemplate,
				hexStr,
			)
		case acltypes.AccessOperationSelectorType_CONTRACT_REFERENCE:
			// Deprecated for ImportContractReference function
			continue
		}
		selectedAccessOps.Add(*opWithSelector.Operation)
	}

	return selectedAccessOps, nil
}
```

**File:** x/accesscontrol/types/access_operations.go (L7-9)
```go
type AccessOperationSet struct {
	ops map[acltypes.AccessOperation]struct{}
}
```

**File:** x/accesscontrol/types/access_operations.go (L46-60)
```go
func (waos *AccessOperationSet) ToSlice() []acltypes.AccessOperation {
	res := []acltypes.AccessOperation{}
	hasCommitOp := false
	for op := range waos.ops {
		if op != *CommitAccessOp() {
			res = append(res, op)
		} else {
			hasCommitOp = true
		}
	}
	if hasCommitOp {
		res = append(res, *CommitAccessOp())
	}
	return res
}
```

**File:** x/accesscontrol/keeper/keeper_test.go (L346-407)
```go
func TestWasmDependencyMappingWithJQSelector(t *testing.T) {
	app := simapp.Setup(false)
	ctx := app.BaseApp.NewContext(false, tmproto.Header{})

	wasmContractAddresses := simapp.AddTestAddrsIncremental(app, ctx, 1, sdk.NewInt(30000000))
	wasmContractAddress := wasmContractAddresses[0]
	wasmMapping := acltypes.WasmDependencyMapping{
		BaseAccessOps: []*acltypes.WasmAccessOperation{
			{
				Operation: &acltypes.AccessOperation{
					ResourceType:       acltypes.ResourceType_KV_WASM,
					AccessType:         acltypes.AccessType_WRITE,
					IdentifierTemplate: wasmContractAddress.String() + "/%s",
				},
				SelectorType: acltypes.AccessOperationSelectorType_JQ,
				Selector:     ".send.from",
			},
			{
				Operation: &acltypes.AccessOperation{
					ResourceType:       acltypes.ResourceType_KV_WASM,
					AccessType:         acltypes.AccessType_WRITE,
					IdentifierTemplate: wasmContractAddress.String() + "/%s",
				},
				SelectorType: acltypes.AccessOperationSelectorType_JQ,
				Selector:     ".receive.amount",
			},
			{
				Operation: &acltypes.AccessOperation{
					ResourceType:       acltypes.ResourceType_KV_WASM,
					AccessType:         acltypes.AccessType_WRITE,
					IdentifierTemplate: wasmContractAddress.String() + "/%s",
				},
				SelectorType: acltypes.AccessOperationSelectorType_JQ,
				Selector:     ".send.amount",
			},
			{
				Operation:    types.CommitAccessOp(),
				SelectorType: acltypes.AccessOperationSelectorType_NONE,
			},
		},
		ContractAddress: wasmContractAddress.String(),
	}
	// set the dependency mapping
	err := app.AccessControlKeeper.SetWasmDependencyMapping(ctx, wasmMapping)
	require.NoError(t, err)
	// test getting the dependency mapping
	mapping, err := app.AccessControlKeeper.GetRawWasmDependencyMapping(ctx, wasmContractAddress)
	require.NoError(t, err)
	require.Equal(t, wasmMapping, *mapping)
	// test getting a dependency mapping with selector
	info, _ := types.NewExecuteMessageInfo([]byte("{\"send\":{\"from\":\"bob\",\"amount\":10}}"))
	deps, err := app.AccessControlKeeper.GetWasmDependencyAccessOps(
		ctx,
		wasmContractAddress,
		"",
		info,
		make(aclkeeper.ContractReferenceLookupMap),
	)
	require.NoError(t, err)
	require.True(t, types.NewAccessOperationSet(deps).HasIdentifier(fmt.Sprintf("%s/%s", wasmContractAddress.String(), hex.EncodeToString([]byte("bob")))))
	require.True(t, types.NewAccessOperationSet(deps).HasIdentifier(fmt.Sprintf("%s/%s", wasmContractAddress.String(), hex.EncodeToString([]byte("10")))))
}
```
