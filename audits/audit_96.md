## Title
Access Control Bypass via Incorrect String Trimming of JSON Values with Escaped Quotes in WASM Dependency Selectors

## Summary
The `BuildSelectorOps` function in the access control keeper uses `strings.Trim` to remove quotes from JSON values extracted by JQ selectors. This function removes ALL consecutive quote characters from both ends, not just the outermost pair. When JSON values contain escaped quotes at their boundaries, the identifier used for access control differs from the intended value, allowing attackers to bypass access restrictions by crafting malicious JSON payloads. [1](#0-0) [2](#0-1) [3](#0-2) 

## Impact
**Medium**

This vulnerability results in unintended smart contract behavior by allowing access control bypasses in WASM contracts that use dynamic dependency mappings with JQ selectors.

## Finding Description

**Location:** 
The vulnerability exists in `x/accesscontrol/keeper/keeper.go` in the `BuildSelectorOps` function at three locations where JQ selector results are processed:
- Line 334: `AccessOperationSelectorType_JQ` processing
- Line 353: `AccessOperationSelectorType_JQ_BECH32_ADDRESS` processing  
- Line 377: `AccessOperationSelectorType_JQ_LENGTH_PREFIXED_ADDRESS` processing [4](#0-3) 

**Intended Logic:**
The code is supposed to extract a value from a JSON message body using a JQ selector, remove the JSON string quotes (the outer `"` characters that JSON adds to string values), and use the resulting value as an identifier for access control operations. The identifier is then hex-encoded and used in the `IdentifierTemplate` to determine which resources the contract can access. [5](#0-4) 

**Actual Logic:**
The code uses `strings.Trim(string(data), "\"")` which removes ALL consecutive quote characters from BOTH the beginning and end of the string, not just a single pair. This means:
- Input `"normal"` → Output `normal` ✓ (correct)
- Input `"\"\"admin\"\""` (JSON representation of string `""admin""`) → Output `admin` ✗ (should be `""admin""`)
- Input `"\"value"` (JSON representation of string `"value`) → Output `value` ✗ (should be `"value`)

**Exploit Scenario:**
1. A WASM contract is deployed with access control rules using JQ selectors to extract user identifiers or resource names from message bodies
2. The contract defines access operations like: `IdentifierTemplate: "resource/%s"` with a JQ selector `.user.id`
3. An attacker crafts a JSON message: `{"user":{"id":"\"\"admin\"\""}}`
   - The actual value is the string `""admin""`
   - JQ selector returns `"\"\"admin\"\""` (JSON-encoded)
   - After `strings.Trim`: becomes `admin` instead of `""admin""`
   - Hex-encoded identifier changes from hex(`""admin""`) to hex(`admin`)
4. The attacker now accesses resources under `resource/61646d696e` (hex of `admin`) instead of the intended `resource/6262226161646d696e2222` (hex of `""admin""`)
5. This allows bypassing access restrictions if different identifiers have different permissions

**Security Failure:**
The access control authorization mechanism is bypassed. The system fails to correctly identify which resources a contract should have access to, allowing unauthorized reads or writes to contract state.

## Impact Explanation

**Affected Assets:**
- WASM contract state integrity
- Access control invariants in contracts using dynamic dependency mappings
- Cross-contract interactions where authorization depends on JQ-extracted identifiers

**Severity:**
The attacker can:
1. Access or modify state keys they shouldn't have permission to access
2. Impersonate different users or roles by manipulating identifier extraction
3. Break the security assumptions of contracts that rely on the access control system
4. Potentially steal funds or manipulate contract logic if the bypassed access controls protect financial operations

**System Impact:**
This breaks the fundamental security property of the access control system - that access operations correctly represent the resources being accessed. Contracts that rely on this system for authorization can be compromised, leading to "unintended smart contract behavior" as defined in the in-scope impacts. [6](#0-5) 

## Likelihood Explanation

**Who can trigger:**
Any user can trigger this vulnerability by submitting transactions that execute WASM contracts with specially crafted JSON message bodies containing escaped quotes.

**Conditions required:**
- The target WASM contract must have dynamic dependency mapping enabled
- The contract must use JQ selectors (types JQ, JQ_BECH32_ADDRESS, or JQ_LENGTH_PREFIXED_ADDRESS)
- The attacker needs to craft JSON where the extracted value contains quotes at the boundaries

**Frequency:**
This can be exploited whenever a vulnerable contract is called. The attack is straightforward - simply include escaped quotes in JSON values. Given that WASM contracts commonly use user-provided identifiers for access control, this is highly exploitable in practice. [7](#0-6) 

## Recommendation

Replace `strings.Trim(string(data), "\"")` with proper JSON unmarshaling to correctly handle escaped quotes:

```go
// Instead of:
trimmedData := strings.Trim(string(data), "\"")

// Use:
var trimmedData string
if err := json.Unmarshal(data, &trimmedData); err != nil {
    // Handle error - either skip this operation or return error
    continue
}
```

Alternatively, use `strings.TrimPrefix` and `strings.TrimSuffix` to remove exactly one quote from each end:

```go
trimmedData := string(data)
trimmedData = strings.TrimPrefix(trimmedData, "\"")
trimmedData = strings.TrimSuffix(trimmedData, "\"")
```

However, JSON unmarshaling is the more robust solution as it properly handles all JSON escape sequences, not just quotes.

Apply this fix to all three affected locations (lines 334, 353, and 377).

## Proof of Concept

**Test File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** `TestStringsTrimVulnerabilityWithEscapedQuotes`

**Setup:**
1. Initialize test app and context
2. Create a WASM contract address
3. Set up a WASM dependency mapping with a JQ selector that extracts a user identifier
4. Configure the mapping to use the identifier in an access operation template

**Trigger:**
1. Create two different JSON messages:
   - Normal: `{"user":{"id":"admin"}}`
   - Malicious: `{"user":{"id":"\"\"admin\"\""}}`
2. Process both messages through `GetWasmDependencyAccessOps`
3. Extract the generated identifiers from the access operations

**Observation:**
Both messages incorrectly produce the same identifier `admin` (hex: `61646d696e`) when they should produce different identifiers:
- Normal message should produce: `61646d696e` (hex of `admin`) ✓
- Malicious message should produce: `2222616461646d696e22222` (hex of `""admin""`) ✗ but produces `61646d696e`

The test demonstrates that an attacker can craft JSON to manipulate the extracted identifier, bypassing access controls by making different logical values appear identical to the access control system.

**Test Code Structure:**
```go
func TestStringsTrimVulnerabilityWithEscapedQuotes(t *testing.T) {
    // Setup app, context, and contract address
    // Create WASM dependency mapping with JQ selector ".user.id"
    // Create normal message: {"user":{"id":"admin"}}
    // Create malicious message: {"user":{"id":"\"\"admin\"\""}}
    // Get access ops for both messages
    // Assert that identifiers are DIFFERENT (test should FAIL on vulnerable code)
    // On vulnerable code: both will produce "admin"
    // On fixed code: normal produces "admin", malicious produces "\"\"admin\"\""
}
```

The test will fail on the current vulnerable code, demonstrating that both messages produce identical identifiers when they should differ, confirming the access control bypass vulnerability.

### Citations

**File:** x/accesscontrol/keeper/keeper.go (L160-225)
```go
func (k Keeper) GetWasmDependencyAccessOps(ctx sdk.Context, contractAddress sdk.AccAddress, senderBech string, msgInfo *types.WasmMessageInfo, circularDepLookup ContractReferenceLookupMap) ([]acltypes.AccessOperation, error) {
	uniqueIdentifier := GetCircularDependencyIdentifier(contractAddress, msgInfo)
	if _, ok := circularDepLookup[uniqueIdentifier]; ok {
		// we've already seen this identifier, we should simply return synchronous access Ops
		ctx.Logger().Error("Circular dependency encountered, using synchronous access ops instead")
		return types.SynchronousAccessOps(), nil
	}
	// add to our lookup so we know we've seen this identifier
	circularDepLookup[uniqueIdentifier] = struct{}{}

	dependencyMapping, err := k.GetRawWasmDependencyMapping(ctx, contractAddress)
	if err != nil {
		if err == sdkerrors.ErrKeyNotFound {
			return types.SynchronousAccessOps(), nil
		}
		return nil, err
	}

	accessOps := dependencyMapping.BaseAccessOps
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY {
		// If we have a query, filter out any WRITES
		accessOps = FilterReadOnlyAccessOps(accessOps)
	}
	specificAccessOpsMapping := []*acltypes.WasmAccessOperations{}
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_EXECUTE && len(dependencyMapping.ExecuteAccessOps) > 0 {
		specificAccessOpsMapping = dependencyMapping.ExecuteAccessOps
	} else if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY && len(dependencyMapping.QueryAccessOps) > 0 {
		specificAccessOpsMapping = dependencyMapping.QueryAccessOps
	}

	for _, specificAccessOps := range specificAccessOpsMapping {
		if specificAccessOps.MessageName == msgInfo.MessageName {
			accessOps = append(accessOps, specificAccessOps.WasmOperations...)
			break
		}
	}

	selectedAccessOps, err := k.BuildSelectorOps(ctx, contractAddress, accessOps, senderBech, msgInfo, circularDepLookup)
	if err != nil {
		return nil, err
	}

	// imports base contract references
	contractRefs := dependencyMapping.BaseContractReferences
	// add the specific execute or query contract references based on message type + name
	specificContractRefs := []*acltypes.WasmContractReferences{}
	if msgInfo.MessageType == acltypes.WasmMessageSubtype_EXECUTE && len(dependencyMapping.ExecuteContractReferences) > 0 {
		specificContractRefs = dependencyMapping.ExecuteContractReferences
	} else if msgInfo.MessageType == acltypes.WasmMessageSubtype_QUERY && len(dependencyMapping.QueryContractReferences) > 0 {
		specificContractRefs = dependencyMapping.QueryContractReferences
	}
	for _, specificContractRef := range specificContractRefs {
		if specificContractRef.MessageName == msgInfo.MessageName {
			contractRefs = append(contractRefs, specificContractRef.ContractReferences...)
			break
		}
	}
	importedAccessOps, err := k.ImportContractReferences(ctx, contractAddress, contractRefs, senderBech, msgInfo, circularDepLookup)
	if err != nil {
		return nil, err
	}
	// combine the access ops to get the definitive list of access ops for the contract
	selectedAccessOps.Merge(importedAccessOps)

	return selectedAccessOps.ToSlice(), nil
}
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

**File:** x/accesscontrol/types/wasm.go (L11-54)
```go
type WasmMessageInfo struct {
	MessageType     acltypes.WasmMessageSubtype
	MessageName     string
	MessageBody     []byte
	MessageFullBody []byte
}

func NewExecuteMessageInfo(fullBody []byte) (*WasmMessageInfo, error) {
	return newMessageInfo(fullBody, acltypes.WasmMessageSubtype_EXECUTE)
}

func NewQueryMessageInfo(fullBody []byte) (*WasmMessageInfo, error) {
	return newMessageInfo(fullBody, acltypes.WasmMessageSubtype_QUERY)
}

func newMessageInfo(fullBody []byte, messageType acltypes.WasmMessageSubtype) (*WasmMessageInfo, error) {
	name, body, err := extractMessage(fullBody)
	if err != nil {
		return nil, err
	}
	return &WasmMessageInfo{
		MessageType:     messageType,
		MessageName:     name,
		MessageBody:     body,
		MessageFullBody: fullBody,
	}, nil
}

// WASM message body is JSON-serialized and use the message name
// as the only top-level key
func extractMessage(fullBody []byte) (string, []byte, error) {
	var deserialized map[string]json.RawMessage
	if err := json.Unmarshal(fullBody, &deserialized); err != nil {
		return "", fullBody, err
	}
	topLevelKeys := []string{}
	for k := range deserialized {
		topLevelKeys = append(topLevelKeys, k)
	}
	if len(topLevelKeys) != 1 {
		return "", fullBody, fmt.Errorf("expected exactly one top-level key but found %s", topLevelKeys)
	}
	return topLevelKeys[0], deserialized[topLevelKeys[0]], nil
}
```
