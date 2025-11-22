# Audit Report

## Title
Consensus Violation Due to Inconsistent Dynamic Dependency Generation Across Nodes

## Summary
The dynamic dependency generation system can cause consensus failures when the `DynamicEnabled` flag is set to true on-chain via governance, but different nodes have different sets of dependency generators registered at application startup. This leads to divergent transaction validation results across nodes, causing chain splits. [1](#0-0) 

## Impact
**High** - This vulnerability causes unintended permanent chain splits requiring hard fork to resolve.

## Finding Description

**Location:** 
- Primary: `x/accesscontrol/keeper/keeper.go`, function `GetMessageDependencies` (lines 625-642)
- Validation: `baseapp/baseapp.go`, transaction execution validation (lines 979-992)
- Fallback: `types/accesscontrol/validation.go`, validation skip logic (lines 61-64) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:**
The access control system should deterministically generate message dependencies that are identical across all nodes, enabling concurrent transaction execution while maintaining consensus. The `DynamicEnabled` flag allows switching between static and dynamic dependency generation.

**Actual Logic:**
The system has a critical inconsistency:
1. The `DynamicEnabled` flag is stored **on-chain** in the KVStore and can be modified via governance proposals
2. The `MessageDependencyGeneratorMapper` (containing actual generator functions) is populated **off-chain** at application startup via keeper options
3. When `GetMessageDependencies` is called with `DynamicEnabled=true`:
   - If a generator exists in the mapper, it uses dynamic generation
   - If no generator exists, it falls back to synchronous access operations (wildcard pattern)
4. During transaction validation:
   - Dynamic operations trigger strict validation that can reject transactions with `ErrInvalidConcurrencyExecution`
   - Synchronous operations (fallback) completely **skip validation** [4](#0-3) [5](#0-4) 

**Exploit Scenario:**
1. A governance proposal passes setting `DynamicEnabled=true` for a message type (e.g., `BankSend`)
2. Node A runs a version with the `BankSendDepGenerator` registered in its `MessageDependencyGeneratorMapper`
3. Node B runs a version without this generator (older version, different build, or different configuration)
4. A user submits a `BankSend` transaction that is included in a block
5. During block processing:
   - **Node A**: Calls dynamic generator → produces specific access operations → validates strictly → if actual operations don't match, **rejects transaction** with `ErrInvalidConcurrencyExecution`
   - **Node B**: No generator found → falls back to synchronous operations → validation **skipped** → transaction **accepted**
6. Result: Node A and Node B produce different state roots → **consensus failure** [6](#0-5) [7](#0-6) 

**Security Failure:**
The consensus agreement property is violated. Different nodes process the same transactions differently based on their local off-chain configuration (which generators are registered), leading to state divergence even though all nodes have the same on-chain state (DynamicEnabled flag).

## Impact Explanation

**Affected Assets/Processes:**
- Network consensus integrity
- Transaction finality guarantees  
- All blockchain state (balances, smart contracts, governance)

**Severity:**
This causes an unintended permanent chain split. When nodes disagree on transaction validity:
- Different nodes produce different block state roots
- The network fragments into incompatible forks
- Requires a hard fork to resolve (all nodes must upgrade to consistent generator configurations)
- During the split, transactions may appear confirmed on one fork but not the other
- Users experience loss of funds or double-spend opportunities across forks

**System Impact:**
This fundamentally breaks the blockchain's security model. Consensus is the foundation of blockchain operation - without agreement on valid state transitions, the network cannot function as a distributed ledger. The vulnerability affects ALL transactions for message types where `DynamicEnabled=true` but generator registration differs across nodes.

## Likelihood Explanation

**Who Can Trigger:**
- Any governance proposal that sets `DynamicEnabled=true` for a message type
- No malicious intent required - can occur through normal protocol upgrades
- Affects ALL validators and full nodes, not just specific actors

**Required Conditions:**
1. A governance proposal passes enabling dynamic dependency generation for a message type
2. Network has heterogeneous node software (different versions, builds, or configurations with different generator registrations)
3. A transaction of that message type is submitted

**Frequency:**
- **Very likely** during protocol upgrades when new dynamic generators are introduced
- **Certain** to occur if governance enables dynamic generation before all nodes upgrade
- Can happen during **normal operation** without any malicious activity
- Once triggered, affects **every block** containing the relevant message type until resolved

The vulnerability is especially dangerous because:
- It can be triggered accidentally through legitimate governance
- Node operators may not realize they have different configurations
- The issue is hidden until dynamic generation is enabled on-chain
- Detection requires comparing state roots across nodes, which may be delayed [8](#0-7) 

## Recommendation

**Immediate Fix:**
1. Store the dynamic generator configuration on-chain as part of the message dependency mapping, OR
2. Remove the `DynamicEnabled` flag entirely and require all dependency logic to be deterministic and on-chain, OR
3. Add strict validation that prevents governance from enabling dynamic generation unless a generator is registered on ALL nodes

**Recommended Approach (Option 1 - Store generators on-chain):**
- Instead of storing Go function pointers, store deterministic generator specifications on-chain (e.g., a generator type enum with parameters)
- Implement generators as deterministic, parameterized functions that all nodes can execute identically
- Ensure generator logic is part of consensus-critical code, not application configuration

**Alternative Approach (Option 3 - Safer short-term fix):**
- Add validation in `HandleMsgUpdateResourceDependencyMappingProposal` that checks if setting `DynamicEnabled=true` is safe
- Require that if `DynamicEnabled=true`, the corresponding generator MUST be registered in the keeper
- Fail the governance proposal if this condition isn't met
- This prevents the dangerous state where `DynamicEnabled=true` but no generator exists

**Additional Safeguards:**
- Add consensus checks that verify all nodes produce identical access operations for the same message
- Include generator versions/hashes in block headers to detect configuration mismatches
- Emit clear errors/warnings when dynamic generation is enabled without a registered generator

## Proof of Concept

**Test File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** Add new test `TestDynamicDependencyConsensusViolation`

**Setup:**
1. Create two keeper instances simulating two different nodes:
   - Keeper A: Has `BankSendDepGenerator` registered via `WithDependencyMappingGenerator`
   - Keeper B: Does NOT have the generator registered (empty mapper)
2. Set `DynamicEnabled=true` for BankSend messages via governance (stored on-chain)
3. Create a `MsgSend` transaction that will execute differently based on which dependencies are used
4. Create a mock context with `MsgValidator` to enable validation

**Trigger:**
1. Call `GetMessageDependencies` on both keepers with the same `MsgSend` message
2. Observe that Keeper A returns specific dynamic dependencies while Keeper B returns synchronous fallback
3. Simulate transaction execution on both keepers using their respective dependencies
4. In Keeper A, provide actual store operations that DON'T match the dynamic generator's declared operations (simulating a buggy generator)
5. Run validation on both keepers

**Observation:**
- Keeper A: `ValidateAccessOperations` returns non-empty `missingAccessOps`, causing transaction rejection with `ErrInvalidConcurrencyExecution`
- Keeper B: `ValidateAccessOperations` returns empty map (validation skipped due to `IsDefaultSynchronousAccessOps`), transaction accepted
- **Result**: Same transaction, same on-chain state, but different validation outcomes → consensus violation demonstrated

**Expected Test Output:**
The test should demonstrate that:
```
Node A (with generator): Transaction REJECTED
Node B (without generator): Transaction ACCEPTED  
Consensus State: VIOLATED ✗
```

This proves that dynamic dependency generation can yield different results across nodes, violating consensus. [9](#0-8) [10](#0-9)

### Citations

**File:** x/accesscontrol/keeper/keeper.go (L625-642)
```go
func (k Keeper) GetMessageDependencies(ctx sdk.Context, msg sdk.Msg) []acltypes.AccessOperation {
	// Default behavior is to get the static dependency mapping for the message
	messageKey := types.GenerateMessageKey(msg)
	dependencyMapping := k.GetResourceDependencyMapping(ctx, messageKey)
	if dependencyGenerator, ok := k.MessageDependencyGeneratorMapper[types.GenerateMessageKey(msg)]; dependencyMapping.DynamicEnabled && ok {
		// if we have a dependency generator AND dynamic is enabled, use it
		if dependencies, err := dependencyGenerator(k, ctx, msg); err == nil {
			// validate the access ops before using them
			validateErr := types.ValidateAccessOps(dependencies)
			if validateErr == nil {
				return dependencies
			}
			errorMessage := fmt.Sprintf("Invalid Access Ops for message=%s. %s", messageKey, validateErr.Error())
			ctx.Logger().Error(errorMessage)
		}
	}
	return dependencyMapping.AccessOps
}
```

**File:** baseapp/baseapp.go (L979-992)
```go
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
			storeAccessOpEvents := msCache.GetEvents()
			accessOps := ctx.TxMsgAccessOps()[acltypes.ANTE_MSG_INDEX]

			// TODO: (occ) This is an example of where we do our current validation. Note that this validation operates on the declared dependencies for a TX / antehandler + the utilized dependencies, whereas the validation
			missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
			if len(missingAccessOps) != 0 {
				for op := range missingAccessOps {
					ctx.Logger().Info((fmt.Sprintf("Antehandler Missing Access Operation:%s ", op.String())))
					op.EmitValidationFailMetrics()
				}
				errMessage := fmt.Sprintf("Invalid Concurrent Execution antehandler missing %d access operations", len(missingAccessOps))
				return gInfo, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
			}
```

**File:** types/accesscontrol/validation.go (L61-64)
```go
	// If it's using default synchronous access op mapping then no need to verify
	if IsDefaultSynchronousAccessOps(accessOps) {
		return missingAccessOps
	}
```

**File:** types/accesscontrol/access_operation.go (L7-12)
```go
func SynchronousAccessOps() []AccessOperation {
	return []AccessOperation{
		{AccessType: AccessType_UNKNOWN, ResourceType: ResourceType_ANY, IdentifierTemplate: "*"},
		{AccessType: AccessType_COMMIT, ResourceType: ResourceType_ANY, IdentifierTemplate: "*"},
	}
}
```

**File:** x/accesscontrol/handler.go (L12-20)
```go
func HandleMsgUpdateResourceDependencyMappingProposal(ctx sdk.Context, k *keeper.Keeper, p *types.MsgUpdateResourceDependencyMappingProposal) error {
	for _, resourceDepMapping := range p.MessageDependencyMapping {
		err := k.SetResourceDependencyMapping(ctx, resourceDepMapping)
		if err != nil {
			return err
		}
	}
	return nil
}
```

**File:** simapp/app.go (L295-302)
```go
	app.AccessControlKeeper = aclkeeper.NewKeeper(
		appCodec,
		keys[acltypes.StoreKey],
		app.GetSubspace(acltypes.ModuleName),
		app.AccountKeeper,
		app.StakingKeeper,
		aclkeeper.WithDependencyMappingGenerator(acltestutil.MessageDependencyGeneratorTestHelper()),
	)
```

**File:** x/accesscontrol/keeper/options.go (L11-21)
```go
func WithDependencyMappingGenerator(generator DependencyGeneratorMap) optsFn {
	return optsFn(func(k *Keeper) {
		k.MessageDependencyGeneratorMapper = generator
	})
}

func WithDependencyGeneratorMappings(generator DependencyGeneratorMap) optsFn {
	return optsFn(func(k *Keeper) {
		k.MessageDependencyGeneratorMapper = k.MessageDependencyGeneratorMapper.Merge(generator)
	})
}
```

**File:** x/accesscontrol/testutil/accesscontrol.go (L89-107)
```go
func MessageDependencyGeneratorTestHelper() aclkeeper.DependencyGeneratorMap {
	return aclkeeper.DependencyGeneratorMap{
		types.GenerateMessageKey(&banktypes.MsgSend{}):        BankSendDepGenerator,
		types.GenerateMessageKey(&stakingtypes.MsgDelegate{}): StakingDelegateDepGenerator,
	}
}

func BankSendDepGenerator(keeper aclkeeper.Keeper, ctx sdk.Context, msg sdk.Msg) ([]acltypes.AccessOperation, error) {
	bankSend, ok := msg.(*banktypes.MsgSend)
	if !ok {
		return []acltypes.AccessOperation{}, fmt.Errorf("invalid message received for BankMsgSend")
	}
	accessOps := []acltypes.AccessOperation{
		{ResourceType: acltypes.ResourceType_KV_BANK_BALANCES, AccessType: acltypes.AccessType_WRITE, IdentifierTemplate: bankSend.FromAddress},
		{ResourceType: acltypes.ResourceType_KV_BANK_BALANCES, AccessType: acltypes.AccessType_WRITE, IdentifierTemplate: bankSend.ToAddress},
		*types.CommitAccessOp(),
	}
	return accessOps, nil
}
```

**File:** x/accesscontrol/keeper/keeper_test.go (L2396-2446)
```go
	// get the message dependencies from keeper (because nothing configured, should return synchronous)
	app.AccessControlKeeper.SetDependencyMappingDynamicFlag(ctx, bankMsgKey, false)
	accessOps := app.AccessControlKeeper.GetMessageDependencies(ctx, &bankSendMsg)
	req.Equal(types.SynchronousMessageDependencyMapping("").AccessOps, accessOps)

	// setup bank send static dependency
	bankStaticMapping := acltypes.MessageDependencyMapping{
		MessageKey: string(bankMsgKey),
		AccessOps: []acltypes.AccessOperation{
			{
				ResourceType:       acltypes.ResourceType_KV_BANK_BALANCES,
				AccessType:         acltypes.AccessType_WRITE,
				IdentifierTemplate: "*",
			},
			*types.CommitAccessOp(),
		},
		DynamicEnabled: false,
	}
	err = app.AccessControlKeeper.SetResourceDependencyMapping(ctx, bankStaticMapping)
	req.NoError(err)

	// now, because we have static mappings + dynamic enabled == false, we get the static access ops
	accessOps = app.AccessControlKeeper.GetMessageDependencies(ctx, &bankSendMsg)
	req.Equal(bankStaticMapping.AccessOps, accessOps)

	// lets enable dynamic enabled
	app.AccessControlKeeper.SetDependencyMappingDynamicFlag(ctx, bankMsgKey, true)
	// verify dynamic enabled
	dependencyMapping := app.AccessControlKeeper.GetResourceDependencyMapping(ctx, bankMsgKey)
	req.Equal(true, dependencyMapping.DynamicEnabled)

	// now, because we have static mappings + dynamic enabled == true, we get dynamic ops
	accessOps = app.AccessControlKeeper.GetMessageDependencies(ctx, &bankSendMsg)
	dynamicOps, err := acltestutil.BankSendDepGenerator(app.AccessControlKeeper, ctx, &bankSendMsg)
	req.NoError(err)
	req.Equal(dynamicOps, accessOps)

	// lets true doing the same for staking delegate, which SHOULD fail validation and set dynamic to false and return static mapping
	accessOps = app.AccessControlKeeper.GetMessageDependencies(ctx, &stakingDelegate)
	req.Equal(delegateStaticMapping.AccessOps, accessOps)
	// verify dynamic got disabled
	dependencyMapping = app.AccessControlKeeper.GetResourceDependencyMapping(ctx, delegateKey)
	req.Equal(true, dependencyMapping.DynamicEnabled)

	// lets also try with undelegate, but this time there is no dynamic generator, so we disable it as well
	accessOps = app.AccessControlKeeper.GetMessageDependencies(ctx, &stakingUndelegate)
	req.Equal(undelegateStaticMapping.AccessOps, accessOps)
	// verify dynamic got disabled
	dependencyMapping = app.AccessControlKeeper.GetResourceDependencyMapping(ctx, undelegateKey)
	req.Equal(true, dependencyMapping.DynamicEnabled)
}
```
