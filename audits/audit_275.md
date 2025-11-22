## Title
BeginBlocker Chain Halt via Malformed ABCI Evidence Address Causing Bech32 Encoding Panic

## Summary
The `FromABCIEvidence` function in the evidence module panics if Bech32 address encoding fails when converting ABCI evidence from CometBFT. This function is called during BeginBlocker processing without any prior validation, meaning malformed evidence with an invalid validator address can cause all nodes to panic and halt the chain. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary vulnerability: `x/evidence/types/evidence.go`, function `FromABCIEvidence`, lines 91-104
- Called from: `x/evidence/abci.go`, function `BeginBlocker`, line 24

**Intended Logic:** 
The evidence module should handle ABCI evidence from CometBFT gracefully, converting it to SDK evidence types for processing. The developers acknowledged in the specification that CometBFT might send unexpected evidence and implemented defensive handling in `HandleEquivocationEvidence` to avoid coupling application expectations too tightly with CometBFT's behavior. [2](#0-1) 

**Actual Logic:** 
The `FromABCIEvidence` function attempts to convert the validator address from ABCI evidence to Bech32 format and panics immediately if the conversion fails. The ABCI proto definition allows validator addresses to be any byte array, with no length constraints enforced at the protocol level. [3](#0-2) 

**Exploit Scenario:**
1. CometBFT sends evidence via `RequestBeginBlock.ByzantineValidators` with a validator address that causes Bech32 encoding to fail (e.g., an address exceeding the encoding length limits or with problematic byte patterns)
2. BeginBlocker calls `FromABCIEvidence` to convert the evidence without any prior validation
3. `Bech32ifyAddressBytes` is called with the malformed address
4. Bech32 encoding fails and returns an error
5. The code panics instead of handling the error gracefully
6. All nodes processing this block encounter the same panic
7. Chain halts as no nodes can proceed past BeginBlock [4](#0-3) 

**Security Failure:** 
This breaks the availability guarantee of the blockchain. A single block with malformed evidence causes all honest nodes to crash during consensus block processing, resulting in a complete network shutdown. The panic occurs before the defensive error handling in `HandleEquivocationEvidence` can catch it.

## Impact Explanation

**Affected Processes:** 
All network nodes become unable to process blocks, causing complete chain halt and loss of network availability.

**Severity of Damage:**
- All nodes crash when processing the malformed evidence
- No new transactions can be confirmed
- The chain cannot progress until the issue is resolved (likely requiring emergency coordination and potentially a hard fork)
- Network downtime persists until all validators manually intervene

**Why This Matters:**
Blockchain availability is a critical security property. A chain halt requires emergency intervention, damages user trust, and can cause significant financial losses for users unable to transact. The vulnerability allows the consensus layer (CometBFT) to crash the application layer (SDK) with malformed data, violating the defense-in-depth principle.

## Likelihood Explanation

**Who Can Trigger:**
This depends on CometBFT's evidence validation:
- If CometBFT has a bug in evidence validation, malformed evidence could occur naturally
- If a Byzantine block proposer can inject malformed evidence that passes CometBFT consensus checks
- If there are protocol upgrade incompatibilities between CometBFT and SDK evidence formats

**Conditions Required:**
- CometBFT must send evidence with a validator address that causes Bech32 encoding to fail
- While normal validator addresses are 20 bytes (valid), the proto definition allows any byte array
- The SDK developers explicitly acknowledged that CometBFT might send unexpected evidence formats

**Frequency:**
If triggered, every node processing the block would experience the panic. The issue would be deterministic - once a block with malformed evidence exists, all nodes attempting to process it would crash. The likelihood depends on CometBFT's validation robustness, but the SDK should defensively handle this case regardless.

## Recommendation

Replace the panic in `FromABCIEvidence` with graceful error handling that returns a default or skips invalid evidence:

```go
func FromABCIEvidence(e abci.Evidence) exported.Evidence {
    bech32PrefixConsAddr := sdk.GetConfig().GetBech32ConsensusAddrPrefix()
    consAddr, err := sdk.Bech32ifyAddressBytes(bech32PrefixConsAddr, e.Validator.Address)
    if err != nil {
        // Log the error and return nil or default evidence
        // This prevents chain halt from malformed external input
        return nil
    }
    // ... rest of function
}
```

Then modify `BeginBlocker` to check for nil evidence:

```go
evidence := types.FromABCIEvidence(tmEvidence)
if evidence == nil {
    k.Logger(ctx).Error(fmt.Sprintf("ignored invalid evidence: failed to convert ABCI evidence"))
    continue
}
k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))
```

This aligns with the defensive approach already implemented in `HandleEquivocationEvidence` where invalid evidence is logged and ignored rather than causing a panic. [5](#0-4) 

## Proof of Concept

**File:** `x/evidence/types/evidence_test.go`

**Test Function:** Add the following test to demonstrate the panic:

```go
func TestFromABCIEvidence_PanicOnBech32EncodingFailure(t *testing.T) {
    // Setup: Configure SDK with a consensus address prefix
    sdk.GetConfig().SetBech32PrefixForConsensusNode("cosmosvalcons", "cosmosvalconspub")
    
    // Test 1: Normal 20-byte address should work fine
    normalEvidence := abci.Evidence{
        Type: abci.MisbehaviorType_DUPLICATE_VOTE,
        Validator: abci.Validator{
            Address: make([]byte, 20), // Standard validator address length
            Power:   100,
        },
        Height:           1,
        Time:             time.Now(),
        TotalVotingPower: 100,
    }
    
    evidence := types.FromABCIEvidence(normalEvidence)
    require.NotNil(t, evidence)
    
    // Test 2: Very long address that would exceed bech32 encoding limits
    // should panic (demonstrating the vulnerability)
    longEvidence := abci.Evidence{
        Type: abci.MisbehaviorType_DUPLICATE_VOTE,
        Validator: abci.Validator{
            Address: make([]byte, 200), // Abnormally long address
            Power:   100,
        },
        Height:           1,
        Time:             time.Now(),
        TotalVotingPower: 100,
    }
    
    // Trigger: This call should panic due to bech32 encoding failure
    require.Panics(t, func() {
        types.FromABCIEvidence(longEvidence)
    }, "FromABCIEvidence should panic with long validator address")
}
```

**Setup:** The test initializes the SDK config with consensus address prefix and creates two ABCI evidence instances - one with normal 20-byte address and one with an abnormally long 200-byte address.

**Trigger:** When `FromABCIEvidence` is called with the long address, it attempts to encode it as Bech32, which fails due to length constraints, triggering the panic.

**Observation:** The test uses `require.Panics` to verify that the function panics when given malformed evidence. This confirms that BeginBlocker would crash if CometBFT sends such evidence, causing a chain halt. The test should pass (confirming the panic occurs), which demonstrates the vulnerability.

### Citations

**File:** x/evidence/types/evidence.go (L91-104)
```go
func FromABCIEvidence(e abci.Evidence) exported.Evidence {
	bech32PrefixConsAddr := sdk.GetConfig().GetBech32ConsensusAddrPrefix()
	consAddr, err := sdk.Bech32ifyAddressBytes(bech32PrefixConsAddr, e.Validator.Address)
	if err != nil {
		panic(err)
	}

	return &Equivocation{
		Height:           e.Height,
		Power:            e.Validator.Power,
		ConsensusAddress: consAddr,
		Time:             e.Time,
	}
}
```

**File:** x/evidence/spec/06_begin_block.md (L56-66)
```markdown
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
```

**File:** third_party/proto/tendermint/abci/types.proto (L411-416)
```text
// Validator
message Validator {
  bytes address = 1;  // The first 20 bytes of SHA256(public key)
  // PubKey pub_key = 2 [(gogoproto.nullable)=false];
  int64 power = 3;  // The voting power
}
```

**File:** x/evidence/abci.go (L16-31)
```go
func BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock, k keeper.Keeper) {
	defer telemetry.ModuleMeasureSince(types.ModuleName, time.Now(), telemetry.MetricKeyBeginBlocker)

	for _, tmEvidence := range req.ByzantineValidators {
		switch tmEvidence.Type {
		// It's still ongoing discussion how should we treat and slash attacks with
		// premeditation. So for now we agree to treat them in the same way.
		case abci.MisbehaviorType_DUPLICATE_VOTE, abci.MisbehaviorType_LIGHT_CLIENT_ATTACK:
			evidence := types.FromABCIEvidence(tmEvidence)
			k.HandleEquivocationEvidence(ctx, evidence.(*types.Equivocation))

		default:
			k.Logger(ctx).Error(fmt.Sprintf("ignored unknown evidence type: %s", tmEvidence.Type))
		}
	}
}
```

**File:** x/evidence/keeper/infraction.go (L29-40)
```go
	if _, err := k.slashingKeeper.GetPubkey(ctx, consAddr.Bytes()); err != nil {
		// Ignore evidence that cannot be handled.
		//
		// NOTE: We used to panic with:
		// `panic(fmt.Sprintf("Validator consensus-address %v not found", consAddr))`,
		// but this couples the expectations of the app to both Tendermint and
		// the simulator.  Both are expected to provide the full range of
		// allowable but none of the disallowed evidence types.  Instead of
		// getting this coordination right, it is easier to relax the
		// constraints and ignore evidence that cannot be handled.
		return
	}
```
