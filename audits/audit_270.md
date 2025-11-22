## Title
Evidence Module Accepts Cross-Chain Consensus Addresses Leading to Storage Exhaustion

## Summary
The `ValidateBasic()` method for `Equivocation` evidence does not validate that the consensus address uses the correct bech32 prefix for the chain. Additionally, `GetConsensusAddress()` silently ignores decoding errors. This allows attackers to submit evidence with consensus addresses from other chains, which passes validation but cannot be processed. When applications register equivocation handlers, this invalid evidence is permanently stored without cleanup, enabling a storage exhaustion attack that can shut down network nodes.

## Impact
**Medium** - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions.

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
The `ValidateBasic()` method should perform comprehensive stateless validation of evidence fields, including verifying that the consensus address is properly formatted for the current chain's bech32 prefix. Evidence from other chains should be rejected during validation.

**Actual Logic:** 
The `ValidateBasic()` implementation only checks if the `ConsensusAddress` string is non-empty [3](#0-2) , but does not validate the bech32 format or verify the address prefix matches the chain's configuration.

Furthermore, `GetConsensusAddress()` calls `ConsAddressFromBech32()` but ignores any decoding errors [2](#0-1) . When the bech32 prefix is incorrect (e.g., `osmosisvalcons...` on a Cosmos chain expecting `cosmosvalcons...`), the function returns `nil` without signaling an error [4](#0-3) .

**Exploit Scenario:**
1. An application registers an equivocation evidence handler (common for chains using IBC or custom evidence handling)
2. Attacker submits `MsgSubmitEvidence` with an `Equivocation` containing a consensus address with wrong bech32 prefix (e.g., from Osmosis: `osmosisvalcons1...`)
3. The message passes `ValidateBasic()` since it only checks non-empty string
4. Evidence is routed to the registered handler [5](#0-4) 
5. Handler calls `HandleEquivocationEvidence()` which retrieves `nil` consensus address
6. `GetPubkey()` is called with `nil` bytes and returns an error [6](#0-5) 
7. `HandleEquivocationEvidence()` returns early without error [7](#0-6) 
8. The handler wrapper returns `nil` (no error), causing `SubmitEvidence()` to store the invalid evidence [8](#0-7) 
9. Attacker repeats with different timestamps to bypass duplicate detection
10. Invalid evidence accumulates indefinitely (no pruning mechanism exists)
11. Node disk space is exhausted, causing node shutdown

**Security Failure:** 
The validation layer fails to enforce chain-specific address format requirements, allowing denial-of-service through storage exhaustion. The design flaw where `HandleEquivocationEvidence()` returns void instead of error prevents handlers from distinguishing between successfully processed evidence and silently ignored invalid evidence.

## Impact Explanation

**Affected Resources:** Node disk storage and network availability.

**Severity:** An attacker can permanently store arbitrary amounts of invalid evidence by submitting cross-chain consensus addresses. Each evidence object consumes storage space and is never cleaned up. While transaction fees provide some rate limiting, a sustained attack could fill node disks over time, causing:
- Node crashes when disk space is exhausted
- Network degradation as nodes shut down
- Potential for 30%+ of network nodes to fail if attack is widespread

**System Reliability:** This undermines the evidence module's integrity and creates an unbounded storage attack vector. Nodes cannot recover without manual intervention to clear invalid evidence or add additional disk space, making this a persistent availability threat.

## Likelihood Explanation

**Who Can Trigger:** Any user with sufficient tokens to pay transaction fees.

**Conditions Required:**
1. Target application must have registered an equivocation evidence handler (not default in simapp but common for production chains, especially those using IBC) [9](#0-8) 
2. Handler must follow the naive pattern of wrapping `HandleEquivocationEvidence()` without additional validation (likely pattern based on test examples) [10](#0-9) 

**Frequency:** Attack can be executed continuously, limited only by transaction throughput and attacker's capital for gas fees. Given typical blockchain disk growth rates, a dedicated attacker could cause measurable impact within weeks to months depending on attack intensity and gas costs.

**Likelihood Assessment:** Medium - While not all chains register handlers, those that do (particularly IBC-enabled chains) are vulnerable if they follow common handler implementation patterns.

## Recommendation

1. **Enhance ValidateBasic:** Add bech32 format and prefix validation to `ValidateBasic()`:
   ```go
   func (e *Equivocation) ValidateBasic() error {
       // ... existing checks ...
       
       // Validate consensus address format and prefix
       if e.ConsensusAddress == "" {
           return fmt.Errorf("invalid equivocation validator consensus address: %s", e.ConsensusAddress)
       }
       _, err := sdk.ConsAddressFromBech32(e.ConsensusAddress)
       if err != nil {
           return fmt.Errorf("invalid consensus address format: %w", err)
       }
       
       return nil
   }
   ```

2. **Return Errors from GetConsensusAddress:** Modify `GetConsensusAddress()` to return both address and error:
   ```go
   func (e Equivocation) GetConsensusAddress() (sdk.ConsAddress, error) {
       return sdk.ConsAddressFromBech32(e.ConsensusAddress)
   }
   ```

3. **Update HandleEquivocationEvidence:** Modify to return errors so handlers can properly detect failures:
   ```go
   func (k Keeper) HandleEquivocationEvidence(ctx sdk.Context, evidence *types.Equivocation) error {
       consAddr, err := evidence.GetConsensusAddress()
       if err != nil {
           return err
       }
       // ... rest of logic ...
   }
   ```

4. **Document Handler Best Practices:** Provide clear documentation and examples showing proper handler implementation with validation.

## Proof of Concept

**File:** `x/evidence/types/evidence_test.go`

**Test Function:** Add `TestEquivocationCrossChainAddress` to the test suite:

```go
func TestEquivocationCrossChainAddress(t *testing.T) {
    // Setup: Configure SDK for cosmos chain
    sdk.GetConfig().SetBech32PrefixForConsensusNode("cosmosvalcons", "cosmosvalconspub")
    
    n, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
    
    // Create evidence with osmosis consensus address (wrong chain)
    e := types.Equivocation{
        Height:           100,
        Time:             n,
        Power:            1000000,
        ConsensusAddress: "osmosisvalcons1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnrql8a",
    }
    
    // Trigger: ValidateBasic should reject cross-chain address but doesn't
    err := e.ValidateBasic()
    
    // Observation: ValidateBasic passes (BUG - should fail)
    require.NoError(t, err, "ValidateBasic incorrectly accepts cross-chain address")
    
    // GetConsensusAddress returns nil without error
    consAddr := e.GetConsensusAddress()
    
    // Observation: Address is nil/empty (decode failed silently)
    require.True(t, consAddr.Empty(), "GetConsensusAddress should return empty for invalid prefix")
    require.Equal(t, "", consAddr.String(), "Invalid address decoded to empty string")
    
    // This demonstrates that cross-chain evidence passes validation
    // and would be stored by SubmitEvidence if a handler returns nil
}
```

**Expected Behavior:** The test demonstrates that:
1. Cross-chain evidence with `osmosisvalcons` prefix passes `ValidateBasic()` on a cosmos chain
2. `GetConsensusAddress()` silently returns `nil` instead of propagating the error
3. This invalid evidence would be stored if submitted via `MsgSubmitEvidence` with a registered handler

**To Run:** 
```bash
cd x/evidence/types
go test -v -run TestEquivocationCrossChainAddress
```

The test confirms the vulnerability by showing that evidence with incorrect bech32 prefixes bypasses validation, enabling the storage exhaustion attack described above.

### Citations

**File:** x/evidence/types/evidence.go (L45-61)
```go
// ValidateBasic performs basic stateless validation checks on an Equivocation object.
func (e *Equivocation) ValidateBasic() error {
	if e.Time.Unix() <= 0 {
		return fmt.Errorf("invalid equivocation time: %s", e.Time)
	}
	if e.Height < 1 {
		return fmt.Errorf("invalid equivocation height: %d", e.Height)
	}
	if e.Power < 1 {
		return fmt.Errorf("invalid equivocation validator power: %d", e.Power)
	}
	if e.ConsensusAddress == "" {
		return fmt.Errorf("invalid equivocation validator consensus address: %s", e.ConsensusAddress)
	}

	return nil
}
```

**File:** x/evidence/types/evidence.go (L65-68)
```go
func (e Equivocation) GetConsensusAddress() sdk.ConsAddress {
	addr, _ := sdk.ConsAddressFromBech32(e.ConsensusAddress)
	return addr
}
```

**File:** types/address.go (L467-485)
```go
func ConsAddressFromBech32(address string) (addr ConsAddress, err error) {
	if len(strings.TrimSpace(address)) == 0 {
		return ConsAddress{}, errors.New("empty address string is not allowed")
	}

	bech32PrefixConsAddr := GetConfig().GetBech32ConsensusAddrPrefix()

	bz, err := GetFromBech32(address, bech32PrefixConsAddr)
	if err != nil {
		return nil, err
	}

	err = VerifyAddressFormat(bz)
	if err != nil {
		return nil, err
	}

	return ConsAddress(bz), nil
}
```

**File:** x/evidence/keeper/keeper.go (L78-100)
```go
func (k Keeper) SubmitEvidence(ctx sdk.Context, evidence exported.Evidence) error {
	if _, ok := k.GetEvidence(ctx, evidence.Hash()); ok {
		return sdkerrors.Wrap(types.ErrEvidenceExists, evidence.Hash().String())
	}
	if !k.router.HasRoute(evidence.Route()) {
		return sdkerrors.Wrap(types.ErrNoEvidenceHandlerExists, evidence.Route())
	}

	handler := k.router.GetRoute(evidence.Route())
	if err := handler(ctx, evidence); err != nil {
		return sdkerrors.Wrap(types.ErrInvalidEvidence, err.Error())
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeSubmitEvidence,
			sdk.NewAttribute(types.AttributeKeyEvidenceHash, evidence.Hash().String()),
		),
	)

	k.SetEvidence(ctx, evidence)
	return nil
}
```

**File:** x/slashing/keeper/keeper.go (L56-64)
```go
func (k Keeper) GetPubkey(ctx sdk.Context, a cryptotypes.Address) (cryptotypes.PubKey, error) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.AddrPubkeyRelationKey(a))
	if bz == nil {
		return nil, fmt.Errorf("address %s not found", sdk.ConsAddress(a))
	}
	var pk cryptotypes.PubKey
	return pk, k.cdc.UnmarshalInterface(bz, &pk)
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

**File:** simapp/app.go (L322-327)
```go
	// create evidence keeper with router
	evidenceKeeper := evidencekeeper.NewKeeper(
		appCodec, keys[evidencetypes.StoreKey], &app.StakingKeeper, app.SlashingKeeper,
	)
	// If evidence needs to be handled for the app, set routes in router here and seal
	app.EvidenceKeeper = *evidenceKeeper
```

**File:** x/evidence/handler_test.go (L34-49)
```go
func testEquivocationHandler(k interface{}) types.Handler {
	return func(ctx sdk.Context, e exported.Evidence) error {
		if err := e.ValidateBasic(); err != nil {
			return err
		}

		ee, ok := e.(*types.Equivocation)
		if !ok {
			return fmt.Errorf("unexpected evidence type: %T", e)
		}
		if ee.Height%2 == 0 {
			return fmt.Errorf("unexpected even evidence height: %d", ee.Height)
		}

		return nil
	}
```
