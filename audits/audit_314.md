## Audit Report

## Title
Insufficient Public Key Type Validation in MsgCreateValidator.ValidateBasic Allows Chain Halt via Incompatible Consensus Keys

## Summary
`MsgCreateValidator.ValidateBasic` only validates that the public key field is not nil, but fails to verify that the public key type is compatible with Tendermint consensus. This allows validators to be created with public key types that are registered in the Cosmos SDK but unsupported by Tendermint (e.g., multisig, sr25519, secp256r1). When such validators become active and the staking module attempts to generate ABCI validator updates during `EndBlock`, the conversion to Tendermint's public key format panics, causing a total chain halt.

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** 
- Primary vulnerability: [1](#0-0) 
- Panic location: [2](#0-1) 
- Unsupported key type handling: [3](#0-2) 

**Intended Logic:** 
`ValidateBasic` should provide stateless validation to reject malformed or invalid messages before they enter the transaction processing pipeline. It should ensure that public keys used for validator consensus are compatible with Tendermint's requirements.

**Actual Logic:** 
The current implementation only checks if the `Pubkey` field is not nil: [4](#0-3) 

It does not validate that the public key type is compatible with Tendermint. Multiple public key types are registered in the SDK (ed25519, secp256k1, multisig, sr25519, secp256r1): [5](#0-4) 

However, the `ToTmProtoPublicKey` function used during validator set updates only supports ed25519 and secp256k1, returning an error for other types: [6](#0-5) 

The check in `CreateValidator` validates against consensus params but only if they are set and only verifies the type is in the allowed list: [7](#0-6) 

The consensus params validation only ensures `PubKeyTypes` is non-empty, not that types are Tendermint-compatible: [8](#0-7) 

**Exploit Scenario:**
1. During genesis or via governance, consensus params are configured to allow an incompatible public key type (e.g., "PubKeyMultisigThreshold")
2. An attacker submits `MsgCreateValidator` with a multisig public key
3. `ValidateBasic` passes (only checks non-nil)
4. `CreateValidator` passes (type is in consensus params' allowed list)
5. Validator is stored successfully
6. When the validator becomes active, `BlockValidatorUpdates` is called during `EndBlock`: [9](#0-8) 
7. This calls `ABCIValidatorUpdate` which panics on unsupported key types: [10](#0-9) 
8. The panic during `EndBlock` halts the entire chain

**Security Failure:** 
Denial-of-service causing total network shutdown. The panic occurs in critical consensus code path during `EndBlock` processing, preventing any further block production.

## Impact Explanation

This vulnerability affects the entire network's availability:
- **Network Availability:** Once triggered, the chain completely halts as the panic occurs during `EndBlock` before the block can be committed
- **Transaction Processing:** All pending and future transactions cannot be processed
- **Consensus Breakdown:** The network cannot reach consensus on new blocks
- **Recovery:** Requires either a coordinated hard fork to remove the malicious validator or a manual state intervention

The severity is critical because:
1. Any user with sufficient tokens to meet minimum self-delegation can create a validator
2. Once the malicious validator activates (via delegation reaching bonded threshold), the next `EndBlock` immediately triggers the panic
3. All nodes in the network experience the same panic, causing complete network paralysis
4. The issue is not self-recovering and requires manual intervention

## Likelihood Explanation

**Triggering Conditions:**
- Requires consensus params to be misconfigured to allow incompatible key types
- Can occur via governance proposal or genesis configuration
- Any user can then create the malicious validator (requires only token holdings)

**Likelihood:**
- **Medium-High** in practice because:
  1. Governance proposals can modify consensus params with sufficient votes
  2. Genesis configurations may be set incorrectly during chain launches
  3. Chain operators may not realize certain SDK-registered key types are incompatible with Tendermint
  4. The multisig key type is particularly dangerous as it might seem like a legitimate feature request
- Once conditions are met, exploitation is trivial and guaranteed
- No special privileges beyond normal validator creation requirements

## Recommendation

Add validation in `ValidateBasic` to ensure the public key type is compatible with Tendermint:

```go
func (msg MsgCreateValidator) ValidateBasic() error {
    // ... existing checks ...
    
    if msg.Pubkey == nil {
        return ErrEmptyValidatorPubKey
    }
    
    // NEW: Validate the cached public key is Tendermint-compatible
    pk, ok := msg.Pubkey.GetCachedValue().(cryptotypes.PubKey)
    if !ok {
        return sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expecting cryptotypes.PubKey, got %T", pk)
    }
    
    // NEW: Verify key type is supported by Tendermint
    _, err := cryptocodec.ToTmProtoPublicKey(pk)
    if err != nil {
        return sdkerrors.Wrapf(
            ErrValidatorPubKeyTypeNotSupported,
            "public key type not supported by Tendermint consensus: %s", pk.Type(),
        )
    }
    
    // ... rest of validation ...
}
```

Additionally, strengthen the consensus params validation in `ValidateValidatorParams` to maintain a whitelist of known-compatible types (ed25519, secp256k1) rather than allowing arbitrary strings.

## Proof of Concept

**File:** `x/staking/keeper/msg_server_test.go` (new test function)

**Setup:**
1. Initialize a test app with consensus params allowing "PubKeyMultisigThreshold" 
2. Create a multisig public key using the SDK's multisig package
3. Create a `MsgCreateValidator` with the multisig key

**Trigger:**
1. Call `ValidateBasic` on the message - it should pass (demonstrating the vulnerability)
2. Execute `CreateValidator` through the message server - it should succeed
3. Simulate the validator becoming active by calling `BlockValidatorUpdates` during `EndBlock`

**Observation:**
The test will panic at step 3 when `ABCIValidatorUpdate` is called, demonstrating that:
- `ValidateBasic` failed to catch the incompatible key type
- The chain would halt in production when this validator activates

```go
func TestCreateValidatorWithIncompatiblePubKeyType(t *testing.T) {
    // Setup app with modified consensus params allowing multisig
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Modify consensus params to allow multisig keys
    cp := app.GetConsensusParams(ctx)
    cp.Validator.PubKeyTypes = append(cp.Validator.PubKeyTypes, "PubKeyMultisigThreshold")
    app.StoreConsensusParams(ctx, cp)
    
    // Create multisig public key
    pk1 := ed25519.GenPrivKey().PubKey()
    pk2 := ed25519.GenPrivKey().PubKey()
    multiPk := multisig.NewLegacyAminoPubKey(2, []cryptotypes.PubKey{pk1, pk2})
    
    // Create validator with multisig key
    valAddr := sdk.ValAddress(pk1.Address())
    description := types.NewDescription("test", "", "", "", "")
    commission := types.NewCommissionRates(sdk.ZeroDec(), sdk.ZeroDec(), sdk.ZeroDec())
    msg, err := types.NewMsgCreateValidator(
        valAddr, multiPk, 
        sdk.NewInt64Coin(sdk.DefaultBondDenom, 1000000),
        description, commission, sdk.OneInt(),
    )
    require.NoError(t, err)
    
    // ValidateBasic should catch this but doesn't
    err = msg.ValidateBasic()
    require.NoError(t, err) // VULNERABILITY: This passes when it shouldn't
    
    // Create validator through message server
    msgServer := keeper.NewMsgServerImpl(app.StakingKeeper)
    _, err = msgServer.CreateValidator(sdk.WrapSDKContext(ctx), msg)
    require.NoError(t, err) // This succeeds
    
    // Simulate validator becoming active - this will panic
    require.Panics(t, func() {
        validator, _ := app.StakingKeeper.GetValidator(ctx, valAddr)
        _ = validator.ABCIValidatorUpdate(app.StakingKeeper.PowerReduction(ctx))
    })
}
```

The test demonstrates that a multisig key passes `ValidateBasic` and validator creation, but causes a panic when converted to ABCI format, proving the vulnerability enables chain halt attacks.

### Citations

**File:** x/staking/types/msg.go (L89-144)
```go
// ValidateBasic implements the sdk.Msg interface.
func (msg MsgCreateValidator) ValidateBasic() error {
	// note that unmarshaling from bech32 ensures either empty or valid
	delAddr, err := sdk.AccAddressFromBech32(msg.DelegatorAddress)
	if err != nil {
		return err
	}
	if delAddr.Empty() {
		return ErrEmptyDelegatorAddr
	}

	if msg.ValidatorAddress == "" {
		return ErrEmptyValidatorAddr
	}

	valAddr, err := sdk.ValAddressFromBech32(msg.ValidatorAddress)
	if err != nil {
		return err
	}
	if !sdk.AccAddress(valAddr).Equals(delAddr) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "validator address is invalid")
	}

	if msg.Pubkey == nil {
		return ErrEmptyValidatorPubKey
	}

	if !msg.Value.IsValid() || !msg.Value.Amount.IsPositive() {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "invalid delegation amount")
	}

	if msg.Description == (Description{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty description")
	}

	if msg.Commission == (CommissionRates{}) {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "empty commission")
	}

	if err := msg.Commission.Validate(); err != nil {
		return err
	}

	if !msg.MinSelfDelegation.IsPositive() {
		return sdkerrors.Wrap(
			sdkerrors.ErrInvalidRequest,
			"minimum self delegation must be a positive integer",
		)
	}

	if msg.Value.Amount.LT(msg.MinSelfDelegation) {
		return ErrSelfDelegationBelowMinimum
	}

	return nil
}
```

**File:** x/staking/types/validator.go (L257-268)
```go
// with the full validator power
func (v Validator) ABCIValidatorUpdate(r sdk.Int) abci.ValidatorUpdate {
	tmProtoPk, err := v.TmConsPublicKey()
	if err != nil {
		panic(err)
	}

	return abci.ValidatorUpdate{
		PubKey: tmProtoPk,
		Power:  v.ConsensusPower(r),
	}
}
```

**File:** crypto/codec/tm.go (L30-48)
```go
// ToTmProtoPublicKey converts our own PubKey to TM's tmprotocrypto.PublicKey.
func ToTmProtoPublicKey(pk cryptotypes.PubKey) (tmprotocrypto.PublicKey, error) {
	switch pk := pk.(type) {
	case *ed25519.PubKey:
		return tmprotocrypto.PublicKey{
			Sum: &tmprotocrypto.PublicKey_Ed25519{
				Ed25519: pk.Key,
			},
		}, nil
	case *secp256k1.PubKey:
		return tmprotocrypto.PublicKey{
			Sum: &tmprotocrypto.PublicKey_Secp256K1{
				Secp256K1: pk.Key,
			},
		}, nil
	default:
		return tmprotocrypto.PublicKey{}, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "cannot convert %v to Tendermint public key", pk)
	}
}
```

**File:** crypto/codec/proto.go (L13-22)
```go
// RegisterInterfaces registers the sdk.Tx interface.
func RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	var pk *cryptotypes.PubKey
	registry.RegisterInterface("cosmos.crypto.PubKey", pk)
	registry.RegisterImplementations(pk, &ed25519.PubKey{})
	registry.RegisterImplementations(pk, &secp256k1.PubKey{})
	registry.RegisterImplementations(pk, &multisig.LegacyAminoPubKey{})
	registry.RegisterImplementations(pk, &sr25519.PubKey{})
	secp256r1.RegisterInterfaces(registry)
}
```

**File:** x/staking/keeper/msg_server.go (L67-75)
```go
	cp := ctx.ConsensusParams()
	if cp != nil && cp.Validator != nil {
		if !utils.StringInSlice(pk.Type(), cp.Validator.PubKeyTypes) {
			return nil, sdkerrors.Wrapf(
				types.ErrValidatorPubKeyTypeNotSupported,
				"got: %s, expected: %s", pk.Type(), cp.Validator.PubKeyTypes,
			)
		}
	}
```

**File:** baseapp/params.go (L87-98)
```go
func ValidateValidatorParams(i interface{}) error {
	v, ok := i.(tmproto.ValidatorParams)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}

	if len(v.PubKeyTypes) == 0 {
		return errors.New("validator allowed pubkey types must not be empty")
	}

	return nil
}
```

**File:** x/staking/keeper/val_state_change.go (L15-30)
```go
// BlockValidatorUpdates calculates the ValidatorUpdates for the current block
// Called in each EndBlock
func (k Keeper) BlockValidatorUpdates(ctx sdk.Context) []abci.ValidatorUpdate {
	// Calculate validator set changes.
	//
	// NOTE: ApplyAndReturnValidatorSetUpdates has to come before
	// UnbondAllMatureValidatorQueue.
	// This fixes a bug when the unbonding period is instant (is the case in
	// some of the tests). The test expected the validator to be completely
	// unbonded after the Endblocker (go from Bonded -> Unbonding during
	// ApplyAndReturnValidatorSetUpdates and then Unbonding -> Unbonded during
	// UnbondAllMatureValidatorQueue).
	validatorUpdates, err := k.ApplyAndReturnValidatorSetUpdates(ctx)
	if err != nil {
		panic(err)
	}
```
