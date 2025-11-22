## Audit Report

## Title
Chain Halt via Malformed Validator Consensus Public Key in Genesis State

## Summary
A validator with a malformed consensus public key in the genesis state will cause all nodes to panic during chain initialization, resulting in a complete network shutdown that requires a hard fork to resolve. The panic occurs when `GetConsAddr()` calls the `Address()` function on a malformed ed25519 public key, and this panic is not caught during the `InitChain` ABCI method.

## Impact
**High**

## Finding Description

**Location:**
- Primary panic location: [1](#0-0) 
- Call site in genesis initialization: [2](#0-1) 
- Genesis processing without panic recovery: [3](#0-2) 
- InitChain without panic recovery: [4](#0-3) 

**Intended Logic:**
The `Address()` function is intended to derive a consensus address from a validator's public key. Genesis initialization should validate and process validators from the genesis state, setting up the initial validator set for the chain. The protobuf unmarshal process should only accept well-formed keys.

**Actual Logic:**
The protobuf `Unmarshal()` method for ed25519 public keys does not validate the key length, allowing keys of any byte length to be deserialized successfully. [5](#0-4)  When `Address()` is later called on such a malformed key, it panics if the length is not exactly 32 bytes. During genesis initialization, `SetValidatorByConsAddr()` is called for each validator, which invokes `GetConsAddr()`, which in turn calls `Address()` on the consensus public key. [6](#0-5)  This panic occurs within `InitChain`, which has no panic recovery mechanism, causing the entire node to crash.

**Exploit Scenario:**
1. An attacker crafts a malicious genesis file containing a validator with an ed25519 consensus public key that has an incorrect byte length (e.g., 31 or 33 bytes instead of the required 32 bytes)
2. Network participants download or are provided this genesis file for chain initialization or upgrade
3. When nodes attempt to start with this genesis file, `InitChain` is called
4. The staking module's `InitGenesis` processes the validators from genesis state
5. For the malformed validator, `SetValidatorByConsAddr()` calls `GetConsAddr()`, which calls `Address()` and panics
6. The panic propagates up through the call stack with no recovery
7. All nodes crash immediately upon startup
8. The chain cannot start, resulting in complete network failure

**Security Failure:**
This is a denial-of-service vulnerability that breaks network availability. The chain cannot initialize, and all nodes crash on startup. Since the malformed validator is permanently encoded in the genesis state, the only resolution is a coordinated hard fork to manually fix the genesis file.

## Impact Explanation

**Affected Components:**
- Network availability: Complete chain halt
- All validator nodes: Crash on startup
- Block production: Impossible, no blocks can be produced
- Transaction processing: No transactions can be confirmed

**Severity of Damage:**
- **Complete network shutdown:** All nodes attempting to start with the malformed genesis will crash
- **Requires hard fork:** The only fix is to manually edit the genesis file and coordinate a new chain start, which constitutes a hard fork
- **Coordination failure risk:** If different participants use different genesis files, it could lead to chain splits
- **No automatic recovery:** Unlike transaction-level panics that are caught by panic recovery in `runTx`, genesis initialization has no such protection

**System Security Impact:**
This vulnerability allows an attacker who can influence genesis file creation or distribution (e.g., during chain upgrades involving genesis export/import) to cause a permanent denial of service. The impact matches the "High: Network not being able to confirm new transactions (total network shutdown)" category from the in-scope impacts.

## Likelihood Explanation

**Who Can Trigger:**
Any party involved in genesis file creation or distribution, including:
- Chain coordinators during initial chain launch
- Upgrade coordinators during chain upgrades that involve genesis export/import
- Malicious actors who can inject or modify genesis files before distribution

**Conditions Required:**
- A validator entry in the genesis state must have a consensus public key with incorrect byte length
- The protobuf unmarshal accepts the malformed key (which it does, as shown in the code)
- The genesis validation step (`validate-genesis` CLI command) must be skipped or the genesis file not validated before use

**Frequency:**
- **Low to Medium likelihood of accidental occurrence:** Could happen due to bugs in genesis generation tools or manual editing errors
- **Medium likelihood of intentional exploit:** Requires ability to influence genesis file, but possible during chain launches or upgrades
- **One-time occurrence causes permanent damage:** A single malformed validator in genesis causes chain halt until manually fixed

The vulnerability is particularly concerning during:
- New chain launches where genesis files are being created
- Chain upgrades that involve genesis export and re-import
- Scenarios where genesis files are transmitted through untrusted channels

## Recommendation

Implement defense in depth with multiple layers of protection:

1. **Add length validation in protobuf Unmarshal:** Modify the `UnmarshalAmino` method for ed25519 (and secp256k1) public keys to validate the key length during deserialization, returning an error instead of accepting malformed keys. [7](#0-6) 

2. **Return error instead of panic in Address():** Replace the panic with an error return in the `Address()` function signature to allow graceful error handling throughout the call chain. This is a breaking change but necessary for robustness.

3. **Add explicit validation in SetValidatorByConsAddr:** Check the return value from `GetConsAddr()` and handle errors gracefully. [8](#0-7) 

4. **Add panic recovery in InitChain:** As a last line of defense, add a defer/recover block in the `InitChain` method to catch any panics during genesis initialization and return them as errors rather than crashing the node.

5. **Mandatory genesis validation:** Ensure the `ValidateGenesis` function is always called before `InitGenesis`, and document that node operators must run `validate-genesis` command before starting nodes with a new genesis file.

## Proof of Concept

**Test File:** `x/staking/genesis_test.go`

**Test Function:** `TestGenesisValidatorWithMalformedConsensusPubKey`

```go
func TestGenesisValidatorWithMalformedConsensusPubKey(t *testing.T) {
    // Setup: Create a genesis state with a validator that has a malformed ed25519 public key
    app := simapp.Setup(false)
    ctx := app.BaseApp.NewContext(false, tmproto.Header{})
    
    // Create a malformed ed25519 public key (31 bytes instead of 32)
    malformedKeyBytes := make([]byte, 31)
    for i := range malformedKeyBytes {
        malformedKeyBytes[i] = byte(i)
    }
    
    // Create the malformed public key
    malformedPk := &ed25519.PubKey{Key: malformedKeyBytes}
    pkAny, err := codectypes.NewAnyWithValue(malformedPk)
    require.NoError(t, err)
    
    // Create a validator with the malformed public key
    valAddr := sdk.ValAddress([]byte("validator"))
    validator := types.Validator{
        OperatorAddress:   valAddr.String(),
        ConsensusPubkey:   pkAny,
        Status:           types.Bonded,
        Tokens:           sdk.NewInt(100),
        DelegatorShares:  sdk.NewDec(100),
        Description:      types.NewDescription("test", "", "", "", ""),
        Commission:       types.NewCommission(sdk.ZeroDec(), sdk.ZeroDec(), sdk.ZeroDec()),
    }
    
    genesisState := types.GenesisState{
        Params: types.DefaultParams(),
        Validators: []types.Validator{validator},
    }
    
    // Trigger: Attempt to initialize genesis with the malformed validator
    // This should panic when SetValidatorByConsAddr calls GetConsAddr -> Address
    require.Panics(t, func() {
        InitGenesis(ctx, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, &genesisState)
    }, "Expected panic when initializing genesis with malformed validator consensus key")
    
    // Observation: The test confirms that a panic occurs during genesis initialization
    // In a real chain start scenario, this panic would crash all nodes
}
```

**Observation:**
When this test runs, it will panic at the point where `SetValidatorByConsAddr()` calls `validator.GetConsAddr()`, which calls `pk.Address()` on the malformed ed25519 key. The panic message will be "pubkey is incorrect size". This demonstrates that a malformed validator in genesis causes an unrecoverable panic during chain initialization, resulting in a complete network failure requiring a hard fork to resolve.

### Citations

**File:** crypto/keys/ed25519/ed25519.go (L162-165)
```go
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("pubkey is incorrect size")
	}
```

**File:** crypto/keys/ed25519/ed25519.go (L210-217)
```go
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errors.Wrap(errors.ErrInvalidPubKey, "invalid pubkey size")
	}
	pubKey.Key = bz

	return nil
}
```

**File:** x/staking/keeper/validator.go (L64-68)
```go
func (k Keeper) SetValidatorByConsAddr(ctx sdk.Context, validator types.Validator) error {
	consPk, err := validator.GetConsAddr()
	if err != nil {
		return err
	}
```

**File:** x/staking/genesis.go (L39-44)
```go
	for _, validator := range data.Validators {
		keeper.SetValidator(ctx, validator)

		// Manually set indices for the first time
		keeper.SetValidatorByConsAddr(ctx, validator)
		keeper.SetValidatorByPowerIndex(ctx, validator)
```

**File:** baseapp/abci.go (L32-76)
```go
// InitChain implements the ABCI interface. It runs the initialization logic
// directly on the CommitMultiStore.
func (app *BaseApp) InitChain(ctx context.Context, req *abci.RequestInitChain) (res *abci.ResponseInitChain, err error) {
	// On a new chain, we consider the init chain block height as 0, even though
	// req.InitialHeight is 1 by default.
	initHeader := tmproto.Header{ChainID: req.ChainId, Time: req.Time}
	app.ChainID = req.ChainId

	// If req.InitialHeight is > 1, then we set the initial version in the
	// stores.
	if req.InitialHeight > 1 {
		app.initialHeight = req.InitialHeight
		initHeader = tmproto.Header{ChainID: req.ChainId, Height: req.InitialHeight, Time: req.Time}
		err := app.cms.SetInitialVersion(req.InitialHeight)
		if err != nil {
			return nil, err
		}
	}

	// initialize the deliver state and check state with a correct header
	app.setDeliverState(initHeader)
	app.setCheckState(initHeader)
	app.setPrepareProposalState(initHeader)
	app.setProcessProposalState(initHeader)

	// Store the consensus params in the BaseApp's paramstore. Note, this must be
	// done after the deliver state and context have been set as it's persisted
	// to state.
	if req.ConsensusParams != nil {
		app.StoreConsensusParams(app.deliverState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.prepareProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.processProposalState.ctx, req.ConsensusParams)
		app.StoreConsensusParams(app.checkState.ctx, req.ConsensusParams)
	}

	app.SetDeliverStateToCommit()

	if app.initChainer == nil {
		return
	}

	resp := app.initChainer(app.deliverState.ctx, *req)
	app.initChainer(app.prepareProposalState.ctx, *req)
	app.initChainer(app.processProposalState.ctx, *req)
	res = &resp
```

**File:** crypto/keys/ed25519/keys.pb.go (L249-330)
```go
func (m *PubKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowKeys
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PubKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PubKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowKeys
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthKeys
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthKeys
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Key = append(m.Key[:0], dAtA[iNdEx:postIndex]...)
			if m.Key == nil {
				m.Key = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipKeys(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthKeys
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
```

**File:** x/staking/types/validator.go (L497-504)
```go
// GetConsAddr extracts Consensus key address
func (v Validator) GetConsAddr() (sdk.ConsAddress, error) {
	pk, ok := v.ConsensusPubkey.GetCachedValue().(cryptotypes.PubKey)
	if !ok {
		return nil, sdkerrors.Wrapf(sdkerrors.ErrInvalidType, "expecting cryptotypes.PubKey, got %T", pk)
	}
	return sdk.ConsAddress(pk.Address()), nil
}
```
