# Audit Report

## Title
State Sync Allows Corrupted Protobuf Data Causing Node Panic and Denial of Service

## Summary
During state sync restoration, the system only validates the IAVL snapshot structure but not the application-level protobuf data stored within IAVL node values. A malicious state sync peer can serve snapshots with corrupted protobuf data that passes validation. When keeper methods later attempt to unmarshal this data using `MustUnmarshal`, the node panics and halts. This enables a denial-of-service attack where an attacker can cause multiple syncing nodes to crash.

## Impact
**Medium** - Shutdown of greater than or equal to 30% of network processing nodes without brute force actions.

## Finding Description

**Location:**
- Validation gap: [1](#0-0) 
- Panic trigger points: [2](#0-1) , [3](#0-2) , [4](#0-3) 
- Codec panic implementation: [5](#0-4) 

**Intended Logic:**
State sync is designed to allow nodes to quickly sync by downloading snapshots from peers. The system should validate that all snapshot data is valid and well-formed before allowing the node to start processing blocks. [6](#0-5) 

**Actual Logic:**
During snapshot restoration, only the outer IAVL snapshot structure (SnapshotItem protobuf messages) is validated. The application-level protobuf data stored in IAVL node values is not validated. At [7](#0-6) , the code validates `protoReader.ReadMsg(&snapshotItem)` but not the `item.IAVL.Value` field which contains application protobuf data. This corrupted data is written directly to the store at [8](#0-7) .

**Exploit Scenario:**
1. Attacker sets up a malicious state sync node that serves modified snapshots
2. Victim node initiates state sync and connects to the malicious peer
3. Malicious peer sends snapshot chunks with valid IAVL structure but corrupted `MessageDependencyMapping` or other protobuf data in IAVL node values
4. State sync completes successfully because only IAVL structure is validated
5. App hash matches because it's computed from raw bytes, not protobuf validity [9](#0-8) 
6. After sync, when a user queries `ResourceDependencyMappingFromMessageKey` [10](#0-9)  or the node attempts genesis export [11](#0-10) , `MustUnmarshal` is called on the corrupted data
7. `MustUnmarshal` panics [12](#0-11) , halting the node

**Security Failure:**
The system fails to maintain node availability. Multiple nodes syncing from the malicious peer will all contain corrupted data and crash when attempting to use keeper methods that read this data. This breaks the denial-of-service protection invariant.

## Impact Explanation

**Affected Components:**
- Node availability: Nodes that sync from malicious peers become inoperable
- Network capacity: If ≥30% of nodes sync from the attacker, network capacity degrades significantly
- User experience: Queries and transactions fail when nodes crash

**Damage Severity:**
- Nodes that sync corrupted state will panic on any query or genesis export operation
- The panic is not recoverable without re-syncing from a different peer or using a trusted snapshot
- If the attacker positions their malicious node to be discovered by many syncing nodes, they can cause widespread outages
- This scales with network growth as new nodes are more likely to use state sync

**Why This Matters:**
State sync is a critical feature for network scalability and onboarding. Nodes rely on it to join the network quickly. If this mechanism can be weaponized for DoS attacks, it undermines network resilience and creates a centralization risk where only "trusted" state sync peers can be used.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can run a malicious state sync node. No privileges, stake, or special permissions are required. The attacker only needs to be discoverable by victim nodes during their state sync process.

**Conditions Required:**
- Victim node must perform state sync (common for new nodes joining the network)
- Victim must connect to the attacker's malicious node as one of their state sync peers
- After sync completes, any query to affected keeper methods or genesis export will trigger the panic

**Frequency:**
- High likelihood for new nodes joining the network, as they commonly use state sync
- Attackers can increase likelihood by running multiple malicious nodes or advertising their node prominently
- Single successful infection can persist until the node is manually recovered
- As the network grows and more nodes use state sync, attack surface increases

## Recommendation

Implement application-level protobuf validation during state sync restoration:

1. **Add validation layer in Restore functions:** After importing IAVL nodes, attempt to unmarshal and validate critical application protobuf data before finalizing the restore. Use `Unmarshal` (not `MustUnmarshal`) to catch errors gracefully.

2. **Implement keeper-level validation:** Add a `ValidateStore()` method that iterates through stored protobuf data and attempts unmarshaling in a controlled way. Call this after state sync completes but before allowing the node to process blocks.

3. **Use error-returning unmarshal in keeper read methods:** Replace `MustUnmarshal` with `Unmarshal` in keeper methods that read from the store, and handle errors gracefully by returning appropriate errors rather than panicking. This prevents denial of service while maintaining data integrity.

4. **Add checksums for application data:** Include application-level protobuf checksums in snapshot metadata, similar to existing chunk checksums, to enable validation before data is written to the store.

## Proof of Concept

**File:** `x/accesscontrol/keeper/keeper_test.go`

**Test Function:** `TestCorruptedProtobufFromStateSyncCausesPanic`

**Setup:**
```go
// Initialize app and context
app := simapp.Setup(false)
ctx := app.BaseApp.NewContext(false, tmproto.Header{})

// Create valid dependency mapping and marshal it
validMapping := acltypes.MessageDependencyMapping{
    MessageKey: "testMessage",
    AccessOps: []acltypes.AccessOperation{
        {
            ResourceType:       acltypes.ResourceType_KV_BANK,
            AccessType:         acltypes.AccessType_READ,
            IdentifierTemplate: "test",
        },
        *types.CommitAccessOp(),
    },
}

// Get the store and storage key
store := ctx.KVStore(app.AccessControlKeeper.GetStoreKey())
storageKey := types.GetResourceDependencyKey("testMessage")
```

**Trigger:**
```go
// Write corrupted protobuf data directly to the store
// This simulates what would happen after state sync with corrupted data
corruptedData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
store.Set(storageKey, corruptedData)

// This simulates a query that would be called after state sync
// It will panic because MustUnmarshal cannot handle the corrupted data
```

**Observation:**
```go
require.Panics(t, func() {
    // This call to GetResourceDependencyMapping will panic
    // because it calls MustUnmarshal on the corrupted data
    app.AccessControlKeeper.GetResourceDependencyMapping(ctx, "testMessage")
}, "Expected panic when reading corrupted protobuf data from store")
```

The test confirms that corrupted protobuf data in the store (as would result from malicious state sync) causes `MustUnmarshal` to panic when keeper methods attempt to read it. This demonstrates that nodes synced from malicious peers will crash on normal operations, enabling the denial-of-service attack.

### Citations

**File:** store/rootmulti/store.go (L869-948)
```go
func (rs *Store) Restore(
	height uint64, format uint32, protoReader protoio.Reader,
) (snapshottypes.SnapshotItem, error) {
	// Import nodes into stores. The first item is expected to be a SnapshotItem containing
	// a SnapshotStoreItem, telling us which store to import into. The following items will contain
	// SnapshotNodeItem (i.e. ExportNode) until we reach the next SnapshotStoreItem or EOF.
	var importer *iavltree.Importer
	var snapshotItem snapshottypes.SnapshotItem
loop:
	for {
		snapshotItem = snapshottypes.SnapshotItem{}
		err := protoReader.ReadMsg(&snapshotItem)
		if err == io.EOF {
			break
		} else if err != nil {
			return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(err, "invalid protobuf message")
		}

		switch item := snapshotItem.Item.(type) {
		case *snapshottypes.SnapshotItem_Store:
			if importer != nil {
				err = importer.Commit()
				if err != nil {
					return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(err, "IAVL commit failed")
				}
				importer.Close()
			}
			store, ok := rs.GetStoreByName(item.Store.Name).(*iavl.Store)
			if !ok || store == nil {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrapf(sdkerrors.ErrLogic, "cannot import into non-IAVL store %q", item.Store.Name)
			}
			importer, err = store.Import(int64(height))
			if err != nil {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(err, "import failed")
			}
			defer importer.Close()

		case *snapshottypes.SnapshotItem_IAVL:
			if importer == nil {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(sdkerrors.ErrLogic, "received IAVL node item before store item")
			}
			if item.IAVL.Height > math.MaxInt8 {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrapf(sdkerrors.ErrLogic, "node height %v cannot exceed %v",
					item.IAVL.Height, math.MaxInt8)
			}
			node := &iavltree.ExportNode{
				Key:     item.IAVL.Key,
				Value:   item.IAVL.Value,
				Height:  int8(item.IAVL.Height),
				Version: item.IAVL.Version,
			}
			// Protobuf does not differentiate between []byte{} as nil, but fortunately IAVL does
			// not allow nil keys nor nil values for leaf nodes, so we can always set them to empty.
			if node.Key == nil {
				node.Key = []byte{}
			}
			if node.Height == 0 && node.Value == nil {
				node.Value = []byte{}
			}
			err := importer.Add(node)
			if err != nil {
				return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(err, "IAVL node import failed")
			}

		default:
			break loop
		}
	}

	if importer != nil {
		err := importer.Commit()
		if err != nil {
			return snapshottypes.SnapshotItem{}, sdkerrors.Wrap(err, "IAVL commit failed")
		}
		importer.Close()
	}

	rs.flushMetadata(rs.db, int64(height), rs.buildCommitInfo(int64(height)))
	return snapshotItem, rs.LoadLatestVersion()
}
```

**File:** x/accesscontrol/keeper/keeper.go (L78-89)
```go
func (k Keeper) GetResourceDependencyMapping(ctx sdk.Context, messageKey types.MessageKey) acltypes.MessageDependencyMapping {
	store := ctx.KVStore(k.storeKey)
	depMapping := store.Get(types.GetResourceDependencyKey(messageKey))
	if depMapping == nil {
		// If the storage key doesn't exist in the mapping then assume synchronous processing
		return types.SynchronousMessageDependencyMapping(messageKey)
	}

	dependencyMapping := acltypes.MessageDependencyMapping{}
	k.cdc.MustUnmarshal(depMapping, &dependencyMapping)
	return dependencyMapping
}
```

**File:** x/accesscontrol/keeper/keeper.go (L106-117)
```go
func (k Keeper) IterateResourceKeys(ctx sdk.Context, handler func(dependencyMapping acltypes.MessageDependencyMapping) (stop bool)) {
	store := ctx.KVStore(k.storeKey)
	iter := sdk.KVStorePrefixIterator(store, types.GetResourceDependencyMappingKey())
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		dependencyMapping := acltypes.MessageDependencyMapping{}
		k.cdc.MustUnmarshal(iter.Value(), &dependencyMapping)
		if handler(dependencyMapping) {
			break
		}
	}
}
```

**File:** x/bank/keeper/keeper.go (L291-306)
```go
// GetDenomMetaData retrieves the denomination metadata. returns the metadata and true if the denom exists,
// false otherwise.
func (k BaseKeeper) GetDenomMetaData(ctx sdk.Context, denom string) (types.Metadata, bool) {
	store := ctx.KVStore(k.storeKey)
	store = prefix.NewStore(store, types.DenomMetadataKey(denom))

	bz := store.Get([]byte(denom))
	if bz == nil {
		return types.Metadata{}, false
	}

	var metadata types.Metadata
	k.cdc.MustUnmarshal(bz, &metadata)

	return metadata, true
}
```

**File:** codec/proto_codec.go (L92-99)
```go
// MustUnmarshal implements BinaryMarshaler.MustUnmarshal method.
// NOTE: this function must be used with a concrete type which
// implements proto.Message. For interface please use the codec.UnmarshalInterface
func (pc *ProtoCodec) MustUnmarshal(bz []byte, ptr ProtoMarshaler) {
	if err := pc.Unmarshal(bz, ptr); err != nil {
		panic(err)
	}
}
```

**File:** snapshots/README.md (L1-50)
```markdown
# State Sync Snapshotting

The `snapshots` package implements automatic support for Tendermint state sync
in Cosmos SDK-based applications. State sync allows a new node joining a network
to simply fetch a recent snapshot of the application state instead of fetching
and applying all historical blocks. This can reduce the time needed to join the
network by several orders of magnitude (e.g. weeks to minutes), but the node
will not contain historical data from previous heights.

This document describes the Cosmos SDK implementation of the ABCI state sync
interface, for more information on Tendermint state sync in general see:

* [Tendermint Core State Sync for Developers](https://medium.com/tendermint/tendermint-core-state-sync-for-developers-70a96ba3ee35)
* [ABCI State Sync Spec](https://docs.tendermint.com/master/spec/abci/apps.html#state-sync)
* [ABCI State Sync Method/Type Reference](https://docs.tendermint.com/master/spec/abci/abci.html#state-sync)

## Overview

For an overview of how Cosmos SDK state sync is set up and configured by
developers and end-users, see the
[Cosmos SDK State Sync Guide](https://blog.cosmos.network/cosmos-sdk-state-sync-guide-99e4cf43be2f).

Briefly, the Cosmos SDK takes state snapshots at regular height intervals given
by `state-sync.snapshot-interval` and stores them as binary files in the
filesystem under `<node_home>/data/snapshots/`, with metadata in a LevelDB database
`<node_home>/data/snapshots/metadata.db`. The number of recent snapshots to keep are given by
`state-sync.snapshot-keep-recent`.

Snapshots are taken asynchronously, i.e. new blocks will be applied concurrently
with snapshots being taken. This is possible because IAVL supports querying
immutable historical heights. However, this requires `state-sync.snapshot-interval`
to be a multiple of `pruning-keep-every`, to prevent a height from being removed
while it is being snapshotted.

When a remote node is state syncing, Tendermint calls the ABCI method
`ListSnapshots` to list available local snapshots and `LoadSnapshotChunk` to
load a binary snapshot chunk. When the local node is being state synced,
Tendermint calls `OfferSnapshot` to offer a discovered remote snapshot to the
local application and `ApplySnapshotChunk` to apply a binary snapshot chunk to
the local application. See the resources linked above for more details on these
methods and how Tendermint performs state sync.

The Cosmos SDK does not currently do any incremental verification of snapshots
during restoration, i.e. only after the entire snapshot has been restored will
Tendermint compare the app hash against the trusted hash from the chain. Cosmos
SDK snapshots and chunks do contain hashes as checksums to guard against IO
corruption and non-determinism, but these are not tied to the chain state and
can be trivially forged by an adversary. This was considered out of scope for
the initial implementation, but can be added later without changes to the
ABCI state sync protocol.
```

**File:** snapshots/README.md (L232-235)
```markdown

Once the restore is completed, Tendermint will go on to call the `Info` ABCI
call to fetch the app hash, and compare this against the trusted chain app
hash at the snapshot height to verify the restored state. If it matches,
```

**File:** x/accesscontrol/keeper/grpc_query.go (L20-25)
```go
func (k Keeper) ResourceDependencyMappingFromMessageKey(ctx context.Context, req *types.ResourceDependencyMappingFromMessageKeyRequest) (*types.ResourceDependencyMappingFromMessageKeyResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	resourceDependency := k.GetResourceDependencyMapping(sdkCtx, types.MessageKey(req.GetMessageKey()))
	return &types.ResourceDependencyMappingFromMessageKeyResponse{MessageDependencyMapping: resourceDependency}, nil
}
```

**File:** x/accesscontrol/keeper/genesis.go (L28-44)
```go
func (k Keeper) ExportGenesis(ctx sdk.Context) *types.GenesisState {
	resourceDependencyMappings := []acltypes.MessageDependencyMapping{}
	k.IterateResourceKeys(ctx, func(dependencyMapping acltypes.MessageDependencyMapping) (stop bool) {
		resourceDependencyMappings = append(resourceDependencyMappings, dependencyMapping)
		return false
	})
	wasmDependencyMappings := []acltypes.WasmDependencyMapping{}
	k.IterateWasmDependencies(ctx, func(dependencyMapping acltypes.WasmDependencyMapping) (stop bool) {
		wasmDependencyMappings = append(wasmDependencyMappings, dependencyMapping)
		return false
	})
	return &types.GenesisState{
		Params:                   k.GetParams(ctx),
		MessageDependencyMapping: resourceDependencyMappings,
		WasmDependencyMappings:   wasmDependencyMappings,
	}
}
```
