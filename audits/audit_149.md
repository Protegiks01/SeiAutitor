## Audit Report

## Title
Missing Sorted Order Validation in CapabilityOwners Enables Authorization Bypass Through Genesis State

## Summary
The `CapabilityOwners` structure relies on a sorted owners list for binary search operations, but genesis state validation does not verify this invariant. [1](#0-0)  Unsorted owners loaded from genesis cause binary search failures in the `Get` method, leading to incorrect authorization decisions and potential duplicate owner entries when `Set` is subsequently called. [2](#0-1) 

## Impact
**Medium** - A bug in the network code that results in unintended behavior with authorization failures affecting cross-module communication and IBC functionality.

## Finding Description

**Location:** 
- Primary issue: `x/capability/types/genesis.go` (validation function)
- Affected methods: `x/capability/types/types.go` lines 46-87 (`Set`, `Get`, `Remove`)

**Intended Logic:**
The `CapabilityOwners` maintains a sorted list of owners to enable efficient O(log n) lookups using binary search. [3](#0-2)  The `Get` method assumes the slice is sorted and uses `sort.Search` to locate owners. [2](#0-1)  The `Set` method relies on `Get` to find the correct insertion position to maintain sorted order. [4](#0-3) 

**Actual Logic:**
Genesis state validation checks owner module/name are non-blank and indices are in range, but does NOT verify that the `Owners` slice is sorted. [5](#0-4)  When `InitGenesis` loads owners via `SetOwners`, unsorted data is directly marshaled and stored without validation. [6](#0-5) [7](#0-6) 

**Exploit Scenario:**
1. A validator creates or migrates a genesis state with `CapabilityOwners` where the `Owners` slice is not sorted (e.g., manually constructed with owners in wrong order)
2. Genesis validation passes because it only checks for blank fields and index ranges
3. During `InitGenesis`, `SetOwners` stores the unsorted data directly
4. When unmarshaled, the owners remain unsorted (protobuf preserves order). [8](#0-7) 
5. Runtime capability operations call `Get` which uses binary search on the unsorted slice, returning incorrect indices
6. Legitimate owner lookups fail (returns `found=false` even when owner exists)
7. Subsequent `Set` operations insert at wrong positions, creating duplicates or further corrupting order
8. Modules fail to authenticate capabilities, breaking IBC channels, cross-module communication, and port bindings

**Security Failure:**
The capability authorization system fails because binary search on unsorted data violates the sorted invariant assumption. This breaks the authorization property - legitimate owners are not found, and duplicate/incorrect owners may be added, compromising the capability security model that underpins cross-module authentication.

## Impact Explanation

**Affected Components:**
- Capability-based authorization across all modules (IBC, staking, bank, etc.)
- IBC channel and port authentication
- Cross-module capability delegation and verification

**Severity:**
- Capability authorization checks fail, preventing modules from using legitimately owned capabilities
- IBC channels become unusable as port capabilities cannot be authenticated
- New capability claims may create duplicates or fail, breaking module initialization
- Chain functionality degrades as inter-module communication fails
- Nodes may panic when encountering inconsistent capability state

**Why It Matters:**
The capability module is fundamental to Cosmos SDK's security architecture. IBC (Inter-Blockchain Communication) protocol relies entirely on capabilities for port/channel authorization. A broken capability system means the chain cannot process IBC transactions, effectively isolating it from the broader Cosmos ecosystem. This constitutes unintended network behavior affecting critical protocol functionality.

## Likelihood Explanation

**Trigger Conditions:**
- Requires privileged genesis state creation or chain upgrade with unsorted capability owners
- Can occur accidentally during manual genesis file construction or automated migration scripts
- More likely during chain upgrades when migrating state from older versions

**Who Can Trigger:**
- Validators/operators during genesis creation (accidental misconfiguration)
- Chain upgrade coordinators during state migration
- Not exploitable by unprivileged users directly

**Frequency:**
- One-time event during chain initialization or upgrade
- Once triggered, the corrupted state persists and affects all subsequent capability operations
- Relatively low probability but catastrophic when it occurs (chain must be restarted with corrected genesis)

## Recommendation

Add sorted order validation in `GenesisState.Validate()`:

```go
// In x/capability/types/genesis.go, add to the Validate() function after line 45:

// Verify owners are sorted by key for binary search correctness
for i := 0; i < len(genOwner.IndexOwners.Owners)-1; i++ {
    if genOwner.IndexOwners.Owners[i].Key() >= genOwner.IndexOwners.Owners[i+1].Key() {
        return fmt.Errorf("owners must be sorted by key, but found %s >= %s at indices %d, %d",
            genOwner.IndexOwners.Owners[i].Key(),
            genOwner.IndexOwners.Owners[i+1].Key(),
            i, i+1)
    }
}
```

Additionally, consider adding a defensive sort in `SetOwners` or `InitializeCapability` to ensure the invariant is maintained even if validation is bypassed.

## Proof of Concept

**File:** `x/capability/types/types_test.go`

**Test Function:** Add the following test:

```go
func TestCapabilityOwners_UnsortedBreaksBinarySearch(t *testing.T) {
    // Simulate genesis state with unsorted owners (bypassing normal Set method)
    co := &types.CapabilityOwners{
        Owners: []types.Owner{
            types.NewOwner("ibc", "port-z"),      // Key: "ibc/port-z"
            types.NewOwner("bank", "send"),       // Key: "bank/send"  
            types.NewOwner("staking", "delegate"), // Key: "staking/delegate"
        },
    }
    
    // List is NOT sorted (correct order: bank, ibc, staking)
    // Binary search will give incorrect results
    
    // Try to find "bank/send" which EXISTS at index 1
    ownerBank := types.NewOwner("bank", "send")
    idx, found := co.Get(ownerBank)
    
    // sort.Search looks for first index where owners[i].Key() >= "bank/send"
    // i=0: "ibc/port-z" >= "bank/send"? Yes -> returns 0
    // owners[0].Key() = "ibc/port-z" != "bank/send"
    // So found = false, even though it exists!
    require.False(t, found, "Binary search failed to find existing owner in unsorted list")
    require.Equal(t, 0, idx, "Wrong insertion index returned")
    
    // Now Set tries to add it (thinks it doesn't exist)
    err := co.Set(ownerBank)
    require.NoError(t, err, "Set should succeed but creates duplicate")
    
    // Verify duplicate was created
    count := 0
    for _, owner := range co.Owners {
        if owner.Key() == ownerBank.Key() {
            count++
        }
    }
    require.Equal(t, 2, count, "Duplicate owner created due to broken binary search")
    
    // Verify list is still not properly sorted
    for i := 0; i < len(co.Owners)-1; i++ {
        if co.Owners[i].Key() >= co.Owners[i+1].Key() {
            t.Logf("Found unsorted pair at indices %d,%d: %s >= %s", 
                i, i+1, co.Owners[i].Key(), co.Owners[i+1].Key())
        }
    }
}
```

**Setup:** None required - test creates unsorted `CapabilityOwners` directly

**Trigger:** Call `Get` and `Set` on the unsorted owners structure

**Observation:** 
- `Get` fails to find an owner that exists in the list (returns `found=false`)
- `Set` adds a duplicate owner without detecting it already exists  
- The list remains unsorted after operations
- This proves binary search correctness depends on sorted order, which is not validated in genesis

The test will pass (demonstrating the vulnerability) on the current code because there's no validation preventing unsorted owners from being created and used.

### Citations

**File:** x/capability/types/genesis.go (L21-49)
```go
func (gs GenesisState) Validate() error {
	// NOTE: index must be greater than 0
	if gs.Index == 0 {
		return fmt.Errorf("capability index must be non-zero")
	}

	for _, genOwner := range gs.Owners {
		if len(genOwner.IndexOwners.Owners) == 0 {
			return fmt.Errorf("empty owners in genesis")
		}

		// all exported existing indices must be between [1, gs.Index)
		if genOwner.Index == 0 || genOwner.Index >= gs.Index {
			return fmt.Errorf("owners exist for index %d outside of valid range: %d-%d", genOwner.Index, 1, gs.Index-1)
		}

		for _, owner := range genOwner.IndexOwners.Owners {
			if strings.TrimSpace(owner.Module) == "" {
				return fmt.Errorf("owner's module cannot be blank: %s", owner)
			}

			if strings.TrimSpace(owner.Name) == "" {
				return fmt.Errorf("owner's name cannot be blank: %s", owner)
			}
		}
	}

	return nil
}
```

**File:** x/capability/types/types.go (L43-45)
```go
// Set attempts to add a given owner to the CapabilityOwners. If the owner
// already exists, an error will be returned. Set runs in O(log n) average time
// and O(n) in the worst case.
```

**File:** x/capability/types/types.go (L46-58)
```go
func (co *CapabilityOwners) Set(owner Owner) error {
	i, ok := co.Get(owner)
	if ok {
		// owner already exists at co.Owners[i]
		return sdkerrors.Wrapf(ErrOwnerClaimed, owner.String())
	}

	// owner does not exist in the set of owners, so we insert at position i
	co.Owners = append(co.Owners, Owner{}) // expand by 1 in amortized O(1) / O(n) worst case
	copy(co.Owners[i+1:], co.Owners[i:])
	co.Owners[i] = owner

	return nil
```

**File:** x/capability/types/types.go (L78-87)
```go
func (co *CapabilityOwners) Get(owner Owner) (int, bool) {
	// find smallest index s.t. co.Owners[i] >= owner in O(log n) time
	i := sort.Search(len(co.Owners), func(i int) bool { return co.Owners[i].Key() >= owner.Key() })
	if i < len(co.Owners) && co.Owners[i].Key() == owner.Key() {
		// owner exists at co.Owners[i]
		return i, true
	}

	return i, false
}
```

**File:** x/capability/keeper/keeper.go (L168-174)
```go
func (k Keeper) SetOwners(ctx sdk.Context, index uint64, owners types.CapabilityOwners) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.KeyPrefixIndexCapability)
	indexKey := types.IndexToKey(index)

	// set owners in persistent store
	prefixStore.Set(indexKey, k.cdc.MustMarshal(&owners))
}
```

**File:** x/capability/genesis.go (L16-19)
```go
	// set owners for each index
	for _, genOwner := range genState.Owners {
		k.SetOwners(ctx, genOwner.Index, genOwner.IndexOwners)
	}
```

**File:** x/capability/types/capability.pb.go (L593-594)
```go
			m.Owners = append(m.Owners, Owner{})
			if err := m.Owners[len(m.Owners)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
```
