# Audit Report

## Title
Listener Panics Cause Non-Deterministic Transaction Failures Breaking Consensus Guarantees

## Summary
In `store/listenkv/store.go`, the `onWrite` function calls registered listeners without panic recovery. When a listener panics during state update notifications, the panic propagates through transaction execution and causes the transaction to fail. Since listeners are configured at the application level by node operators, different validators may have different listener implementations or configurations. This creates a critical consensus vulnerability where the same transaction succeeds on some validators but fails on others, leading to network halts and potential chain splits. [1](#0-0) 

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: `store/listenkv/store.go`, `onWrite` function (lines 159-163)
- Transaction execution: `baseapp/baseapp.go`, `runTx` function with panic recovery (lines 904-915)
- Store wrapping: `store/rootmulti/store.go`, listener wrapping (lines 642-644)
- Cache write path: `baseapp/baseapp.go`, `msCache.Write()` calls (lines 998, 1016)

**Intended Logic:**
According to ADR-038, listeners are meant to observe state changes for monitoring, auditing, and streaming purposes without affecting transaction execution. The design document shows that listener errors should be logged but not propagate. [2](#0-1) 

**Actual Logic:**
The implemented `onWrite` function completely ignores the return value from `OnWrite` calls and provides no panic recovery: [1](#0-0) 

When a listener panics:
1. During transaction execution, `Set()` or `Delete()` operations trigger `onWrite`
2. The panic bubbles up through `msCache.Write()` [3](#0-2) 

3. It's caught by the panic recovery in `runTx` [4](#0-3) 

4. The panic is converted to an error by the default recovery middleware [5](#0-4) 

5. The transaction fails with `ErrPanic`

**Exploit Scenario:**
1. Validators install different third-party listener plugins for state streaming, monitoring, or audit logging
2. One plugin (e.g., a file-based streaming listener) has a bug causing panic under specific conditions (nil pointer, buffer overflow, file system errors, etc.)
3. An attacker analyzes the plugin code and identifies transaction patterns that trigger the panic
4. The attacker submits transactions designed to trigger the listener panic
5. Validators with the buggy listener have transactions fail during `msCache.Write()`
6. Validators without the listener or with different implementations have transactions succeed
7. Validators produce different block results, causing consensus to halt

**Security Failure:**
This breaks the fundamental consensus invariant of determinism: identical transactions must produce identical results across all validators. Since listener configuration is application-level (not consensus-level), validators can have heterogeneous setups, causing non-deterministic transaction outcomes. [6](#0-5) 

## Impact Explanation

**Affected Components:**
- Transaction finality and consensus agreement
- Network availability and liveness
- Block production and validation

**Damage Severity:**
1. **Consensus Breakdown:** When validators disagree on transaction results due to different listener behaviors, they cannot reach consensus on blocks. The network halts until manual intervention.

2. **Chain Split Risk:** If the network attempts to continue with divergent state, it could result in a permanent chain split requiring a hard fork to resolve.

3. **Targeted DoS:** An attacker who understands which validators use vulnerable listeners can selectively prevent certain transaction types from being processed, degrading network functionality.

4. **Loss of Determinism:** Validators with identical code but different listener plugins will produce different results, violating the core blockchain principle that execution must be deterministic.

This vulnerability affects the integrity of the consensus protocol itself, not just individual node reliability.

## Likelihood Explanation

**Who Can Trigger:**
Any network participant can submit transactions. An attacker only needs to craft transaction data that triggers a panic in commonly-used listener implementations.

**Required Conditions:**
1. Validators must have heterogeneous listener configurations (some with vulnerable listeners, others without)
2. A listener implementation must have a panic-triggering bug
3. The attacker must discover the bug and how to trigger it via transaction data

**Likelihood Assessment:**
- **High:** The Cosmos ecosystem encourages modularity and third-party plugins. State streaming listeners are commonly deployed for monitoring, indexing, and data export.
- **Moderate Complexity:** Discovering listener bugs requires some code analysis, but many listener implementations are open source.
- **Persistent Risk:** Once discovered, the attack can be repeated indefinitely until all validators upgrade or disable the vulnerable listener.
- **Real-World Precedent:** Panic-related consensus failures have occurred in other blockchain systems when non-consensus components (like RPC interfaces or monitoring tools) unexpectedly affected consensus-critical paths.

## Recommendation

Implement panic recovery in the `onWrite` function to isolate listener failures from transaction execution:

```go
func (s *Store) onWrite(delete bool, key, value []byte) {
    for _, l := range s.listeners {
        func(listener types.WriteListener) {
            defer func() {
                if r := recover(); r != nil {
                    // Log the panic but don't propagate it
                    // This ensures listener failures cannot affect transaction execution
                    s.logger.Error("listener panic during OnWrite", 
                        "error", r, 
                        "storeKey", s.parentStoreKey.Name())
                }
            }()
            if err := l.OnWrite(s.parentStoreKey, key, value, delete); err != nil {
                // Log error as intended in ADR-038
                s.logger.Error("listener error during OnWrite",
                    "error", err,
                    "storeKey", s.parentStoreKey.Name())
            }
        }(l)
    }
}
```

This ensures:
1. Listener panics are caught and logged instead of propagating
2. Listener errors are checked and logged (fixing the missing error handling)
3. Transaction execution remains deterministic regardless of listener configuration
4. Observability is preserved through logging

## Proof of Concept

**File:** `store/listenkv/store_test.go`

**Test Function:** `TestListenerPanicDoesNotFailTransaction`

**Setup:**
Create a malicious listener that panics when it receives a specific key pattern. Configure a store with this listener.

**Trigger:**
Perform a `Set` operation with a key that triggers the listener panic. In a real BaseApp transaction, this would occur during `msCache.Write()`.

**Observation:**
The test demonstrates that without panic recovery, a panicking listener causes the entire operation to panic (simulating transaction failure). The test should panic to confirm the vulnerability.

```go
// Add to store/listenkv/store_test.go

// PanicListener panics when it sees a specific key
type PanicListener struct {
    panicKey []byte
}

func (p *PanicListener) OnWrite(storeKey types.StoreKey, key []byte, value []byte, delete bool) error {
    if bytes.Equal(key, p.panicKey) {
        panic("intentional panic to demonstrate vulnerability")
    }
    return nil
}

func TestListenerPanicCausesOperationFailure(t *testing.T) {
    // Setup: Create a store with a panic-triggering listener
    panicListener := &PanicListener{panicKey: []byte("trigger-panic")}
    memDB := dbadapter.Store{DB: dbm.NewMemDB()}
    store := listenkv.NewStore(memDB, testStoreKey, []types.WriteListener{panicListener})
    
    // Trigger: Attempt to set a key that triggers the listener panic
    // This simulates what happens during transaction execution when msCache.Write() is called
    require.Panics(t, func() {
        store.Set([]byte("trigger-panic"), []byte("some-value"))
    }, "Expected panic from listener to propagate and cause operation failure")
    
    // Observation: The panic propagates, demonstrating that in a real transaction,
    // this would cause the transaction to fail on nodes with this listener but
    // succeed on nodes without it, breaking consensus determinism.
}
```

**Running the Test:**
```bash
cd store/listenkv
go test -v -run TestListenerPanicCausesOperationFailure
```

**Expected Result:**
The test passes (confirming the panic occurs), which proves the vulnerability: listener panics propagate and would cause transaction failures in production, creating non-deterministic behavior across validators with different listener configurations.

### Citations

**File:** store/listenkv/store.go (L159-163)
```go
func (s *Store) onWrite(delete bool, key, value []byte) {
	for _, l := range s.listeners {
		l.OnWrite(s.parentStoreKey, key, value, delete)
	}
}
```

**File:** docs/architecture/adr-038-state-listening.md (L128-135)
```markdown
// onWrite writes a KVStore operation to all of the WriteListeners
func (s *Store) onWrite(delete bool, key, value []byte) {
	for _, l := range s.listeners {
		if err := l.OnWrite(s.parentStoreKey, key, value, delete); err != nil {
                    // log error
                }
	}
}
```

**File:** baseapp/baseapp.go (L904-915)
```go
	defer func() {
		if r := recover(); r != nil {
			acltypes.SendAllSignalsForTx(ctx.TxCompletionChannels())
			recoveryMW := newOutOfGasRecoveryMiddleware(gasWanted, ctx, app.runTxRecoveryMiddleware)
			recoveryMW = newOCCAbortRecoveryMiddleware(recoveryMW) // TODO: do we have to wrap with occ enabled check?
			err, result = processRecovery(r, recoveryMW), nil
			if mode != runTxModeDeliver {
				ctx.MultiStore().ResetEvents()
			}
		}
		gInfo = sdk.GasInfo{GasWanted: gasWanted, GasUsed: ctx.GasMeter().GasConsumed(), GasEstimate: gasEstimate}
	}()
```

**File:** baseapp/baseapp.go (L998-998)
```go
		msCache.Write()
```

**File:** baseapp/recovery.go (L87-96)
```go
func newDefaultRecoveryMiddleware() recoveryMiddleware {
	handler := func(recoveryObj interface{}) error {
		return sdkerrors.Wrap(
			sdkerrors.ErrPanic, fmt.Sprintf(
				"recovered: %v\nstack:\n%v", recoveryObj, string(debug.Stack()),
			),
		)
	}

	return newRecoveryMiddleware(handler, nil)
```

**File:** baseapp/options.go (L362-371)
```go
// SetStreamingService is used to set a streaming service into the BaseApp hooks and load the listeners into the multistore
func (app *BaseApp) SetStreamingService(s StreamingService) {
	// add the listeners for each StoreKey
	for key, lis := range s.Listeners() {
		app.cms.AddListeners(key, lis)
	}
	// register the StreamingService within the BaseApp
	// BaseApp will pass BeginBlock, DeliverTx, and EndBlock requests and responses to the streaming services to update their ABCI context
	app.abciListeners = append(app.abciListeners, s)
}
```
