# Audit Report

## Title
Event Emission on Concurrent Execution Validation Failure Creates Misleading On-Chain Event Data

## Summary
When a transaction fails concurrent execution validation due to missing access operations, the system emits events from successfully executed messages even though their state changes are rolled back. This creates misleading event data where events indicate state changes that never occurred on-chain, violating the fundamental invariant that events should reflect actual state transitions.

## Impact
**Medium** - This matches the in-scope impact: "A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk."

## Finding Description

**Location:** 
- Primary issue in [1](#0-0) 
- State rollback logic at [2](#0-1) 
- Event emission in response at [3](#0-2) 

**Intended Logic:** 
Events should only be emitted for state changes that are actually persisted to the blockchain. When a transaction fails, either no events should be emitted, or only events from the ante handler (which executes before message processing) should be included, not events from message execution that was rolled back.

**Actual Logic:**
The concurrent execution validation occurs AFTER messages have executed and their events have been collected. When validation fails:

1. Messages execute normally in `runMsgs()` and emit events [4](#0-3) 
2. Each message's state changes are written to its cache at [5](#0-4) 
3. Validation occurs after execution at [6](#0-5) 
4. When validation fails, a Result with accumulated events is returned along with the error [7](#0-6) 
5. In `runTx()`, because an error occurred, the parent cache's `Write()` is NOT called [2](#0-1) , so state changes are discarded
6. However, the Result containing the events is still passed to `DeliverTx()` [3](#0-2) 
7. These events are emitted in the `ResponseDeliverTx` even though the transaction failed [8](#0-7) 

**Exploit Scenario:**
1. Attacker crafts a transaction with one or more messages that perform actions (transfers, contract calls, etc.)
2. The attacker intentionally declares incorrect or incomplete access operations for the transaction
3. The messages execute successfully, modifying state and emitting events
4. The concurrent execution validator detects missing access operations [9](#0-8) 
5. The transaction fails with `ErrInvalidConcurrencyExecution`, and all state changes are rolled back
6. BUT the events from the executed messages are still emitted in the response
7. External systems (indexers, block explorers, dApps, wallets) observe these events and incorrectly believe the state changes occurred
8. This can be used to manipulate off-chain systems, create confusion, or trigger incorrect behavior in smart contracts that listen to events

**Security Failure:**
The system violates the event data integrity invariant. Events are meant to be an immutable, authoritative record of state transitions that occurred on-chain. When events are emitted for rolled-back transactions, they become misleading and can no longer be trusted by external systems that depend on them for indexing, tracking, and decision-making.

## Impact Explanation

**Affected Components:**
- Event data integrity across the blockchain
- External indexers and block explorers that parse events
- DApps and smart contracts that listen to and react to events
- User wallets and interfaces that display transaction results based on events
- Any off-chain system that relies on events for state synchronization

**Severity:**
The damage is significant because:
1. Events are a critical part of blockchain transparency and observability
2. Many systems (indexers like The Graph, block explorers, dApp frontends) rely exclusively on events to understand on-chain state
3. Smart contracts can emit events that other contracts or off-chain systems consume to trigger actions
4. An attacker can deliberately create misleading events without requiring any special privileges
5. The misleading data persists in the blockchain's event log indefinitely
6. Detecting and correcting misleading events requires manual intervention and cross-referencing with actual state

This matters because blockchain systems must maintain strong invariants about data integrity. When events don't reflect actual state changes, the entire event system becomes unreliable, undermining trust in the protocol.

## Likelihood Explanation

**Who can trigger it:**
Any network participant can trigger this vulnerability by submitting a transaction with intentionally incorrect access operation declarations. No special privileges are required.

**Conditions required:**
1. The network must have concurrent execution validation enabled (OCC mode with `MsgValidator` configured) [10](#0-9) 
2. A transaction with one or more messages that execute successfully
3. Incomplete or incorrect access operations declared for the transaction
4. The transaction must be in `runTxModeDeliver` (actual execution, not simulation)

**Frequency:**
This can be exploited as frequently as an attacker wants to submit transactions. There are no rate limits or special requirements beyond creating a valid transaction with incorrect access operation metadata. An attacker could:
- Submit many such transactions to pollute the event log with misleading data
- Target specific events that external systems monitor to trigger incorrect behavior
- Time the attack to coincide with important protocol events or state transitions

The vulnerability is highly practical because:
- Access operation declarations are part of transaction metadata that users control
- Validation only occurs after execution, so the attack always reaches the vulnerable code path
- No sophisticated knowledge is required - simply omitting some access operations from the declaration triggers the issue

## Recommendation

**Primary Fix:**
Modify the concurrent execution validation logic to occur BEFORE message execution, not after. This prevents messages from executing and emitting events if they will fail validation.

**Alternative Fix (if pre-execution validation is not feasible):**
When validation fails after message execution, do NOT return a Result with events. Instead, return only the error without events, similar to how the ante handler validation failure is handled [11](#0-10) .

Change in `runMsgs()` at lines 1169-1173:
```go
// Instead of returning Result with events:
return &sdk.Result{
    Log:    strings.TrimSpace(msgLogs.String()),
    Events: events.ToABCIEvents(),
}, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)

// Return nil Result:
return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
```

This ensures that when validation fails, the transaction's response includes only ante handler events (if any), not message execution events, maintaining the invariant that emitted events correspond to persisted state changes.

**Additional Consideration:**
The comment at line 1169 states "we need to bubble up the events for inspection" [12](#0-11) , suggesting this behavior may be intentional for debugging. If debugging information is needed, it should be logged internally or provided through a separate debugging interface, not emitted as authoritative on-chain events that external systems consume.

## Proof of Concept

**File:** `baseapp/deliver_tx_validation_test.go` (new test file to be added)

**Setup:**
1. Create a BaseApp with concurrent execution validation enabled
2. Register a message handler that modifies store state and emits events
3. Configure the handler with an AnteDepGenerator that declares incomplete access operations
4. Initialize the blockchain state with a test key-value pair

**Trigger:**
1. Create a transaction containing a message that will:
   - Read and write to the store (triggering access operations)
   - Emit a distinctive event (e.g., "transfer_executed" with amount details)
   - Declare incomplete access operations (missing the write operation)
2. Execute the transaction via `DeliverTx` in deliver mode
3. The message executes successfully and emits its event
4. Validation detects the missing write access operation
5. Transaction fails with `ErrInvalidConcurrencyExecution`

**Observation:**
1. Verify the transaction returns an error code indicating validation failure
2. Verify the `ResponseDeliverTx.Events` contains the "transfer_executed" event
3. Query the store to verify the state change was NOT persisted (rolled back)
4. This demonstrates that events were emitted for state changes that didn't occur

**Test Code Structure:**
```go
func TestMisleadingEventsOnValidationFailure(t *testing.T) {
    // Setup BaseApp with OCC validation enabled
    // Register handler that:
    //   - Sets a store value
    //   - Emits event with that value
    //   - Has incomplete access ops (missing write declaration)
    
    // Execute transaction
    // Assert: tx.Code != 0 (failed)
    // Assert: tx.Events contains the emitted event
    // Assert: store.Get(key) returns original value (state not changed)
    // This proves events were emitted without state changes
}
```

The test demonstrates the core issue: events appear in the transaction response indicating successful execution, but querying the actual state shows the changes were rolled back. This violates the fundamental assumption that events reflect actual on-chain state transitions.

### Citations

**File:** baseapp/baseapp.go (L979-979)
```go
		if ctx.MsgValidator() != nil && mode == runTxModeDeliver {
```

**File:** baseapp/baseapp.go (L985-991)
```go
			if len(missingAccessOps) != 0 {
				for op := range missingAccessOps {
					ctx.Logger().Info((fmt.Sprintf("Antehandler Missing Access Operation:%s ", op.String())))
					op.EmitValidationFailMetrics()
				}
				errMessage := fmt.Sprintf("Invalid Concurrent Execution antehandler missing %d access operations", len(missingAccessOps))
				return gInfo, nil, nil, 0, nil, nil, ctx, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
```

**File:** baseapp/baseapp.go (L1015-1016)
```go
	if err == nil && mode == runTxModeDeliver {
		msCache.Write()
```

**File:** baseapp/baseapp.go (L1138-1144)
```go
		msgEvents = msgEvents.AppendEvents(msgResult.GetEvents())

		// append message events, data and logs
		//
		// Note: Each message result's data must be length-prefixed in order to
		// separate each result.
		events = events.AppendEvents(msgEvents)
```

**File:** baseapp/baseapp.go (L1149-1149)
```go
		msgMsCache.Write()
```

**File:** baseapp/baseapp.go (L1155-1174)
```go
		if ctx.MsgValidator() == nil {
			continue
		}
		storeAccessOpEvents := msgMsCache.GetEvents()
		accessOps := ctx.TxMsgAccessOps()[i]
		missingAccessOps := ctx.MsgValidator().ValidateAccessOperations(accessOps, storeAccessOpEvents)
		// TODO: (occ) This is where we are currently validating our per message dependencies,
		// whereas validation will be done holistically based on the mvkv for OCC approach
		if len(missingAccessOps) != 0 {
			for op := range missingAccessOps {
				ctx.Logger().Info((fmt.Sprintf("eventMsgName=%s Missing Access Operation:%s ", eventMsgName, op.String())))
				op.EmitValidationFailMetrics()
			}
			errMessage := fmt.Sprintf("Invalid Concurrent Execution messageIndex=%d, missing %d access operations", i, len(missingAccessOps))
			// we need to bubble up the events for inspection
			return &sdk.Result{
				Log:    strings.TrimSpace(msgLogs.String()),
				Events: events.ToABCIEvents(),
			}, sdkerrors.Wrap(sdkerrors.ErrInvalidConcurrencyExecution, errMessage)
		}
```

**File:** baseapp/abci.go (L305-312)
```go
	if err != nil {
		resultStr = "failed"
		// if we have a result, use those events instead of just the anteEvents
		if result != nil {
			return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(result.Events, app.indexEvents), app.trace)
		}
		return sdkerrors.ResponseDeliverTxWithEvents(err, gInfo.GasWanted, gInfo.GasUsed, sdk.MarkEventsToIndex(anteEvents, app.indexEvents), app.trace)
	}
```
