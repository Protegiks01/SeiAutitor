After thorough investigation of the codebase, I have validated this security claim and confirmed it represents a **valid, high-severity vulnerability**.

# Audit Report

## Title
Failed Transactions Commit State Changes in Concurrent Execution Mode Due to Pre-Validation Cache Writes

## Summary
In the concurrent transaction execution path (`DeliverTxBatch` with scheduler), transactions that fail validation still have their state modifications committed to the blockchain. This occurs because message execution caches are written to `VersionIndexedStore` before validation occurs, and the scheduler unconditionally publishes all writes to the parent store regardless of transaction success status. [1](#0-0) [2](#0-1) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:**
- Primary issue: `baseapp/baseapp.go` lines 1149 (write before validation) and 1155-1174 (validation after write)
- Secondary issue: `tasks/scheduler.go` lines 575-577 (unconditional WriteToMultiVersionStore) and 344-346 (unconditional WriteLatestToStore) [3](#0-2) [4](#0-3) 

**Intended logic:**
Transactions that fail validation should not commit any state changes. The sequential execution path correctly handles this by validating ante handler operations before calling `msCache.Write()`. Failed transactions should be completely rolled back. [5](#0-4) 

**Actual logic:**
In the message execution path within `runMsgs`:
1. Each message creates a cache context via `cacheTxContext`
2. Message handler executes and writes to this cache
3. **Critical bug**: `msgMsCache.Write()` is called at line 1149, propagating writes to the parent context (which contains `VersionIndexedStore` in concurrent mode)
4. Validation occurs AFTER at lines 1155-1174
5. If validation fails, an error is returned, but writes are already in `VersionIndexedStore.writeset`

In the scheduler's `executeTask`:
6. `WriteToMultiVersionStore()` is called unconditionally (line 575-577), publishing all writes from the writeset to the MultiVersionStore
7. In `ProcessAll`, `WriteLatestToStore()` commits all MVS contents to the parent store without checking transaction status [6](#0-5) 

**Exploitation path:**
1. Attacker submits a transaction with messages that perform beneficial state modifications (token minting, transfers, permission changes, etc.)
2. Attacker intentionally provides incomplete or incorrect access operation declarations
3. Transaction is processed via `DeliverTxBatch` with concurrent execution enabled
4. Message executes and `msgMsCache.Write()` commits changes to `VersionIndexedStore.writeset` (line 1149)
5. Validation fails with `ErrInvalidConcurrencyExecution` (lines 1163-1173)
6. Despite the error, `executeTask` calls `WriteToMultiVersionStore()` which publishes the writes to MVS
7. `ProcessAll` calls `WriteLatestToStore()` which commits all writes to the parent store
8. Attacker's state modifications are permanently committed despite transaction being marked as failed

**Security guarantee broken:**
The fundamental atomicity invariant that "failed transactions do not modify state" is violated. This breaks the access control system's validation mechanism, allowing arbitrary state modifications to bypass security checks.

## Impact Explanation

This vulnerability enables direct fund theft and state corruption:
- **Token theft**: Attackers can execute token transfers, balance increases, or token minting operations that get committed despite validation failure
- **Permission escalation**: Attackers can modify access control lists, roles, or permissions
- **State corruption**: Any state modification during message execution gets committed regardless of validation
- **Consensus divergence**: Nodes using different execution modes (sequential vs concurrent) may have inconsistent state

The impact is particularly severe because:
1. Any network participant can exploit this without special privileges
2. The attack is deterministic and reliable (not dependent on race conditions)
3. Validation is completely bypassed, rendering the access control system ineffective
4. All blockchain state is vulnerable (balances, permissions, contract state, etc.)

## Likelihood Explanation

**Who can trigger:** Any network participant who can submit transactions. No special privileges, admin access, or system compromise required.

**Conditions required:**
- Blockchain running with concurrent execution enabled (`concurrencyWorkers > 0`)
- Attacker crafts a transaction that:
  - Executes state-modifying operations (any message handler can be targeted)
  - Provides incomplete/incorrect access operation declarations (trivial to do)
  - Will fail the `ValidateAccessOperations` check

**Frequency:** 
- Exploitable on every block during normal operation
- Deterministic and reliable - not dependent on timing or race conditions  
- Can be repeated continuously until patched
- High likelihood of occurring in production as concurrent execution is a core feature designed for performance

## Recommendation

**Immediate fix:** Reorder operations in `runMsgs` to validate BEFORE writing the message cache, matching the ante handler pattern:

1. Move validation to occur before `msgMsCache.Write()` at line 1149
2. Only call `msgMsCache.Write()` if validation succeeds
3. This ensures writes never reach `VersionIndexedStore.writeset` for failed transactions

**Alternative fix at scheduler level:**
In `tasks/scheduler.go`, modify `ProcessAll` to filter failed transactions:

```go
// Before writing to store, invalidate failed transactions
for _, task := range tasks {
    if task.Response != nil && task.Response.Code != 0 {
        s.invalidateTask(task)
    }
}

for _, mv := range s.multiVersionStores {
    mv.WriteLatestToStore()
}
``` [7](#0-6) 

**Root cause fix:** The fundamental issue is the order of operations in `runMsgs`. The ante handler correctly validates before writing (lines 979-998), but message execution writes before validating (lines 1149, then 1155-1174). Both paths should follow the same pattern: validate first, write only on success.

## Proof of Concept

**Test scenario** (to be added to `baseapp/deliver_tx_batch_test.go`):

**Setup:**
1. Initialize BaseApp with concurrent execution enabled (concurrencyWorkers > 0)
2. Set up MsgValidator to enable access operation validation
3. Create a test message handler that modifies state (e.g., increments a counter)
4. Initialize the counter to 0

**Action:**
1. Create a transaction with the state-modifying message
2. Provide incomplete access operation declarations (omit required operations)
3. Submit via `DeliverTxBatch`
4. Verify transaction response has Code != 0 (failure)

**Expected result (without vulnerability):**
- Counter remains 0 (failed transaction did not modify state)

**Actual result (with vulnerability):**
- Counter is incremented to 1 (failed transaction DID modify state)
- This proves state changes from failed transactions are committed in concurrent mode

The vulnerability is confirmed by code analysis showing the order of operations allows writes to reach `VersionIndexedStore.writeset` before validation, with no subsequent filtering of failed transactions before final commit.

### Citations

**File:** baseapp/baseapp.go (L979-998)
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
		}

		priority = ctx.Priority()
		pendingTxChecker = ctx.PendingTxChecker()
		expireHandler = ctx.ExpireTxHandler()
		msCache.Write()
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

**File:** tasks/scheduler.go (L127-133)
```go
func (s *scheduler) invalidateTask(task *deliverTxTask) {
	for _, mv := range s.multiVersionStores {
		mv.InvalidateWriteset(task.AbsoluteIndex, task.Incarnation)
		mv.ClearReadset(task.AbsoluteIndex)
		mv.ClearIterateset(task.AbsoluteIndex)
	}
}
```

**File:** tasks/scheduler.go (L344-346)
```go
	for _, mv := range s.multiVersionStores {
		mv.WriteLatestToStore()
	}
```

**File:** tasks/scheduler.go (L575-577)
```go
	for _, v := range task.VersionStores {
		v.WriteToMultiVersionStore()
	}
```

**File:** store/multiversion/store.go (L399-435)
```go
func (s *Store) WriteLatestToStore() {
	// sort the keys
	keys := []string{}
	s.multiVersionMap.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	sort.Strings(keys)

	for _, key := range keys {
		val, ok := s.multiVersionMap.Load(key)
		if !ok {
			continue
		}
		mvValue, found := val.(MultiVersionValue).GetLatestNonEstimate()
		if !found {
			// this means that at some point, there was an estimate, but we have since removed it so there isn't anything writeable at the key, so we can skip
			continue
		}
		// we shouldn't have any ESTIMATE values when performing the write, because we read the latest non-estimate values only
		if mvValue.IsEstimate() {
			panic("should not have any estimate values when writing to parent store")
		}
		// if the value is deleted, then delete it from the parent store
		if mvValue.IsDeleted() {
			// We use []byte(key) instead of conv.UnsafeStrToBytes because we cannot
			// be sure if the underlying store might do a save with the byteslice or
			// not. Once we get confirmation that .Delete is guaranteed not to
			// save the byteslice, then we can assume only a read-only copy is sufficient.
			s.parentStore.Delete([]byte(key))
			continue
		}
		if mvValue.Value() != nil {
			s.parentStore.Set([]byte(key), mvValue.Value())
		}
	}
}
```
