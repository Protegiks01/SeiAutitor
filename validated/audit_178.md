# Audit Report

## Title
Array Index Out-of-Bounds Panic in Slashing Module Migration Causes Network Halt During Upgrade

## Summary
The `Migrate3to4` function in the slashing module's migration code lacks an upper bound check when converting missed block heights to a boolean array. When the chain experiences a rollback and then executes an upgrade, stored missed block heights from before the rollback (which are greater than the current block height) cause an array index out-of-bounds panic, halting all nodes and preventing the network from processing any blocks. [1](#0-0) 

## Impact
**High** - Network not being able to confirm new transactions (total network shutdown)

## Finding Description

**Location:** The vulnerability exists in `x/slashing/keeper/migrations.go`, specifically in the `Migrate3to4` function at lines 206-212 where missed block heights are converted to a boolean array. [2](#0-1) 

**Intended Logic:** The migration should convert legacy missed block height data into a boolean array representation for the current sliding window. It should only include heights within the valid window range `[startWindowHeight, ctx.BlockHeight())` by filtering out heights outside this range.

**Actual Logic:** The code calculates `startWindowHeight = ctx.BlockHeight() - window` and creates `newBoolArray` with length `window`. When iterating through missed heights, it only checks if `height < startWindowHeight` (lower bound) but does NOT validate that `height < ctx.BlockHeight()` (upper bound). For any height >= ctx.BlockHeight(), the calculated index becomes `height - startWindowHeight >= window`, causing an out-of-bounds array access that triggers a panic.

**Exploitation Path:**
1. Blockchain operates normally, accumulating missed block data for validators at various heights
2. Chain experiences a rollback to an earlier height (due to consensus failure, network split, or state corruption)
3. Missed block height data from before the rollback (higher heights) remains in the state store
4. An upgrade is scheduled and executed at the rolled-back height
5. During BeginBlocker, the upgrade mechanism calls `Migrate3to4` migration [3](#0-2) 
6. The migration encounters stored missed block heights greater than the current block height
7. The code attempts to access `newBoolArray[index]` where `index >= window`
8. Go runtime panics with "index out of range"
9. All nodes crash when processing the upgrade block
10. Network halts completely as no node can successfully process the block

**Security Guarantee Broken:** This violates the blockchain's liveness and availability guarantees. The upgrade mechanism, which executes in BeginBlocker before other module operations, panics and prevents all block processing, causing complete network shutdown.

## Impact Explanation

**Affected Components:** The entire blockchain network. All validator nodes and full nodes attempting to process the upgrade block will experience the identical panic and halt.

**Severity of Damage:**
- Complete network shutdown - no blocks can be produced or validated
- All transaction finality ceases network-wide  
- Cannot recover without manual intervention (state surgery to remove invalid heights or coordinated rollback)
- Requires emergency coordination among validators to resolve
- May require hard fork if state cannot be easily repaired
- Undermines the blockchain's fundamental property of continuous operation

The upgrade mechanism, intended to improve the system, instead becomes a deterministic kill switch when specific state conditions exist from chain rollbacks.

## Likelihood Explanation

**Triggering Conditions:** 
This is not directly attacker-triggered but occurs automatically when operational conditions align:
- The blockchain experiences a rollback to a height lower than some stored missed block heights
- An upgrade is scheduled and executed after the rollback  
- The slashing module's consensus version upgrades from version 3 to 4 [4](#0-3) 

**Frequency:** While chain rollbacks are rare in production, they DO occur during:
- Major consensus bugs requiring coordinated rollback
- Network splits requiring state reconciliation
- Testnet/devnet operations where rollbacks are more common
- State replay during node recovery from backups

Once these conditions exist, the vulnerability triggers deterministically during the upgrade with 100% reproducibility. Every node processing the upgrade block will panic identically.

## Recommendation

Add an upper bound check before array access to ensure the calculated index is within valid range:

```go
for _, height := range heights {
    if height < startWindowHeight {
        continue
    }
    // Add upper bound check
    if height >= ctx.BlockHeight() {
        continue  // Skip heights beyond current block height
    }
    index := height - startWindowHeight
    newBoolArray[index] = true
}
```

This ensures only heights within the valid window `[startWindowHeight, ctx.BlockHeight())` are processed, preventing out-of-bounds access while properly handling the rollback scenario by silently ignoring future heights.

## Proof of Concept

**Test Function:** Add to `x/slashing/keeper/migrations_test.go`:

**Setup:**
- Initialize test app and blockchain context at height 9000 (simulating post-rollback state)
- Create validator with signing info
- Set SignedBlocksWindow parameter to 100
- Calculate: startWindowHeight = 9000 - 100 = 8900

**Action:**
- Store legacy missed block heights [9950, 9960, 9970] that are greater than current block height 9000
- These simulate data from before a chain rollback
- Call `Migrate3to4` migration function

**Result:**
- Migration calculates: index = 9950 - 8900 = 1050
- Attempts to access `newBoolArray[1050]`
- Array only has length 100 (valid indices 0-99)
- Go runtime panics: "index out of range [1050] with length 100"
- This demonstrates the vulnerability causes BeginBlocker to panic during upgrade, which would halt the entire network in production

The test demonstrates that when missed block heights from before a rollback remain in state, the migration code deterministically panics, causing complete network shutdown during the upgrade.

## Notes

This vulnerability is particularly severe because:
1. It affects the upgrade mechanism itself, which runs in BeginBlocker before any other operations
2. The panic is deterministic - all nodes will fail identically when processing the upgrade block
3. Recovery requires manual state intervention, not just a binary update
4. The scenario (rollback + upgrade) is operationally realistic, especially in testnets and during consensus issues
5. The missing bounds check is a straightforward oversight that violates defensive programming practices for array access

### Citations

**File:** x/slashing/keeper/migrations.go (L192-212)
```go
	startWindowHeight := ctx.BlockHeight() - window
	iter := sdk.KVStorePrefixIterator(store, types.ValidatorMissedBlockBitArrayKeyPrefix)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var missedInfo types.ValidatorMissedBlockArrayLegacyMissedHeights
		key := iter.Key()
		consAddrBytes := key[2:]

		consAddr := sdk.ConsAddress(consAddrBytes)
		ctx.Logger().Info(fmt.Sprintf("Migrating for next validator with consAddr: %s\n", consAddr.String()))

		newBoolArray := make([]bool, window)
		m.keeper.cdc.MustUnmarshal(iter.Value(), &missedInfo)
		heights := missedInfo.MissedHeights
		for _, height := range heights {
			if height < startWindowHeight {
				continue
			}
			index := height - startWindowHeight
			newBoolArray[index] = true
		}
```

**File:** x/upgrade/abci.go (L61-72)
```go
	if plan.ShouldExecute(ctx) {
		// If skip upgrade has been set for current height, we clear the upgrade plan
		if k.IsSkipHeight(ctx.BlockHeight()) {
			skipUpgrade(k, ctx, plan)
			return
		}
		// If we don't have an upgrade handler for this upgrade name, then we need to shutdown
		if !k.HasHandler(plan.Name) {
			panicUpgradeNeeded(k, ctx, plan)
		}
		applyUpgrade(k, ctx, plan)
		return
```

**File:** x/slashing/module.go (L152-156)
```go
	m := keeper.NewMigrator(am.keeper)
	cfg.RegisterMigration(types.ModuleName, 1, m.Migrate1to2)
	cfg.RegisterMigration(types.ModuleName, 2, m.Migrate2to3)
	cfg.RegisterMigration(types.ModuleName, 3, m.Migrate3to4)
}
```
