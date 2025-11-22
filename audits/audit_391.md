## Audit Report

## Title
Non-Atomic Upgrade Info File Write Causes Node Startup Failure After Partial Write

## Summary
The `DumpUpgradeInfoWithInfoToDisk` function uses a non-atomic write operation that can leave a corrupted upgrade-info.json file if the write fails partway through. This prevents nodes from restarting after upgrades, potentially causing network-wide availability issues during coordinated upgrade events. [1](#0-0) 

## Impact
**Medium**

## Finding Description

**Location:** 
- File: `x/upgrade/keeper/keeper.go`
- Function: `DumpUpgradeInfoWithInfoToDisk` (lines 410-427)
- Specific issue: Line 426 uses `os.WriteFile()` without atomic write guarantees

**Intended Logic:**
The function should safely write upgrade information to disk so that when a node restarts after an upgrade, it can read the upgrade details from `upgrade-info.json` to apply necessary store migrations. The file must remain valid even if write operations encounter errors. [2](#0-1) 

**Actual Logic:**
The function uses `os.WriteFile(upgradeInfoFilePath, bz, 0o600)` which performs these operations in sequence:
1. Opens/creates the file with O_WRONLY|O_CREATE|O_TRUNC flags (truncating any existing content)
2. Writes the JSON data
3. Closes the file

If step 2 fails partway (disk full, I/O error, filesystem issues), the file is left with partial JSON data. There is no rollback or recovery mechanism.

**Exploit Scenario:**
1. Network-wide upgrade is scheduled at height H
2. At height H, validators' old binaries call `panicUpgradeNeeded`
3. This calls `DumpUpgradeInfoWithInfoToDisk` to write upgrade info
4. During the write, a node experiences disk space exhaustion or I/O error
5. File is truncated and partially written with invalid JSON: `{"Name":"upgrade-v2","He`
6. The function returns an error and node panics (expected)
7. Operator upgrades the binary and attempts to restart
8. During initialization, `ReadUpgradeInfoFromDisk` is called
9. JSON unmarshal fails on the corrupted file
10. Following the documented pattern, app initialization panics
11. Node cannot start and remains offline [3](#0-2) [4](#0-3) 

**Security Failure:**
This breaks the **availability** guarantee. During coordinated network upgrades when many nodes restart simultaneously and may experience resource constraints, multiple validators can be left unable to restart their nodes. The corrupted file prevents recovery without manual intervention.

## Impact Explanation

**Affected Components:**
- Node availability after upgrades
- Network consensus participation during upgrade windows
- Operator ability to recover nodes automatically

**Severity of Damage:**
During a coordinated network upgrade where disk space may be constrained across multiple validators (due to simultaneous restarts, log accumulation, or storage issues):
- Individual nodes become permanently unable to restart without manual file cleanup
- Operators may not immediately understand the root cause (error message is generic JSON unmarshal failure)
- If 10-30% of validators are affected, this causes "Low" impact node shutdown
- If 30%+ of validators are affected, this causes "Medium" impact node shutdown
- Network availability is degraded during the critical upgrade window

**System Impact:**
Blockchain networks rely on coordinated upgrades for security patches and feature deployment. A flaw that prevents nodes from restarting after upgrades directly threatens network availability and upgrade success. This is particularly critical because:
- Upgrades are mandatory for network participation
- Timing is synchronized across all validators
- Resource constraints (disk space, I/O) are often correlated across nodes during this high-activity period

## Likelihood Explanation

**Who Can Trigger:**
This is not directly triggerable by an attacker but occurs naturally during upgrade operations when:
- Disk space is limited (common in production environments)
- Filesystem I/O errors occur
- System resources are constrained during the restart surge

**Conditions Required:**
- A network upgrade is in progress
- Write operation to upgrade-info.json fails partway through
- This is more likely during coordinated upgrades when:
  - Many processes restart simultaneously
  - Disk usage spikes due to log accumulation
  - I/O subsystem is under load

**Frequency:**
- Occurs during each upgrade where write failures happen
- Risk increases with network size (more validators = higher probability some experience issues)
- Not daily, but affects critical maintenance windows
- Each occurrence prevents affected nodes from participating post-upgrade until manual intervention

## Recommendation

Implement atomic file writes using the write-then-rename pattern:

```go
func (k Keeper) DumpUpgradeInfoWithInfoToDisk(height int64, name string, info string) error {
    upgradeInfoFilePath, err := k.GetUpgradeInfoPath()
    if err != nil {
        return err
    }

    upgradeInfo := upgradeInfo{
        Name:   name,
        Height: height,
        Info:   info,
    }
    bz, err := json.Marshal(upgradeInfo)
    if err != nil {
        return err
    }

    // Write to temporary file first
    tmpFile := upgradeInfoFilePath + ".tmp"
    if err := os.WriteFile(tmpFile, bz, 0o600); err != nil {
        return err
    }

    // Atomic rename to final location
    return os.Rename(tmpFile, upgradeInfoFilePath)
}
```

This ensures either the old file remains intact or the new file is completely written. On POSIX systems, `os.Rename` is atomic, preventing partial states.

## Proof of Concept

**File:** `x/upgrade/keeper/keeper_test.go`

**Test Function:** Add `TestCorruptedUpgradeInfoPreventsRestart` to the `KeeperTestSuite`

**Setup:**
1. Initialize a test keeper with a temporary home directory
2. Create a valid upgrade plan

**Trigger:**
1. Write a corrupted/partial JSON file to the upgrade-info.json path (simulating a failed write)
2. Attempt to read the upgrade info using `ReadUpgradeInfoFromDisk()`

**Observation:**
The test demonstrates that corrupted upgrade-info.json files cause unmarshal errors, which would panic app initialization following the documented pattern. The test would fail on the current vulnerable code by successfully showing the error condition.

```go
func (s *KeeperTestSuite) TestCorruptedUpgradeInfoPreventsRestart() {
    // Get the upgrade info file path
    upgradeInfoPath, err := s.app.UpgradeKeeper.GetUpgradeInfoPath()
    s.Require().NoError(err)

    // Simulate a partially written file (corrupted JSON from failed write)
    corruptedJSON := []byte(`{"Name":"test-upgrade","Height":100,"In`)
    err = os.WriteFile(upgradeInfoPath, corruptedJSON, 0o600)
    s.Require().NoError(err)

    // Attempt to read the upgrade info (this is what happens during app initialization)
    _, err = s.app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
    
    // Verify that reading corrupted file returns an error
    // In production, following the documented pattern, this error causes panic during app init
    s.Require().Error(err, "Reading corrupted upgrade info should return error")
    s.Require().Contains(err.Error(), "unexpected end of JSON input", 
        "Error should indicate JSON unmarshal failure")
}
```

This test proves that if `DumpUpgradeInfoWithInfoToDisk` leaves a partially written file (as can happen with `os.WriteFile` on write failures), the subsequent `ReadUpgradeInfoFromDisk` call will fail, preventing node startup per the documented initialization pattern.

### Citations

**File:** x/upgrade/keeper/keeper.go (L410-427)
```go
func (k Keeper) DumpUpgradeInfoWithInfoToDisk(height int64, name string, info string) error {
	upgradeInfoFilePath, err := k.GetUpgradeInfoPath()
	if err != nil {
		return err
	}

	upgradeInfo := upgradeInfo{
		Name:   name,
		Height: height,
		Info:   info,
	}
	bz, err := json.Marshal(upgradeInfo)
	if err != nil {
		return err
	}

	return os.WriteFile(upgradeInfoFilePath, bz, 0o600)
}
```

**File:** x/upgrade/keeper/keeper.go (L449-472)
```go
func (k Keeper) ReadUpgradeInfoFromDisk() (store.UpgradeInfo, error) {
	var upgradeInfo store.UpgradeInfo

	upgradeInfoPath, err := k.GetUpgradeInfoPath()
	if err != nil {
		return upgradeInfo, err
	}

	data, err := ioutil.ReadFile(upgradeInfoPath)
	if err != nil {
		// if file does not exist, assume there are no upgrades
		if os.IsNotExist(err) {
			return upgradeInfo, nil
		}

		return upgradeInfo, err
	}

	if err := json.Unmarshal(data, &upgradeInfo); err != nil {
		return upgradeInfo, err
	}

	return upgradeInfo, nil
}
```

**File:** x/upgrade/abci.go (L100-113)
```go
// panicUpgradeNeeded shuts down the node and prints a message that the upgrade needs to be applied.
func panicUpgradeNeeded(k keeper.Keeper, ctx sdk.Context, plan types.Plan) {
	// Write the upgrade info to disk. The UpgradeStoreLoader uses this info to perform or skip
	// store migrations.
	err := k.DumpUpgradeInfoWithInfoToDisk(ctx.BlockHeight(), plan.Name, plan.Info)
	if err != nil {
		panic(fmt.Errorf("unable to write upgrade info to filesystem: %s", err.Error()))
	}

	upgradeMsg := BuildUpgradeNeededMsg(plan)
	ctx.Logger().Error(upgradeMsg)

	panic(upgradeMsg)
}
```

**File:** docs/core/upgrade.md (L80-84)
```markdown
```go
upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
if err != nil {
	panic(err)
}
```
