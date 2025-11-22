# Audit Report

## Title
Upgrade Plan Name Injection Allows Cosmovisor to Execute Wrong Binary Leading to Network Halt

## Summary
The upgrade module's `Plan.Name` field lacks validation for special characters, allowing injection of double quotes that can manipulate the upgrade message format. This causes Cosmovisor's regex parser to extract the wrong upgrade name, leading to execution of an incorrect binary and permanent chain halt requiring hard fork recovery.

## Impact
**High**

## Finding Description

**Location:** 
- Validation: [1](#0-0) 
- Message Construction: [2](#0-1) 
- Cosmovisor Parsing: [3](#0-2) 

**Intended Logic:** The upgrade system should validate Plan.Name to ensure it contains only safe characters that won't interfere with message formatting or parsing. Cosmovisor should reliably extract the correct upgrade name from the panic message to load the appropriate binary.

**Actual Logic:** The `ValidateBasic()` function only checks if Plan.Name is non-empty, allowing any characters including double quotes and newlines. When `BuildUpgradeNeededMsg()` constructs the panic message using `fmt.Sprintf("UPGRADE \"%s\" NEEDED at %s: %s", plan.Name, plan.DueAt(), plan.Info)`, a malicious Plan.Name containing `"` can break out of the quoted string. Cosmovisor's regex `UPGRADE "(.*)" NEEDED at ((height): (\d+)|(time): (\S+)):\s+(\S*)` then matches the first occurrence, extracting an attacker-controlled fake upgrade name instead of the real one.

**Exploit Scenario:**
1. Attacker submits governance proposal with crafted Plan.Name: `fake" NEEDED at height: 1: malicious_info\nUPGRADE "real_upgrade`
2. Proposal passes community vote (name appears legitimate in proposal JSON)
3. At upgrade height, BeginBlocker calls `panicUpgradeNeeded()` [4](#0-3) 
4. The panic message becomes: `UPGRADE "fake" NEEDED at height: 1: malicious_info\nUPGRADE "real_upgrade" NEEDED at height: 1000: actual_info`
5. Cosmovisor's `WaitForUpdate()` parses this with the regex [5](#0-4) 
6. Regex matches first occurrence, extracting "fake" as upgrade name
7. Cosmovisor attempts to execute `upgrades/fake/bin/` which doesn't exist
8. All validators fail to upgrade simultaneously, causing permanent network halt

**Security Failure:** Input validation failure allowing format string injection that breaks upgrade orchestration, resulting in consensus failure and total network shutdown.

## Impact Explanation

This vulnerability causes **permanent network shutdown** affecting all validators simultaneously:
- **Network Availability**: Chain halts at upgrade height and cannot progress
- **Transaction Processing**: All pending and new transactions cannot be confirmed
- **Recovery**: Requires coordinated hard fork with manual binary deployment bypassing Cosmovisor
- **Validator Resources**: All validator nodes stuck in crash loop until manual intervention

This falls under the **High severity** in-scope impact: "Network not being able to confirm new transactions (total network shutdown)".

## Likelihood Explanation

**High likelihood** of exploitation:
- **Who**: Any participant with sufficient tokens to submit governance proposals
- **Conditions**: Requires governance approval, but malicious name can be obfuscated (e.g., using Unicode lookalikes or embedding in longer legitimate-looking names)
- **Timing**: Guaranteed to trigger at scheduled upgrade height once proposal passes
- **Frequency**: One successful malicious proposal causes permanent network halt

The attack vector exists in every upgrade governance flow, and validators have no defense once the proposal is approved on-chain.

## Recommendation

Add strict validation to `Plan.ValidateBasic()` to reject Plan.Name and Plan.Info containing special characters that could interfere with message formatting:

```go
func (p Plan) ValidateBasic() error {
    // ... existing checks ...
    
    // Validate name contains only safe characters
    if strings.ContainsAny(p.Name, "\"\n\r\t") {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot contain quotes, newlines, or control characters")
    }
    
    // Validate info doesn't contain characters that break parsing
    if strings.ContainsAny(p.Info, "\"\n\r") {
        return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "info cannot contain quotes or newlines")
    }
    
    return nil
}
```

Alternatively, escape special characters in `BuildUpgradeNeededMsg()` before formatting, or use a more robust message format (JSON) that Cosmovisor can parse safely.

## Proof of Concept

**Test File**: `x/upgrade/types/plan_test.go`

**Test Function**: Add the following test case to demonstrate the vulnerability:

```go
func TestPlanNameInjectionVulnerability(t *testing.T) {
    // Malicious plan with injected double quote to break regex parsing
    maliciousPlan := types.Plan{
        Name:   "fake\" NEEDED at height: 1: malicious\nUPGRADE \"real_upgrade",
        Height: 1000,
        Info:   "actual_info",
    }
    
    // This should fail validation but currently passes
    err := maliciousPlan.ValidateBasic()
    require.NoError(t, err, "Malicious plan passes validation - THIS IS THE BUG")
    
    // Simulate the message that would be logged/panicked
    msg := fmt.Sprintf("UPGRADE \"%s\" NEEDED at height: %d: %s", 
        maliciousPlan.Name, maliciousPlan.Height, maliciousPlan.Info)
    
    // This is what cosmovisor would see in the logs
    t.Logf("Malicious message:\n%s", msg)
    
    // Simulate cosmovisor's regex parsing
    upgradeRegex := regexp.MustCompile(`UPGRADE "(.*)" NEEDED at ((height): (\d+)|(time): (\S+)):\s+(\S*)`)
    matches := upgradeRegex.FindStringSubmatch(msg)
    
    require.NotNil(t, matches, "Regex should match")
    extractedName := matches[1]
    
    // The extracted name is "fake" not "real_upgrade" - cosmovisor will load wrong binary
    t.Logf("Extracted upgrade name: %s", extractedName)
    require.Equal(t, "fake", extractedName, "Cosmovisor extracts wrong upgrade name")
    require.NotEqual(t, maliciousPlan.Name, extractedName, "Demonstrates the injection attack")
}
```

**Setup**: Run in existing test suite: `go test ./x/upgrade/types/... -run TestPlanNameInjectionVulnerability -v`

**Trigger**: The test creates a Plan with an injected double quote that breaks regex parsing

**Observation**: The test demonstrates that:
1. Malicious Plan.Name passes ValidateBasic() validation
2. The constructed upgrade message contains injected content
3. Cosmovisor's regex extracts "fake" instead of the intended upgrade name
4. This would cause Cosmovisor to load the wrong binary, leading to network halt

This test will PASS on vulnerable code (proving the bug exists) and should FAIL after implementing the recommended fix.

### Citations

**File:** x/upgrade/types/plan.go (L21-36)
```go
func (p Plan) ValidateBasic() error {
	if !p.Time.IsZero() {
		return sdkerrors.ErrInvalidRequest.Wrap("time-based upgrades have been deprecated in the SDK")
	}
	if p.UpgradedClientState != nil {
		return sdkerrors.ErrInvalidRequest.Wrap("upgrade logic for IBC has been moved to the IBC module")
	}
	if len(p.Name) == 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "name cannot be empty")
	}
	if p.Height <= 0 {
		return sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "height must be greater than 0")
	}

	return nil
}
```

**File:** x/upgrade/abci.go (L101-113)
```go
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

**File:** x/upgrade/abci.go (L128-130)
```go
func BuildUpgradeNeededMsg(plan types.Plan) string {
	return fmt.Sprintf("UPGRADE \"%s\" NEEDED at %s: %s", plan.Name, plan.DueAt(), plan.Info)
}
```

**File:** cosmovisor/scanner.go (L17-17)
```go
var upgradeRegex = regexp.MustCompile(`UPGRADE "(.*)" NEEDED at ((height): (\d+)|(time): (\S+)):\s+(\S*)`)
```

**File:** cosmovisor/scanner.go (L29-39)
```go
func WaitForUpdate(scanner *bufio.Scanner) (*UpgradeInfo, error) {
	for scanner.Scan() {
		line := scanner.Text()
		if upgradeRegex.MatchString(line) {
			subs := upgradeRegex.FindStringSubmatch(line)
			info := UpgradeInfo{
				Name: subs[1],
				Info: subs[7],
			}
			return &info, nil
		}
```
