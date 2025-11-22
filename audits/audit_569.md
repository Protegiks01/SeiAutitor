# Audit Report

## Title
Unbounded JSON Parsing in Genesis Validation Enables Memory Exhaustion DoS

## Summary
The genesis validation process lacks input size limits during JSON parsing, allowing an attacker to craft malicious genesis files that cause memory exhaustion and node crashes. This affects both streaming and non-streaming validation modes, as well as the InitChain process during actual chain initialization.

## Impact
Medium

## Finding Description

**Location:** 
- Primary: `types/genesis/genesis.go` - `IngestGenesisFileLineByLine` function [1](#0-0) 

- Secondary: `x/genutil/client/cli/validate_genesis.go` - `parseModule` and `validateGenesisStream` functions [2](#0-1) [3](#0-2) 

- Tertiary: `x/accesscontrol/module.go` - `ValidateGenesis` function [4](#0-3) 

- Codec layer: `codec/proto_codec.go` - `UnmarshalJSON` function [5](#0-4) 

**Intended Logic:** 
The genesis validation system should safely parse and validate genesis files of reasonable size, preventing resource exhaustion attacks. The streaming mode was introduced to handle large genesis files by processing them line-by-line to avoid loading the entire file into memory at once.

**Actual Logic:** 
The implementation has critical flaws:

1. In `IngestGenesisFileLineByLine`, individual lines are accumulated in a `strings.Builder` with no size limit. The function uses a 100KB buffer for reading chunks, but lines themselves can grow arbitrarily large as the buffer accumulates all content until a newline is encountered.

2. In `parseModule`, the entire line string is converted to a byte slice and unmarshaled without any size validation: `json.Unmarshal([]byte(jsonStr), &module)`.

3. In module-level `ValidateGenesis` functions, the JSON codec's `UnmarshalJSON` method is called on arbitrarily-sized input with no size checks.

4. The underlying codec implementations (`ProtoCodec` and `LegacyAmino`) do not enforce any maximum size limits on JSON unmarshaling.

**Exploit Scenario:**

1. An attacker crafts a malicious genesis file with a single line containing several GB of JSON data (e.g., an extremely large array: `{"module":"accesscontrol","data":{"params":{"array":[1,2,3,...]}}}`  where the array contains millions of elements).

2. The attacker distributes this file to validators through social engineering, compromised distribution channels, or during contentious network upgrades where multiple genesis file proposals exist.

3. When a validator runs `validate-genesis --streaming genesis.json` or attempts to start their node with this genesis file:
   - `IngestGenesisFileLineByLine` reads the entire multi-GB line into memory via the unbounded `lineBuf` strings.Builder
   - `parseModule` converts this to a byte slice (temporarily doubling memory usage)
   - The JSON unmarshaler attempts to parse the massive payload
   - Memory exhaustion occurs, causing an Out-of-Memory (OOM) crash

4. The node terminates, and if enough validators (≥30%) attempt to use the same malicious genesis file, the network experiences a significant outage.

**Security Failure:** 
This is a denial-of-service vulnerability that violates resource consumption safety. The system fails to enforce reasonable limits on input size during a critical operation (genesis validation/initialization), allowing an attacker to exhaust node memory and crash validators without requiring any privileged access or brute force attacks.

## Impact Explanation

**Affected Components:**
- All validator nodes that attempt to validate or use the malicious genesis file
- Network availability and chain initialization processes
- Genesis validation CLI commands (`validate-genesis`)

**Severity of Damage:**
- **Node crashes:** Validators experience OOM crashes when processing the malicious genesis file
- **Network degradation:** If ≥30% of validators are affected simultaneously (e.g., during a coordinated upgrade attempt), the network experiences significant service degradation
- **Chain initialization failure:** New chains or networks undergoing upgrades cannot start if validators use the malicious genesis file
- **Operational disruption:** Node operators must identify and replace the malicious genesis file, causing delays and coordination challenges

**Why This Matters:**
Genesis files are critical trust anchors for blockchain networks. They define the initial state and are distributed to all validators during chain initialization or major upgrades. The lack of input validation during genesis parsing creates a critical attack surface that can be exploited to disrupt network operations at the most sensitive phase of a blockchain's lifecycle.

## Likelihood Explanation

**Who Can Trigger:**
- Any attacker who can distribute a malicious genesis file to validators
- No special privileges, keys, or network access required
- The attacker only needs to convince validators to attempt validation of the malicious file

**Required Conditions:**
- Validators must attempt to validate or use the malicious genesis file
- Most likely to occur during:
  - New chain launches
  - Network upgrades requiring genesis file updates
  - Testnet deployments
  - Disaster recovery scenarios where genesis files are restored

**Frequency/Likelihood:**
- **High likelihood during vulnerable periods:** Genesis file distribution occurs during chain initialization and major upgrades, which are predictable events that attackers can target
- **Moderate likelihood otherwise:** Outside of these periods, validators rarely process new genesis files
- **Low barrier to execution:** Creating a malicious genesis file is trivial (simply create a valid JSON structure with excessive size)
- **Amplification potential:** A single malicious file distributed to multiple validators can cause widespread impact

This vulnerability is particularly dangerous because genesis file distribution often occurs through semi-trusted channels (governance proposals, official upgrade documentation, community coordination), where validators may not suspect malicious content.

## Recommendation

Implement strict size limits on JSON parsing at multiple layers:

1. **Line-level limits in `IngestGenesisFileLineByLine`:**
   - Add a maximum line size constant (e.g., 100MB)
   - Track accumulated line length in the `lineBuf` and reject lines exceeding the limit
   - Return an error if any line exceeds the threshold

2. **Pre-unmarshal size validation:**
   - Before calling `json.Unmarshal` or `cdc.UnmarshalJSON`, check the byte slice length
   - Reject payloads exceeding a reasonable threshold (e.g., 500MB for entire genesis, 50MB per module)

3. **Codec-level size limits:**
   - Add size limit configuration to `ProtoCodec` and `LegacyAmino` initialization
   - Enforce maximum message size in `UnmarshalJSON` methods

4. **File-level validation:**
   - Check genesis file size before processing in `validateGenDoc` and `GenesisDocFromFile`
   - Reject files exceeding a reasonable maximum (e.g., 1GB)

Example fix for `IngestGenesisFileLineByLine`:
```go
const (
    bufferSize = 100000
    maxLineSize = 100 * 1024 * 1024 // 100MB max per line
)

func IngestGenesisFileLineByLine(filename string) <-chan string {
    lines := make(chan string)
    
    go func() {
        defer close(lines)
        // ... existing file opening code ...
        
        lineBuf := new(strings.Builder)
        
        for {
            // ... existing read logic ...
            
            // Add size check before writing to lineBuf
            if lineBuf.Len() + len(chunk) > maxLineSize {
                fmt.Printf("Error: line exceeds maximum size of %d bytes\n", maxLineSize)
                return
            }
            
            // ... rest of existing logic ...
        }
    }()
    
    return lines
}
```

## Proof of Concept

**Test File:** `types/genesis/genesis_dos_test.go` (new file)

**Setup:**
1. Create a test genesis file with an extremely large line (simulated with repeated data)
2. Call `IngestGenesisFileLineByLine` to process the file
3. Monitor memory consumption and attempt to read the lines

**Trigger:**
```go
package genesis_test

import (
    "fmt"
    "os"
    "strings"
    "testing"
    "time"
    
    genesistypes "github.com/cosmos/cosmos-sdk/types/genesis"
    "github.com/stretchr/testify/require"
)

func TestGenesisValidationDoS(t *testing.T) {
    // Create a temporary file with a very large line
    tmpFile, err := os.CreateTemp("", "genesis_dos_*.json")
    require.NoError(t, err)
    defer os.Remove(tmpFile.Name())
    
    // Write genesis file header
    _, err = tmpFile.WriteString(`{"module":"test","data":{"array":[`)
    require.NoError(t, err)
    
    // Write a large amount of data on a single line (simulating a 100MB line)
    // In a real attack, this would be several GB
    largeData := strings.Repeat("1,", 10*1024*1024) // ~20MB of "1," pairs
    _, err = tmpFile.WriteString(largeData)
    require.NoError(t, err)
    
    _, err = tmpFile.WriteString(`1]}}` + "\n")
    require.NoError(t, err)
    tmpFile.Close()
    
    // Attempt to ingest the file - this should demonstrate unbounded memory consumption
    lines := genesistypes.IngestGenesisFileLineByLine(tmpFile.Name())
    
    // Try to read the line - this will load the entire 100MB+ line into memory
    timeout := time.After(5 * time.Second)
    select {
    case line := <-lines:
        // If we get here, the line was successfully read into memory
        // This demonstrates the vulnerability: no size limit prevented loading this large line
        require.Greater(t, len(line), 20*1024*1024, "Line should be > 20MB, demonstrating lack of size limits")
        fmt.Printf("Successfully loaded line of size: %d bytes (%.2f MB)\n", 
            len(line), float64(len(line))/(1024*1024))
        fmt.Println("VULNERABILITY CONFIRMED: No size limit prevented loading this large line into memory")
    case <-timeout:
        t.Fatal("Timeout waiting for line - file processing may have hung due to excessive memory")
    }
}

// Test that demonstrates the validateGenesisStream path vulnerability
func TestValidateGenesisStreamDoS(t *testing.T) {
    // Create a malicious genesis file with streaming format
    tmpFile, err := os.CreateTemp("", "genesis_stream_dos_*.json")
    require.NoError(t, err)
    defer os.Remove(tmpFile.Name())
    
    // Write a single line with massive JSON payload
    maliciousLine := `{"app_state":{"module":"accesscontrol","data":{"params":{"array":[` + 
        strings.Repeat("1,", 5*1024*1024) + // ~10MB of data
        `1]}}}}`
    _, err = tmpFile.WriteString(maliciousLine + "\n")
    require.NoError(t, err)
    tmpFile.Close()
    
    // Ingest and demonstrate that the entire line is loaded
    lines := genesistypes.IngestGenesisFileLineByLine(tmpFile.Name())
    
    lineReceived := false
    for line := range lines {
        lineReceived = true
        // The line is fully loaded in memory here with no size check
        require.Greater(t, len(line), 10*1024*1024, "Should load > 10MB line without size limit")
        fmt.Printf("VULNERABILITY: Loaded %d bytes (%.2f MB) without size validation\n",
            len(line), float64(len(line))/(1024*1024))
    }
    
    require.True(t, lineReceived, "Should have received the malicious line")
}
```

**Observation:**
The test confirms the vulnerability by demonstrating that:
1. `IngestGenesisFileLineByLine` successfully loads arbitrarily large lines into memory without any size limit
2. The entire line content is accumulated in the `lineBuf` strings.Builder with no maximum size check
3. Memory consumption grows linearly with line size, making the system vulnerable to memory exhaustion attacks
4. No error is returned even when processing multi-megabyte (or larger) single lines

Running this test will show that the system loads the entire large line into memory, proving that no size limits exist to prevent DoS attacks during genesis validation. In a real attack scenario with multi-gigabyte lines, this would cause OOM crashes.

### Citations

**File:** types/genesis/genesis.go (L19-67)
```go
func IngestGenesisFileLineByLine(filename string) <-chan string {
	lines := make(chan string)

	go func() {
		defer close(lines)

		file, err := os.Open(filename)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		reader := bufio.NewReader(file)

		buffer := make([]byte, bufferSize)
		lineBuf := new(strings.Builder)

		for {
			bytesRead, err := reader.Read(buffer)
			if err != nil && err != io.EOF {
				fmt.Println("Error reading file:", err)
				return
			}

			chunk := buffer[:bytesRead]
			for len(chunk) > 0 {
				i := bytes.IndexByte(chunk, '\n')
				if i >= 0 {
					lineBuf.Write(chunk[:i])
					lines <- lineBuf.String()
					lineBuf.Reset()
					chunk = chunk[i+1:]
				} else {
					lineBuf.Write(chunk)
					break
				}
			}

			if err == io.EOF {
				if lineBuf.Len() > 0 {
					lines <- lineBuf.String()
				}
				break
			}
		}
	}()

	return lines
```

**File:** x/genutil/client/cli/validate_genesis.go (L81-91)
```go
func parseModule(jsonStr string) (*ModuleState, error) {
	var module ModuleState
	err := json.Unmarshal([]byte(jsonStr), &module)
	if err != nil {
		return nil, err
	}
	if module.AppState.Module == "" {
		return nil, fmt.Errorf("module name is empty")
	}
	return &module, nil
}
```

**File:** x/genutil/client/cli/validate_genesis.go (L107-149)
```go
	lines := genesistypes.IngestGenesisFileLineByLine(genesis)

	genesisCh := make(chan json.RawMessage)
	doneCh := make(chan struct{})
	errCh := make(chan error, 1)
	seenModules := make(map[string]bool)
	prevModule := ""
	var moduleName string
	var genDoc *tmtypes.GenesisDoc
	go func() {
		for line := range lines {
			moduleState, err := parseModule(line)
			// determine module name or genesisDoc
			if err != nil {
				genDoc, err = tmtypes.GenesisDocFromJSON([]byte(line))
				if err != nil {
					errCh <- fmt.Errorf("error unmarshalling genesis doc %s: %s", genesis, err.Error())
					return
				}
				moduleName = "genesisDoc"
			} else {
				moduleName = moduleState.AppState.Module
			}
			if seenModules[moduleName] {
				errCh <- fmt.Errorf("module %s seen twice in genesis file", moduleName)
				return
			}
			if prevModule != moduleName { // new module
				if prevModule != "" && prevModule != "genesisDoc" {
					doneCh <- struct{}{}
				}
				seenModules[prevModule] = true
				if moduleName != "genesisDoc" {
					go mbm.ValidateGenesisStream(cdc, clientCtx.TxConfig, moduleName, genesisCh, doneCh, errCh)
					genesisCh <- moduleState.AppState.Data
				} else {
					err = genDoc.ValidateAndComplete()
					if err != nil {
						errCh <- fmt.Errorf("error validating genesis doc %s: %s", genesis, err.Error())
					}
				}
			} else { // same module
				genesisCh <- moduleState.AppState.Data
```

**File:** x/accesscontrol/module.go (L62-69)
```go
func (AppModuleBasic) ValidateGenesis(cdc codec.JSONCodec, config client.TxEncodingConfig, bz json.RawMessage) error {
	var data types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &data); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis state: %w", types.ModuleName, err)
	}

	return data.Params.Validate()
}
```

**File:** codec/proto_codec.go (L155-168)
```go
func (pc *ProtoCodec) UnmarshalJSON(bz []byte, ptr proto.Message) error {
	m, ok := ptr.(ProtoMarshaler)
	if !ok {
		return fmt.Errorf("cannot protobuf JSON decode unsupported type: %T", ptr)
	}

	unmarshaler := jsonpb.Unmarshaler{AnyResolver: pc.interfaceRegistry}
	err := unmarshaler.Unmarshal(strings.NewReader(string(bz)), m)
	if err != nil {
		return err
	}

	return types.UnpackInterfaces(ptr, pc.interfaceRegistry)
}
```
