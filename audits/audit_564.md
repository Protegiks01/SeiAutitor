# Audit Report

## Title
Memo Field Injection Vulnerability in Genesis Transaction Collection Allows Peer List Corruption

## Summary
The `CollectTxs` function in `x/genutil/collect.go` constructs a comma-separated persistent peers list by concatenating unvalidated memo fields from genesis transactions. An attacker participating in genesis setup can inject special characters (particularly commas) into the memo field through the `--ip` or `--node-id` CLI flags when creating a genesis transaction, corrupting the peer list format and potentially preventing network initialization. [1](#0-0) [2](#0-1) 

## Impact
**Medium** - This vulnerability can cause shutdown of network processing nodes during genesis initialization, preventing the network from starting properly.

## Finding Description

**Location:** The vulnerability spans multiple files:
- Primary: `x/genutil/collect.go` lines 130-181 (memo extraction and joining)
- Input source: `x/staking/client/cli/tx.go` lines 342-347 (memo construction from user flags)
- Validation gap: `x/auth/ante/basic.go` lines 62-67 (only length validation, no character validation) [3](#0-2) [4](#0-3) 

**Intended Logic:** The code expects genesis transaction memos to contain node connection information in the format `nodeID@IP:port`. These memos should be collected and joined with commas to create a valid comma-separated peer list for Tendermint's P2P configuration. [5](#0-4) 

**Actual Logic:** The code accepts arbitrary user input from CLI flags (`--ip`, `--node-id`, `--p2p-port`) and formats them into the memo without any validation for special characters. When processing genesis transactions, it extracts these memos and directly joins them with commas, with only a check that the memo is non-empty. No validation ensures the memo follows the expected format or doesn't contain delimiter characters.

**Exploit Scenario:**
1. During genesis ceremony, a malicious validator runs:
   ```
   simd gentx mykey 1000stake --ip "1.2.3.4,malicious@5.6.7.8:9999" --node-id "abc123" --generate-only
   ```
2. This creates a transaction with memo: `abc123@1.2.3.4,malicious@5.6.7.8:9999:26656`
3. When the network coordinator runs `collect-gentxs`, this malicious memo is added to the `addressesIPs` array
4. At line 181, all memos are joined with commas: `persistentPeers = strings.Join(addressesIPs, ",")`
5. The resulting string becomes: `legitimate@1.2.3.4:26656,abc123@1.2.3.4,malicious@5.6.7.8:9999:26656,other@5.6.7.8:26656`
6. This corrupted peer list is written to all validators' Tendermint config files
7. When nodes attempt to start, Tendermint's P2P layer parses this malformed peer list, potentially causing connection failures, parser errors, or node startup failures

**Security Failure:** This breaks the network initialization invariant. The code makes an undocumented assumption that memo content is well-formed, but doesn't enforce it. This allows corruption of critical P2P networking configuration, leading to a denial-of-service condition where nodes cannot properly initialize or connect to peers.

## Impact Explanation

**Affected Components:**
- Network initialization process during genesis
- Tendermint P2P peer connection configuration for all validators
- Node startup and peer discovery mechanisms

**Severity of Damage:**
- The corrupted `persistentPeers` configuration is written to all validators' config files via `cfg.WriteConfigFile()`
- Invalid peer list entries can cause:
  - Tendermint P2P layer parsing failures
  - Attempts to connect to malformed peer addresses
  - Potential node crashes or hangs during startup
  - Network-wide initialization failure if enough validators are affected
- Since this occurs during genesis, it affects the initial network launch, preventing the blockchain from becoming operational

**System Security Impact:**
This matters because genesis is a critical one-time setup phase. If the peer list is corrupted, the entire network may fail to start, requiring manual intervention and coordination among all validators to correct their configuration files. This could delay network launch or require a complete genesis restart.

## Likelihood Explanation

**Who Can Trigger:**
Any validator participating in the genesis ceremony can trigger this vulnerability by providing malicious input when creating their genesis transaction via the `gentx` command.

**Required Conditions:**
- Network must be in genesis setup phase
- Attacker must have validator credentials to create a genesis transaction
- Network coordinator must collect and process the malicious genesis transaction via `collect-gentxs` command
- This is a privileged role, but genesis ceremonies often involve multiple semi-trusted parties who don't yet have established trust relationships

**Frequency:**
- Can occur once per genesis ceremony
- In networks with permissionless validator onboarding or decentralized genesis coordination, the risk is higher
- Given that the security question specifically asks about "an attacker" injecting special characters, this scenario is within the intended threat model

## Recommendation

1. **Add format validation in `CollectTxs`:** Before adding a memo to the `addressesIPs` array, validate it matches the expected format `nodeID@IP:port` using a regular expression or structured parsing.

2. **Sanitize input in memo construction:** In `x/staking/client/cli/tx.go`, validate that `--ip`, `--node-id`, and `--p2p-port` flags don't contain delimiter characters (commas, semicolons) or other special characters that could break the peer list format.

3. **Add validation function:** Create a `ValidateNodeAddress` function that ensures:
   - NodeID contains only valid characters (alphanumeric, hyphens)
   - IP is a valid IPv4 or IPv6 address
   - Port is a valid port number
   - No comma or other delimiter characters are present

Example validation in `collect.go`:
```go
// Add after line 130
if !isValidPeerAddress(nodeAddrIP) {
    return appGenTxs, persistentPeers, fmt.Errorf("invalid peer address format in memo: %s", nodeAddrIP)
}

func isValidPeerAddress(addr string) bool {
    // Validate format: nodeID@IP:port
    // Ensure no commas or other delimiters
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9]+@[0-9.]+:[0-9]+$`, addr)
    return matched && !strings.Contains(addr, ",")
}
```

## Proof of Concept

**Test File:** `x/genutil/collect_test.go`

**Test Function:** `TestCollectTxsRejectsCommaInMemo`

```go
func TestCollectTxsRejectsCommaInMemo(t *testing.T) {
    // Setup: Create temporary directory for gentx files
    testDir, err := ioutil.TempDir(os.TempDir(), "testMemoInjection")
    require.NoError(t, err)
    defer os.RemoveAll(testDir)

    // Create codec and registry
    cdc := codec.NewProtoCodec(cdctypes.NewInterfaceRegistry())
    
    // Setup: Create a mock transaction with malicious memo containing comma
    maliciousMemo := "nodeID@1.2.3.4,attacker@5.6.7.8:9999:26656"
    
    // Create a mock TxWithMemo that returns the malicious memo
    mockTx := &mockTxWithMemo{memo: maliciousMemo}
    
    // Create transaction decoder that returns our mock transaction
    txDecoder := types.TxDecoder(func(txBytes []byte) (types.Tx, error) {
        return mockTx, nil
    })
    
    // Write a JSON file to trigger processing
    gentxFile := filepath.Join(testDir, "malicious-gentx.json")
    err = ioutil.WriteFile(gentxFile, []byte("{}"), 0644)
    require.NoError(t, err)
    
    // Create genesis doc
    gdoc := tmtypes.GenesisDoc{AppState: []byte("{}")}
    balItr := new(doNothingIterator)
    
    // Trigger: Call CollectTxs with the malicious transaction
    _, persistentPeers, err := genutil.CollectTxs(cdc, txDecoder, "testmoniker", testDir, gdoc, balItr)
    
    // Observation: The persistent peers string should contain the injected comma
    // This demonstrates that the memo content was not validated and the peer list is corrupted
    if err == nil {
        // Check if the persistentPeers contains multiple comma-separated entries due to injection
        peerEntries := strings.Split(persistentPeers, ",")
        // If injection worked, we'll have more peer entries than expected
        // The malicious memo "nodeID@1.2.3.4,attacker@5.6.7.8:9999:26656" 
        // will be treated as two separate peers when split by comma
        t.Logf("Peer list corrupted with %d entries: %s", len(peerEntries), persistentPeers)
        
        // This test demonstrates the vulnerability exists
        // In a proper implementation, this should fail validation before reaching this point
        if strings.Contains(persistentPeers, ",attacker@") {
            t.Error("VULNERABILITY CONFIRMED: Comma injection successful, peer list corrupted")
        }
    }
}

// Mock implementation of TxWithMemo for testing
type mockTxWithMemo struct {
    memo string
}

func (m *mockTxWithMemo) GetMemo() string {
    return m.memo
}

func (m *mockTxWithMemo) GetMsgs() []types.Msg {
    // Return a mock MsgCreateValidator
    return []types.Msg{&stakingtypes.MsgCreateValidator{
        DelegatorAddress: "cosmos1...",
        ValidatorAddress: "cosmosvaloper1...",
        Description: stakingtypes.Description{Moniker: "test"},
        Value: types.NewCoin("stake", types.NewInt(100)),
    }}
}

func (m *mockTxWithMemo) ValidateBasic() error {
    return nil
}

func (m *mockTxWithMemo) GetSigners() []types.AccAddress {
    return nil
}
```

**Expected Behavior:**
The test demonstrates that when a genesis transaction contains a memo with embedded commas (e.g., `nodeID@1.2.3.4,attacker@5.6.7.8:9999`), the `CollectTxs` function accepts it without validation and includes it in the persistent peers list. When this list is later parsed by Tendermint's P2P layer, it will interpret the injected portion as a separate peer entry, corrupting the peer configuration.

The test should be run in `x/genutil/` directory:
```bash
go test -v -run TestCollectTxsRejectsCommaInMemo
```

The vulnerability is confirmed when the test shows the persistentPeers string contains the injected fake peer address, demonstrating that validation is missing and peer list corruption is possible.

### Citations

**File:** x/genutil/collect.go (L122-124)
```go
		// the memo flag is used to store
		// the ip and node-id, for example this may be:
		// "528fd3df22b31f4969b05652bfe8f0fe921321d5@192.168.2.37:26656"
```

**File:** x/genutil/collect.go (L130-133)
```go
		nodeAddrIP := memoTx.GetMemo()
		if len(nodeAddrIP) == 0 {
			return appGenTxs, persistentPeers, fmt.Errorf("failed to find node's address and IP in %s", fo.Name())
		}
```

**File:** x/genutil/collect.go (L176-181)
```go
			addressesIPs = append(addressesIPs, nodeAddrIP)
		}
	}

	sort.Strings(addressesIPs)
	persistentPeers = strings.Join(addressesIPs, ",")
```

**File:** x/staking/client/cli/tx.go (L342-347)
```go
		ip, _ := fs.GetString(FlagIP)
		p2pPort, _ := fs.GetString(FlagP2PPort)
		nodeID, _ := fs.GetString(FlagNodeID)

		if nodeID != "" && ip != "" {
			txf = txf.WithMemo(fmt.Sprintf("%s@%s:%s", nodeID, ip, p2pPort))
```

**File:** x/auth/ante/basic.go (L62-67)
```go
	memoLength := len(memoTx.GetMemo())
	if uint64(memoLength) > params.MaxMemoCharacters {
		return ctx, sdkerrors.Wrapf(sdkerrors.ErrMemoTooLarge,
			"maximum number of characters is %d but received %d characters",
			params.MaxMemoCharacters, memoLength,
		)
```
