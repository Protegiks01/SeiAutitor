## Audit Report

## Title
Missing Address-to-Public-Key Validation in Ledger Device Response Enables Public Key Substitution Attack

## Summary
The `SaveLedgerKey` function in `crypto/keyring/keyring.go` and its underlying `getPubKeyAddrSafe` function in `crypto/ledger/ledger_secp256k1.go` fail to validate that the address returned by a Ledger hardware wallet actually corresponds to the public key returned by the same device. This allows a compromised Ledger device to substitute a malicious public key while displaying a legitimate address to the user, leading to direct loss of funds. [1](#0-0) [2](#0-1) 

## Impact
**High** - Direct loss of funds

## Finding Description

**Location:**
- Primary: `crypto/ledger/ledger_secp256k1.go`, function `getPubKeyAddrSafe()` at lines 273-289
- Secondary: `crypto/keyring/keyring.go`, function `SaveLedgerKey()` at lines 356-372

**Intended Logic:**
When a user adds a Ledger hardware wallet key, the system should:
1. Retrieve the public key from the Ledger device at a specific BIP44 derivation path
2. Display the corresponding address to the user on the Ledger screen for confirmation
3. Store the validated public key in the keyring
4. Ensure the stored public key derives to the address the user confirmed

The security invariant is that the public key stored in the keyring must correspond to the address displayed and confirmed by the user on their Ledger device.

**Actual Logic:**
The `getPubKeyAddrSafe` function receives both a `publicKey` and an `addr` from the Ledger device via `device.GetAddressPubKeySECP256K1()`. The function validates that the public key is a valid secp256k1 curve point using `btcec.ParsePubKey()`, but **never validates that the returned address actually derives from the returned public key**. [3](#0-2) 

Furthermore, in `SaveLedgerKey`, the address returned from the Ledger is immediately discarded (line 366: `priv, _, err :=`), and only the unvalidated public key is stored. [4](#0-3) 

Later, when the key is used, addresses are derived from the stored public key via `GetAddress()` which computes `RIPEMD160(SHA256(pubkey))`. [5](#0-4) [6](#0-5) 

**Exploit Scenario:**
1. Attacker compromises a Ledger device's firmware (or supplies a malicious Ledger-like device)
2. User connects the compromised device and runs: `keys add mykey --ledger --coin-type 118 --account 0 --index 0`
3. The compromised Ledger device:
   - Derives the **correct** public key and address for the requested HD path
   - Displays the **correct** address (e.g., `cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h`) on its screen
   - User sees this address and confirms it
   - Returns to the host computer:
     - `addr` = the correct address string `"cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h"`
     - `publicKey` = a **different** malicious public key (for which the attacker controls the private key)
4. The code validates the malicious public key is a valid secp256k1 point (passes `btcec.ParsePubKey`)
5. The code does NOT validate that `publicKey` derives to `addr`
6. The malicious public key is stored in the keyring
7. When the user later queries their key info (via `keys show mykey`), they see a **different** address derived from the malicious public key (e.g., `cosmos1attacker...`)
8. User may not immediately notice the mismatch
9. Any funds sent to the derived address `cosmos1attacker...` are controlled by the attacker who knows the private key

**Security Failure:**
This breaks the fundamental security property that hardware wallets provide: the guarantee that the address shown on the trusted display corresponds to the key being stored. The validation gap allows address-to-public-key binding to be broken, enabling public key substitution attacks.

## Impact Explanation

**Assets Affected:** User funds sent to addresses derived from Ledger keys added via `SaveLedgerKey`.

**Severity:** An attacker with a compromised Ledger device can steal all funds sent to addresses the user believes are secured by their legitimate hardware wallet. Since users trust the Ledger screen as the source of truth for address verification, they will confirm the legitimate address displayed, unaware that a different public key (and thus a different address) is being stored.

**Concrete Impact:**
- Users lose all funds sent to the derived address
- The attack is undetectable at the time of key creation since the Ledger shows the correct address
- Users only discover the issue after funds are sent and the attacker claims them
- This fundamentally undermines the security model of hardware wallets

This vulnerability enables **direct loss of funds**, which is explicitly in scope as a High severity impact.

## Likelihood Explanation

**Who can trigger:** Any attacker who can compromise Ledger firmware or supply a malicious hardware wallet device to the victim.

**Conditions required:**
- User must add a new Ledger key using the compromised device
- No additional privileges or special network conditions needed
- Attack succeeds during normal operation

**Frequency:** Every time a user adds a Ledger key with a compromised device, the malicious public key is stored. The attack is persistent - once the malicious key is stored, all future funds sent to that address are at risk.

**Realistic attack vector:** While compromising Ledger firmware is non-trivial, supply chain attacks and malicious device substitution are realistic threat vectors. The vulnerability makes such attacks more impactful because users have no way to detect the substitution through the code's validation.

## Recommendation

Add validation in the `getPubKeyAddrSafe` function to verify that the address returned by the device matches the address derived from the public key:

```go
// In crypto/ledger/ledger_secp256k1.go, getPubKeyAddrSafe function
// After line 286, add:

import sdk "github.com/cosmos/cosmos-sdk/types"

// Validate that the address matches the public key
pub := &secp256k1.PubKey{Key: compressedPublicKey}
expectedAddr := sdk.AccAddress(pub.Address()).String()
if expectedAddr != addr {
    return nil, "", fmt.Errorf("address validation failed: device returned address %s but public key derives to address %s - possible device compromise", addr, expectedAddr)
}
```

This ensures that if a compromised device returns mismatched values, the validation will fail and the key will not be stored, protecting users from the attack.

## Proof of Concept

**File:** `crypto/ledger/ledger_secp256k1_test.go` (new test file or add to existing test file)

**Test Function:** `TestMaliciousLedgerPublicKeySubstitution`

**Setup:**
Create a malicious mock Ledger device that implements the `SECP256K1` interface but returns mismatched public key and address values.

**Test Code:**

```go
package ledger

import (
	"testing"
	
	"github.com/stretchr/testify/require"
	
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// MaliciousLedgerMock simulates a compromised Ledger device that returns
// a malicious public key but displays a legitimate address to the user
type MaliciousLedgerMock struct{}

func (mock MaliciousLedgerMock) Close() error {
	return nil
}

func (mock MaliciousLedgerMock) GetPublicKeySECP256K1(derivationPath []uint32) ([]byte, error) {
	// Return a different public key (attacker-controlled)
	attackerPrivKey := secp256k1.GenPrivKey()
	return attackerPrivKey.PubKey().Bytes(), nil
}

func (mock MaliciousLedgerMock) GetAddressPubKeySECP256K1(derivationPath []uint32, hrp string) ([]byte, string, error) {
	// Get the CORRECT public key for this path (what should be shown to user)
	legitimateMock := LedgerSECP256K1Mock{}
	correctPk, correctAddr, err := legitimateMock.GetAddressPubKeySECP256K1(derivationPath, hrp)
	if err != nil {
		return nil, "", err
	}
	
	// But return a MALICIOUS public key (attacker-controlled)
	attackerPrivKey := secp256k1.GenPrivKey()
	maliciousPk := attackerPrivKey.PubKey().Bytes()
	
	// Return malicious PK with correct address - this is the vulnerability
	return maliciousPk, correctAddr, nil
}

func (mock MaliciousLedgerMock) SignSECP256K1(derivationPath []uint32, message []byte) ([]byte, error) {
	return nil, nil
}

// TestMaliciousLedgerPublicKeySubstitution demonstrates the vulnerability
func TestMaliciousLedgerPublicKeySubstitution(t *testing.T) {
	// Temporarily replace the discoverLedger function with our malicious mock
	originalDiscover := discoverLedger
	defer func() { discoverLedger = originalDiscover }()
	
	discoverLedger = func() (SECP256K1, error) {
		return MaliciousLedgerMock{}, nil
	}
	
	// User adds a Ledger key
	path := *hd.NewFundraiserParams(0, sdk.CoinType, 0)
	priv, returnedAddr, err := NewPrivKeySecp256k1(path, "cosmos")
	
	// The operation should succeed (this is the vulnerability)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotEmpty(t, returnedAddr)
	
	// Derive the actual address from the stored public key
	actualAddr := sdk.AccAddress(priv.PubKey().Address()).String()
	
	// VULNERABILITY DEMONSTRATION:
	// The returned address (what user saw on Ledger) differs from the actual stored key's address
	// This proves the address validation is missing
	require.NotEqual(t, returnedAddr, actualAddr, 
		"VULNERABILITY: Malicious public key was accepted! "+
		"User saw address %s on Ledger but actual stored key derives to address %s. "+
		"Funds sent to %s will be lost!", 
		returnedAddr, actualAddr, actualAddr)
	
	t.Logf("Vulnerability confirmed:")
	t.Logf("  Address shown to user (on Ledger): %s", returnedAddr)
	t.Logf("  Address from stored public key:     %s", actualAddr)
	t.Logf("  These addresses DIFFER - attacker can steal funds sent to %s", actualAddr)
}
```

**Expected Behavior:**
- **Current (vulnerable) code:** Test passes, demonstrating that mismatched public key and address are accepted
- **After fix:** Test should fail or the `NewPrivKeySecp256k1` call should return an error when address validation detects the mismatch

**Observation:**
The test proves that a compromised Ledger device can successfully substitute a malicious public key while displaying a legitimate address. The code accepts this without validation, storing the malicious key. The test output shows two different addresses, confirming the vulnerability allows public key substitution attacks that lead to direct loss of funds.

### Citations

**File:** crypto/keyring/keyring.go (L356-372)
```go
func (ks keystore) SaveLedgerKey(uid string, algo SignatureAlgo, hrp string, coinType, account, index uint32) (Info, error) {
	if !ks.options.SupportedAlgosLedger.Contains(algo) {
		return nil, fmt.Errorf(
			"%w: signature algo %s is not defined in the keyring options",
			ErrUnsupportedSigningAlgo, algo.Name(),
		)
	}

	hdPath := hd.NewFundraiserParams(account, coinType, index)

	priv, _, err := ledger.NewPrivKeySecp256k1(*hdPath, hrp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ledger key: %w", err)
	}

	return ks.writeLedgerKey(uid, priv.PubKey(), *hdPath, algo.Name())
}
```

**File:** crypto/ledger/ledger_secp256k1.go (L273-289)
```go
func getPubKeyAddrSafe(device SECP256K1, path hd.BIP44Params, hrp string) (types.PubKey, string, error) {
	publicKey, addr, err := device.GetAddressPubKeySECP256K1(path.DerivationPath(), hrp)
	if err != nil {
		return nil, "", fmt.Errorf("%w: address rejected for path %s", err, path.String())
	}

	// re-serialize in the 33-byte compressed format
	cmp, err := btcec.ParsePubKey(publicKey)
	if err != nil {
		return nil, "", fmt.Errorf("error parsing public key: %v", err)
	}

	compressedPublicKey := make([]byte, secp256k1.PubKeySize)
	copy(compressedPublicKey, cmp.SerializeCompressed())

	return &secp256k1.PubKey{Key: compressedPublicKey}, addr, nil
}
```

**File:** crypto/keyring/info.go (L119-121)
```go
func (i ledgerInfo) GetAddress() types.AccAddress {
	return i.PubKey.Address().Bytes()
}
```

**File:** crypto/keys/secp256k1/secp256k1.go (L149-159)
```go
// Address returns a Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("length of pubkey is incorrect")
	}

	sha := sha256.Sum256(pubKey.Key)
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha[:]) // does not error
	return crypto.Address(hasherRIPEMD160.Sum(nil))
}
```
