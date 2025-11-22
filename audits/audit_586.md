## Title
Genesis Balance Duplication Allows Supply Inflation via Bypassed Validation

## Summary
The `ValidateAccountInGenesis` function and genesis initialization process improperly handle duplicate account entries in genesis balances. While the bank module's `ValidateGenesis` checks for duplicates, this validation is not automatically enforced during node startup. When duplicate balances exist, `InitGenesis` overwrites the account balance with the last occurrence but accumulates all occurrences into the total supply, creating an exploitable supply inflation vulnerability.

## Impact
**High**

## Finding Description

**Location:** 
- Primary issue: [1](#0-0) 
- Validation bypass: [2](#0-1) 
- Balance overwrite mechanism: [3](#0-2) 

**Intended Logic:** 
The genesis state should contain exactly one balance entry per account. The bank module's validation logic [4](#0-3)  is designed to detect and reject duplicate account balances during genesis validation. The total supply should equal the sum of all account balances.

**Actual Logic:** 
1. `SanitizeGenesisBalances` only sorts balances without removing duplicates [5](#0-4) 
2. During `InitGenesis`, the code loops through ALL balance entries including duplicates [6](#0-5) 
3. The `initBalances` function uses `Set()` which OVERWRITES existing balances [7](#0-6) 
4. However, the `totalSupply` accumulates by ADDING each balance entry [8](#0-7) 
5. Result: If account A appears twice with [100 tokens, 50 tokens], the final state is: A has 50 tokens but supply shows 150 tokens

**Exploit Scenario:**
1. An attacker creates a malicious genesis.json file with duplicate balance entries for target accounts
2. The attacker bypasses the `gentx` and `validate-genesis` commands which would catch duplicates [9](#0-8) 
3. During `collect-gentxs`, validation is NOT performed and the balancesMap only keeps the last occurrence [10](#0-9) 
4. When nodes start with the `start` command, no automatic genesis validation occurs [11](#0-10) 
5. `InitGenesis` processes the duplicate entries, creating inflated supply
6. The supply mismatch check may be bypassed if the attacker also manipulates the Supply field to match the inflated calculation

**Security Failure:** 
This breaks the fundamental accounting invariant that total supply must equal the sum of all actual account balances. It enables supply inflation attacks that can destabilize the entire economic model of the blockchain.

## Impact Explanation

**Assets Affected:** The entire token supply and economic integrity of the blockchain.

**Severity of Damage:**
- **Direct Supply Inflation:** Attackers can artificially inflate the reported total supply without creating actual tokens in accounts
- **Economic Exploits:** The supply discrepancy can be exploited in DeFi protocols that rely on accurate supply data
- **Protocol Instability:** Breaks core invariants that other modules and external systems depend upon
- **Consensus Risk:** Different nodes may have different views of supply if some validate genesis and others don't

**Why This Matters:**
The total supply is a critical protocol parameter used for:
- Monetary policy calculations
- Staking rewards distribution
- Economic security assumptions
- External integrations and price discovery
- Inflation/deflation mechanisms

A manipulated supply undermines trust in the entire blockchain's economic system.

## Likelihood Explanation

**Who Can Trigger:**
- Chain coordinators during genesis file preparation
- Any party responsible for collecting and distributing the genesis.json file
- Validators who skip the recommended `validate-genesis` command

**Conditions Required:**
1. The ability to modify or create the genesis.json file
2. Validators/nodes that start without running explicit `validate-genesis` command
3. The genesis coordinator bypassing or not using the standard `gentx` workflow

**Frequency:**
- **One-time at genesis:** This vulnerability is exploited during chain initialization
- **High likelihood in practice:** Many chain launches involve manual genesis file preparation where the `validate-genesis` command is optional and not enforced programmatically
- **Difficult to detect:** Once a chain starts with inflated supply, the discrepancy persists and may go unnoticed until economic anomalies appear

The vulnerability is realistic because the validation is not mandatory - it's an optional CLI command that coordinators might skip during rushed deployments or if unaware of its importance.

## Recommendation

1. **Enforce automatic genesis validation during node startup** in the `start` command before InitChain is called:
   - Add `mbm.ValidateGenesis()` call in `server/start.go` before initializing the application
   - Make genesis validation mandatory and non-bypassable

2. **Add duplicate detection in InitGenesis as defense-in-depth:**
   - Modify `x/bank/keeper/genesis.go` to check for duplicates even if validation was skipped
   - Panic immediately if duplicate addresses are detected during balance initialization

3. **Strengthen CollectTxs validation:**
   - In `x/genutil/collect.go`, add explicit duplicate checking when building balancesMap
   - Return an error if duplicate accounts are detected

4. **Add invariant check after InitGenesis:**
   - After all modules complete InitGenesis, verify that the sum of all account balances equals the total supply
   - Panic if there's any discrepancy

## Proof of Concept

**File:** `x/bank/keeper/genesis_test.go`

**Test Function:** Add a new test case `TestInitGenesisWithDuplicateBalances`

**Setup:**
1. Create a GenesisState with duplicate balance entries for the same account address
2. First entry: account with 100 tokens
3. Second entry: same account with 50 tokens  
4. Set the Supply field to 150 tokens (sum of both entries) to bypass the supply check

**Trigger:**
1. Call `BankKeeper.InitGenesis(ctx, genesisState)` with the duplicate balance genesis state
2. The function should complete without panicking (demonstrating the vulnerability)

**Observation:**
1. Query the account balance - it will show 50 tokens (last occurrence)
2. Query the total supply - it will show 150 tokens (sum of both entries)
3. Calculate actual sum of all account balances - it equals 50 tokens
4. Demonstrate the discrepancy: totalSupply (150) ≠ sum of actual balances (50)
5. This proves a 100 token supply inflation occurred

The test demonstrates that duplicate balances bypass proper validation during InitGenesis, creating an artificial supply inflation that violates the fundamental invariant that total supply must equal the sum of all account balances. This vulnerability can be exploited at genesis time to permanently inflate the protocol's token supply.

### Citations

**File:** x/bank/keeper/genesis.go (L18-27)
```go
	genState.Balances = types.SanitizeGenesisBalances(genState.Balances)
	for _, balance := range genState.Balances {
		addr := balance.GetAddress()
		coins := balance.Coins
		if err := k.initBalances(ctx, addr, coins); err != nil {
			panic(fmt.Errorf("error on setting balances %w", err))
		}

		totalSupply = totalSupply.Add(coins...)
	}
```

**File:** x/genutil/gentx.go (L55-78)
```go
	genBalIterator.IterateGenesisBalances(cdc, appGenesisState,
		func(bal bankexported.GenesisBalance) (stop bool) {
			accAddress := bal.GetAddress()
			accCoins := bal.GetCoins()

			// ensure that account is in genesis
			if accAddress.Equals(addr) {
				// ensure account contains enough funds of default bond denom
				if coins.AmountOf(bondDenom).GT(accCoins.AmountOf(bondDenom)) {
					err = fmt.Errorf(
						"account %s has a balance in genesis, but it only has %v%s available to stake, not %v%s",
						addr, accCoins.AmountOf(bondDenom), bondDenom, coins.AmountOf(bondDenom), bondDenom,
					)

					return true
				}

				accountIsInGenesis = true
				return true
			}

			return false
		},
	)
```

**File:** x/bank/keeper/send.go (L277-294)
```go
// An error is returned upon failure.
func (k BaseSendKeeper) initBalances(ctx sdk.Context, addr sdk.AccAddress, balances sdk.Coins) error {
	accountStore := k.getAccountStore(ctx, addr)
	for i := range balances {
		balance := balances[i]
		if !balance.IsValid() {
			return sdkerrors.Wrap(sdkerrors.ErrInvalidCoins, balance.String())
		}

		// Bank invariants require to not store zero balances.
		if !balance.IsZero() {
			bz := k.cdc.MustMarshal(&balance)
			accountStore.Set([]byte(balance.Denom), bz)
		}
	}

	return nil
}
```

**File:** x/bank/types/genesis.go (L56-61)
```go
	seenBalances := make(map[string]bool)
	for _, balance := range genState.Balances {
		if seenBalances[balance.Address] {
			return nil, fmt.Errorf("duplicate balance for address %s", balance.Address)
		}
		seenBalances[balance.Address] = true
```

**File:** x/bank/types/balance.go (L53-74)
```go
func SanitizeGenesisBalances(balances []Balance) []Balance {
	// Given that this function sorts balances, using the standard library's
	// Quicksort based algorithms, we have algorithmic complexities of:
	// * Best case: O(nlogn)
	// * Worst case: O(n^2)
	// The comparator used MUST be cheap to use lest we incur expenses like we had
	// before whereby sdk.AccAddressFromBech32, which is a very expensive operation
	// compared n * n elements yet discarded computations each time, as per:
	//  https://github.com/cosmos/cosmos-sdk/issues/7766#issuecomment-786671734

	// 1. Retrieve the address equivalents for each Balance's address.
	addresses := make([]sdk.AccAddress, len(balances))
	for i := range balances {
		addr, _ := sdk.AccAddressFromBech32(balances[i].Address)
		addresses[i] = addr
	}

	// 2. Sort balances.
	sort.Sort(balanceByAddress{addresses: addresses, balances: balances})

	return balances
}
```

**File:** x/genutil/client/cli/gentx.go (L96-98)
```go
			if err = mbm.ValidateGenesis(cdc, txEncCfg, genesisState); err != nil {
				return errors.Wrap(err, "failed to validate genesis state")
			}
```

**File:** x/genutil/collect.go (L88-96)
```go
	balancesMap := make(map[string]bankexported.GenesisBalance)

	genBalIterator.IterateGenesisBalances(
		cdc, appState,
		func(balance bankexported.GenesisBalance) (stop bool) {
			balancesMap[balance.GetAddress().String()] = balance
			return false
		},
	)
```

**File:** server/start.go (L196-201)
```go
			if !config.Genesis.StreamImport {
				genesisFile, _ := tmtypes.GenesisDocFromFile(serverCtx.Config.GenesisFile())
				if genesisFile.ChainID != clientCtx.ChainID {
					panic(fmt.Sprintf("genesis file chain-id=%s does not equal config.toml chain-id=%s", genesisFile.ChainID, clientCtx.ChainID))
				}
			}
```
