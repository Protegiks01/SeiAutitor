**Generate 150 security audit questions for a Cosmos‑SDK/CometBFT codebase.**

**Context**: The target project is a Cosmos‑based L1 chain or appchain (e.g., Sei, Neutron, Gaia). It is built on the Cosmos‑SDK, CometBFT (formerly Tendermint) consensus engine and may integrate modules such as x/authz, x/bank, x/staking, x/gov, x/ibc, x/group, and CosmWasm smart‑contract support. The chain may include custom modules and hooks (BeginBlocker/EndBlocker), as well as IBC middleware. The codebase uses Go; the business logic spans multiple files, and invariants (state consistency checks) may be defined across modules.

**Scope**:
- Note only focus on **[contrib](/Cosmos/sei-cosmos/contrib)
[cosmovisor](/Cosmos/sei-cosmos/cosmovisor)
[crypto](/Cosmos/sei-cosmos/crypto)
[docs](/Cosmos/sei-cosmos/docs)
[ics23](/Cosmos/sei-cosmos/ics23)
[internal](/Cosmos/sei-cosmos/internal)
[proto](/Cosmos/sei-cosmos/proto)
[scripts](/Cosmos/sei-cosmos/scripts)
[server](/Cosmos/sei-cosmos/server)
[simapp](/Cosmos/sei-cosmos/simapp)
[snapshots](/Cosmos/sei-cosmos/snapshots)
[std](/Cosmos/sei-cosmos/std)
[store](/Cosmos/sei-cosmos/store)
[storev2](/Cosmos/sei-cosmos/storev2)
[tasks](/Cosmos/sei-cosmos/tasks)
[telemetry](/Cosmos/sei-cosmos/telemetry)
[tests](/Cosmos/sei-cosmos/tests)
[testutil](/Cosmos/sei-cosmos/testutil)
[third_party](/Cosmos/sei-cosmos/third_party)
[types](/Cosmos/sei-cosmos/types)
[utils](/Cosmos/sei-cosmos/utils)
[version](/Cosmos/sei-cosmos/version)** folder and all files in it this is very important 
- Focus on **Cosmos‑specific logic and invariants** rather than generic Go patterns.

**Some Known Focus Areas**:
- **Consensus logic & state transitions**: CometBFT consensus rules (block proposal, vote extensions, commit, fork choice), changes to consensus parameters, and cross‑module interactions. Check for determinism, proper validation of commit signatures, and correct handling of vote 
- **AnteHandler & transaction processing**: Pre‑execution checks for fees, signatures, mempool filtering, and nested messages. Look for bypasses in custom AnteHandlers (e.g., x/authz `MsgExec` nested messages):contentReference
- **BeginBlocker/EndBlocker & panic handling**: Ensure module hooks do not panic or run unbounded loops. Unhandled panics in these hooks can halt the chain
- **Gas metering & fee market**: Verify that expensive operations (in modules or custom logic) are metered. Unmetered computation in hooks or mispriced state operations can lead to DoS:contentReference
- **Module logic & invariants**: x/bank (token supply vs. account balances), x/staking (bonding/unbonding, slashing), x/gov (proposal execution, tallying), x/authz/x/group (permission management), x/distribution (rewards) – check invariants defined in the code and whether state transitions preserve them
- **IBC & cross‑chain communication**: Packet proof verification, channel handshake logic, timeout/retry callbacks, relayer interactions, source‑channel authentication, and reentrancy in IBC application modules:contentReference
- **Storage & key design**: Ensure KV store keys are deterministic and collision‑free; verify prefix management to avoid state corruption
- **Non‑determinism sources**: Iteration over Go maps, use of `time.Now()` instead of block time, floating‑point arithmetic, unsafe concurrency – all can cause consensus split
- **CosmWasm integration**: Contract execution, gas accounting, reentrancy via cross‑module hooks, memory safety, and correct handling of panics or errors returned from the Wasm VM.
- **Upgrades & parameter changes**: Governance‑driven upgrades or parameter changes; verify that upgrade handlers correctly migrate state and respect invariants.
- **P2P networking & RPC/API**: Node‑to‑node message parsing (ABCI), mempool propagation, RPC/grpc/gRPC‑Gateway endpoints – look for malformed message handling or DoS vectors.

**Goals**:
- Each question should target a **real, exploitable vulnerability scenario** in a Cosmos chain. Focus on external attack surfaces: malicious transactions, untrusted IBC packets, malformed P2P messages, or RPC calls from unauthenticated users.
- Draw on **historical Cosmos vulnerability patterns** as inspiration (e.g., nested message bypasses, consensus non‑determinism due to time.Now, chain halts from unhandled panics{index=13}, underpriced gas leading to DoS, and IBC packet forgery.
- Emphasise **invariants**: design questions that check whether core invariants (e.g., total supply = sum of account balances, bonded tokens ≤ total supply, distribution module keeps reward pools intact) are preserved across transactions and module interactions.
- Formulate questions that are **specific to the codebase**: mention relevant modules, files, functions, or invariants and hypothesise how an attacker could exploit them (e.g., “Does the Bank module’s `SendCoins` implementation in `x/bank/keeper/msg_server.go` correctly update supply and prevent overflow?”).
- Avoid repeating known patched issues unless there’s evidence the project’s modifications could reintroduce them.
- Prioritise high‑impact or critical vulnerabilities that would be accepted in programs like Sherlock and Immunefi (e.g., chain halts, consensus failures, fund loss, unauthorized transfers).

**Constraints**:
- Assume validators and chain operators are honest (privileged actions are trusted). Focus on attacks by unprivileged users or external nodes.
- Questions must be **concrete and actionable**, guiding the AI agent to inspect a specific invariant, function, or logic path to see if it could break under malicious input.
- Do not include generic Go issues unrelated to the Cosmos framework (e.g., standard web server bugs), and avoid trivialities like gas optimizations or style issues.
- Ensure breadth: collectively cover consensus, AnteHandlers, module logic, gas, storage, IBC, CosmWasm, networking, and API layers.


**Impact In Scope** 
* Direct loss of funds
* Critical
* Permanent freezing of funds (fix requires hard fork)
* High
* RPC API crash affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer
* High
* Unintended permanent chain split requiring hard fork (network partition requiring hard fork)
* High
* Network not being able to confirm new transactions (total network shutdown)
* Medium
* Increasing network processing node resource consumption by at least 30% without brute force actions, compared to the preceding 24 hours
* Medium
* Shutdown of greater than or equal to 30% of network processing nodes without brute force actions, but does not shut down the network
* Medium
* A bug in the respective layer 0/1/2 network code that results in unintended smart contract behavior with no concrete funds at direct risk
* Medium
* Temporary freezing of network transactions by delaying one block by 500% or more of the average block time of the preceding 24 hours beyond standard difficulty adjustments
* Medium
* Causing network processing nodes to process transactions from the mempool beyond set parameters
* Low
* Shutdown of greater than 10% or equal to but less than 30% of network processing nodes without brute force actions, but does not shut down the network
* Low
* Modification of transaction fees outside of design parameters


**Output**: Produce a list of **150 distinct, well‑phrased security audit questions**. Each question should stand on its own, specify where in the code (module/file/function) or which invariant it concerns, and hint at the conditions under which a real attacker could exploit a flaw. The questions should collectively cover all the focus areas and meet the above goals, providing a robust starting point for an AI‑driven security audit.


