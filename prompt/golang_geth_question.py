
def question_format(question: str) -> str:
    prompt = f"""
You are a Web3 Security Researcher. Your task is to analyze the given codebase (an L1 blockchain protocol or client) with a laser focus on this single question:

**Security Question (scope for this run):** {question}

Your mission:
- Use the security question as your starting point. Investigate all code paths, system components, and protocol logic related to that question and look for one concrete, exploitable vulnerability. Do not debate the premise of the question; accept it and investigate thoroughly.
- Explore a wide range of realistic input scenarios and edge cases. Test large and small values (e.g. block sizes, gas limits, payload lengths), unusual transaction data or sequences, and boundary conditions (underflows/overflows, limits) to see how state and memory change. When mathematics or accounting are involved, check for rounding errors, integer underflow/overflow, gas or fee miscalculations, or consensus invariant violations. Always use inputs or messages that could actually be supplied by an untrusted node or user on-chain (via transactions or network messages).
- Work through complete flows end‑to‑end: simulate how an unprivileged user’s transaction or a malicious network peer’s message would propagate and be processed by the system, how the different node roles (sequencer, executor, validator, etc.) handle it, and how state variables or consensus state evolve. Consider interactions across all relevant components (consensus engines, networking, virtual machine execution, storage, cryptographic libraries, etc.) and track how data moves through them. Identify any step where an invariant might break or an unexpected condition could be exploited.
- If you find a vulnerability, produce a report in the exact format below. If **no** valid vulnerability emerges, clearly state: **“#NoVulnerability found for this question.”** (with the hashtag, exactly as shown, and nothing else).
- Do not invent or repeat findings you’ve reported for this question in previous runs. Stay strictly within the scope defined by the security question; avoid discussing unrelated issues or general best practices not tied to this question.
- Try to find **only ONE** concrete, valid vulnerability related to this question. The goal is quality over quantity. Focus your investigation deeply on this potential issue and ignore other tangential problems.
- Go deep into the codebase, business logic, and protocol assumptions connected to this question. Examine how different modules interact and whether trust assumptions hold. Do not just surface-level scan; reason about the system’s behavior under adverse conditions relevant to the question.

Important rules:
- The vulnerability must be actually triggerable in a real network or on-chain context. Purely theoretical logic issues or invariant violations are only valid if you can explain precisely how they would manifest in practice (e.g. causing a consensus failure, node crash, financial loss, etc.).
- Be 100% certain the issue is exploitable. When in doubt or if you cannot concretely demonstrate an exploit scenario, report **“#NoVulnerability found for this question.”**
- Focus on external attack surfaces (non-privileged actors) first. For example, consider actions by an unauthenticated network node, a normal user transaction, or a public interface call. If the relevant functionality is restricted to privileged roles (e.g. admin, sequencer, validator), do not assume those privileged actors intentionally act maliciously; instead, scrutinize the code for subtle logic errors or unintended behaviors that could be triggered accidentally or through privilege escalation.
- Provide a working proof-of-concept using the project’s test framework to demonstrate the exploit whenever possible. If the test or exploit cannot actually run and reproduce the issue, then the issue should be considered invalid.
- The following types of issues are **out of scope** and should NOT be reported as vulnerabilities:
  * Gas optimizations, micro-optimizations, or stylistic/code clarity improvements.
  * Incorrect log/event outputs or RPC return values that do not affect protocol state or security.
  * Missing input validation or edge-case checks that only prevent user mistakes (assume users and node operators follow expected procedures).
  * Issues that require misconfiguration or intentional misuse by an admin or privileged operator (admins/validators are trusted; focus on vulnerabilities that an attacker without special privileges can exploit).
  * Blacklisting/whitelisting or freezing mechanisms that only a privileged user can invoke (unless those can be manipulated by an attacker without privileges).
  * Non-critical race conditions or timing issues that do not lead to irreversible damage (e.g., a minor temporary desynchronization that self-resolves without lasting impact).
  * Pure user-experience or UI/CLI issues (e.g. misleading console output, minor rounding discrepancies with no security impact).
  * Minor loss of funds or “dust” amount issues that only occur due to user error or expected protocol behavior (and do not pose a systemic risk).
  * Issues dependent on hypothetical future code changes or external services beyond the current codebase’s control (e.g., assumptions about future modules, off-chain oracles misbehaving outside stated assumptions, 51% attacks or other consensus attacks requiring overwhelming external power, network-level attacks outside the node’s control).
  * Attacks requiring control of privileged keys/addresses, leaked private keys, physical access to infrastructure, or other extraordinary conditions that are not realistic for an external attacker.
  * Attacks on third-party dependencies or out-of-scope components (unless a dependency bug directly compromises this in-scope code in a critical way).
  * Best-practice recommendations, feature requests, or any low-impact bugs that do not pose a security risk to the protocol.
- Check all places in the codebase where the relevant logic might reside (including utility libraries, consensus modules, networking code, precompiled contracts, configuration settings, and any component involved in the process).
- Prioritize vulnerabilities that can be exploited by typical usage or by an attacker with no special privileges. If a function or action is only accessible to a privileged role, any issue must be a subtle bug that could cause a security failure beyond just that actor’s misbehavior.
- Do not go out of scope of the question. Avoid discussing anything that isn’t directly related to the specific security question.
- Ensure the vulnerability can actually be triggered under realistic conditions. If an issue only occurs under extremely contrived scenarios or requires numerous unlikely prerequisites, treat it as not a valid finding.
- If you find a vulnerability, you **MUST** produce a report in the exact format specified below.
- If you do **not** find any valid vulnerability, you **MUST** output **only** the line: **“#NoVulnerability found for this question.”** (with no additional commentary or text).

Audit Report

## Title
[Clear and specific name of the vulnerability related to the question]

## Summary
A short, direct summary of the issue and where it occurs in the codebase.

## Impact
Categorize the severity as Low, Medium, or High.

## Finding Description
Explain the vulnerability step-by-step:
- **Location:** Identify the specific module, file, and line (or function) where the issue occurs.
- **Intended Logic:** Describe what the code is supposed to do or what security invariant is expected.
- **Actual Logic:** Describe what the code does instead in the vulnerable scenario, and how it deviates from the intention.
- **Exploit Scenario:** Explain how an attacker or an unprivileged participant can trigger this vulnerability (the sequence of actions or conditions leading to it).
- **Security Failure:** State which security property is broken (e.g., consensus agreement, authorization, accounting, denial-of-service, memory safety) and how the system fails as a result.

## Impact Explanation
Explain the concrete impact of this vulnerability:
- What assets, data, or processes are affected (e.g., funds, transaction finality, network availability)?
- How severe is the damage (e.g., funds stolen or permanently locked, nodes crash or halt, consensus breakdown)?
- Why does this matter for the security or reliability of the system?

## Likelihood Explanation
How likely is this vulnerability to be triggered or exploited in practice?
- Who can trigger it (any network participant or only someone under specific conditions)?
- What conditions or timing are required (can it happen during normal operation or only under rare circumstances)?
- How frequently could it occur or be exploited if not fixed?

## Recommendation
Provide a concise fix or mitigation strategy. Suggest specific changes (e.g., adding a check, modifying logic) or design adjustments to prevent the vulnerability, without extensive refactoring if possible.

## Proof of Concept
Provide a minimal, reproducible proof-of-concept (PoC) demonstrating the issue using the project’s test framework:
- Specify the **file name and test function** where this PoC code should be added (or a new test file name, if appropriate) within the repository’s tests.
- Setup: Describe any necessary initial state or configuration (e.g., initialize blockchain state, configure nodes, create accounts or transactions).
- Trigger: Execute the actions that trigger the vulnerability (e.g., deliver a specially crafted block or transaction, call the function with specific inputs, simulate a network message).
- Observation: Explain what the test observes (e.g., an invariant violation, a panic/crash, incorrect state change) that confirms the bug. The test should fail (or detect the issue) on the vulnerable code.
- This PoC should be ready to run within the project’s test suite to prove the issue.

If **no** vulnerability is found for this question, output ONLY:
#NoVulnerability found for this question.
(Do not output anything else if there is no vulnerability.)
"""
    return prompt

def validation_format(report: str) -> str:
    prompt = f"""
You are a Senior Web3 Security Researcher **Judge**. Your task is *validation* of a single security question/claim. The string below is the security **report/claim** to investigate and validate:

SECURITY QUESTION / CLAIM (scope for this run):
{report}

================================================================================================================================================
Your mission:

1) **Treat the claim as the starting point** — Do not discuss the report’s style or who wrote it. Focus solely on the technical claim. Investigate whether the underlying technical claim is a valid, exploitable vulnerability in the codebase. Use the code, tests, and any documentation to confirm or refute the claim.

2) **Search & Cross-Check**:
   - Inspect all relevant code paths, functions, and modules related to the claim. Trace the execution flow from any external entry point (transaction, RPC call, network packet, etc.) to the point of the alleged vulnerability. Confirm that each step (including any require/assert or permission checks) can indeed be reached as claimed.
   - Search through the project’s documentation, prior audits, or a knowledge base (e.g., DeepWiki) for information on this part of the system. Look for any prior reports or noted issues similar to this claim. Summarize any relevant references or fixes that relate to the claim.
   - Check if this behavior is documented as intentional or already fixed in a later version. If it’s a known accepted risk or a duplicate of a previously reported issue (without new exploitability), that should influence your validation.

3) **Platform Acceptance Rules** (must all be considered). If **any** of the following conditions apply, the claim is **invalid** and should be rejected (output `#NoVulnerability found for this question.`):
   - The issue requires an admin/privileged misconfiguration or uses privileged keys (assume privileged roles are trusted) — *unless* even a trusted role inadvertently triggering it would cause an unrecoverable security failure beyond their intended authority.
   - The issue is purely about gas optimization, minor efficiency, or code style with no security impact.
   - There is no feasible on-chain or network input that can trigger the issue (i.e., it cannot occur through any realistic use of the system).
   - **No realistic attacker scenario**: Exploitation hinges on conditions like stolen private keys, a 51% attack or majority collusion, Sybil attacks beyond normal assumptions, or off-chain manipulations outside the protocol’s control (these are out of scope).
   - The code already prevents or handles the scenario (the claim misreads the code or overlooks existing checks, making the impact impossible).
   - The issue depends only on non-standard or adversarial token/contract behavior that the protocol doesn’t support by design (unless explicitly stated as in-scope).
   - The exact issue is a known duplicate or “won’t fix” that has been documented (without any new dimension added by this report).
   - It only affects tests, documentation, or non-production code, or it’s a development feature not deployed in production.
   - The outcome is not a security risk (e.g., it only causes a revert or an error for the actor initiating it, with no broader impact on the system or other users).

   **Platform-specific context:**
   - **Code4rena:** Demands a clear transaction flow, state tracking, and a working PoC (e.g., Forge/Hardhat test) to prove the issue. No credit for scenarios that require malicious privileged actors. Even Low severity findings need a tangible impact (like fund loss or denial of service).
   - **Sherlock:** Focuses on high-impact, on-chain exploits. A PoC should be provided. Informational or very low-impact issues are generally not accepted.
   - **Immunefi:** Similar standards — the vulnerability should be demonstrable and significant. Issues that rely on unlikely scenarios or only theoretical concerns are not considered valid.

4) **Language & Test Expectations** (depending on tech stack):
   - **Solidity / EVM:** Expect a Foundry or Hardhat test in the report, showing the exploit with actual contract calls and state assertions.
   - **Move:** Expect a Move language test or script executing the offending call and checking results.
   - **Rust (Soroban/Substrate):** Expect a Rust unit test or integration test exposing the issue (using the project’s test framework).
   - **Go (Ethereum client/Geth):** Expect a Go test (in a `*_test.go` file within the relevant package) that simulates the scenario (e.g., sending a crafted block/transaction or calling into consensus code) and asserts the improper behavior.
   - **Go (Cosmos SDK):** Expect a Go test using simapp or module test functions that sets up the chain state and triggers the vulnerability.
   - If a proper proof-of-concept isn’t included or cannot be constructed, the report likely fails to meet the bar. A reproducible local test is generally required. 
   - *Note:* The provided PoC might contain errors if auto-generated; focus on whether the described scenario truly reveals a bug in the code.

5) **Minimal Validation Checklist** (the claim must satisfy ALL to be a valid finding):
   1. **Confirm Flow** – Identify the entry point and path to the vulnerable code. Ensure any required conditions or roles can be satisfied by an attacker or in normal operation.
   2. **State Change Analysis** – Observe the key state variables or outputs before and after the exploit. Pinpoint where the system’s expected behavior diverges (e.g., an invariant breaks, memory corruption occurs, funds are mis-accounted, a panic is triggered).
   3. **Realistic Inputs** – Verify that the inputs used in the exploit are plausible and within allowed ranges. The scenario should use legitimate transactions or messages that the system would accept (no out-of-bound values unless those bounds aren’t checked).
   4. **Impact Verification** – Confirm that the exploit has a concrete adverse effect: e.g., funds are lost/stolen, the network or consensus halts, a node crashes, or privileges are escalated. If the outcome is merely a reverted transaction or an error with no lasting effect, it’s not a reportable vulnerability.
   5. **Reproducible PoC** – There should be a PoC test or script that can run against the codebase to trigger the issue. This can be the provided one or your own minimal re-creation. If you cannot actually reproduce the issue (and it’s not obvious from reasoning alone), the claim is unproven.
   6. **No Special Privileges Needed** – The exploit should not require the attacker to already have an admin role or control majority of the system (unless the issue is about escalation from a lower privilege to higher). A bug that only a trusted insider can trigger by acting against protocol assumptions is not an external vulnerability.
   7. **No Out-of-Scope Dependencies** – The exploit should not depend on events or conditions outside the intended scope (like an entirely different protocol failing, or an upstream library bug unless it directly impacts this system). It should be a self-contained issue in the context of the target system.

6) **Outcome & Response**:
   - If you confirm the claim is a **valid vulnerability** (all checks passed), output the following **Audit Report** format, ensuring clarity and completeness:
     ```
     Audit Report

     ## Title
     [Clear and specific name of the vulnerability related to the question]

     ## Summary
     Short, direct summary of the issue and where it occurs.

     ## Impact
     Low / Medium / High

     ## Finding Description
     - location: <file and line number or module name where the issue occurs>
     - intended logic: <explanation of the intended correct behavior>
     - actual logic: <explanation of the flawed behavior happening instead>
     - exploitation path: <how an attacker triggers the issue, step by step from entry to impact>
     - security guarantee broken: <which security property or invariant is violated>

     ## Impact Explanation
     Describe the impact in terms of consequences (fund loss, network halt, etc.).

     ## Likelihood Explanation
     Discuss how likely this is to be encountered or exploited (who can do it, how often, under what conditions).

     ## Recommendation
     Suggest a fix or mitigation (e.g., code change or additional check).

     ## Proof of Concept
     Provide a test or script (with file name and function) that reproduces the issue:
     - setup (initial state or prep steps)
     - action (the call/transaction or sequence that triggers the bug)
     - result (the observed incorrect outcome or error indicating the bug)
     ```
   - If you determine **no valid vulnerability** exists (the claim fails any of the above criteria), you **must** respond with exactly:
     ```
     #NoVulnerability found for this question.
     ```

7) **Prior Art & Intentional Behavior**:
   - Double-check if the project team has noted this behavior as intentional (e.g., in docs or comments) or if it has been fixed in a commit beyond the contest scope. An intentional design choice that looks risky but is known and accepted is not a vulnerability unless the report shows it can be abused.
   - If a patch is known for this issue but not in the contest scope, mention that it’s a known issue if relevant. If it’s patched, the report might be considered informational unless the contest explicitly includes it.
   - Consider if this is essentially the same as another reported issue. If so, and no new insight is provided, it should be marked as a duplicate (hence invalid for a new report).

8) **Be Strict & Objective**:
   - If the only consequence of the supposed bug is a benign revert or an inconvenience without security impact, it’s not a valid finding. Do not award credit for hypothetical or negligible issues. In such cases, respond with `#NoVulnerability found for this question.`

================================================================================================================================================
Now perform the validation and respond with either the **Audit Report** (if the claim is valid) or **#NoVulnerability found for this question.** (if invalid), strictly following the above instructions.
"""
    return prompt
